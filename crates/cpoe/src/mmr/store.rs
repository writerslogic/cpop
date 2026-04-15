// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::mmr::errors::MmrError;
use crate::mmr::node::{Node, NODE_SIZE};
use crate::RwLockRecover;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::RwLock;

pub trait Store: Send + Sync {
    fn append(&self, node: &Node) -> Result<(), MmrError>;
    fn get(&self, index: u64) -> Result<Node, MmrError>;
    fn size(&self) -> Result<u64, MmrError>;
    fn sync(&self) -> Result<(), MmrError>;
    fn close(&self) -> Result<(), MmrError>;
}

#[derive(Debug)]
pub struct FileStore {
    file: RwLock<File>,
    writer: RwLock<BufWriter<File>>,
    size: RwLock<u64>,
    cache: RwLock<HashMap<u64, Node>>,
    append_count: std::sync::atomic::AtomicU32,
}

const AUTO_SYNC_THRESHOLD: u32 = 100;

impl FileStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, MmrError> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // MMR store is appended to, not truncated
            .open(path)?;
        crate::crypto::restrict_permissions(path, 0o600)?;
        let metadata = file.metadata()?;
        let len = metadata.len();
        if len % NODE_SIZE as u64 != 0 {
            return Err(MmrError::CorruptedStore);
        }
        let node_count = len / NODE_SIZE as u64;
        let mut append_file = file.try_clone()?;
        append_file.seek(SeekFrom::End(0))?;
        Ok(Self {
            file: RwLock::new(file),
            writer: RwLock::new(BufWriter::with_capacity(4096, append_file)),
            size: RwLock::new(node_count),
            cache: RwLock::new(HashMap::new()),
            append_count: std::sync::atomic::AtomicU32::new(0),
        })
    }
}

impl Store for FileStore {
    fn append(&self, node: &Node) -> Result<(), MmrError> {
        let mut size = self.size.write_recover();
        if node.index != *size {
            return Err(MmrError::CorruptedStore);
        }
        let mut writer = self.writer.write_recover();
        writer.write_all(&node.serialize())?;
        self.cache.write_recover().insert(node.index, node.clone());
        *size += 1;

        if self
            .append_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            >= AUTO_SYNC_THRESHOLD
        {
            drop(writer);
            drop(size);
            self.sync()?;
        }

        Ok(())
    }

    fn get(&self, index: u64) -> Result<Node, MmrError> {
        let size = *self.size.read_recover();
        if index >= size {
            return Err(MmrError::IndexOutOfRange);
        }
        if let Some(node) = self.cache.read_recover().get(&index) {
            return Ok(node.clone());
        }
        {
            let mut writer = self.writer.write_recover();
            writer.flush()?;
        }
        let mut file = self.file.write_recover();
        let offset = index * NODE_SIZE as u64;
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; NODE_SIZE];
        file.read_exact(&mut buf)?;
        Node::deserialize(&buf)
    }

    fn size(&self) -> Result<u64, MmrError> {
        Ok(*self.size.read_recover())
    }

    fn sync(&self) -> Result<(), MmrError> {
        {
            let mut writer = self.writer.write_recover();
            writer.flush()?;
        }
        self.cache.write_recover().clear();
        self.append_count
            .store(0, std::sync::atomic::Ordering::SeqCst);
        let file = self.file.read_recover();
        file.sync_all()?;
        Ok(())
    }

    fn close(&self) -> Result<(), MmrError> {
        self.sync()
    }
}

#[derive(Debug)]
pub struct MemoryStore {
    nodes: RwLock<Vec<Node>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(Vec::new()),
        }
    }
}

impl Store for MemoryStore {
    fn append(&self, node: &Node) -> Result<(), MmrError> {
        let mut nodes = self.nodes.write_recover();
        if node.index != nodes.len() as u64 {
            return Err(MmrError::CorruptedStore);
        }
        nodes.push(node.clone());
        Ok(())
    }

    fn get(&self, index: u64) -> Result<Node, MmrError> {
        let nodes = self.nodes.read_recover();
        if index >= nodes.len() as u64 {
            return Err(MmrError::IndexOutOfRange);
        }
        Ok(nodes[index as usize].clone())
    }

    fn size(&self) -> Result<u64, MmrError> {
        Ok(self.nodes.read_recover().len() as u64)
    }

    fn sync(&self) -> Result<(), MmrError> {
        Ok(())
    }

    fn close(&self) -> Result<(), MmrError> {
        Ok(())
    }
}
