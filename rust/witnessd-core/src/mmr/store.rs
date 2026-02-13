use crate::mmr::errors::MmrError;
use crate::mmr::node::{Node, NODE_SIZE};
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

pub struct FileStore {
    file: RwLock<File>,
    writer: RwLock<BufWriter<File>>,
    size: RwLock<u64>,
}

impl FileStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, MmrError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // MMR store is appended to, not truncated
            .open(path)?;
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
        })
    }
}

impl Store for FileStore {
    fn append(&self, node: &Node) -> Result<(), MmrError> {
        let mut size = self.size.write().unwrap();
        if node.index != *size {
            return Err(MmrError::CorruptedStore);
        }
        let mut writer = self.writer.write().unwrap();
        writer.write_all(&node.serialize())?;
        *size += 1;
        Ok(())
    }

    fn get(&self, index: u64) -> Result<Node, MmrError> {
        let size = *self.size.read().unwrap();
        if index >= size {
            return Err(MmrError::IndexOutOfRange);
        }
        {
            let mut writer = self.writer.write().unwrap();
            writer.flush()?;
        }
        let mut file = self.file.write().unwrap();
        let offset = index * NODE_SIZE as u64;
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; NODE_SIZE];
        file.read_exact(&mut buf)?;
        Node::deserialize(&buf)
    }

    fn size(&self) -> Result<u64, MmrError> {
        Ok(*self.size.read().unwrap())
    }

    fn sync(&self) -> Result<(), MmrError> {
        {
            let mut writer = self.writer.write().unwrap();
            writer.flush()?;
        }
        let file = self.file.read().unwrap();
        file.sync_all()?;
        Ok(())
    }

    fn close(&self) -> Result<(), MmrError> {
        self.sync()
    }
}

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
        let mut nodes = self.nodes.write().unwrap();
        if node.index != nodes.len() as u64 {
            return Err(MmrError::CorruptedStore);
        }
        nodes.push(node.clone());
        Ok(())
    }

    fn get(&self, index: u64) -> Result<Node, MmrError> {
        let nodes = self.nodes.read().unwrap();
        if index >= nodes.len() as u64 {
            return Err(MmrError::IndexOutOfRange);
        }
        Ok(nodes[index as usize].clone())
    }

    fn size(&self) -> Result<u64, MmrError> {
        Ok(self.nodes.read().unwrap().len() as u64)
    }

    fn sync(&self) -> Result<(), MmrError> {
        Ok(())
    }

    fn close(&self) -> Result<(), MmrError> {
        Ok(())
    }
}
