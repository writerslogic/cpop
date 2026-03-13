// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::crypto::{decode_message, encode_message};
use super::messages::IpcMessage;
use anyhow::{anyhow, Result};
use std::path::PathBuf;
use std::time::Duration;

#[cfg(not(target_os = "windows"))]
use std::io::{Read, Write};

#[cfg(not(target_os = "windows"))]
pub struct IpcClient {
    stream: std::os::unix::net::UnixStream,
}

#[cfg(not(target_os = "windows"))]
impl IpcClient {
    pub fn connect(path: PathBuf) -> Result<Self> {
        let stream = std::os::unix::net::UnixStream::connect(&path).map_err(|e| {
            anyhow!(
                "Failed to connect to daemon socket at {}: {}",
                path.display(),
                e
            )
        })?;

        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        Ok(Self { stream })
    }

    pub fn send_message(&mut self, msg: &IpcMessage) -> Result<()> {
        let encoded = encode_message(msg)?;
        let len = encoded.len() as u32;
        self.stream.write_all(&len.to_le_bytes())?;
        self.stream.write_all(&encoded)?;
        self.stream.flush()?;
        Ok(())
    }

    pub fn recv_message(&mut self) -> Result<IpcMessage> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > super::messages::MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large: {} bytes", len));
        }

        let mut buffer = vec![0u8; len];
        self.stream.read_exact(&mut buffer)?;
        decode_message(&buffer)
    }

    pub fn send_and_recv(&mut self, msg: &IpcMessage) -> Result<IpcMessage> {
        self.send_message(msg)?;
        self.recv_message()
    }
}

/// Pipe name: `\\.\pipe\writerslogic-{filename}`. Same length-prefixed
/// bincode wire protocol as the Unix client.
#[cfg(target_os = "windows")]
pub struct IpcClient {
    // std::fs::File can open Named Pipes as regular file handles,
    // avoiding raw Win32 CreateFileW calls.
    pipe: std::fs::File,
}

#[cfg(target_os = "windows")]
impl IpcClient {
    pub fn connect(path: PathBuf) -> Result<Self> {
        let pipe_name = format!(
            r"\\.\pipe\writerslogic-{}",
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "sentinel".to_string())
        );

        let pipe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pipe_name)
            .map_err(|e| {
                anyhow!(
                    "Failed to connect to daemon named pipe at {}: {}. \
                     Is the WritersLogic daemon running?",
                    pipe_name,
                    e
                )
            })?;

        Ok(Self { pipe })
    }

    pub fn send_message(&mut self, msg: &IpcMessage) -> Result<()> {
        use std::io::Write;

        let encoded = encode_message(msg)?;
        let len = encoded.len() as u32;
        self.pipe.write_all(&len.to_le_bytes())?;
        self.pipe.write_all(&encoded)?;
        self.pipe.flush()?;
        Ok(())
    }

    pub fn recv_message(&mut self) -> Result<IpcMessage> {
        use std::io::Read;

        let mut len_buf = [0u8; 4];
        self.pipe.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > super::messages::MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large: {} bytes", len));
        }

        let mut buffer = vec![0u8; len];
        self.pipe.read_exact(&mut buffer)?;
        decode_message(&buffer)
    }

    pub fn send_and_recv(&mut self, msg: &IpcMessage) -> Result<IpcMessage> {
        self.send_message(msg)?;
        self.recv_message()
    }
}
