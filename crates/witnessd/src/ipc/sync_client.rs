// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::crypto::{decode_message, encode_message};
use super::messages::IpcMessage;
use anyhow::{anyhow, Result};
use std::path::PathBuf;
use std::time::Duration;

#[cfg(not(target_os = "windows"))]
use std::io::{Read, Write};

/// Synchronous IPC client using length-prefixed bincode framing.
///
/// NOTE: This client uses a raw bincode wire protocol (no SecureJson magic header).
/// The async `IpcServer` only accepts SecureJson connections and will reject this
/// client. This client is intended for local-only, same-process or test scenarios
/// where the server side also speaks raw bincode (e.g. the sentinel's synchronous
/// command socket). It must NOT be used against the async IPC server.
#[cfg(not(target_os = "windows"))]
#[derive(Debug)]
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
        if encoded.len() > super::messages::MAX_MESSAGE_SIZE {
            return Err(anyhow!(
                "Outgoing message too large: {} bytes (max {})",
                encoded.len(),
                super::messages::MAX_MESSAGE_SIZE
            ));
        }
        let len =
            u32::try_from(encoded.len()).map_err(|_| anyhow!("Message length exceeds u32::MAX"))?;
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
#[derive(Debug)]
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
                     Is the CPOP daemon running?",
                    pipe_name,
                    e
                )
            })?;

        Ok(Self { pipe })
    }

    pub fn send_message(&mut self, msg: &IpcMessage) -> Result<()> {
        use std::io::Write;

        let encoded = encode_message(msg)?;
        if encoded.len() > super::messages::MAX_MESSAGE_SIZE {
            return Err(anyhow!(
                "Outgoing message too large: {} bytes (max {})",
                encoded.len(),
                super::messages::MAX_MESSAGE_SIZE
            ));
        }
        let len =
            u32::try_from(encoded.len()).map_err(|_| anyhow!("Message length exceeds u32::MAX"))?;
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
