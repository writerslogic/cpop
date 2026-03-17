// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub mod secure_channel;
#[cfg(unix)]
pub mod unix_socket;

mod async_client;
pub(crate) mod crypto;
mod messages;
mod server;
mod sync_client;

#[cfg(test)]
mod tests;

pub use async_client::{AsyncIpcClient, AsyncIpcClientError};
pub use messages::{IpcErrorCode, IpcMessage, IpcMessageHandler};
pub use server::IpcServer;
pub use sync_client::IpcClient;
