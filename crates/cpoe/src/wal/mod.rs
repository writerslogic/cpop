// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

mod operations;
mod serialization;
mod types;

#[cfg(test)]
mod tests;

pub use types::{Entry, EntryType, Header, Wal, WalError, WalVerification};
