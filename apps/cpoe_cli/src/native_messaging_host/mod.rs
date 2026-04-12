// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Native Messaging Host for CPoE Browser Extension
//!
//! Implements the Chrome/Firefox Native Messaging protocol:
//! - Reads 4-byte LE length-prefixed JSON from stdin
//! - Writes 4-byte LE length-prefixed JSON to stdout
//! - Translates browser extension messages to cpoe_engine FFI calls
//!
//! Install manifests are in `browser-extension/native-manifests/`.

mod handlers;
mod jitter;
mod protocol;
mod tests;
pub(crate) mod types;

use handlers::{
    handle_checkpoint, handle_get_status, handle_inject_jitter, handle_start_session,
    handle_stop_session,
};
use protocol::{read_message, request_type_name, write_message, PROTOCOL_VERSION};
use types::{Request, Response};

fn main() {
    eprintln!(
        "writerslogic-native-messaging-host v{}",
        env!("CARGO_PKG_VERSION")
    );

    let init_result = cpoe::ffi::ffi_init();
    if !init_result.success {
        eprintln!(
            "Warning: cpoe init failed: {}",
            init_result.error_message.as_deref().unwrap_or("unknown")
        );
    }

    loop {
        let request = match read_message() {
            Ok(Some(req)) => req,
            Ok(None) => {
                eprintln!("Connection closed (EOF)");
                break;
            }
            Err(e) => {
                eprintln!("Read error: {e}");
                let _ = write_message(&Response::Error {
                    message: format!("Invalid message: {e}"),
                    code: "PARSE_ERROR".into(),
                });
                // Stream may be desynchronized after a framing error — terminate
                // to prevent parsing garbage as the next length prefix.
                break;
            }
        };

        eprintln!("Received: {}", request_type_name(&request));

        let response = match request {
            Request::StartSession {
                document_url,
                document_title,
                protocol_version,
            } => {
                if let Some(ref v) = protocol_version {
                    if v != PROTOCOL_VERSION {
                        eprintln!(
                            "protocol_version mismatch: client={v} server={PROTOCOL_VERSION}"
                        ); // intentional
                    }
                }
                handle_start_session(document_url, document_title)
            }
            Request::Checkpoint {
                content_hash,
                char_count,
                delta,
                commitment,
                ordinal,
            } => handle_checkpoint(content_hash, char_count, delta, commitment, ordinal),
            Request::StopSession => handle_stop_session(),
            Request::GetStatus => handle_get_status(),
            Request::InjectJitter { intervals } => handle_inject_jitter(intervals),
            Request::Ping { protocol_version } => {
                if let Some(ref v) = protocol_version {
                    if v != PROTOCOL_VERSION {
                        eprintln!(
                            "protocol_version mismatch: client={v} server={PROTOCOL_VERSION}"
                        ); // intentional
                    }
                }
                Response::Pong {
                    version: env!("CARGO_PKG_VERSION").into(),
                }
            }
        };

        if let Err(e) = write_message(&response) {
            eprintln!("Write error: {e}");
            break;
        }
    }
}
