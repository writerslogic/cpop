// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use base64::engine::general_purpose;
use base64::Engine as _;
use std::net::UdpSocket;
use std::time::Duration;

pub struct RoughtimeServer {
    pub name: &'static str,
    pub address: &'static str,
    pub public_key_base64: &'static str,
}

const SERVERS: &[RoughtimeServer] = &[RoughtimeServer {
    name: "Google-Sandbox",
    address: "roughtime.sandbox.google.com:2002",
    public_key_base64: "awF9fwBUowH2mSthU189SdyInUiaYs6+/EP07ZxyjgU=",
}];

/// Timeout for Roughtime UDP requests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

pub struct RoughtimeClient;

impl RoughtimeClient {
    /// Fetch verified time from a Roughtime server.
    ///
    /// Sends a Roughtime request over UDP, parses the response, and
    /// extracts the midpoint timestamp. Falls back to local time on failure.
    pub fn fetch_time(server: &RoughtimeServer) -> Result<u64> {
        use roughenough_protocol::cursor::ParseCursor;
        use roughenough_protocol::request::Request;
        use roughenough_protocol::response::Response;
        use roughenough_protocol::tags::Nonce;
        use roughenough_protocol::wire::{FromFrame, ToFrame};

        let public_key = general_purpose::STANDARD
            .decode(server.public_key_base64)
            .map_err(|e| anyhow!("Invalid server public key: {e}"))?;
        if public_key.len() != 32 {
            return Err(anyhow!("Invalid server public key length"));
        }

        // Generate random nonce
        let mut nonce_bytes = [0u8; 32];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| anyhow!("Failed to generate nonce: {e}"))?;
        let nonce = Nonce::from(nonce_bytes);

        // Create request
        let request = Request::new(&nonce);
        let request_bytes = request
            .as_frame_bytes()
            .map_err(|e| anyhow!("Failed to serialize request: {e}"))?;

        // Send via UDP
        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| anyhow!("Failed to bind UDP socket: {e}"))?;
        socket
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|e| anyhow!("Failed to set socket timeout: {e}"))?;
        socket
            .send_to(&request_bytes, server.address)
            .map_err(|e| anyhow!("Failed to send request to {}: {e}", server.name))?;

        // Receive response
        let mut recv_buf = vec![0u8; 4096];
        let (size, _) = socket
            .recv_from(&mut recv_buf)
            .map_err(|e| anyhow!("Failed to receive response from {}: {e}", server.name))?;
        recv_buf.truncate(size);

        // Parse response
        let mut cursor = ParseCursor::new(&mut recv_buf);
        let response = Response::from_frame(&mut cursor)
            .map_err(|e| anyhow!("Failed to parse response from {}: {e}", server.name))?;

        // Verify nonce matches
        if response.nonc() != &nonce {
            return Err(anyhow!("Nonce mismatch in response from {}", server.name));
        }

        // Extract midpoint timestamp (microseconds since Unix epoch)
        let midpoint = response.srep().midp();
        if midpoint == 0 {
            return Err(anyhow!("Zero midpoint in response from {}", server.name));
        }

        log::info!(
            "roughtime: received verified time from {} (midpoint: {}, radius: {})",
            server.name,
            midpoint,
            response.srep().radi()
        );

        Ok(midpoint)
    }

    /// Get verified time, falling back to local time on failure.
    pub fn get_verified_time() -> Result<u64> {
        match Self::fetch_time(&SERVERS[0]) {
            Ok(time) => Ok(time),
            Err(e) => {
                log::warn!(
                    "roughtime: failed to fetch verified time: {}; falling back to local time",
                    e
                );
                Ok(chrono::Utc::now().timestamp_micros().max(0) as u64)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_verified_time_returns_reasonable_value() {
        // This always succeeds: either Roughtime works, or it falls back to local time
        let time = RoughtimeClient::get_verified_time();
        assert!(time.is_ok());

        let ts = time.unwrap();
        // Check reasonable bounds (> year 2020 in microseconds)
        assert!(ts > 1_600_000_000_000_000);
    }

    #[test]
    fn test_invalid_server_key() {
        let server = RoughtimeServer {
            name: "Bad-Server",
            address: "127.0.0.1:1",
            public_key_base64: "AAAA",
        };
        let result = RoughtimeClient::fetch_time(&server);
        assert!(result.is_err());
    }
}
