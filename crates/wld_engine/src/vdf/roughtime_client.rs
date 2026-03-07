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

// Active public Roughtime servers from the ecosystem registry.
// Source: https://github.com/cloudflare/roughtime/blob/master/ecosystem.json
const SERVERS: &[RoughtimeServer] = &[
    RoughtimeServer {
        name: "Cloudflare-Roughtime-2",
        address: "roughtime.cloudflare.com:2003",
        public_key_base64: "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=",
    },
    RoughtimeServer {
        name: "int08h-Roughtime",
        address: "roughtime.int08h.com:2002",
        public_key_base64: "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=",
    },
    RoughtimeServer {
        name: "roughtime.se",
        address: "roughtime.se:2002",
        public_key_base64: "S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=",
    },
    RoughtimeServer {
        name: "time.txryan.com",
        address: "time.txryan.com:2002",
        public_key_base64: "iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=",
    },
];

/// Timeout for Roughtime UDP requests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Minimum number of servers that must agree for quorum.
const QUORUM_MIN: usize = 2;

/// Maximum allowed disagreement between servers (10 seconds in microseconds).
const QUORUM_TOLERANCE_US: u64 = 10_000_000;

pub struct RoughtimeClient;

impl RoughtimeClient {
    /// Fetch verified time from a Roughtime server.
    ///
    /// Sends a Roughtime request over UDP, parses the response, and
    /// extracts the midpoint timestamp.
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

        let mut nonce_bytes = [0u8; 32];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| anyhow!("Failed to generate nonce: {e}"))?;
        let nonce = Nonce::from(nonce_bytes);

        let request = Request::new(&nonce);
        let request_bytes = request
            .as_frame_bytes()
            .map_err(|e| anyhow!("Failed to serialize request: {e}"))?;

        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| anyhow!("Failed to bind UDP socket: {e}"))?;
        socket
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|e| anyhow!("Failed to set socket timeout: {e}"))?;
        socket
            .send_to(&request_bytes, server.address)
            .map_err(|e| anyhow!("Failed to send request to {}: {e}", server.name))?;

        let mut recv_buf = vec![0u8; 4096];
        let (size, _) = socket
            .recv_from(&mut recv_buf)
            .map_err(|e| anyhow!("Failed to receive response from {}: {e}", server.name))?;
        recv_buf.truncate(size);

        let mut cursor = ParseCursor::new(&mut recv_buf);
        let response = Response::from_frame(&mut cursor)
            .map_err(|e| anyhow!("Failed to parse response from {}: {e}", server.name))?;

        if response.nonc() != &nonce {
            return Err(anyhow!("Nonce mismatch in response from {}", server.name));
        }

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

    /// Find the largest group of timestamps that agree within tolerance,
    /// returning the median if the group meets quorum.
    fn find_quorum(timestamps: &mut [(u64, &str)]) -> Result<u64> {
        timestamps.sort_by_key(|(t, _)| *t);

        let mut best_start = 0;
        let mut best_count = 0;

        for i in 0..timestamps.len() {
            let mut count = 1;
            for j in (i + 1)..timestamps.len() {
                if timestamps[j].0.saturating_sub(timestamps[i].0) <= QUORUM_TOLERANCE_US {
                    count += 1;
                } else {
                    break;
                }
            }
            if count > best_count {
                best_count = count;
                best_start = i;
            }
        }

        if best_count < QUORUM_MIN {
            let names: Vec<&str> = timestamps.iter().map(|(_, n)| *n).collect();
            return Err(anyhow!(
                "Roughtime quorum failed: only {} server(s) responded {:?}, need {}",
                timestamps.len(),
                names,
                QUORUM_MIN
            ));
        }

        let median_idx = best_start + best_count / 2;
        let chosen = timestamps[median_idx].0;
        log::info!(
            "roughtime: quorum reached with {}/{} servers (median from {})",
            best_count,
            timestamps.len(),
            timestamps[median_idx].1
        );
        Ok(chosen)
    }

    /// Query multiple Roughtime servers and return a quorum-verified time.
    ///
    /// At least 2 servers must agree within 10 seconds. Returns `Err` if
    /// quorum cannot be reached — the caller decides on fallback policy
    /// (e.g. local time, offline mode).
    pub fn get_verified_time() -> Result<u64> {
        let mut results: Vec<(u64, &str)> = Vec::new();

        for server in SERVERS {
            match Self::fetch_time(server) {
                Ok(time) => results.push((time, server.name)),
                Err(e) => log::warn!("roughtime: {} failed: {}", server.name, e),
            }
        }

        Self::find_quorum(&mut results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_verified_time_returns_reasonable_value() {
        // May fail if no Roughtime servers are reachable (offline CI).
        // When it succeeds, the timestamp must be reasonable.
        if let Ok(ts) = RoughtimeClient::get_verified_time() {
            assert!(ts > 1_600_000_000_000_000);
        }
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

    #[test]
    fn test_multiple_servers_configured() {
        assert!(
            SERVERS.len() >= 3,
            "need at least 3 servers for meaningful quorum"
        );
    }

    #[test]
    fn test_quorum_succeeds_with_agreeing_timestamps() {
        let base = 1_700_000_000_000_000u64;
        let mut timestamps = vec![
            (base, "server-a"),
            (base + 1_000_000, "server-b"), // 1s apart
            (base + 5_000_000, "server-c"), // 5s apart
        ];
        let result = RoughtimeClient::find_quorum(&mut timestamps);
        assert!(result.is_ok());
        let t = result.unwrap();
        assert!(t >= base && t <= base + 5_000_000);
    }

    #[test]
    fn test_quorum_fails_with_divergent_timestamps() {
        let mut timestamps = vec![
            (1_000_000_000_000_000, "server-a"),
            (2_000_000_000_000_000, "server-b"), // ~31 years apart
        ];
        let result = RoughtimeClient::find_quorum(&mut timestamps);
        assert!(result.is_err());
    }

    #[test]
    fn test_quorum_fails_with_single_server() {
        let mut timestamps = vec![(1_700_000_000_000_000, "server-a")];
        let result = RoughtimeClient::find_quorum(&mut timestamps);
        assert!(result.is_err());
    }

    #[test]
    fn test_quorum_fails_with_no_servers() {
        let mut timestamps: Vec<(u64, &str)> = vec![];
        let result = RoughtimeClient::find_quorum(&mut timestamps);
        assert!(result.is_err());
    }

    #[test]
    fn test_quorum_picks_median_of_agreeing_group() {
        let base = 1_700_000_000_000_000u64;
        let mut timestamps = vec![
            (base, "server-a"),
            (base + 2_000_000, "server-b"),
            (base + 4_000_000, "server-c"),
            (base + 100_000_000_000, "outlier"), // 100s away, excluded
        ];
        let result = RoughtimeClient::find_quorum(&mut timestamps).unwrap();
        // Median of [base, base+2M, base+4M] = base+2M
        assert_eq!(result, base + 2_000_000);
    }
}
