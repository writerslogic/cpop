use anyhow::{anyhow, Result};
use base64::engine::general_purpose;
use base64::Engine as _;

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

pub struct RoughtimeClient;

impl RoughtimeClient {
    pub fn fetch_time(server: &RoughtimeServer) -> Result<u64> {
        let public_key = general_purpose::STANDARD
            .decode(server.public_key_base64)
            .map_err(|e| anyhow!("Invalid server public key: {e}"))?;
        if public_key.len() != 32 {
            return Err(anyhow!("Invalid server public key length"));
        }

        // DEFERRED: Full Roughtime request/response verification pending implementation.
        log::warn!("roughtime: verification not implemented; returning local time anchor");
        Ok(chrono::Utc::now().timestamp_micros() as u64)
    }

    pub fn get_verified_time() -> Result<u64> {
        Self::fetch_time(&SERVERS[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_time_stub() {
        // This test validates the current stub behavior.
        // It should be updated when real Roughtime support is implemented.
        let time = RoughtimeClient::get_verified_time();
        assert!(time.is_ok());

        let ts = time.unwrap();
        // Check reasonable bounds (e.g. not 0, not in far future)
        assert!(ts > 1_600_000_000_000_000); // > Year 2020 in micros
    }
}
