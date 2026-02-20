use super::{Binding, Capabilities, Provider, Quote, TPMError};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::sync::Mutex;

pub struct SoftwareProvider {
    state: Mutex<SoftwareState>,
}

struct SoftwareState {
    device_id: String,
    counter: u64,
}

impl Default for SoftwareProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftwareProvider {
    pub fn new() -> Self {
        let seed = Utc::now().to_rfc3339();
        let hash = Sha256::digest(seed.as_bytes());
        let device_id = format!("sw-{}", hex::encode(&hash[..8]));
        Self {
            state: Mutex::new(SoftwareState {
                device_id,
                counter: 0,
            }),
        }
    }

    fn sign_payload(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }
}

impl Provider for SoftwareProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_backed: false,
            supports_pcrs: false,
            supports_sealing: false,
            supports_attestation: true,
            monotonic_counter: true,
            secure_clock: false,
        }
    }

    fn device_id(&self) -> String {
        self.state.lock().unwrap().device_id.clone()
    }

    fn public_key(&self) -> Vec<u8> {
        Vec::new()
    }

    fn quote(&self, nonce: &[u8], _pcrs: &[u32]) -> Result<Quote, TPMError> {
        let device_id = self.device_id();
        let timestamp = Utc::now();
        let mut payload = Vec::new();
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(&timestamp.timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        payload.extend_from_slice(device_id.as_bytes());

        let signature = Self::sign_payload(&payload);

        Ok(Quote {
            provider_type: "software".to_string(),
            device_id,
            timestamp,
            nonce: nonce.to_vec(),
            attested_data: payload,
            signature,
            public_key: Vec::new(),
            pcr_values: Vec::new(),
            extra: Default::default(),
        })
    }

    fn bind(&self, data: &[u8]) -> Result<Binding, TPMError> {
        let mut state = self.state.lock().unwrap();
        state.counter += 1;

        let data_hash = Sha256::digest(data).to_vec();
        let timestamp = Utc::now();

        let mut payload = Vec::new();
        payload.extend_from_slice(&data_hash);
        payload.extend_from_slice(&timestamp.timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        payload.extend_from_slice(state.device_id.as_bytes());

        let signature = Self::sign_payload(&payload);

        Ok(Binding {
            version: 1,
            provider_type: "software".to_string(),
            device_id: state.device_id.clone(),
            timestamp,
            attested_hash: data_hash,
            signature,
            public_key: Vec::new(),
            monotonic_counter: Some(state.counter),
            safe_clock: Some(true),
            attestation: Some(super::Attestation {
                payload,
                quote: None,
            }),
        })
    }

    fn verify(&self, binding: &Binding) -> Result<(), TPMError> {
        crate::tpm::verification::verify_binding(binding)
    }

    fn seal(&self, _data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TPMError> {
        Err(TPMError::Sealing("software provider cannot seal".into()))
    }

    fn unseal(&self, _sealed: &[u8]) -> Result<Vec<u8>, TPMError> {
        Err(TPMError::Unsealing(
            "software provider cannot unseal".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_provider_lifecycle() {
        let provider = SoftwareProvider::new();

        // 1. Capabilities
        let caps = provider.capabilities();
        assert!(!caps.hardware_backed);
        assert!(caps.supports_attestation);
        assert!(caps.monotonic_counter);
        assert!(!caps.supports_sealing);

        // 2. Device ID
        let device_id = provider.device_id();
        assert!(device_id.starts_with("sw-"));

        // 3. Binding
        let data = b"test-binding";
        let binding = provider.bind(data).expect("bind failed");
        assert_eq!(binding.provider_type, "software");
        assert_eq!(binding.device_id, device_id);

        provider.verify(&binding).expect("verify failed");

        // 4. Quote
        let nonce = b"nonce";
        let quote = provider.quote(nonce, &[]).expect("quote failed");
        assert_eq!(quote.nonce, nonce);
        crate::tpm::verify_quote(&quote).expect("quote verify failed");

        // 5. Counter
        // Since we can't easily access internal state directly without consuming the provider or using a lock,
        // we implicitly tested it via bind() which increments the counter.
        // Let's call bind again and check if it might be exposed (it's in the binding).
        let binding2 = provider.bind(data).expect("bind 2");
        assert!(binding2.monotonic_counter.unwrap() > binding.monotonic_counter.unwrap());

        // 6. Sealing (unsupported)
        assert!(provider.seal(b"secret", &[]).is_err());
        assert!(provider.unseal(b"sealed").is_err());
    }
}
