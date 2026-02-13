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
