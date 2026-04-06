// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::ProviderHandle;
use coset::iana;
use authorproof_protocol::crypto::EvidenceSigner;

pub struct TpmSigner {
    provider: ProviderHandle,
}

impl TpmSigner {
    pub fn new(provider: ProviderHandle) -> Self {
        Self { provider }
    }
}

impl EvidenceSigner for TpmSigner {
    fn sign(&self, data: &[u8]) -> authorproof_protocol::error::Result<Vec<u8>> {
        self.provider
            .sign(data)
            .map_err(|e| authorproof_protocol::error::Error::Crypto(format!("TPM sign error: {}", e)))
    }

    fn algorithm(&self) -> iana::Algorithm {
        self.provider.algorithm()
    }

    fn public_key(&self) -> Vec<u8> {
        self.provider.public_key()
    }
}
