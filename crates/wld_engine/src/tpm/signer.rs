// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::ProviderHandle;
use coset::iana;
use wld_protocol::crypto::PoPSigner;

pub struct TpmSigner {
    provider: ProviderHandle,
}

impl TpmSigner {
    pub fn new(provider: ProviderHandle) -> Self {
        Self { provider }
    }
}

impl PoPSigner for TpmSigner {
    fn sign(&self, data: &[u8]) -> wld_protocol::error::Result<Vec<u8>> {
        self.provider
            .sign(data)
            .map_err(|e| wld_protocol::error::Error::Crypto(format!("TPM sign error: {}", e)))
    }

    fn algorithm(&self) -> iana::Algorithm {
        self.provider.algorithm()
    }

    fn public_key(&self) -> Vec<u8> {
        self.provider.public_key()
    }
}
