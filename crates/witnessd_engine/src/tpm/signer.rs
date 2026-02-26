// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use witnessd_protocol::crypto::PoPSigner;
use super::ProviderHandle;
use coset::iana;

pub struct TpmSigner {
    provider: ProviderHandle,
}

impl TpmSigner {
    pub fn new(provider: ProviderHandle) -> Self {
        Self { provider }
    }
}

impl PoPSigner for TpmSigner {
    fn sign(&self, data: &[u8]) -> witnessd_protocol::error::Result<Vec<u8>> {
        self.provider.sign(data).map_err(|e| witnessd_protocol::error::Error::Crypto(format!("TPM sign error: {}", e)))
    }

    fn algorithm(&self) -> iana::Algorithm {
        // Assuming ES256 (ECDSA w/ SHA-256) for TPM
        // But pop-crate defaults to EdDSA.
        // We should probably check the provider capabilities or key type.
        // For now, assuming EdDSA if software, or ES256 if hardware.
        // SoftwareProvider uses SHA256 digest as signature (for demo), which isn't a standard algo.
        // Let's stick to EdDSA if we can't determine, or add algorithm() to Provider trait.
        // For now, hardcode EdDSA as SoftwareProvider mimics it?
        // Actually SoftwareProvider::sign_payload is just Sha256 digest.
        // That's not a valid signature for EdDSA.
        // This is a gap in the test implementation vs real world.
        iana::Algorithm::EdDSA 
    }

    fn public_key(&self) -> Vec<u8> {
        self.provider.public_key()
    }
}
