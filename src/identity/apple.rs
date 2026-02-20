use anyhow::{anyhow, Result};
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::key::{Algorithm, SecKey};

pub struct SecureEnclaveIdentity {
    pub key: SecKey,
}

impl SecureEnclaveIdentity {
    pub fn load(label: &str) -> Result<Self> {
        let mut search = ItemSearchOptions::default();
        search.class(ItemClass::key());
        search.label(label);
        search.limit(Limit::All);

        let results = search
            .search()
            .map_err(|_| anyhow!("Key not found in Secure Enclave"))?;

        for item in results {
            if let SearchResult::Ref(Reference::Key(k)) = item {
                return Ok(Self { key: k });
            }
        }

        Err(anyhow!("No valid key reference found in Secure Enclave"))
    }

    pub fn sign(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        let signature = self
            .key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, hash)
            .map_err(|e| anyhow!("Hardware signing failed: {:?}", e))?;

        Ok(signature)
    }
}
