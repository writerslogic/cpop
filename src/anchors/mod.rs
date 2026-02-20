mod bitcoin;
mod ethereum;
mod notary;
mod ots;
mod rfc3161;
mod types;
mod verification;

pub use types::*;
pub use verification::verify_proof;

use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait AnchorProvider: Send + Sync {
    fn provider_type(&self) -> ProviderType;
    fn name(&self) -> &str;
    async fn is_available(&self) -> bool;
    async fn submit(&self, hash: &[u8; 32]) -> Result<Proof, AnchorError>;
    async fn check_status(&self, proof: &Proof) -> Result<Proof, AnchorError>;
    async fn verify(&self, proof: &Proof) -> Result<bool, AnchorError>;
    async fn upgrade(&self, _proof: &Proof) -> Result<Option<Proof>, AnchorError> {
        Ok(None)
    }
}

pub type ProviderHandle = Arc<dyn AnchorProvider>;

pub struct AnchorManager {
    providers: Vec<ProviderHandle>,
    config: AnchorManagerConfig,
}

#[derive(Debug, Clone)]
pub struct AnchorManagerConfig {
    pub multi_anchor: bool,
    pub timeout: std::time::Duration,
    pub retry_count: u32,
}

impl Default for AnchorManagerConfig {
    fn default() -> Self {
        Self {
            multi_anchor: true,
            timeout: std::time::Duration::from_secs(30),
            retry_count: 3,
        }
    }
}

impl AnchorManager {
    pub fn new(config: AnchorManagerConfig) -> Self {
        Self {
            providers: Vec::new(),
            config,
        }
    }

    pub fn add_provider(&mut self, provider: ProviderHandle) {
        self.providers.push(provider);
    }

    pub fn with_default_providers() -> Self {
        let mut manager = Self::new(AnchorManagerConfig::default());
        manager.add_provider(Arc::new(ots::OpenTimestampsProvider::new()));
        manager.add_provider(Arc::new(rfc3161::Rfc3161Provider::default()));
        if let Ok(btc) = bitcoin::BitcoinProvider::from_env() {
            manager.add_provider(Arc::new(btc));
        }
        if let Ok(eth) = ethereum::EthereumProvider::from_env() {
            manager.add_provider(Arc::new(eth));
        }
        if let Ok(notary) = notary::NotaryProvider::from_env() {
            manager.add_provider(Arc::new(notary));
        }
        manager
    }

    pub async fn anchor(&self, hash: &[u8; 32]) -> Result<Anchor, AnchorError> {
        let mut anchor = Anchor::new(*hash);
        let mut last_error = None;

        for provider in &self.providers {
            if !provider.is_available().await {
                continue;
            }

            match provider.submit(hash).await {
                Ok(proof) => {
                    anchor.add_proof(proof);
                    if !self.config.multi_anchor {
                        break;
                    }
                }
                Err(e) => {
                    log::warn!("Provider {} failed: {e}", provider.name());
                    last_error = Some(e);
                }
            }
        }

        if anchor.proofs.is_empty() {
            return Err(
                last_error.unwrap_or(AnchorError::Unavailable("No providers available".into()))
            );
        }

        Ok(anchor)
    }

    pub async fn refresh(&self, anchor: &mut Anchor) -> Result<(), AnchorError> {
        for proof in &mut anchor.proofs {
            if proof.status != ProofStatus::Pending {
                continue;
            }

            if let Some(provider) = self
                .providers
                .iter()
                .find(|p| p.provider_type() == proof.provider)
            {
                match provider.check_status(proof).await {
                    Ok(updated) => *proof = updated,
                    Err(e) => log::warn!("Status check failed: {e}"),
                }

                if let Ok(Some(upgraded)) = provider.upgrade(proof).await {
                    *proof = upgraded;
                }
            }
        }

        if anchor
            .proofs
            .iter()
            .any(|p| p.status == ProofStatus::Confirmed)
        {
            anchor.status = ProofStatus::Confirmed;
        }

        Ok(())
    }

    pub async fn verify_anchor(&self, anchor: &Anchor) -> Result<bool, AnchorError> {
        for proof in &anchor.proofs {
            if proof.status != ProofStatus::Confirmed {
                continue;
            }
            if proof.anchored_hash != anchor.hash {
                return Err(AnchorError::HashMismatch);
            }
            if let Some(provider) = self
                .providers
                .iter()
                .find(|p| p.provider_type() == proof.provider)
            {
                if provider.verify(proof).await? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
