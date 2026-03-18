// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::{AnchorError, AnchorProvider, Proof, ProofStatus, ProviderType};
use async_trait::async_trait;

/// Anchor provider that embeds hashes in Bitcoin OP_RETURN transactions.
pub struct BitcoinProvider {
    rpc_url: String,
    rpc_user: String,
    rpc_password: String,
    network: BitcoinNetwork,
    client: reqwest::Client,
}

/// Bitcoin network selector.
#[derive(Debug, Clone, Copy)]
pub enum BitcoinNetwork {
    /// Production Bitcoin network.
    Mainnet,
    /// Public test network.
    Testnet,
    /// Local regression testing network.
    Regtest,
}

impl BitcoinProvider {
    /// Create a provider with explicit RPC credentials and network.
    pub fn new(
        rpc_url: String,
        rpc_user: String,
        rpc_password: String,
        network: BitcoinNetwork,
    ) -> Self {
        Self {
            rpc_url,
            rpc_user,
            rpc_password,
            network,
            client: reqwest::Client::new(),
        }
    }

    /// Create from `BITCOIN_RPC_URL`, `BITCOIN_RPC_USER`, `BITCOIN_RPC_PASSWORD` env vars.
    pub fn from_env() -> Result<Self, AnchorError> {
        let rpc_url = std::env::var("BITCOIN_RPC_URL")
            .map_err(|_| AnchorError::Unavailable("BITCOIN_RPC_URL not set".into()))?;
        let rpc_user = std::env::var("BITCOIN_RPC_USER").unwrap_or_default();
        let rpc_password = std::env::var("BITCOIN_RPC_PASSWORD").unwrap_or_default();
        let network = match std::env::var("BITCOIN_NETWORK").as_deref() {
            Ok("mainnet") => BitcoinNetwork::Mainnet,
            Ok("testnet") => BitcoinNetwork::Testnet,
            Ok("regtest") => BitcoinNetwork::Regtest,
            _ => BitcoinNetwork::Mainnet,
        };
        Ok(Self::new(rpc_url, rpc_user, rpc_password, network))
    }

    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AnchorError> {
        super::http::json_rpc_call_with_auth(
            &self.client,
            &self.rpc_url,
            method,
            params,
            &self.rpc_user,
            &self.rpc_password,
        )
        .await
    }

    async fn create_op_return_tx(&self, hash: &[u8; 32]) -> Result<String, AnchorError> {
        let utxos = self.rpc_call("listunspent", serde_json::json!([])).await?;
        let utxos = utxos
            .as_array()
            .ok_or_else(|| AnchorError::Submission("No UTXOs available".into()))?;
        if utxos.is_empty() {
            return Err(AnchorError::Submission("No UTXOs available".into()));
        }

        let utxo = &utxos[0];
        let txid = utxo["txid"].as_str().unwrap_or("");
        let vout = utxo["vout"].as_u64().unwrap_or(0);
        let amount = utxo["amount"].as_f64().unwrap_or(0.0);

        if txid.is_empty() || amount <= 0.0 {
            return Err(AnchorError::Submission("Invalid UTXO".into()));
        }

        let change_address = self
            .rpc_call("getnewaddress", serde_json::json!([]))
            .await?;
        let change_address = change_address.as_str().unwrap_or("");

        let fee = 0.0001;
        let change_amount = amount - fee;
        if change_amount <= 0.0 {
            return Err(AnchorError::Submission("Insufficient funds".into()));
        }

        let inputs = serde_json::json!([
            {"txid": txid, "vout": vout}
        ]);

        let outputs = serde_json::json!({
            change_address: change_amount,
            "data": hex::encode(hash)
        });

        let raw_tx = self
            .rpc_call("createrawtransaction", serde_json::json!([inputs, outputs]))
            .await?;

        let signed = self
            .rpc_call("signrawtransactionwithwallet", serde_json::json!([raw_tx]))
            .await?;
        let signed_hex = signed["hex"].as_str().unwrap_or("");

        let txid = self
            .rpc_call("sendrawtransaction", serde_json::json!([signed_hex]))
            .await?;

        Ok(txid.as_str().unwrap_or("").to_string())
    }

    async fn get_tx_confirmations(&self, txid: &str) -> Result<u64, AnchorError> {
        let tx = self
            .rpc_call("gettransaction", serde_json::json!([txid]))
            .await?;
        Ok(tx["confirmations"].as_u64().unwrap_or(0))
    }
}

#[async_trait]
impl AnchorProvider for BitcoinProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Bitcoin
    }

    fn name(&self) -> &str {
        "Bitcoin"
    }

    async fn is_available(&self) -> bool {
        self.rpc_call("getblockchaininfo", serde_json::json!([]))
            .await
            .is_ok()
    }

    async fn submit(&self, hash: &[u8; 32]) -> Result<Proof, AnchorError> {
        let txid = self.create_op_return_tx(hash).await?;

        Ok(Proof {
            id: txid.clone(),
            provider: ProviderType::Bitcoin,
            status: ProofStatus::Pending,
            anchored_hash: *hash,
            submitted_at: chrono::Utc::now(),
            confirmed_at: None,
            proof_data: txid.as_bytes().to_vec(),
            location: Some(txid),
            attestation_path: None,
            extra: [(
                "network".to_string(),
                serde_json::json!(format!("{:?}", self.network)),
            )]
            .into_iter()
            .collect(),
        })
    }

    async fn check_status(&self, proof: &Proof) -> Result<Proof, AnchorError> {
        let txid = proof.location.clone().unwrap_or_default();
        if txid.is_empty() {
            return Err(AnchorError::InvalidFormat("Missing txid".into()));
        }

        let confirmations = self.get_tx_confirmations(&txid).await?;
        let mut updated = proof.clone();
        if confirmations > 0 {
            updated.status = ProofStatus::Confirmed;
            updated.confirmed_at = Some(chrono::Utc::now());
            updated.location = Some(format!("{} ({} conf)", txid, confirmations));
        }
        Ok(updated)
    }

    async fn verify(&self, proof: &Proof) -> Result<bool, AnchorError> {
        let txid = proof.location.clone().unwrap_or_default();
        if txid.is_empty() {
            return Err(AnchorError::InvalidFormat("Missing txid".into()));
        }
        let confirmations = self.get_tx_confirmations(&txid).await?;
        Ok(confirmations > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_provider_init() {
        let provider = BitcoinProvider::new(
            "http://localhost:8332".to_string(),
            "user".to_string(),
            "pass".to_string(),
            BitcoinNetwork::Testnet,
        );
        assert_eq!(provider.provider_type(), ProviderType::Bitcoin);
        assert_eq!(provider.name(), "Bitcoin");
    }

    #[test]
    fn test_bitcoin_provider_from_env_missing() {
        if std::env::var("BITCOIN_RPC_URL").is_err() {
            assert!(BitcoinProvider::from_env().is_err());
        }
    }
}
