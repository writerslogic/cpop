// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

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
    ) -> Result<Self, AnchorError> {
        Ok(Self {
            rpc_url,
            rpc_user,
            rpc_password,
            network,
            client: super::http::build_http_client(None)?,
        })
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
        Self::new(rpc_url, rpc_user, rpc_password, network)
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
        let txid = utxo["txid"]
            .as_str()
            .ok_or_else(|| AnchorError::Submission("Invalid UTXO txid".into()))?;
        let vout = utxo["vout"].as_u64().unwrap_or(0);
        // Amounts from bitcoind are BTC floats; convert to satoshis immediately.
        let amount_btc = utxo["amount"]
            .as_f64()
            .ok_or_else(|| AnchorError::Submission("Invalid UTXO amount".into()))?;
        let amount_sats = (amount_btc * 100_000_000.0).round() as u64;

        if txid.is_empty() || amount_sats == 0 {
            return Err(AnchorError::Submission("Invalid UTXO".into()));
        }

        let change_address = self
            .rpc_call("getnewaddress", serde_json::json!([]))
            .await?;
        let change_address = change_address
            .as_str()
            .ok_or_else(|| AnchorError::Submission("Invalid change address from node".into()))?;

        // 10_000 satoshis (0.0001 BTC) fee.
        const FEE_SATS: u64 = 10_000;
        let change_sats = amount_sats
            .checked_sub(FEE_SATS)
            .filter(|&v| v > 0)
            .ok_or_else(|| AnchorError::Submission("Insufficient funds".into()))?;
        // Convert back to BTC float only for the RPC serialization layer.
        let change_amount_btc = change_sats as f64 / 100_000_000.0;

        let inputs = serde_json::json!([
            {"txid": txid, "vout": vout}
        ]);

        let outputs = serde_json::json!({
            change_address: change_amount_btc,
            "data": hex::encode(hash)
        });

        let raw_tx = self
            .rpc_call("createrawtransaction", serde_json::json!([inputs, outputs]))
            .await?;

        let signed = self
            .rpc_call("signrawtransactionwithwallet", serde_json::json!([raw_tx]))
            .await?;
        let signed_hex = signed["hex"].as_str().ok_or_else(|| {
            AnchorError::Submission("Missing hex in signrawtransactionwithwallet response".into())
        })?;

        let result = self
            .rpc_call("sendrawtransaction", serde_json::json!([signed_hex]))
            .await?;
        let txid = result
            .as_str()
            .ok_or_else(|| AnchorError::Submission("Invalid txid from node".into()))?;

        Ok(txid.to_string())
    }

    /// Returns `(confirmations, block_time_secs)`.  `block_time_secs` is 0 when unconfirmed.
    async fn get_tx_info(&self, txid: &str) -> Result<(u64, i64), AnchorError> {
        let tx = self
            .rpc_call("gettransaction", serde_json::json!([txid]))
            .await?;
        let confirmations = tx["confirmations"].as_u64().unwrap_or(0);
        let blocktime = tx["blocktime"].as_i64().unwrap_or(0);
        Ok((confirmations, blocktime))
    }

    /// Fetch the raw transaction and scan its outputs for an OP_RETURN carrying `hash`.
    async fn tx_contains_op_return(
        &self,
        txid: &str,
        hash: &[u8; 32],
    ) -> Result<bool, AnchorError> {
        let tx = self
            .rpc_call("getrawtransaction", serde_json::json!([txid, true]))
            .await?;
        let vout = tx["vout"]
            .as_array()
            .ok_or_else(|| AnchorError::InvalidFormat("getrawtransaction missing vout".into()))?;
        let expected = hex::encode(hash);
        for output in vout {
            let script_type = output["scriptPubKey"]["type"].as_str().unwrap_or("");
            if script_type == "nulldata" {
                let asm = output["scriptPubKey"]["asm"].as_str().unwrap_or("");
                // asm is "OP_RETURN <hex-data>"
                if let Some(data_hex) = asm.strip_prefix("OP_RETURN ") {
                    if data_hex.eq_ignore_ascii_case(&expected) {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
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
        let raw_location = proof.location.clone().unwrap_or_default();
        if raw_location.is_empty() {
            return Err(AnchorError::InvalidFormat("Missing txid".into()));
        }
        // Strip the " (N conf)" suffix that may have been appended on a previous check.
        let txid = raw_location
            .split_whitespace()
            .next()
            .unwrap_or(&raw_location)
            .to_string();

        let (confirmations, blocktime) = self.get_tx_info(&txid).await?;
        let mut updated = proof.clone();
        if confirmations > 0 {
            updated.status = ProofStatus::Confirmed;
            // Use the block timestamp recorded by the network, not wall-clock time.
            updated.confirmed_at = Some(if blocktime > 0 {
                chrono::DateTime::from_timestamp(blocktime, 0).unwrap_or_else(chrono::Utc::now)
            } else {
                chrono::Utc::now()
            });
            updated.location = Some(format!("{} ({} conf)", txid, confirmations));
        }
        Ok(updated)
    }

    async fn verify(&self, proof: &Proof) -> Result<bool, AnchorError> {
        let raw_location = proof.location.clone().unwrap_or_default();
        if raw_location.is_empty() {
            return Err(AnchorError::InvalidFormat("Missing txid".into()));
        }
        // Strip the " (N conf)" suffix that may have been appended by check_status.
        let txid = raw_location
            .split_whitespace()
            .next()
            .unwrap_or(&raw_location)
            .to_string();

        let (confirmations, _) = self.get_tx_info(&txid).await?;
        if confirmations == 0 {
            return Ok(false);
        }
        // Confirm the transaction actually embeds the expected hash in an OP_RETURN output.
        self.tx_contains_op_return(&txid, &proof.anchored_hash)
            .await
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
        )
        .expect("client build should succeed");
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
