// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Ethereum anchor provider -- submits content hashes to a smart contract
//! via EIP-155 signed transactions with automatic nonce/gas management.

use super::{AnchorError, AnchorProvider, Proof, ProofStatus, ProviderType};
use async_trait::async_trait;
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey, VerifyingKey};
use rlp::RlpStream;
use tiny_keccak::{Hasher, Keccak};

/// Max retries on nonce conflicts
const MAX_NONCE_RETRIES: u32 = 3;

/// secp256k1 curve order `n`, used for EIP-2 `s`-value normalization
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Solidity selector: `keccak256("anchor(bytes32)")[:4]`
const ANCHOR_FUNCTION_SELECTOR: [u8; 4] = [0xee, 0xcd, 0xf9, 0x27];

/// Ethereum anchor provider with EIP-155 transaction signing.
///
/// Signing key is zeroized on drop via `k256` internals.
pub struct EthereumProvider {
    rpc_url: String,
    contract_address: String,
    signing_key: SigningKey,
    chain_id: u64,
    client: reqwest::Client,
    cached_address: String,
}

impl EthereumProvider {
    /// Create a provider with explicit RPC URL, contract, private key, and chain ID.
    pub fn new(
        rpc_url: String,
        contract_address: String,
        private_key_hex: &str,
        chain_id: u64,
    ) -> Result<Self, AnchorError> {
        let key_bytes = zeroize::Zeroizing::new(
            hex_to_bytes(private_key_hex)
                .map_err(|e| AnchorError::Configuration(format!("Invalid private key: {e}")))?,
        );

        if key_bytes.len() != 32 {
            return Err(AnchorError::Configuration(
                "Private key must be 32 bytes".into(),
            ));
        }

        let signing_key = SigningKey::from_bytes(key_bytes.as_slice().into())
            .map_err(|e| AnchorError::Configuration(format!("Invalid secp256k1 key: {e}")))?;

        let cached_address = derive_eth_address(&signing_key);

        Ok(Self {
            rpc_url,
            contract_address: contract_address.to_lowercase(),
            signing_key,
            chain_id,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            cached_address,
        })
    }

    /// Create from environment variables.
    ///
    /// Requires `ETHEREUM_RPC_URL`, `ETHEREUM_CONTRACT_ADDRESS`,
    /// `ETHEREUM_PRIVATE_KEY` (hex, optional `0x`), and optionally
    /// `ETHEREUM_CHAIN_ID` (default: 1).
    pub fn from_env() -> Result<Self, AnchorError> {
        let rpc_url = std::env::var("ETHEREUM_RPC_URL")
            .map_err(|_| AnchorError::Unavailable("ETHEREUM_RPC_URL not set".into()))?;

        if let (Ok(contract), Ok(private_key)) = (
            std::env::var("ETHEREUM_CONTRACT_ADDRESS"),
            std::env::var("ETHEREUM_PRIVATE_KEY"),
        ) {
            let chain_id = std::env::var("ETHEREUM_CHAIN_ID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1u64);

            return Self::new(rpc_url, contract, &private_key, chain_id);
        }

        if std::env::var("ETHEREUM_RAW_TX_TEMPLATE").is_ok() {
            log::warn!(
                "ETHEREUM_RAW_TX_TEMPLATE is deprecated. \
                 Use ETHEREUM_CONTRACT_ADDRESS and ETHEREUM_PRIVATE_KEY instead."
            );
            return Err(AnchorError::Configuration(
                "Legacy ETHEREUM_RAW_TX_TEMPLATE mode is no longer supported. \
                 Please configure ETHEREUM_CONTRACT_ADDRESS and ETHEREUM_PRIVATE_KEY."
                    .into(),
            ));
        }

        Err(AnchorError::Unavailable(
            "Ethereum provider requires ETHEREUM_CONTRACT_ADDRESS and ETHEREUM_PRIVATE_KEY".into(),
        ))
    }

    fn address(&self) -> String {
        self.cached_address.clone()
    }

    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AnchorError> {
        super::http::json_rpc_call(&self.client, &self.rpc_url, method, params).await
    }

    async fn get_nonce(&self) -> Result<u64, AnchorError> {
        let address = self.address();
        let result = self
            .rpc_call(
                "eth_getTransactionCount",
                serde_json::json!([address, "pending"]),
            )
            .await?;

        let nonce_hex = result
            .as_str()
            .ok_or_else(|| AnchorError::Network("Invalid nonce response".into()))?;

        u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16)
            .map_err(|e| AnchorError::Network(format!("Failed to parse nonce: {e}")))
    }

    async fn get_gas_price(&self) -> Result<u128, AnchorError> {
        let result = self.rpc_call("eth_gasPrice", serde_json::json!([])).await?;

        let price_hex = result
            .as_str()
            .ok_or_else(|| AnchorError::Network("Invalid gas price response".into()))?;

        u128::from_str_radix(price_hex.trim_start_matches("0x"), 16)
            .map_err(|e| AnchorError::Network(format!("Failed to parse gas price: {e}")))
    }

    async fn estimate_gas(&self, data: &[u8]) -> Result<u64, AnchorError> {
        let address = self.address();
        let result = self
            .rpc_call(
                "eth_estimateGas",
                serde_json::json!([{
                    "from": address,
                    "to": &self.contract_address,
                    "data": format!("0x{}", hex::encode(data)),
                }]),
            )
            .await;

        match result {
            Ok(gas) => {
                let gas_hex = gas
                    .as_str()
                    .ok_or_else(|| AnchorError::Network("Invalid gas estimate".into()))?;
                let base_gas =
                    u64::from_str_radix(gas_hex.trim_start_matches("0x"), 16).map_err(|e| {
                        AnchorError::Network(format!("Failed to parse gas estimate: {e}"))
                    })?;
                Ok(base_gas * 120 / 100)
            }
            Err(_) => Ok(90000),
        }
    }

    fn encode_anchor_call(&self, content_hash: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&ANCHOR_FUNCTION_SELECTOR);
        data.extend_from_slice(content_hash);
        data
    }

    fn sign_transaction(
        &self,
        nonce: u64,
        gas_price: u128,
        gas_limit: u64,
        data: &[u8],
    ) -> Result<Vec<u8>, AnchorError> {
        let to_bytes = hex_to_bytes(&self.contract_address)
            .map_err(|e| AnchorError::Configuration(format!("Invalid contract address: {e}")))?;

        // EIP-155 signing tuple: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        let mut unsigned = RlpStream::new_list(9);
        unsigned.append(&nonce);
        unsigned.append(&gas_price);
        unsigned.append(&gas_limit);
        unsigned.append(&to_bytes.as_slice());
        unsigned.append(&0u64); // value
        unsigned.append(&data);
        unsigned.append(&self.chain_id);
        unsigned.append(&0u8);
        unsigned.append(&0u8);

        let unsigned_bytes = unsigned.out();

        let mut hasher = Keccak::v256();
        let mut tx_hash = [0u8; 32];
        hasher.update(&unsigned_bytes);
        hasher.finalize(&mut tx_hash);

        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash(&tx_hash)
            .map_err(|e| AnchorError::Signing(format!("Failed to sign transaction: {e}")))?;

        let sig_bytes: [u8; 64] = signature.to_bytes().into();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[0..32]);
        s.copy_from_slice(&sig_bytes[32..64]);

        // EIP-2: force `s` into the lower half of the curve order
        let mut recovery = recovery_id.to_byte();
        if is_high_s(&s) {
            s = negate_s(&s);
            recovery = if recovery == 0 { 1 } else { 0 };
        }

        // EIP-155: v = chainId * 2 + 35 + recovery
        let v = self.chain_id * 2 + 35 + u64::from(recovery);
        let mut signed = RlpStream::new_list(9);
        signed.append(&nonce);
        signed.append(&gas_price);
        signed.append(&gas_limit);
        signed.append(&to_bytes.as_slice());
        signed.append(&0u64); // value
        signed.append(&data);
        signed.append(&v);
        signed.append(&r.as_slice());
        signed.append(&s.as_slice());

        Ok(signed.out().to_vec())
    }

    async fn submit_transaction(&self, content_hash: &[u8; 32]) -> Result<String, AnchorError> {
        let data = self.encode_anchor_call(content_hash);
        let mut last_error = None;

        for attempt in 0..MAX_NONCE_RETRIES {
            let nonce = self.get_nonce().await?;
            let base_gas_price = self.get_gas_price().await?;
            let gas_limit = self.estimate_gas(&data).await?;

            // Bump gas price +15% per retry to outbid stuck txns.
            // First attempt (attempt=0) uses base_gas_price * 100/100 = base_gas_price.
            let gas_multiplier = 100u128 + u128::from(attempt * 15);
            let gas_price = base_gas_price * gas_multiplier / 100;

            log::debug!(
                "Ethereum TX attempt {}/{}: nonce={}, gas_price={}, gas_limit={}",
                attempt + 1,
                MAX_NONCE_RETRIES,
                nonce,
                gas_price,
                gas_limit
            );

            let raw_tx = self.sign_transaction(nonce, gas_price, gas_limit, &data)?;
            let raw_tx_hex = format!("0x{}", hex::encode(&raw_tx));

            match self
                .rpc_call("eth_sendRawTransaction", serde_json::json!([raw_tx_hex]))
                .await
            {
                Ok(result) => {
                    let tx_hash = result.as_str().unwrap_or("").to_string();
                    if tx_hash.is_empty() {
                        return Err(AnchorError::Submission("Empty transaction hash".into()));
                    }
                    log::info!("Ethereum anchor submitted: {}", tx_hash);
                    return Ok(tx_hash);
                }
                Err(e) => {
                    let is_nonce_error = matches!(&e, AnchorError::Submission(msg)
                        if msg.to_lowercase().contains("nonce")
                            || msg.to_lowercase().contains("already known")
                            || msg.to_lowercase().contains("replacement"));

                    if is_nonce_error && attempt < MAX_NONCE_RETRIES - 1 {
                        log::warn!("Nonce conflict on attempt {}, retrying: {}", attempt + 1, e);
                        last_error = Some(e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            1000 * u64::from(attempt + 1),
                        ))
                        .await;
                        continue;
                    }
                    return Err(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            AnchorError::Submission("Transaction failed after max retries".into())
        }))
    }

    async fn get_receipt(&self, txid: &str) -> Result<serde_json::Value, AnchorError> {
        self.rpc_call("eth_getTransactionReceipt", serde_json::json!([txid]))
            .await
    }
}

#[async_trait]
impl AnchorProvider for EthereumProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Ethereum
    }

    fn name(&self) -> &str {
        "Ethereum"
    }

    async fn is_available(&self) -> bool {
        self.rpc_call("eth_chainId", serde_json::json!([]))
            .await
            .is_ok()
    }

    async fn submit(&self, hash: &[u8; 32]) -> Result<Proof, AnchorError> {
        let txid = self.submit_transaction(hash).await?;

        Ok(Proof {
            id: txid.clone(),
            provider: ProviderType::Ethereum,
            status: ProofStatus::Pending,
            anchored_hash: *hash,
            submitted_at: chrono::Utc::now(),
            confirmed_at: None,
            proof_data: txid.as_bytes().to_vec(),
            location: Some(txid.clone()),
            attestation_path: None,
            extra: {
                let mut extra = std::collections::HashMap::new();
                extra.insert(
                    "chain_id".to_string(),
                    serde_json::Value::from(self.chain_id),
                );
                extra.insert(
                    "contract".to_string(),
                    serde_json::Value::from(self.contract_address.clone()),
                );
                extra
            },
        })
    }

    async fn check_status(&self, proof: &Proof) -> Result<Proof, AnchorError> {
        let txid = proof.location.clone().unwrap_or_default();
        if txid.is_empty() {
            return Err(AnchorError::InvalidFormat("Missing txid".into()));
        }

        let receipt = self.get_receipt(&txid).await?;
        let mut updated = proof.clone();

        if !receipt.is_null() {
            if let Some(block_number) = receipt.get("blockNumber") {
                if !block_number.is_null() {
                    let status = receipt
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("0x0");

                    if status == "0x1" {
                        updated.status = ProofStatus::Confirmed;
                        // Note: this records the poll/observation time, not the
                        // on-chain block timestamp. Use block_metadata for the
                        // actual mined timestamp if precise timing is needed.
                        updated.confirmed_at = Some(chrono::Utc::now());

                        if let Some(bn) = block_number.as_str() {
                            updated
                                .extra
                                .insert("block_number".to_string(), serde_json::Value::from(bn));
                        }
                    } else {
                        updated.status = ProofStatus::Failed;
                    }
                }
            }
        }

        Ok(updated)
    }

    async fn verify(&self, proof: &Proof) -> Result<bool, AnchorError> {
        let txid = proof.location.clone().unwrap_or_default();
        if txid.is_empty() {
            return Err(AnchorError::InvalidFormat("Missing txid".into()));
        }

        let receipt = self.get_receipt(&txid).await?;

        if receipt.is_null() {
            return Ok(false);
        }

        let status = receipt
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("0x0");

        if status != "0x1" {
            return Ok(false);
        }

        if let Some(to) = receipt.get("to").and_then(|t| t.as_str()) {
            if to.to_lowercase() != self.contract_address.to_lowercase() {
                return Ok(false);
            }
        }

        // Verify the transaction sender matches our signing key.
        if let Some(from) = receipt.get("from").and_then(|f| f.as_str()) {
            if from.to_lowercase() != self.cached_address.to_lowercase() {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }

        if !receipt.get("blockNumber").is_some_and(|bn| !bn.is_null()) {
            return Ok(false);
        }

        // Fetch the full transaction to verify calldata matches the anchored hash.
        let tx = self
            .rpc_call("eth_getTransactionByHash", serde_json::json!([txid]))
            .await?;

        if tx.is_null() {
            return Ok(false);
        }

        let input_hex = tx.get("input").and_then(|v| v.as_str()).unwrap_or("");
        let input_bytes = hex_to_bytes(input_hex)
            .map_err(|e| AnchorError::InvalidFormat(format!("Invalid tx input: {e}")))?;

        // Must be at least 4 bytes selector + 32 bytes hash parameter.
        if input_bytes.len() < 36 {
            return Ok(false);
        }

        if input_bytes[0..4] != ANCHOR_FUNCTION_SELECTOR {
            return Ok(false);
        }

        if input_bytes[4..36] != proof.anchored_hash {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Derive the checksumless Ethereum address from a signing key.
fn derive_eth_address(signing_key: &SigningKey) -> String {
    let verifying_key = VerifyingKey::from(signing_key);
    let public_key_bytes = verifying_key.to_encoded_point(false);
    let public_key_slice = &public_key_bytes.as_bytes()[1..]; // skip 0x04 uncompressed prefix

    let mut hasher = Keccak::v256();
    let mut hash = [0u8; 32];
    hasher.update(public_key_slice);
    hasher.finalize(&mut hash);

    format!("0x{}", hex::encode(&hash[12..]))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let clean = hex.trim_start_matches("0x");
    hex::decode(clean).map_err(|e| e.to_string())
}

/// True if `s > secp256k1_order / 2` (needs EIP-2 normalization).
fn is_high_s(s: &[u8; 32]) -> bool {
    let half_order: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B,
        0x20, 0xA0,
    ];

    for (a, b) in s.iter().zip(half_order.iter()) {
        match a.cmp(b) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    false
}

/// Compute `curve_order - s` (EIP-2 low-s normalization).
fn negate_s(s: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow = 0u16;

    for i in (0..32).rev() {
        let diff = SECP256K1_ORDER[i] as u16 - s[i] as u16 - borrow;
        result[i] = diff as u8;
        borrow = if diff > 0xFF { 1 } else { 0 };
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(hex_to_bytes("0x1234").unwrap(), vec![0x12, 0x34]);
        assert_eq!(hex_to_bytes("1234").unwrap(), vec![0x12, 0x34]);
        assert!(hex_to_bytes("invalid").is_err());
    }

    #[test]
    fn test_anchor_function_selector() {
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(b"anchor(bytes32)");
        hasher.finalize(&mut hash);
        assert_eq!(&hash[0..4], &ANCHOR_FUNCTION_SELECTOR);
    }

    #[test]
    fn test_is_high_s() {
        let low_s = [0u8; 32];
        let high_s = [0xFF; 32];
        assert!(!is_high_s(&low_s));
        assert!(is_high_s(&high_s));
    }
}
