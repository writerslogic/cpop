// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Chain verification and encoding for seeded jitter chains.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::session::{compute_jitter_value, Parameters, Sample};
use crate::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub samples_verified: u64,
    pub errors: Vec<String>,
}

pub fn verify_chain(
    samples: &[Sample],
    seed: &[u8],
    params: Parameters,
) -> crate::error::Result<()> {
    if samples.is_empty() {
        return Err(Error::validation("empty sample chain"));
    }
    if seed.is_empty() {
        return Err(Error::validation("seed is nil or empty"));
    }

    for (i, sample) in samples.iter().enumerate() {
        let prev = if i > 0 { Some(&samples[i - 1]) } else { None };
        verify_sample(sample, prev, seed, params)
            .map_err(|e| Error::validation(format!("sample {i}: {e}")))?;
    }

    Ok(())
}

pub fn verify_sample(
    sample: &Sample,
    prev_sample: Option<&Sample>,
    seed: &[u8],
    params: Parameters,
) -> crate::error::Result<()> {
    if seed.is_empty() {
        return Err(Error::validation("seed is nil or empty"));
    }

    if sample.compute_hash().ct_eq(&sample.hash).unwrap_u8() == 0 {
        return Err(Error::validation("sample hash mismatch"));
    }

    if let Some(prev) = prev_sample {
        if sample.previous_hash.ct_eq(&prev.hash).unwrap_u8() == 0 {
            return Err(Error::validation("chain link broken"));
        }
        if sample.timestamp <= prev.timestamp {
            return Err(Error::validation("timestamp not monotonically increasing"));
        }
        if sample.keystroke_count <= prev.keystroke_count {
            return Err(Error::validation(
                "keystroke count not monotonically increasing",
            ));
        }
    } else if sample.previous_hash.ct_eq(&[0u8; 32]).unwrap_u8() == 0 {
        return Err(Error::validation("first sample has non-zero previous hash"));
    }

    let prev_jitter = prev_sample.map(|p| p.hash).unwrap_or([0u8; 32]);
    let expected = compute_jitter_value(
        seed,
        sample.document_hash,
        sample.keystroke_count,
        sample.timestamp,
        prev_jitter,
        params,
    );
    if expected
        .to_be_bytes()
        .ct_eq(&sample.jitter_micros.to_be_bytes())
        .unwrap_u8()
        == 0
    {
        return Err(Error::validation("jitter value mismatch"));
    }

    Ok(())
}

pub fn verify_chain_detailed(
    samples: &[Sample],
    seed: &[u8],
    params: Parameters,
) -> VerificationResult {
    let mut result = VerificationResult {
        valid: true,
        samples_verified: 0,
        errors: Vec::new(),
    };

    if samples.is_empty() {
        result.valid = false;
        result.errors.push("empty sample chain".to_string());
        return result;
    }
    if seed.is_empty() {
        result.valid = false;
        result.errors.push("seed is nil or empty".to_string());
        return result;
    }

    for (i, sample) in samples.iter().enumerate() {
        let prev = if i > 0 { Some(&samples[i - 1]) } else { None };
        if let Err(err) = verify_sample(sample, prev, seed, params) {
            result.valid = false;
            result.errors.push(format!("sample {i}: {err}"));
        } else {
            result.samples_verified += 1;
        }
    }

    result
}

pub fn verify_chain_with_seed(
    samples: &[Sample],
    seed: [u8; 32],
    params: Parameters,
) -> crate::error::Result<()> {
    verify_chain(samples, &seed, params)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainData {
    pub version: i32,
    pub params: Parameters,
    pub samples: Vec<Sample>,
    pub created_at: DateTime<Utc>,
}

pub fn encode_chain(samples: &[Sample], params: Parameters) -> crate::error::Result<Vec<u8>> {
    let data = ChainData {
        version: 1,
        params,
        samples: samples.to_vec(),
        created_at: Utc::now(),
    };
    serde_json::to_vec(&data).map_err(|e| Error::validation(e.to_string()))
}

pub fn decode_chain(data: &[u8]) -> crate::error::Result<(Vec<Sample>, Parameters)> {
    let chain: ChainData =
        serde_json::from_slice(data).map_err(|e| Error::validation(e.to_string()))?;
    if chain.version != 1 {
        return Err(Error::validation(format!(
            "unsupported chain version: {}",
            chain.version
        )));
    }
    Ok((chain.samples, chain.params))
}
