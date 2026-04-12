// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Binary codec, chain comparison/continuity, format validation, and signing marshal
//! for jitter sample chains.

use chrono::{DateTime, Utc};
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;

use super::session::{Parameters, Sample};
use super::timestamp_nanos_u64;
use super::verification::verify_sample;
use crate::error::Error;

/// Size of the binary chain header: version(1) + min_jitter(4) + max_jitter(4)
/// + sample_interval(4) + inject_enabled(1) + sample_count(4).
const CHAIN_HEADER_SIZE: usize = 18;

/// Encode a single sample into a 116-byte big-endian binary representation.
pub fn encode_sample_binary(sample: &Sample) -> Vec<u8> {
    let mut buf = vec![0u8; 116];
    let mut offset = 0usize;

    buf[offset..offset + 8].copy_from_slice(&timestamp_nanos_u64(sample.timestamp).to_be_bytes());
    offset += 8;
    buf[offset..offset + 8].copy_from_slice(&sample.keystroke_count.to_be_bytes());
    offset += 8;
    buf[offset..offset + 32].copy_from_slice(&sample.document_hash);
    offset += 32;
    buf[offset..offset + 4].copy_from_slice(&sample.jitter_micros.to_be_bytes());
    offset += 4;
    buf[offset..offset + 32].copy_from_slice(&sample.hash);
    offset += 32;
    buf[offset..offset + 32].copy_from_slice(&sample.previous_hash);

    buf
}

/// Decode a 116-byte big-endian binary blob into a [`Sample`].
pub fn decode_sample_binary(data: &[u8]) -> crate::error::Result<Sample> {
    if data.len() != 116 {
        return Err(Error::validation(format!(
            "invalid sample data length: expected 116, got {}",
            data.len()
        )));
    }

    let mut offset = 0usize;
    let timestamp_nanos = u64::from_be_bytes(
        data[offset..offset + 8]
            .try_into()
            .map_err(|e| Error::validation(format!("failed to decode timestamp: {e}")))?,
    );
    offset += 8;
    let keystroke_count = u64::from_be_bytes(
        data[offset..offset + 8]
            .try_into()
            .map_err(|e| Error::validation(format!("failed to decode keystroke count: {e}")))?,
    );
    offset += 8;
    let mut document_hash = [0u8; 32];
    document_hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let jitter_micros = u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|e| Error::validation(format!("failed to decode jitter: {e}")))?,
    );
    offset += 4;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let mut previous_hash = [0u8; 32];
    previous_hash.copy_from_slice(&data[offset..offset + 32]);

    Ok(Sample {
        timestamp: DateTime::<Utc>::from(
            SystemTime::UNIX_EPOCH + Duration::from_nanos(timestamp_nanos),
        ),
        keystroke_count,
        document_hash,
        jitter_micros,
        hash,
        previous_hash,
    })
}

/// Encode a full sample chain (header + samples) into binary format.
pub fn encode_chain_binary(
    samples: &[Sample],
    params: Parameters,
) -> crate::error::Result<Vec<u8>> {
    let header_size = CHAIN_HEADER_SIZE;
    let total_size = header_size
        + samples
            .len()
            .checked_mul(116)
            .ok_or_else(|| Error::validation("sample count overflow in binary encoding"))?;
    let mut buf = vec![0u8; total_size];
    let mut offset = 0usize;

    buf[offset] = 1;
    offset += 1;
    buf[offset..offset + 4].copy_from_slice(&params.min_jitter_micros.to_be_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&params.max_jitter_micros.to_be_bytes());
    offset += 4;
    let sample_interval_u32 = u32::try_from(params.sample_interval).map_err(|_| {
        Error::validation(format!(
            "sample_interval {} exceeds u32::MAX",
            params.sample_interval
        ))
    })?;
    buf[offset..offset + 4].copy_from_slice(&sample_interval_u32.to_be_bytes());
    offset += 4;
    buf[offset] = if params.inject_enabled { 1 } else { 0 };
    offset += 1;
    let sample_count_u32 = u32::try_from(samples.len()).map_err(|_| {
        Error::validation(format!("sample count {} exceeds u32::MAX", samples.len()))
    })?;
    buf[offset..offset + 4].copy_from_slice(&sample_count_u32.to_be_bytes());
    offset += 4;

    for sample in samples {
        let bytes = encode_sample_binary(sample);
        buf[offset..offset + 116].copy_from_slice(&bytes);
        offset += 116;
    }

    Ok(buf)
}

/// Decode a binary-encoded chain into samples and parameters.
pub fn decode_chain_binary(data: &[u8]) -> crate::error::Result<(Vec<Sample>, Parameters)> {
    if data.len() < CHAIN_HEADER_SIZE {
        return Err(Error::validation("data too short for chain header"));
    }

    let mut offset = 0usize;
    let version = data[offset];
    if version != 1 {
        return Err(Error::validation(format!(
            "unsupported chain version: {version}"
        )));
    }
    offset += 1;

    let min_jitter_micros = u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| Error::validation("truncated min_jitter_micros field"))?,
    );
    offset += 4;
    let max_jitter_micros = u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| Error::validation("truncated max_jitter_micros field"))?,
    );
    offset += 4;
    let sample_interval = u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| Error::validation("truncated sample_interval field"))?,
    ) as u64;
    offset += 4;
    let inject_enabled = data[offset] == 1;
    offset += 1;

    let sample_count = u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| Error::validation("truncated sample_count field"))?,
    ) as usize;
    offset += 4;

    // Limit allocation to prevent DoS from crafted sample_count
    const MAX_SAMPLE_COUNT: usize = 10_000_000;
    if sample_count > MAX_SAMPLE_COUNT {
        return Err(Error::validation(format!(
            "sample count {sample_count} exceeds maximum ({MAX_SAMPLE_COUNT})"
        )));
    }

    let expected_len = CHAIN_HEADER_SIZE
        + sample_count
            .checked_mul(116)
            .ok_or_else(|| Error::validation("sample count overflow in binary decoding"))?;
    if data.len() != expected_len {
        return Err(Error::validation(format!(
            "invalid data length: expected {expected_len}, got {}",
            data.len()
        )));
    }

    let mut samples = Vec::with_capacity(sample_count);
    for i in 0..sample_count {
        let start = offset + i * 116;
        let end = start + 116;
        let sample = decode_sample_binary(&data[start..end])
            .map_err(|e| Error::validation(format!("failed to decode sample {i}: {e}")))?;
        samples.push(sample);
    }

    Ok((
        samples,
        Parameters {
            min_jitter_micros,
            max_jitter_micros,
            sample_interval,
            inject_enabled,
        },
    ))
}

/// Return true if two sample chains are field-by-field identical.
pub fn compare_chains(a: &[Sample], b: &[Sample]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if !compare_samples(&a[i], &b[i]) {
            return false;
        }
    }
    true
}

/// Return true if two samples are field-by-field identical.
/// Hash fields use constant-time comparison to avoid timing side-channels.
pub fn compare_samples(a: &Sample, b: &Sample) -> bool {
    a.timestamp == b.timestamp
        && a.keystroke_count == b.keystroke_count
        && a.document_hash == b.document_hash
        && a.jitter_micros == b.jitter_micros
        && a.hash.ct_eq(&b.hash).unwrap_u8() == 1
        && a.previous_hash.ct_eq(&b.previous_hash).unwrap_u8() == 1
}

/// Return the index where two chains first diverge, or -1 if identical.
pub fn find_chain_divergence(a: &[Sample], b: &[Sample]) -> i64 {
    let min_len = a.len().min(b.len());
    for i in 0..min_len {
        if !compare_samples(&a[i], &b[i]) {
            return i as i64;
        }
    }
    if a.len() != b.len() {
        return min_len as i64;
    }
    -1
}

/// Collect the hash from each sample into a vector.
pub fn extract_chain_hashes(samples: &[Sample]) -> Vec<[u8; 32]> {
    samples.iter().map(|s| s.hash).collect()
}

/// Verify that `new_samples` chain correctly from `existing_samples`.
pub fn verify_chain_continuity(
    existing_samples: &[Sample],
    new_samples: &[Sample],
    seed: &[u8],
    params: Parameters,
) -> crate::error::Result<()> {
    if new_samples.is_empty() {
        return Ok(());
    }
    if seed.is_empty() {
        return Err(Error::validation("seed is nil or empty"));
    }

    let last_existing = existing_samples.last();
    if let Some(last) = last_existing {
        let first_new = &new_samples[0];
        if first_new.previous_hash.ct_eq(&last.hash).unwrap_u8() == 0 {
            return Err(Error::validation("new samples don't chain from existing"));
        }
        if first_new.timestamp <= last.timestamp {
            return Err(Error::validation("timestamp not monotonically increasing"));
        }
        if first_new.keystroke_count <= last.keystroke_count {
            return Err(Error::validation(
                "keystroke count not monotonically increasing",
            ));
        }
    }

    for i in 0..new_samples.len() {
        let prev = if i > 0 {
            Some(&new_samples[i - 1])
        } else {
            last_existing
        };
        verify_sample(&new_samples[i], prev, seed, params)
            .map_err(|e| Error::validation(format!("new sample {i}: {e}")))?;
    }

    Ok(())
}

/// Return the hash of the last sample, or all-zeros if the chain is empty.
pub fn hash_chain_root(samples: &[Sample]) -> [u8; 32] {
    samples.last().map(|s| s.hash).unwrap_or([0u8; 32])
}

/// Validate that a sample has a plausible timestamp and non-zero hash.
pub fn validate_sample_format(sample: &Sample) -> crate::error::Result<()> {
    if sample.timestamp.timestamp() <= 0 {
        return Err(Error::validation("timestamp is zero or pre-epoch"));
    }
    if sample.timestamp > Utc::now() + chrono::Duration::hours(24) {
        return Err(Error::validation("timestamp is in the future"));
    }
    if sample.hash == [0u8; 32] {
        return Err(Error::validation("sample hash is zero"));
    }
    Ok(())
}

/// Serialize a sample into the canonical byte layout used for signing.
pub fn marshal_sample_for_signing(sample: &Sample) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"cpoe-sample-v1\n");
    buf.extend_from_slice(&timestamp_nanos_u64(sample.timestamp).to_be_bytes());
    buf.extend_from_slice(&sample.keystroke_count.to_be_bytes());
    buf.extend_from_slice(&sample.document_hash);
    buf.extend_from_slice(&sample.jitter_micros.to_be_bytes());
    buf.extend_from_slice(&sample.previous_hash);
    buf.extend_from_slice(&sample.hash);
    buf
}
