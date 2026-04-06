// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! EAT/CWT encoding and decoding for RATS attestation results.
//!
//! Encodes an `EarToken` as a CWT (CBOR Web Token, RFC 8392) wrapped in a
//! COSE_Sign1 envelope, using CWT standard claim keys and EAR private-use
//! keys from `war::ear`.

use std::collections::BTreeMap;

use ciborium::Value;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};

use crate::error::{Error, Result};
use crate::tpm;
use crate::war::ear::{
    Ar4siStatus, EarAppraisal, EarToken, TrustworthinessVector, VerifierId, CWT_KEY_EAT_PROFILE,
    CWT_KEY_IAT, CWT_KEY_SUBMODS, EAR_KEY_POLICY_ID, EAR_KEY_STATUS, EAR_KEY_TRUST_VECTOR,
    EAR_KEY_VERIFIER_ID, POP_KEY_CHAIN_DURATION, POP_KEY_CHAIN_LENGTH, POP_KEY_WARNINGS,
};

/// CWT standard claim keys (RFC 8392 Section 4).
const CWT_ISS: i64 = 1;
const CWT_SUB: i64 = 2;
#[allow(dead_code)]
const CWT_EXP: i64 = 4;
#[allow(dead_code)]
const CWT_NBF: i64 = 5;

/// Encode an `EarToken` as a signed CWT (COSE_Sign1) using the given TPM provider.
///
/// The CWT payload is a CBOR map with:
/// - Standard CWT claims (iss=1, sub=2, iat=6)
/// - EAT profile (265), submods (266)
/// - EAR claims (1000-1004) and POP private-use claims (70001-70011)
///
/// The result is a COSE_Sign1 envelope suitable for wire transmission.
pub fn encode_eat_cwt(ear: &EarToken, signer: &dyn tpm::Provider) -> Result<Vec<u8>> {
    let payload_cbor = ear_to_cbor_map(ear)?;

    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload_cbor, &mut payload_bytes)
        .map_err(|e| Error::crypto(format!("CBOR encode error: {e}")))?;

    let alg = signer.algorithm();
    let protected = HeaderBuilder::new().algorithm(alg).build();

    let mut sign_error: Option<Error> = None;
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes)
        .create_signature(&[], |sig_data| match signer.sign(sig_data) {
            Ok(sig) => sig,
            Err(e) => {
                sign_error = Some(Error::crypto(format!("TPM sign error: {e}")));
                Vec::new()
            }
        })
        .build();

    if let Some(e) = sign_error {
        return Err(e);
    }

    if sign1.signature.is_empty() {
        return Err(Error::crypto("COSE signing produced empty signature"));
    }

    sign1
        .to_vec()
        .map_err(|e| Error::crypto(format!("COSE encoding error: {e}")))
}

/// Decode a CWT (COSE_Sign1) back into an `EarToken`.
///
/// This extracts the payload without verifying the signature, which is
/// appropriate when the caller has already verified via a separate path
/// or for inspection/debugging.
pub fn decode_eat_cwt(bytes: &[u8]) -> Result<EarToken> {
    let sign1 = coset::CoseSign1::from_slice(bytes)
        .map_err(|e| Error::crypto(format!("COSE decode error: {e}")))?;

    let payload = sign1
        .payload
        .ok_or_else(|| Error::crypto("missing CWT payload"))?;

    let value: Value = ciborium::from_reader(payload.as_slice())
        .map_err(|e| Error::crypto(format!("CBOR decode error: {e}")))?;

    cbor_map_to_ear(&value)
}

/// Serialize an `EarToken` into a CBOR map Value.
fn ear_to_cbor_map(ear: &EarToken) -> Result<Value> {
    let vid_map: Vec<(Value, Value)> = vec![
        (
            Value::Text("build".to_string()),
            Value::Text(ear.ear_verifier_id.build.clone()),
        ),
        (
            Value::Text("developer".to_string()),
            Value::Text(ear.ear_verifier_id.developer.clone()),
        ),
    ];

    let submods_map: Vec<(Value, Value)> = ear
        .submods
        .iter()
        .map(|(name, appraisal)| (Value::Text(name.clone()), appraisal_to_cbor(appraisal)))
        .collect();

    let map: Vec<(Value, Value)> = vec![
        // CWT standard claims
        (
            Value::Integer(CWT_ISS.into()),
            Value::Text("cpop-engine".to_string()),
        ),
        (
            Value::Integer(CWT_SUB.into()),
            Value::Text("pop-attestation".to_string()),
        ),
        (
            Value::Integer(CWT_KEY_IAT.into()),
            Value::Integer(ear.iat.into()),
        ),
        // EAT profile
        (
            Value::Integer(CWT_KEY_EAT_PROFILE.into()),
            Value::Text(ear.eat_profile.clone()),
        ),
        // Verifier ID (1004)
        (
            Value::Integer(EAR_KEY_VERIFIER_ID.into()),
            Value::Map(vid_map),
        ),
        // Submods (266)
        (
            Value::Integer(CWT_KEY_SUBMODS.into()),
            Value::Map(submods_map),
        ),
    ];

    Ok(Value::Map(map))
}

/// Serialize a single `EarAppraisal` into a CBOR map Value.
fn appraisal_to_cbor(a: &EarAppraisal) -> Value {
    let mut map: Vec<(Value, Value)> = Vec::new();

    map.push((
        Value::Integer(EAR_KEY_STATUS.into()),
        Value::Integer((a.ear_status as i8 as i64).into()),
    ));

    if let Some(ref tv) = a.ear_trustworthiness_vector {
        map.push((
            Value::Integer(EAR_KEY_TRUST_VECTOR.into()),
            trust_vector_to_cbor(tv),
        ));
    }

    if let Some(ref policy_id) = a.ear_appraisal_policy_id {
        map.push((
            Value::Integer(EAR_KEY_POLICY_ID.into()),
            Value::Text(policy_id.clone()),
        ));
    }

    if let Some(chain_len) = a.pop_chain_length {
        map.push((
            Value::Integer(POP_KEY_CHAIN_LENGTH.into()),
            Value::Integer((chain_len as i64).into()),
        ));
    }

    if let Some(chain_dur) = a.pop_chain_duration {
        map.push((
            Value::Integer(POP_KEY_CHAIN_DURATION.into()),
            Value::Integer((chain_dur as i64).into()),
        ));
    }

    if let Some(ref warnings) = a.pop_warnings {
        let arr: Vec<Value> = warnings.iter().map(|w| Value::Text(w.clone())).collect();
        map.push((Value::Integer(POP_KEY_WARNINGS.into()), Value::Array(arr)));
    }

    Value::Map(map)
}

/// Serialize a `TrustworthinessVector` into a CBOR map.
fn trust_vector_to_cbor(tv: &TrustworthinessVector) -> Value {
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Integer(0.into()),
            Value::Integer((tv.instance_identity as i64).into()),
        ),
        (
            Value::Integer(1.into()),
            Value::Integer((tv.configuration as i64).into()),
        ),
        (
            Value::Integer(2.into()),
            Value::Integer((tv.executables as i64).into()),
        ),
        (
            Value::Integer(3.into()),
            Value::Integer((tv.file_system as i64).into()),
        ),
        (
            Value::Integer(4.into()),
            Value::Integer((tv.hardware as i64).into()),
        ),
        (
            Value::Integer(5.into()),
            Value::Integer((tv.runtime_opaque as i64).into()),
        ),
        (
            Value::Integer(6.into()),
            Value::Integer((tv.storage_opaque as i64).into()),
        ),
        (
            Value::Integer(7.into()),
            Value::Integer((tv.sourced_data as i64).into()),
        ),
    ];
    Value::Map(entries)
}

/// Parse a CBOR Value back into an `EarToken`.
fn cbor_map_to_ear(value: &Value) -> Result<EarToken> {
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(Error::crypto("CWT payload is not a CBOR map")),
    };

    let mut eat_profile = String::new();
    let mut iat: i64 = 0;
    let mut ear_verifier_id = VerifierId::default();
    let mut submods = BTreeMap::new();

    for (k, v) in map {
        let key = cbor_int(k).unwrap_or(0);
        match key {
            k if k == CWT_KEY_EAT_PROFILE => {
                if let Value::Text(s) = v {
                    eat_profile = s.clone();
                }
            }
            k if k == CWT_KEY_IAT => {
                iat = cbor_int(v).unwrap_or(0);
            }
            k if k == EAR_KEY_VERIFIER_ID => {
                if let Value::Map(vm) = v {
                    for (vk, vv) in vm {
                        if let (Value::Text(field), Value::Text(val)) = (vk, vv) {
                            match field.as_str() {
                                "build" => ear_verifier_id.build = val.clone(),
                                "developer" => ear_verifier_id.developer = val.clone(),
                                _ => {}
                            }
                        }
                    }
                }
            }
            k if k == CWT_KEY_SUBMODS => {
                if let Value::Map(sm) = v {
                    for (sk, sv) in sm {
                        if let Value::Text(name) = sk {
                            submods.insert(name.clone(), cbor_to_appraisal(sv)?);
                        }
                    }
                }
            }
            _ => {} // skip iss, sub, exp, nbf, cti, unknown
        }
    }

    Ok(EarToken {
        eat_profile,
        iat,
        ear_verifier_id,
        submods,
    })
}

/// Parse a CBOR map into an `EarAppraisal`.
fn cbor_to_appraisal(value: &Value) -> Result<EarAppraisal> {
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(Error::crypto("appraisal is not a CBOR map")),
    };

    let mut status = Ar4siStatus::None;
    let mut trust_vector = None;
    let mut policy_id = None;
    let mut chain_length = None;
    let mut chain_duration = None;
    let mut warnings = None;

    for (k, v) in map {
        let key = cbor_int(k).unwrap_or(0);
        match key {
            k if k == EAR_KEY_STATUS => {
                status = Ar4siStatus::from_i8(cbor_int(v).unwrap_or(0) as i8);
            }
            k if k == EAR_KEY_TRUST_VECTOR => {
                trust_vector = Some(cbor_to_trust_vector(v)?);
            }
            k if k == EAR_KEY_POLICY_ID => {
                if let Value::Text(s) = v {
                    policy_id = Some(s.clone());
                }
            }
            k if k == POP_KEY_CHAIN_LENGTH => {
                chain_length = Some(cbor_int(v).unwrap_or(0) as u64);
            }
            k if k == POP_KEY_CHAIN_DURATION => {
                chain_duration = Some(cbor_int(v).unwrap_or(0) as u64);
            }
            k if k == POP_KEY_WARNINGS => {
                if let Value::Array(arr) = v {
                    let ws: Vec<String> = arr
                        .iter()
                        .filter_map(|item| {
                            if let Value::Text(s) = item {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                        .collect();
                    warnings = Some(ws);
                }
            }
            _ => {}
        }
    }

    Ok(EarAppraisal {
        ear_status: status,
        ear_trustworthiness_vector: trust_vector,
        ear_appraisal_policy_id: policy_id,
        pop_seal: None,
        pop_evidence_ref: None,
        pop_entropy_report: None,
        pop_forgery_cost: None,
        pop_forensic_summary: None,
        pop_chain_length: chain_length,
        pop_chain_duration: chain_duration,
        pop_absence_claims: None,
        pop_warnings: warnings,
        pop_process_start: None,
        pop_process_end: None,
    })
}

/// Parse a CBOR map into a `TrustworthinessVector`.
fn cbor_to_trust_vector(value: &Value) -> Result<TrustworthinessVector> {
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(Error::crypto("trust vector is not a CBOR map")),
    };

    let mut tv = TrustworthinessVector::default();
    for (k, v) in map {
        let idx = cbor_int(k).unwrap_or(-1);
        let val = cbor_int(v).unwrap_or(0) as i8;
        match idx {
            0 => tv.instance_identity = val,
            1 => tv.configuration = val,
            2 => tv.executables = val,
            3 => tv.file_system = val,
            4 => tv.hardware = val,
            5 => tv.runtime_opaque = val,
            6 => tv.storage_opaque = val,
            7 => tv.sourced_data = val,
            _ => {}
        }
    }
    Ok(tv)
}

/// Extract an i64 from a CBOR integer Value.
fn cbor_int(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => {
            let val: i128 = (*i).into();
            i64::try_from(val).ok()
        }
        _ => None,
    }
}
