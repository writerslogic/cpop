// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use serde::Serialize;

/// DIF Presentation Exchange 2.0 Presentation Definition.
///
/// Allows verifiers to request specific CPOP attestation claims from a holder.
#[derive(Debug, Clone, Serialize)]
pub struct PresentationDefinition {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub input_descriptors: Vec<InputDescriptor>,
}

/// Describes a single input the verifier requires.
#[derive(Debug, Clone, Serialize)]
pub struct InputDescriptor {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub constraints: Constraints,
}

/// Constraints on the fields a verifier requires.
#[derive(Debug, Clone, Serialize)]
pub struct Constraints {
    pub fields: Vec<Field>,
}

/// A single field constraint within an input descriptor.
#[derive(Debug, Clone, Serialize)]
pub struct Field {
    pub path: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// Build a presentation definition requesting a CPOP attestation.
///
/// The definition requires:
/// - A checkpoint chain duration of at least `min_chain_duration_secs` seconds.
/// - A forensic tier at or above `min_tier` (e.g. "gold", "silver", "bronze").
pub fn cpop_attestation_request(
    min_chain_duration_secs: u64,
    min_tier: &str,
) -> PresentationDefinition {
    PresentationDefinition {
        id: "cpop-attestation-request".to_string(),
        name: Some("CPOP Authorship Attestation".to_string()),
        purpose: Some("Verify human authorship via cryptographic proof-of-process".to_string()),
        input_descriptors: vec![
            InputDescriptor {
                id: "chain_duration".to_string(),
                name: Some("Checkpoint Chain Duration".to_string()),
                purpose: Some(format!(
                    "Chain must span at least {} seconds",
                    min_chain_duration_secs
                )),
                constraints: Constraints {
                    fields: vec![Field {
                        path: vec!["$.chain_duration_secs".to_string()],
                        filter: Some(serde_json::json!({
                            "type": "number",
                            "minimum": min_chain_duration_secs
                        })),
                        purpose: None,
                    }],
                },
            },
            InputDescriptor {
                id: "forensic_tier".to_string(),
                name: Some("Forensic Assessment Tier".to_string()),
                purpose: Some(format!("Tier must be at least {}", min_tier)),
                constraints: Constraints {
                    fields: vec![Field {
                        path: vec!["$.forensic_tier".to_string()],
                        filter: Some(serde_json::json!({
                            "type": "string",
                            "const": min_tier
                        })),
                        purpose: None,
                    }],
                },
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presentation_definition_for_cpop() {
        let pd = cpop_attestation_request(3600, "gold");

        assert_eq!(pd.id, "cpop-attestation-request");
        assert_eq!(pd.input_descriptors.len(), 2);

        let chain = &pd.input_descriptors[0];
        assert_eq!(chain.id, "chain_duration");
        assert_eq!(chain.constraints.fields.len(), 1);
        assert_eq!(chain.constraints.fields[0].path[0], "$.chain_duration_secs");
        let filter = chain.constraints.fields[0].filter.as_ref().unwrap();
        assert_eq!(filter["minimum"], 3600);

        let tier = &pd.input_descriptors[1];
        assert_eq!(tier.id, "forensic_tier");
        let tier_filter = tier.constraints.fields[0].filter.as_ref().unwrap();
        assert_eq!(tier_filter["const"], "gold");
    }
}
