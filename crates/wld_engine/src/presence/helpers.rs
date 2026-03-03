// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use sha2::{Digest, Sha256};
use std::time::Duration;

use super::types::{Evidence, Session};

pub fn hash_response(response: &str) -> String {
    let normalized = response.trim().to_lowercase();
    let digest = Sha256::digest(normalized.as_bytes());
    hex::encode(digest)
}

pub fn compile_evidence(sessions: &[Session]) -> Evidence {
    let mut evidence = Evidence {
        sessions: sessions.to_vec(),
        total_duration: Duration::from_secs(0),
        total_challenges: 0,
        total_passed: 0,
        overall_rate: 0.0,
    };

    for session in sessions {
        if let Some(end_time) = session.end_time {
            let duration = end_time
                .signed_duration_since(session.start_time)
                .to_std()
                .unwrap_or(Duration::from_secs(0));
            evidence.total_duration += duration;
        }
        evidence.total_challenges += session.challenges_issued;
        evidence.total_passed += session.challenges_passed;
    }

    if evidence.total_challenges > 0 {
        evidence.overall_rate = evidence.total_passed as f64 / evidence.total_challenges as f64;
    }

    evidence
}
