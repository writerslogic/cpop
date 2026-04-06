// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use rand::rngs::{OsRng, StdRng};
use rand::Rng;
use rand::SeedableRng;
use rand::TryRngCore;
use std::time::Duration;
use subtle::ConstantTimeEq;

use super::helpers::hash_response;
use super::types::{Challenge, ChallengeStatus, ChallengeType, Config, Session};

/// Issue and verify interactive presence challenges during authoring sessions.
pub struct Verifier {
    config: Config,
    session: Option<Session>,
    rng: StdRng,
}

impl Verifier {
    /// Create a verifier with the given challenge configuration.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            session: None,
            rng: StdRng::from_os_rng(),
        }
    }

    /// Begin a new presence verification session.
    pub fn start_session(&mut self) -> Result<Session, String> {
        if self.session.as_ref().map(|s| s.active).unwrap_or(false) {
            return Err("session already active".to_string());
        }

        let mut id = [0u8; 16];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut id)
            .map_err(|e| format!("os rng failure: {e}"))?;

        let session = Session {
            id: hex::encode(id),
            start_time: Utc::now(),
            end_time: None,
            active: true,
            challenges: Vec::new(),
            checkpoint_ordinals: Vec::new(),
            challenges_issued: 0,
            challenges_passed: 0,
            challenges_failed: 0,
            challenges_missed: 0,
            verification_rate: 0.0,
        };

        self.session = Some(session.clone());
        Ok(session)
    }

    /// Finalize the active session and compute aggregate statistics.
    pub fn end_session(&mut self) -> Result<Session, String> {
        let mut session = self
            .session
            .take()
            .ok_or_else(|| "no active session".to_string())?;
        if !session.active {
            return Err("no active session".to_string());
        }

        session.end_time = Some(Utc::now());
        session.active = false;

        session.challenges_issued = session.challenges.len() as i32;
        for challenge in &session.challenges {
            match challenge.status {
                ChallengeStatus::Passed => session.challenges_passed += 1,
                ChallengeStatus::Failed => session.challenges_failed += 1,
                ChallengeStatus::Expired | ChallengeStatus::Pending => {
                    session.challenges_missed += 1
                }
            }
        }

        if session.challenges_issued > 0 {
            session.verification_rate =
                session.challenges_passed as f64 / session.challenges_issued as f64;
        }

        Ok(session)
    }

    /// Generate and record a new random challenge for the active session.
    pub fn issue_challenge(&mut self) -> Result<Challenge, String> {
        let active = self
            .session
            .as_ref()
            .ok_or_else(|| "no active session".to_string())?
            .active;
        if !active {
            return Err("no active session".to_string());
        }

        let challenge_type = if self.config.enabled_challenges.is_empty() {
            ChallengeType::TypePhrase
        } else {
            let index = self
                .rng
                .random_range(0..self.config.enabled_challenges.len());
            self.config.enabled_challenges[index].clone()
        };

        let (prompt, expected) = match challenge_type {
            ChallengeType::TypePhrase => self.generate_phrase(),
            ChallengeType::SimpleMath => self.generate_math(),
            ChallengeType::TypeWord => self.generate_word(),
        };

        let mut id = [0u8; 8];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut id)
            .map_err(|e| format!("os rng failure: {e}"))?;
        let now = Utc::now();

        let challenge = Challenge {
            id: hex::encode(id),
            challenge_type,
            issued_at: now,
            expires_at: now
                + chrono::Duration::from_std(self.config.response_window)
                    .unwrap_or(chrono::Duration::seconds(60)),
            window: self.config.response_window,
            prompt,
            expected_hash: hash_response(&expected),
            responded_at: None,
            response_hash: None,
            status: ChallengeStatus::Pending,
        };

        let session = self
            .session
            .as_mut()
            .ok_or_else(|| "no active session".to_string())?;
        Self::expire_pending(session);
        session.challenges.push(challenge.clone());
        Ok(challenge)
    }

    /// Submit a response to a pending challenge; return `true` if correct.
    pub fn respond_to_challenge(
        &mut self,
        challenge_id: &str,
        response: &str,
    ) -> Result<bool, String> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| "no active session".to_string())?;
        if !session.active {
            return Err("no active session".to_string());
        }

        let challenge = session
            .challenges
            .iter_mut()
            .find(|c| c.id == challenge_id)
            .ok_or_else(|| "challenge not found".to_string())?;

        if challenge.status != ChallengeStatus::Pending {
            return Err(format!(
                "challenge already resolved: {:?}",
                challenge.status
            ));
        }

        let now = Utc::now();
        challenge.responded_at = Some(now);
        challenge.response_hash = Some(hash_response(response));

        if now > challenge.expires_at {
            challenge.status = ChallengeStatus::Expired;
            return Ok(false);
        }

        let response_matches = challenge
            .response_hash
            .as_deref()
            .zip(Some(challenge.expected_hash.as_str()))
            .map(|(r, e)| bool::from(r.as_bytes().ct_eq(e.as_bytes())))
            .unwrap_or(false);
        if response_matches {
            challenge.status = ChallengeStatus::Passed;
            return Ok(true);
        }

        challenge.status = ChallengeStatus::Failed;
        Ok(false)
    }

    /// Compute the next challenge time with randomized jitter.
    pub fn next_challenge_time(&mut self) -> Option<DateTime<Utc>> {
        let session = self.session.as_ref()?;
        if !session.active {
            return None;
        }

        let last_time = session
            .challenges
            .last()
            .map(|c| c.issued_at)
            .unwrap_or(session.start_time);

        let interval = self.config.challenge_interval;
        let variance = interval.as_secs_f64()
            * self.config.interval_variance
            * (self.rng.random_range(-1.0..1.0));

        let total_secs = (interval.as_secs_f64() + variance).max(0.0);
        // Guard against NaN/Inf from extreme config values
        let total_secs = if total_secs.is_finite() {
            total_secs
        } else {
            interval.as_secs_f64()
        };
        let next = last_time
            + chrono::Duration::from_std(Duration::from_secs_f64(total_secs))
                .unwrap_or(chrono::Duration::seconds(600));
        Some(next)
    }

    /// Return `true` if the next challenge time has passed.
    pub fn should_issue_challenge(&mut self) -> bool {
        self.next_challenge_time()
            .map(|time| Utc::now() > time)
            .unwrap_or(false)
    }

    /// Attach a previously persisted session so challenges resume against it.
    pub fn restore_session(&mut self, session: Session) -> Result<(), String> {
        if !session.active {
            return Err("cannot restore an inactive session".to_string());
        }
        self.session = Some(session);
        Ok(())
    }

    /// Return a reference to the current session, if any.
    pub fn active_session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    fn expire_pending(session: &mut Session) {
        let now = Utc::now();
        for challenge in &mut session.challenges {
            if challenge.status == ChallengeStatus::Pending && now > challenge.expires_at {
                challenge.status = ChallengeStatus::Expired;
            }
        }
    }

    fn generate_phrase(&mut self) -> (String, String) {
        let phrases = [
            "the quick brown fox",
            "hello world today",
            "verify my presence",
            "cryptographic proof",
            "authentic authorship",
            "digital signature",
            "hash chain valid",
            "timestamp verified",
            "witness protocol",
            "merkle mountain",
        ];
        let phrase = phrases[self.rng.random_range(0..phrases.len())];
        (format!("Type the phrase: {phrase}"), phrase.to_lowercase())
    }

    #[allow(clippy::type_complexity)]
    fn generate_math(&mut self) -> (String, String) {
        let a = self.rng.random_range(1..=20);
        let b = self.rng.random_range(1..=20);
        fn add(x: i32, y: i32) -> i32 {
            x + y
        }
        fn sub(x: i32, y: i32) -> i32 {
            x - y
        }
        fn mul(x: i32, y: i32) -> i32 {
            x * y
        }

        let ops: [(&str, fn(i32, i32) -> i32); 3] = [("+", add), ("-", sub), ("*", mul)];
        let (symbol, op) = ops[self.rng.random_range(0..ops.len())];
        let result = op(a, b);
        (format!("Solve: {a} {symbol} {b} = ?"), format!("{result}"))
    }

    fn generate_word(&mut self) -> (String, String) {
        let words = [
            "cryptography",
            "authentication",
            "verification",
            "signature",
            "timestamp",
            "blockchain",
            "integrity",
            "provenance",
            "authorship",
            "attestation",
            "declaration",
            "witness",
        ];
        let word = words[self.rng.random_range(0..words.len())];
        (format!("Type the word: {word}"), word.to_lowercase())
    }
}
