#![allow(clippy::items_after_test_module)]

use chrono::{DateTime, Utc};
use rand::rngs::{OsRng, StdRng};
use rand::Rng;
use rand::SeedableRng;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub active: bool,
    pub challenges: Vec<Challenge>,
    pub checkpoint_ordinals: Vec<u64>,
    pub challenges_issued: i32,
    pub challenges_passed: i32,
    pub challenges_failed: i32,
    pub challenges_missed: i32,
    pub verification_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: String,
    pub challenge_type: ChallengeType,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub window: Duration,
    pub prompt: String,
    pub expected_hash: String,
    pub responded_at: Option<DateTime<Utc>>,
    pub response_hash: Option<String>,
    pub status: ChallengeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    TypePhrase,
    SimpleMath,
    TypeWord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Pending,
    Passed,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub challenge_interval: Duration,
    pub interval_variance: f64,
    pub response_window: Duration,
    pub enabled_challenges: Vec<ChallengeType>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            challenge_interval: Duration::from_secs(10 * 60),
            interval_variance: 0.5,
            response_window: Duration::from_secs(60),
            enabled_challenges: vec![
                ChallengeType::TypePhrase,
                ChallengeType::SimpleMath,
                ChallengeType::TypeWord,
            ],
        }
    }
}

pub struct Verifier {
    config: Config,
    session: Option<Session>,
    rng: StdRng,
}

impl Verifier {
    pub fn new(config: Config) -> Self {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_nanos() as u64;
        Self {
            config,
            session: None,
            rng: StdRng::seed_from_u64(seed),
        }
    }

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
            expires_at: now + chrono::Duration::from_std(self.config.response_window).unwrap(),
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

        if challenge.response_hash.as_deref() == Some(&challenge.expected_hash) {
            challenge.status = ChallengeStatus::Passed;
            return Ok(true);
        }

        challenge.status = ChallengeStatus::Failed;
        Ok(false)
    }

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

        let next = last_time
            + chrono::Duration::from_std(Duration::from_secs_f64(
                (interval.as_secs_f64() + variance).max(0.0),
            ))
            .unwrap();
        Some(next)
    }

    pub fn should_issue_challenge(&mut self) -> bool {
        self.next_challenge_time()
            .map(|time| Utc::now() > time)
            .unwrap_or(false)
    }

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub sessions: Vec<Session>,
    pub total_duration: Duration,
    pub total_challenges: i32,
    pub total_passed: i32,
    pub overall_rate: f64,
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

impl Session {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self).map_err(|e| e.to_string())
    }

    pub fn decode(data: &[u8]) -> Result<Session, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config {
            challenge_interval: Duration::from_secs(1),
            interval_variance: 0.0,
            response_window: Duration::from_secs(60),
            enabled_challenges: vec![
                ChallengeType::TypePhrase,
                ChallengeType::SimpleMath,
                ChallengeType::TypeWord,
            ],
        }
    }

    #[test]
    fn test_challenge_lifecycle_type_word() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..Default::default()
        });

        let _session = verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue challenge");

        let word = challenge
            .prompt
            .strip_prefix("Type the word: ")
            .expect("prompt format");
        let ok = verifier
            .respond_to_challenge(&challenge.id, word)
            .expect("respond");
        assert!(ok);

        let session = verifier.end_session().expect("end session");
        assert_eq!(session.challenges_passed, 1);
        assert_eq!(session.challenges_failed, 0);
        assert_eq!(session.challenges_missed, 0);
    }

    #[test]
    fn test_challenge_lifecycle_type_phrase() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypePhrase],
            ..test_config()
        });

        let _session = verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue challenge");

        let phrase = challenge
            .prompt
            .strip_prefix("Type the phrase: ")
            .expect("prompt format");
        let ok = verifier
            .respond_to_challenge(&challenge.id, phrase)
            .expect("respond");
        assert!(ok);

        let session = verifier.end_session().expect("end session");
        assert_eq!(session.challenges_passed, 1);
    }

    #[test]
    fn test_challenge_lifecycle_simple_math() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::SimpleMath],
            ..test_config()
        });

        let _session = verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue challenge");

        // Parse the math problem
        let prompt = challenge
            .prompt
            .strip_prefix("Solve: ")
            .expect("prompt format");
        let prompt = prompt.strip_suffix(" = ?").expect("prompt suffix");

        // Parse operands and operator
        let parts: Vec<&str> = prompt.split_whitespace().collect();
        assert_eq!(parts.len(), 3);
        let a: i32 = parts[0].parse().expect("first operand");
        let op = parts[1];
        let b: i32 = parts[2].parse().expect("second operand");

        let result = match op {
            "+" => a + b,
            "-" => a - b,
            "*" => a * b,
            _ => panic!("unknown operator"),
        };

        let ok = verifier
            .respond_to_challenge(&challenge.id, &result.to_string())
            .expect("respond");
        assert!(ok);

        let session = verifier.end_session().expect("end session");
        assert_eq!(session.challenges_passed, 1);
    }

    #[test]
    fn test_start_session_while_active() {
        let mut verifier = Verifier::new(test_config());

        verifier.start_session().expect("start session");
        let err = verifier.start_session().unwrap_err();
        assert!(err.contains("already active"));
    }

    #[test]
    fn test_end_session_no_active() {
        let mut verifier = Verifier::new(test_config());

        let err = verifier.end_session().unwrap_err();
        assert!(err.contains("no active session"));
    }

    #[test]
    fn test_end_session_already_ended() {
        let mut verifier = Verifier::new(test_config());

        verifier.start_session().expect("start session");
        verifier.end_session().expect("end session");
        let err = verifier.end_session().unwrap_err();
        assert!(err.contains("no active session"));
    }

    #[test]
    fn test_issue_challenge_no_session() {
        let mut verifier = Verifier::new(test_config());

        let err = verifier.issue_challenge().unwrap_err();
        assert!(err.contains("no active session"));
    }

    #[test]
    fn test_respond_no_session() {
        let mut verifier = Verifier::new(test_config());

        let err = verifier
            .respond_to_challenge("some-id", "response")
            .unwrap_err();
        assert!(err.contains("no active session"));
    }

    #[test]
    fn test_respond_challenge_not_found() {
        let mut verifier = Verifier::new(test_config());

        verifier.start_session().expect("start session");
        let err = verifier
            .respond_to_challenge("nonexistent-id", "response")
            .unwrap_err();
        assert!(err.contains("challenge not found"));
    }

    #[test]
    fn test_wrong_response_fails() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });

        verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue challenge");

        let ok = verifier
            .respond_to_challenge(&challenge.id, "completely wrong answer")
            .expect("respond");
        assert!(!ok);

        let session = verifier.end_session().expect("end session");
        assert_eq!(session.challenges_passed, 0);
        assert_eq!(session.challenges_failed, 1);
    }

    #[test]
    fn test_respond_twice_to_same_challenge() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });

        verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue challenge");

        let word = challenge
            .prompt
            .strip_prefix("Type the word: ")
            .expect("prompt format");
        verifier
            .respond_to_challenge(&challenge.id, word)
            .expect("first respond");

        let err = verifier
            .respond_to_challenge(&challenge.id, word)
            .unwrap_err();
        assert!(err.contains("already resolved"));
    }

    #[test]
    fn test_multiple_challenges() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });

        verifier.start_session().expect("start session");

        for _ in 0..5 {
            let challenge = verifier.issue_challenge().expect("issue");
            let word = challenge
                .prompt
                .strip_prefix("Type the word: ")
                .expect("prompt");
            verifier
                .respond_to_challenge(&challenge.id, word)
                .expect("respond");
        }

        let session = verifier.end_session().expect("end session");
        assert_eq!(session.challenges_issued, 5);
        assert_eq!(session.challenges_passed, 5);
        assert_eq!(session.verification_rate, 1.0);
    }

    #[test]
    fn test_verification_rate_calculation() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });

        verifier.start_session().expect("start session");

        // Pass 2 challenges
        for _ in 0..2 {
            let challenge = verifier.issue_challenge().expect("issue");
            let word = challenge
                .prompt
                .strip_prefix("Type the word: ")
                .expect("prompt");
            verifier
                .respond_to_challenge(&challenge.id, word)
                .expect("respond");
        }

        // Fail 2 challenges
        for _ in 0..2 {
            let challenge = verifier.issue_challenge().expect("issue");
            verifier
                .respond_to_challenge(&challenge.id, "wrong")
                .expect("respond");
        }

        let session = verifier.end_session().expect("end session");
        assert_eq!(session.challenges_issued, 4);
        assert_eq!(session.challenges_passed, 2);
        assert_eq!(session.challenges_failed, 2);
        assert_eq!(session.verification_rate, 0.5);
    }

    #[test]
    fn test_active_session() {
        let mut verifier = Verifier::new(test_config());

        assert!(verifier.active_session().is_none());

        verifier.start_session().expect("start session");
        assert!(verifier.active_session().is_some());
        assert!(verifier.active_session().unwrap().active);

        verifier.end_session().expect("end session");
        assert!(verifier.active_session().is_none());
    }

    #[test]
    fn test_next_challenge_time_no_session() {
        let mut verifier = Verifier::new(test_config());
        assert!(verifier.next_challenge_time().is_none());
    }

    #[test]
    fn test_next_challenge_time_with_session() {
        let mut verifier = Verifier::new(test_config());
        verifier.start_session().expect("start session");

        let next_time = verifier.next_challenge_time();
        assert!(next_time.is_some());
    }

    #[test]
    fn test_should_issue_challenge() {
        let mut verifier = Verifier::new(Config {
            challenge_interval: Duration::from_millis(1),
            interval_variance: 0.0,
            ..test_config()
        });

        verifier.start_session().expect("start session");
        std::thread::sleep(Duration::from_millis(10));
        assert!(verifier.should_issue_challenge());
    }

    #[test]
    fn test_should_issue_challenge_no_session() {
        let mut verifier = Verifier::new(test_config());
        assert!(!verifier.should_issue_challenge());
    }

    #[test]
    fn test_case_insensitive_response() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });

        verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue");

        let word = challenge
            .prompt
            .strip_prefix("Type the word: ")
            .expect("prompt");
        let uppercase = word.to_uppercase();

        let ok = verifier
            .respond_to_challenge(&challenge.id, &uppercase)
            .expect("respond");
        assert!(ok);
    }

    #[test]
    fn test_response_with_whitespace() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });

        verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue");

        let word = challenge
            .prompt
            .strip_prefix("Type the word: ")
            .expect("prompt");
        let with_spaces = format!("  {}  ", word);

        let ok = verifier
            .respond_to_challenge(&challenge.id, &with_spaces)
            .expect("respond");
        assert!(ok);
    }

    #[test]
    fn test_session_encode_decode() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });

        verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue");
        let word = challenge
            .prompt
            .strip_prefix("Type the word: ")
            .expect("prompt");
        verifier
            .respond_to_challenge(&challenge.id, word)
            .expect("respond");
        let session = verifier.end_session().expect("end session");

        let encoded = session.encode().expect("encode");
        let decoded = Session::decode(&encoded).expect("decode");

        assert_eq!(decoded.id, session.id);
        assert_eq!(decoded.challenges.len(), session.challenges.len());
        assert_eq!(decoded.challenges_passed, session.challenges_passed);
    }

    #[test]
    fn test_compile_evidence_empty() {
        let evidence = compile_evidence(&[]);
        assert_eq!(evidence.total_challenges, 0);
        assert_eq!(evidence.total_passed, 0);
        assert_eq!(evidence.overall_rate, 0.0);
    }

    #[test]
    fn test_compile_evidence_multiple_sessions() {
        let mut verifier1 = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });
        verifier1.start_session().expect("start");
        let c1 = verifier1.issue_challenge().expect("issue");
        let w1 = c1.prompt.strip_prefix("Type the word: ").expect("prompt");
        verifier1.respond_to_challenge(&c1.id, w1).expect("respond");
        let session1 = verifier1.end_session().expect("end");

        let mut verifier2 = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });
        verifier2.start_session().expect("start");
        let c2 = verifier2.issue_challenge().expect("issue");
        verifier2
            .respond_to_challenge(&c2.id, "wrong")
            .expect("respond");
        let session2 = verifier2.end_session().expect("end");

        let evidence = compile_evidence(&[session1, session2]);
        assert_eq!(evidence.total_challenges, 2);
        assert_eq!(evidence.total_passed, 1);
        assert_eq!(evidence.overall_rate, 0.5);
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.challenge_interval, Duration::from_secs(10 * 60));
        assert_eq!(config.interval_variance, 0.5);
        assert_eq!(config.response_window, Duration::from_secs(60));
        assert_eq!(config.enabled_challenges.len(), 3);
    }

    #[test]
    fn test_empty_enabled_challenges_falls_back() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![],
            ..test_config()
        });

        verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue challenge");

        // Should fall back to TypePhrase
        assert!(challenge.prompt.starts_with("Type the phrase:"));
    }

    #[test]
    fn test_challenge_status_transitions() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });

        verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue");
        assert_eq!(challenge.status, ChallengeStatus::Pending);

        let word = challenge
            .prompt
            .strip_prefix("Type the word: ")
            .expect("prompt");
        verifier
            .respond_to_challenge(&challenge.id, word)
            .expect("respond");

        let session = verifier.active_session().unwrap();
        assert_eq!(session.challenges[0].status, ChallengeStatus::Passed);
    }

    #[test]
    fn test_session_has_unique_id() {
        let mut verifier = Verifier::new(test_config());

        let session1 = verifier.start_session().expect("start 1");
        verifier.end_session().expect("end 1");

        let session2 = verifier.start_session().expect("start 2");
        verifier.end_session().expect("end 2");

        assert_ne!(session1.id, session2.id);
    }

    #[test]
    fn test_challenge_has_unique_id() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });

        verifier.start_session().expect("start session");
        let c1 = verifier.issue_challenge().expect("issue 1");
        let c2 = verifier.issue_challenge().expect("issue 2");

        assert_ne!(c1.id, c2.id);
    }

    #[test]
    fn test_challenge_timestamps() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            response_window: Duration::from_secs(60),
            ..test_config()
        });

        verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue");

        assert!(challenge.expires_at > challenge.issued_at);
        assert_eq!(challenge.window, Duration::from_secs(60));
    }

    #[test]
    fn test_session_timestamps() {
        let mut verifier = Verifier::new(test_config());

        let session = verifier.start_session().expect("start");
        let start_time = session.start_time;
        assert!(session.end_time.is_none());

        std::thread::sleep(Duration::from_millis(10));
        let ended = verifier.end_session().expect("end");
        assert!(ended.end_time.is_some());
        assert!(ended.end_time.unwrap() > start_time);
    }

    #[test]
    fn test_challenge_response_recorded() {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![ChallengeType::TypeWord],
            ..test_config()
        });

        verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue");
        let word = challenge
            .prompt
            .strip_prefix("Type the word: ")
            .expect("prompt");

        verifier
            .respond_to_challenge(&challenge.id, word)
            .expect("respond");

        let session = verifier.active_session().unwrap();
        assert!(session.challenges[0].responded_at.is_some());
        assert!(session.challenges[0].response_hash.is_some());
    }

    #[test]
    fn test_all_challenge_types_verifiable() {
        for challenge_type in [
            ChallengeType::TypePhrase,
            ChallengeType::SimpleMath,
            ChallengeType::TypeWord,
        ] {
            let mut verifier = Verifier::new(Config {
                enabled_challenges: vec![challenge_type.clone()],
                ..test_config()
            });

            verifier.start_session().expect("start session");
            let challenge = verifier.issue_challenge().expect("issue");

            // Verify challenge has expected format
            match challenge_type {
                ChallengeType::TypePhrase => {
                    assert!(challenge.prompt.starts_with("Type the phrase:"))
                }
                ChallengeType::SimpleMath => assert!(challenge.prompt.starts_with("Solve:")),
                ChallengeType::TypeWord => assert!(challenge.prompt.starts_with("Type the word:")),
            }

            verifier.end_session().expect("end session");
        }
    }
}

fn hash_response(response: &str) -> String {
    let normalized = response.trim().to_lowercase();
    let digest = Sha256::digest(normalized.as_bytes());
    hex::encode(digest)
}
