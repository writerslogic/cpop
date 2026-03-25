// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::DateTimeNanosExt;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

/// Action recorded in the access log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessAction {
    Read,
    Write,
    Delete,
    Export,
    Verify,
}

impl AccessAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Export => "export",
            Self::Verify => "verify",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "delete" => Some(Self::Delete),
            "export" => Some(Self::Export),
            "verify" => Some(Self::Verify),
            _ => None,
        }
    }
}

/// Result of an access attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessResult {
    Success,
    Denied,
}

impl AccessResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "success" => Some(Self::Success),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

/// Single entry in the administrative access audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogEntry {
    /// Row ID (populated after insert).
    pub id: Option<i64>,
    /// Nanosecond UTC timestamp.
    pub timestamp_ns: i64,
    /// Device ID or DID of the actor.
    pub actor_id: String,
    /// What kind of operation was performed.
    pub action: AccessAction,
    /// Resource affected (file path, session ID, etc.).
    pub resource: String,
    /// Whether the operation succeeded or was denied.
    pub result: AccessResult,
    /// Source of the request (e.g. "ipc", "cli", "ffi").
    pub ip_or_source: String,
}

/// SQLite-backed administrative access audit log for SOC 2 compliance.
pub struct AccessLog {
    conn: Connection,
}

impl AccessLog {
    /// Open or create an access log database at `path`.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.execute_batch("PRAGMA busy_timeout=5000;")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS access_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ns  INTEGER NOT NULL,
                actor_id      TEXT NOT NULL,
                action        TEXT NOT NULL,
                resource      TEXT NOT NULL,
                result        TEXT NOT NULL,
                ip_or_source  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_access_log_ts
                ON access_log(timestamp_ns);
            CREATE INDEX IF NOT EXISTS idx_access_log_actor
                ON access_log(actor_id, timestamp_ns);",
        )?;

        Ok(Self { conn })
    }

    /// Open an in-memory access log (useful for tests).
    #[cfg(test)]
    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::open(":memory:")
    }

    /// Record an access event.
    pub fn log_access(&self, entry: &mut AccessLogEntry) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO access_log (timestamp_ns, actor_id, action, resource, result, ip_or_source)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                entry.timestamp_ns,
                entry.actor_id,
                entry.action.as_str(),
                entry.resource,
                entry.result.as_str(),
                entry.ip_or_source,
            ],
        )?;
        entry.id = Some(self.conn.last_insert_rowid());
        Ok(())
    }

    /// Query access log entries within a time range, optionally filtered by actor.
    pub fn query_access_log(
        &self,
        from_ns: i64,
        to_ns: i64,
        actor: Option<&str>,
    ) -> anyhow::Result<Vec<AccessLogEntry>> {
        let (query, boxed_params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match actor {
            Some(a) => (
                "SELECT id, timestamp_ns, actor_id, action, resource, result, ip_or_source \
                 FROM access_log \
                 WHERE timestamp_ns >= ? AND timestamp_ns <= ? AND actor_id = ? \
                 ORDER BY timestamp_ns ASC"
                    .to_string(),
                vec![Box::new(from_ns), Box::new(to_ns), Box::new(a.to_string())],
            ),
            None => (
                "SELECT id, timestamp_ns, actor_id, action, resource, result, ip_or_source \
                 FROM access_log \
                 WHERE timestamp_ns >= ? AND timestamp_ns <= ? \
                 ORDER BY timestamp_ns ASC"
                    .to_string(),
                vec![Box::new(from_ns), Box::new(to_ns)],
            ),
        };

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            boxed_params.iter().map(|b| b.as_ref()).collect();
        let mut stmt = self.conn.prepare(&query)?;
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            let action_str: String = row.get(3)?;
            let result_str: String = row.get(5)?;
            Ok(AccessLogEntry {
                id: Some(row.get(0)?),
                timestamp_ns: row.get(1)?,
                actor_id: row.get(2)?,
                action: AccessAction::from_str(&action_str).unwrap_or_else(|| {
                    log::warn!("Unknown access action '{}', defaulting to Read", action_str);
                    AccessAction::Read
                }),
                resource: row.get(4)?,
                result: AccessResult::from_str(&result_str).unwrap_or_else(|| {
                    log::warn!(
                        "Unknown access result '{}', defaulting to Success",
                        result_str
                    );
                    AccessResult::Success
                }),
                ip_or_source: row.get(6)?,
            })
        })?;

        rows.map(|r| r.map_err(anyhow::Error::from)).collect()
    }

    /// Export the full access log as CSV for SOC 2 auditors.
    pub fn export_access_log_csv(&self) -> anyhow::Result<String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp_ns, actor_id, action, resource, result, ip_or_source \
             FROM access_log ORDER BY timestamp_ns ASC",
        )?;

        let mut csv = String::from("id,timestamp_ns,actor_id,action,resource,result,source\n");
        let rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let ts: i64 = row.get(1)?;
            let actor: String = row.get(2)?;
            let action: String = row.get(3)?;
            let resource: String = row.get(4)?;
            let result: String = row.get(5)?;
            let source: String = row.get(6)?;
            Ok((id, ts, actor, action, resource, result, source))
        })?;

        for row in rows {
            let (id, ts, actor, action, resource, result, source) = row?;
            // Escape fields that might contain commas or quotes.
            csv.push_str(&format!(
                "{},{},\"{}\",{},\"{}\",{},\"{}\"\n",
                id,
                ts,
                actor.replace('"', "\"\""),
                action,
                resource.replace('"', "\"\""),
                result,
                source.replace('"', "\"\""),
            ));
        }

        Ok(csv)
    }

    /// Return the total number of entries in the log.
    pub fn entry_count(&self) -> anyhow::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM access_log", [], |row| row.get(0))
            .map_err(anyhow::Error::from)
    }
}

/// Helper to create an `AccessLogEntry` with the current timestamp.
pub fn new_access_entry(
    actor_id: impl Into<String>,
    action: AccessAction,
    resource: impl Into<String>,
    result: AccessResult,
    source: impl Into<String>,
) -> AccessLogEntry {
    AccessLogEntry {
        id: None,
        timestamp_ns: chrono::Utc::now().timestamp_nanos_safe(),
        actor_id: actor_id.into(),
        action,
        resource: resource.into(),
        result,
        ip_or_source: source.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(action: AccessAction, resource: &str) -> AccessLogEntry {
        AccessLogEntry {
            id: None,
            timestamp_ns: 1_000_000_000,
            actor_id: "did:key:z6MkTest".to_string(),
            action,
            resource: resource.to_string(),
            result: AccessResult::Success,
            ip_or_source: "ipc".to_string(),
        }
    }

    #[test]
    fn test_access_log_roundtrip() {
        let log = AccessLog::open_in_memory().expect("open");
        let mut entry = make_entry(AccessAction::Read, "/tmp/doc.txt");
        log.log_access(&mut entry).expect("insert");
        assert!(entry.id.is_some());

        let results = log.query_access_log(0, i64::MAX, None).expect("query");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].actor_id, "did:key:z6MkTest");
        assert_eq!(results[0].action, AccessAction::Read);
        assert_eq!(results[0].resource, "/tmp/doc.txt");
    }

    #[test]
    fn test_access_log_filter_by_actor() {
        let log = AccessLog::open_in_memory().expect("open");
        let mut e1 = make_entry(AccessAction::Write, "/a.txt");
        e1.actor_id = "actor-a".to_string();
        log.log_access(&mut e1).expect("insert");

        let mut e2 = make_entry(AccessAction::Export, "/b.txt");
        e2.actor_id = "actor-b".to_string();
        log.log_access(&mut e2).expect("insert");

        let results = log
            .query_access_log(0, i64::MAX, Some("actor-a"))
            .expect("query");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].resource, "/a.txt");
    }

    #[test]
    fn test_access_log_time_range() {
        let log = AccessLog::open_in_memory().expect("open");

        let mut e1 = make_entry(AccessAction::Read, "/early.txt");
        e1.timestamp_ns = 100;
        log.log_access(&mut e1).expect("insert");

        let mut e2 = make_entry(AccessAction::Verify, "/mid.txt");
        e2.timestamp_ns = 500;
        log.log_access(&mut e2).expect("insert");

        let mut e3 = make_entry(AccessAction::Delete, "/late.txt");
        e3.timestamp_ns = 900;
        log.log_access(&mut e3).expect("insert");

        let results = log.query_access_log(200, 600, None).expect("query");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].resource, "/mid.txt");
    }

    #[test]
    fn test_access_log_csv_export() {
        let log = AccessLog::open_in_memory().expect("open");
        let mut entry = make_entry(AccessAction::Export, "/report.cpop");
        log.log_access(&mut entry).expect("insert");

        let csv = log.export_access_log_csv().expect("csv");
        assert!(csv.starts_with("id,timestamp_ns,actor_id,action,resource,result,source\n"));
        assert!(csv.contains("export"));
        assert!(csv.contains("/report.cpop"));
    }

    #[test]
    fn test_access_log_denied_result() {
        let log = AccessLog::open_in_memory().expect("open");
        let mut entry = make_entry(AccessAction::Write, "/secret.txt");
        entry.result = AccessResult::Denied;
        log.log_access(&mut entry).expect("insert");

        let results = log.query_access_log(0, i64::MAX, None).expect("query");
        assert_eq!(results[0].result, AccessResult::Denied);
    }

    #[test]
    fn test_access_log_entry_count() {
        let log = AccessLog::open_in_memory().expect("open");
        assert_eq!(log.entry_count().expect("count"), 0);

        let mut e1 = make_entry(AccessAction::Read, "/a.txt");
        log.log_access(&mut e1).expect("insert");
        let mut e2 = make_entry(AccessAction::Write, "/b.txt");
        log.log_access(&mut e2).expect("insert");
        assert_eq!(log.entry_count().expect("count"), 2);
    }

    #[test]
    fn test_new_access_entry_helper() {
        let entry = new_access_entry(
            "device-001",
            AccessAction::Verify,
            "session-abc",
            AccessResult::Success,
            "cli",
        );
        assert_eq!(entry.actor_id, "device-001");
        assert_eq!(entry.action, AccessAction::Verify);
        assert!(entry.timestamp_ns > 0);
    }

    #[test]
    fn test_access_action_roundtrip() {
        for action in [
            AccessAction::Read,
            AccessAction::Write,
            AccessAction::Delete,
            AccessAction::Export,
            AccessAction::Verify,
        ] {
            let s = action.as_str();
            assert_eq!(AccessAction::from_str(s), Some(action));
        }
        assert_eq!(AccessAction::from_str("unknown"), None);
    }

    #[test]
    fn test_access_result_roundtrip() {
        for result in [AccessResult::Success, AccessResult::Denied] {
            let s = result.as_str();
            assert_eq!(AccessResult::from_str(s), Some(result));
        }
        assert_eq!(AccessResult::from_str("unknown"), None);
    }
}
