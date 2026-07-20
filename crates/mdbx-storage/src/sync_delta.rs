use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};
use crate::tiga_policy::{optional_integrity_tag, verify_optional_integrity_tag};

pub const SYNC_DELTA_FORMAT: &str = "mdbx-storage-sync-delta-v1";
pub const DEFAULT_MAX_SYNC_DELTA_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_SYNC_DELTA_ROWS: usize = 50_000;
pub const DEFAULT_MAX_SYNC_DELTA_COMMITS: usize = 512;
pub const HARD_MAX_SYNC_DELTA_PAYLOAD_BYTES: usize = 96 * 1024 * 1024;
pub const HARD_MAX_SYNC_DELTA_ROWS: usize = 250_000;
pub const HARD_MAX_SYNC_DELTA_COMMITS: usize = 4_096;
const MAX_SYNC_DELTA_ID_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncDeltaLimits {
    max_payload_bytes: usize,
    max_rows: usize,
    max_commits: usize,
}

impl SyncDeltaLimits {
    pub fn new(
        max_payload_bytes: usize,
        max_rows: usize,
        max_commits: usize,
    ) -> StorageResult<Self> {
        validate_configured_limit(
            "sync delta payload bytes",
            max_payload_bytes,
            HARD_MAX_SYNC_DELTA_PAYLOAD_BYTES,
        )?;
        validate_configured_limit("sync delta rows", max_rows, HARD_MAX_SYNC_DELTA_ROWS)?;
        validate_configured_limit(
            "sync delta commits",
            max_commits,
            HARD_MAX_SYNC_DELTA_COMMITS,
        )?;
        Ok(Self {
            max_payload_bytes,
            max_rows,
            max_commits,
        })
    }

    pub const fn max_payload_bytes(self) -> usize {
        self.max_payload_bytes
    }

    pub const fn max_rows(self) -> usize {
        self.max_rows
    }

    pub const fn max_commits(self) -> usize {
        self.max_commits
    }
}

impl Default for SyncDeltaLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_MAX_SYNC_DELTA_PAYLOAD_BYTES,
            max_rows: DEFAULT_MAX_SYNC_DELTA_ROWS,
            max_commits: DEFAULT_MAX_SYNC_DELTA_COMMITS,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SyncDeltaBatchKind {
    Commit,
    Auxiliary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSyncDeltaEnvelope {
    pub batch_id: String,
    pub batch_kind: SyncDeltaBatchKind,
    pub commit_ids: Vec<String>,
    pub logical_row_count: u32,
    pub payload: Vec<u8>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncDeltaEnvelope {
    pub format: String,
    pub batch_id: String,
    pub vault_id: String,
    pub batch_kind: SyncDeltaBatchKind,
    pub commit_ids: Vec<String>,
    pub logical_row_count: u32,
    pub payload: Vec<u8>,
    pub payload_sha256: Vec<u8>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_tag: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct SyncDeltaIntegrityValue<'a> {
    format: &'a str,
    batch_id: &'a str,
    vault_id: &'a str,
    batch_kind: SyncDeltaBatchKind,
    commit_ids: &'a [String],
    logical_row_count: u32,
    payload_sha256: &'a [u8],
    payload: &'a [u8],
    created_at: &'a str,
}

impl SyncDeltaEnvelope {
    pub fn new(
        conn: &VaultConnection,
        input: NewSyncDeltaEnvelope,
        limits: SyncDeltaLimits,
    ) -> StorageResult<Self> {
        let vault_id = load_vault_id(conn)?;
        let payload_sha256 = Sha256::digest(&input.payload).to_vec();
        let mut envelope = Self {
            format: SYNC_DELTA_FORMAT.to_string(),
            batch_id: input.batch_id,
            vault_id,
            batch_kind: input.batch_kind,
            commit_ids: input.commit_ids,
            logical_row_count: input.logical_row_count,
            payload: input.payload,
            payload_sha256,
            created_at: input.created_at,
            integrity_tag: None,
        };
        envelope.validate_structure(limits)?;
        envelope.integrity_tag = optional_integrity_tag(
            conn,
            b"mdbx-sync-delta-envelope-v1",
            &envelope.integrity_value(),
        )?;
        Ok(envelope)
    }

    pub fn encode(&self, limits: SyncDeltaLimits) -> StorageResult<Vec<u8>> {
        self.validate_structure(limits)?;
        let mut writer = LimitedVecWriter::new(limits.max_payload_bytes);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            writer
                .limit_error()
                .unwrap_or_else(|| StorageError::SchemaCreation(error.to_string()))
        })?;
        Ok(writer.bytes)
    }

    pub fn decode(bytes: &[u8], limits: SyncDeltaLimits) -> StorageResult<Self> {
        validate_actual_limit(
            "sync delta payload bytes",
            bytes.len(),
            limits.max_payload_bytes,
        )?;
        let envelope: Self = serde_json::from_slice(bytes)
            .map_err(|error| StorageError::SchemaCreation(error.to_string()))?;
        envelope.validate_structure(limits)?;
        Ok(envelope)
    }

    pub fn verify(&self, conn: &VaultConnection, limits: SyncDeltaLimits) -> StorageResult<()> {
        self.validate_structure(limits)?;
        if self.vault_id != load_vault_id(conn)? {
            return Err(StorageError::Validation(
                "sync delta belongs to a different vault".to_string(),
            ));
        }
        verify_optional_integrity_tag(
            conn,
            b"mdbx-sync-delta-envelope-v1",
            &self.integrity_value(),
            self.integrity_tag.as_deref(),
        )
    }

    fn integrity_value(&self) -> SyncDeltaIntegrityValue<'_> {
        SyncDeltaIntegrityValue {
            format: &self.format,
            batch_id: &self.batch_id,
            vault_id: &self.vault_id,
            batch_kind: self.batch_kind,
            commit_ids: &self.commit_ids,
            logical_row_count: self.logical_row_count,
            payload_sha256: &self.payload_sha256,
            payload: &self.payload,
            created_at: &self.created_at,
        }
    }

    fn validate_structure(&self, limits: SyncDeltaLimits) -> StorageResult<()> {
        if self.format != SYNC_DELTA_FORMAT {
            return Err(StorageError::Validation(format!(
                "unsupported sync delta format: {}",
                self.format
            )));
        }
        validate_id("batch ID", &self.batch_id)?;
        validate_id("vault ID", &self.vault_id)?;
        validate_id("created_at", &self.created_at)?;
        validate_actual_limit(
            "sync delta payload bytes",
            self.payload.len(),
            limits.max_payload_bytes,
        )?;
        validate_actual_limit(
            "sync delta rows",
            self.logical_row_count as usize,
            limits.max_rows,
        )?;
        validate_actual_limit(
            "sync delta commits",
            self.commit_ids.len(),
            limits.max_commits,
        )?;
        match self.batch_kind {
            SyncDeltaBatchKind::Commit if self.commit_ids.is_empty() => {
                return Err(StorageError::Validation(
                    "commit sync delta must reference at least one commit".to_string(),
                ));
            }
            SyncDeltaBatchKind::Auxiliary if !self.commit_ids.is_empty() => {
                return Err(StorageError::Validation(
                    "auxiliary sync delta cannot reference commits".to_string(),
                ));
            }
            _ => {}
        }
        let mut unique = std::collections::HashSet::new();
        for commit_id in &self.commit_ids {
            validate_id("commit ID", commit_id)?;
            if !unique.insert(commit_id) {
                return Err(StorageError::Validation(
                    "sync delta contains duplicate commit IDs".to_string(),
                ));
            }
        }
        let expected_digest = Sha256::digest(&self.payload);
        if self.payload_sha256.as_slice() != expected_digest.as_slice() {
            return Err(StorageError::Validation(
                "sync delta payload digest mismatch".to_string(),
            ));
        }
        if self
            .integrity_tag
            .as_ref()
            .is_some_and(|tag| tag.len() != 32)
        {
            return Err(StorageError::Validation(
                "sync delta integrity tag must be 32 bytes".to_string(),
            ));
        }
        Ok(())
    }
}

fn load_vault_id(conn: &VaultConnection) -> StorageResult<String> {
    conn.inner()
        .query_row("SELECT vault_id FROM vault_meta LIMIT 1", [], |row| {
            row.get(0)
        })
        .map_err(StorageError::Database)
}

fn validate_id(name: &str, value: &str) -> StorageResult<()> {
    if value.trim().is_empty() || value.len() > MAX_SYNC_DELTA_ID_BYTES {
        return Err(StorageError::Validation(format!(
            "sync delta {name} must contain between 1 and {MAX_SYNC_DELTA_ID_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_configured_limit(name: &str, actual: usize, hard: usize) -> StorageResult<()> {
    if actual == 0 || actual > hard {
        return Err(StorageError::Validation(format!(
            "{name} limit must be between 1 and {hard}"
        )));
    }
    Ok(())
}

fn validate_actual_limit(name: &str, actual: usize, limit: usize) -> StorageResult<()> {
    if actual > limit {
        return Err(StorageError::ResourceLimit {
            resource: name.to_string(),
            actual: actual as u64,
            limit: limit as u64,
        });
    }
    Ok(())
}

struct LimitedVecWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded_at: Option<usize>,
}

impl LimitedVecWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded_at: None,
        }
    }

    fn limit_error(&self) -> Option<StorageError> {
        self.exceeded_at.map(|actual| StorageError::ResourceLimit {
            resource: "sync delta payload bytes".to_string(),
            actual: actual as u64,
            limit: self.limit as u64,
        })
    }
}

impl Write for LimitedVecWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let actual = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .unwrap_or(usize::MAX);
        if actual > self.limit {
            self.exceeded_at = Some(actual);
            return Err(io::Error::other("sync delta payload limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{initialize_vault, VaultInitParams};

    fn setup() -> VaultConnection {
        let conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        conn
    }

    #[test]
    fn sync_delta_envelope_round_trips_and_detects_payload_tampering() {
        let conn = setup();
        let limits = SyncDeltaLimits::default();
        let envelope = SyncDeltaEnvelope::new(
            &conn,
            NewSyncDeltaEnvelope {
                batch_id: "batch-1".to_string(),
                batch_kind: SyncDeltaBatchKind::Commit,
                commit_ids: vec!["commit-1".to_string()],
                logical_row_count: 2,
                payload: b"bounded delta body".to_vec(),
                created_at: "2026-07-20T00:00:00Z".to_string(),
            },
            limits,
        )
        .unwrap();
        let encoded = envelope.encode(limits).unwrap();
        let decoded = SyncDeltaEnvelope::decode(&encoded, limits).unwrap();
        decoded.verify(&conn, limits).unwrap();

        let mut tampered = decoded;
        tampered.payload[0] ^= 1;
        assert!(tampered.verify(&conn, limits).is_err());
    }

    #[test]
    fn sync_delta_enforces_kind_and_resource_limits() {
        let conn = setup();
        let limits = SyncDeltaLimits::new(8, 1, 1).unwrap();
        let oversized = SyncDeltaEnvelope::new(
            &conn,
            NewSyncDeltaEnvelope {
                batch_id: "batch-2".to_string(),
                batch_kind: SyncDeltaBatchKind::Commit,
                commit_ids: vec!["commit-1".to_string()],
                logical_row_count: 1,
                payload: vec![0; 9],
                created_at: "2026-07-20T00:00:00Z".to_string(),
            },
            limits,
        )
        .unwrap_err();
        assert!(matches!(oversized, StorageError::ResourceLimit { .. }));

        let invalid = SyncDeltaEnvelope::new(
            &conn,
            NewSyncDeltaEnvelope {
                batch_id: "batch-3".to_string(),
                batch_kind: SyncDeltaBatchKind::Auxiliary,
                commit_ids: vec!["commit-1".to_string()],
                logical_row_count: 0,
                payload: Vec::new(),
                created_at: "2026-07-20T00:00:00Z".to_string(),
            },
            SyncDeltaLimits::default(),
        )
        .unwrap_err();
        assert!(invalid.to_string().contains("cannot reference commits"));
    }
}
