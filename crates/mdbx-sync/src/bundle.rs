use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

use crate::error::{SyncError, SyncResult};
use crate::message::{ObjectPayload, SerializedCommit, TombstoneRecord};

/// 文件格式魔数：`MDBXSYNC`
const BUNDLE_MAGIC: &[u8; 8] = b"MDBXSYNC";
/// 当前格式版本
const BUNDLE_VERSION: u32 = 3;
const PREVIOUS_BUNDLE_VERSION: u32 = 2;
const LEGACY_BUNDLE_VERSION: u32 = 1;
const BUNDLE_RESERVED_BYTES: usize = 20;
const BUNDLE_HASH_BYTES: usize = 32;
pub const DEFAULT_MAX_BUNDLE_PAYLOAD_BYTES: u64 = 128 * 1024 * 1024;
pub const DESKTOP_MAX_BUNDLE_PAYLOAD_BYTES: u64 = 1024 * 1024 * 1024;
const HARD_MAX_BUNDLE_PAYLOAD_BYTES: u64 = DESKTOP_MAX_BUNDLE_PAYLOAD_BYTES;
const HARD_MAX_BUNDLE_PAYLOAD_BYTES_USIZE: usize = HARD_MAX_BUNDLE_PAYLOAD_BYTES as usize;

/// 离线同步包。
///
/// 包含一组 commit 及其关联的对象数据，用于通过文件（USB、邮件等）进行离线同步。
///
/// 文件格式：
/// ```text
/// ┌──────────────────────────────────────┐
/// │ magic:    [u8; 8]  = b"MDBXSYNC"   │
/// │ version:  u32 (LE)  = 3             │
/// │ length:   u64 (LE) payload bytes    │
/// │ reserved: [u8; 12]  (zero)          │
/// │ payload:  <bincode 2 serde>         │
/// │ hash:     [u8; 32]  SHA-256(body)   │
/// └──────────────────────────────────────┘
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBundle {
    /// 导出时的 UTC 时间戳 (RFC 3339)
    pub exported_at: String,
    /// 导出设备 ID
    pub source_device_id: String,
    /// 源 vault ID
    pub vault_id: String,
    /// 包含的 commits 列表
    pub commits: Vec<SerializedCommit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleReadLimits {
    max_payload_bytes: u64,
}

impl BundleReadLimits {
    pub fn new(max_payload_bytes: u64) -> SyncResult<Self> {
        if max_payload_bytes == 0 || max_payload_bytes > HARD_MAX_BUNDLE_PAYLOAD_BYTES {
            return Err(SyncError::BundleFormat(format!(
                "bundle payload limit must be between 1 and {HARD_MAX_BUNDLE_PAYLOAD_BYTES} bytes"
            )));
        }
        Ok(Self { max_payload_bytes })
    }

    pub const fn desktop() -> Self {
        Self {
            max_payload_bytes: DESKTOP_MAX_BUNDLE_PAYLOAD_BYTES,
        }
    }

    pub const fn max_payload_bytes(self) -> u64 {
        self.max_payload_bytes
    }
}

impl Default for BundleReadLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_MAX_BUNDLE_PAYLOAD_BYTES,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacySyncBundleV1 {
    exported_at: String,
    source_device_id: String,
    vault_id: String,
    commits: Vec<LegacySerializedCommitV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacySerializedCommitV1 {
    commit: mdbx_core::model::Commit,
    parent_ids: Vec<String>,
    tombstones: Vec<TombstoneRecord>,
    object_payloads: Vec<ObjectPayload>,
}

impl From<LegacySyncBundleV1> for SyncBundle {
    fn from(legacy: LegacySyncBundleV1) -> Self {
        Self {
            exported_at: legacy.exported_at,
            source_device_id: legacy.source_device_id,
            vault_id: legacy.vault_id,
            commits: legacy
                .commits
                .into_iter()
                .map(|commit| SerializedCommit {
                    commit: commit.commit,
                    operation: None,
                    parent_ids: commit.parent_ids,
                    tombstones: commit.tombstones,
                    object_payloads: commit.object_payloads,
                })
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// 构建
// ---------------------------------------------------------------------------

/// 从 vault 导出一组 commit 为 SyncBundle。
pub fn build_bundle(
    vault_id: &str,
    source_device_id: &str,
    commits: Vec<SerializedCommit>,
) -> SyncBundle {
    SyncBundle {
        exported_at: chrono::Utc::now().to_rfc3339(),
        source_device_id: source_device_id.to_string(),
        vault_id: vault_id.to_string(),
        commits,
    }
}

// ---------------------------------------------------------------------------
// 文件写入
// ---------------------------------------------------------------------------

/// 将 SyncBundle 写入文件。
pub fn write_bundle(bundle: &SyncBundle, writer: &mut impl Write) -> SyncResult<()> {
    let mut counter = LimitedCountingWriter::new(HARD_MAX_BUNDLE_PAYLOAD_BYTES);
    let encoded_len =
        bincode::serde::encode_into_std_write(bundle, &mut counter, bincode::config::standard())
            .map_err(|error| {
                if let Some(actual) = counter.exceeded_at() {
                    SyncError::ResourceLimit {
                        resource: "sync bundle payload".to_string(),
                        actual,
                        limit: HARD_MAX_BUNDLE_PAYLOAD_BYTES,
                    }
                } else {
                    map_bundle_encode_error(error)
                }
            })?;
    let payload_len = counter.bytes_written();
    if encoded_len as u64 != payload_len {
        return Err(SyncError::BundleFormat(
            "bundle encoder reported an inconsistent payload length".to_string(),
        ));
    }

    // 写入 header
    writer.write_all(BUNDLE_MAGIC)?;
    writer.write_all(&BUNDLE_VERSION.to_le_bytes())?;
    let mut reserved = [0u8; BUNDLE_RESERVED_BYTES];
    reserved[..8].copy_from_slice(&payload_len.to_le_bytes());
    writer.write_all(&reserved)?;
    let mut hashing_writer = HashingWriter::new(writer);
    let written = bincode::serde::encode_into_std_write(
        bundle,
        &mut hashing_writer,
        bincode::config::standard(),
    )
    .map_err(map_bundle_encode_error)?;
    if written as u64 != payload_len {
        return Err(SyncError::BundleFormat(
            "bundle changed while it was being encoded".to_string(),
        ));
    }
    let hash = hashing_writer.finalize();
    writer.write_all(&hash)?;

    Ok(())
}

fn map_bundle_encode_error(error: bincode::error::EncodeError) -> SyncError {
    match error {
        bincode::error::EncodeError::Io { inner, .. } => SyncError::IoError(inner),
        other => SyncError::Serialization(other.to_string()),
    }
}

struct LimitedCountingWriter {
    bytes_written: u64,
    limit: u64,
    exceeded_at: Option<u64>,
}

impl LimitedCountingWriter {
    fn new(limit: u64) -> Self {
        Self {
            bytes_written: 0,
            limit,
            exceeded_at: None,
        }
    }

    fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    fn exceeded_at(&self) -> Option<u64> {
        self.exceeded_at
    }
}

impl Write for LimitedCountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let incoming = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        let next = self.bytes_written.saturating_add(incoming);
        if next > self.limit {
            self.exceeded_at = Some(next);
            return Err(std::io::Error::other("sync bundle payload limit exceeded"));
        }
        self.bytes_written = next;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct HashingWriter<'a, W> {
    inner: &'a mut W,
    hasher: Sha256,
}

impl<'a, W: Write> HashingWriter<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finalize(self) -> [u8; BUNDLE_HASH_BYTES] {
        let digest = self.hasher.finalize();
        let mut hash = [0u8; BUNDLE_HASH_BYTES];
        hash.copy_from_slice(&digest);
        hash
    }
}

impl<W: Write> Write for HashingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// 导出 SyncBundle 到字节数组（用于测试和传输）。
pub fn bundle_to_bytes(bundle: &SyncBundle) -> SyncResult<Vec<u8>> {
    let mut buf = Vec::new();
    write_bundle(bundle, &mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// 文件读取
// ---------------------------------------------------------------------------

/// 从 reader 读取并验证 SyncBundle。
pub fn read_bundle(reader: &mut impl Read) -> SyncResult<SyncBundle> {
    read_bundle_with_limits(reader, BundleReadLimits::default())
}

pub fn read_bundle_with_limits(
    reader: &mut impl Read,
    limits: BundleReadLimits,
) -> SyncResult<SyncBundle> {
    // 读取 magic
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if &magic != BUNDLE_MAGIC {
        return Err(SyncError::BundleFormat("invalid magic bytes".to_string()));
    }

    // 读取 version
    let mut version_buf = [0u8; 4];
    reader.read_exact(&mut version_buf)?;
    let version = u32::from_le_bytes(version_buf);
    if version != BUNDLE_VERSION
        && version != PREVIOUS_BUNDLE_VERSION
        && version != LEGACY_BUNDLE_VERSION
    {
        return Err(SyncError::BundleFormat(format!(
            "unsupported version: {version}; supported versions are {LEGACY_BUNDLE_VERSION}, {PREVIOUS_BUNDLE_VERSION}, and {BUNDLE_VERSION}"
        )));
    }

    let mut reserved = [0u8; BUNDLE_RESERVED_BYTES];
    reader.read_exact(&mut reserved)?;

    let (payload_data, stored_hash) = if version == BUNDLE_VERSION {
        read_length_prefixed_body(reader, &reserved, limits)?
    } else {
        read_legacy_body(reader, limits)?
    };

    // 验证 hash
    let computed = {
        let mut h = Sha256::new();
        h.update(&payload_data);
        h.finalize()
    };
    if stored_hash.as_slice() != computed.as_slice() {
        return Err(SyncError::BundleIntegrity(
            "SHA-256 hash mismatch".to_string(),
        ));
    }

    // 反序列化
    let (bundle, bytes_read) = if version == LEGACY_BUNDLE_VERSION {
        let (legacy, bytes_read): (LegacySyncBundleV1, usize) = bincode::serde::decode_from_slice(
            &payload_data,
            bincode::config::standard().with_limit::<HARD_MAX_BUNDLE_PAYLOAD_BYTES_USIZE>(),
        )
        .map_err(|e| SyncError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        (legacy.into(), bytes_read)
    } else {
        bincode::serde::decode_from_slice(
            &payload_data,
            bincode::config::standard().with_limit::<HARD_MAX_BUNDLE_PAYLOAD_BYTES_USIZE>(),
        )
        .map_err(|e| SyncError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?
    };
    if bytes_read != payload_data.len() {
        return Err(SyncError::BundleFormat(format!(
            "trailing payload bytes: {}",
            payload_data.len() - bytes_read
        )));
    }

    Ok(bundle)
}

fn read_length_prefixed_body(
    reader: &mut impl Read,
    reserved: &[u8; BUNDLE_RESERVED_BYTES],
    limits: BundleReadLimits,
) -> SyncResult<(Vec<u8>, [u8; BUNDLE_HASH_BYTES])> {
    if reserved[8..].iter().any(|byte| *byte != 0) {
        return Err(SyncError::BundleFormat(
            "non-zero reserved bundle header bytes".to_string(),
        ));
    }
    let mut payload_len_bytes = [0u8; 8];
    payload_len_bytes.copy_from_slice(&reserved[..8]);
    let payload_len = u64::from_le_bytes(payload_len_bytes);
    ensure_payload_within_limit(payload_len, limits.max_payload_bytes())?;
    let payload_len_usize = usize::try_from(payload_len).map_err(|_| SyncError::ResourceLimit {
        resource: "sync bundle payload".to_string(),
        actual: payload_len,
        limit: limits.max_payload_bytes(),
    })?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_len_usize)
        .map_err(|error| {
            SyncError::IoError(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                format!("unable to reserve sync bundle payload: {error}"),
            ))
        })?;
    payload.resize(payload_len_usize, 0);
    reader.read_exact(&mut payload)?;
    let mut stored_hash = [0u8; BUNDLE_HASH_BYTES];
    reader.read_exact(&mut stored_hash)?;
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(SyncError::BundleFormat(
            "trailing bytes after bundle hash".to_string(),
        ));
    }
    Ok((payload, stored_hash))
}

fn read_legacy_body(
    reader: &mut impl Read,
    limits: BundleReadLimits,
) -> SyncResult<(Vec<u8>, [u8; BUNDLE_HASH_BYTES])> {
    let body_limit = limits
        .max_payload_bytes()
        .checked_add(BUNDLE_HASH_BYTES as u64)
        .ok_or_else(|| SyncError::BundleFormat("bundle size limit overflow".to_string()))?;
    let read_limit = body_limit
        .checked_add(1)
        .ok_or_else(|| SyncError::BundleFormat("bundle size limit overflow".to_string()))?;
    let mut body = Vec::new();
    reader.take(read_limit).read_to_end(&mut body)?;
    if body.len() as u64 > body_limit {
        return Err(SyncError::ResourceLimit {
            resource: "legacy sync bundle payload".to_string(),
            actual: limits.max_payload_bytes().saturating_add(1),
            limit: limits.max_payload_bytes(),
        });
    }
    if body.len() < BUNDLE_HASH_BYTES {
        return Err(SyncError::BundleFormat(
            "payload too short (missing hash)".to_string(),
        ));
    }
    let hash_offset = body.len() - BUNDLE_HASH_BYTES;
    let mut stored_hash = [0u8; BUNDLE_HASH_BYTES];
    stored_hash.copy_from_slice(&body[hash_offset..]);
    body.truncate(hash_offset);
    ensure_payload_within_limit(body.len() as u64, limits.max_payload_bytes())?;
    Ok((body, stored_hash))
}

fn ensure_payload_within_limit(actual: u64, limit: u64) -> SyncResult<()> {
    if actual > limit {
        return Err(SyncError::ResourceLimit {
            resource: "sync bundle payload".to_string(),
            actual,
            limit,
        });
    }
    Ok(())
}

/// 从字节数组读取 SyncBundle。
pub fn bundle_from_bytes(data: &[u8]) -> SyncResult<SyncBundle> {
    let mut cursor = std::io::Cursor::new(data);
    read_bundle(&mut cursor)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::ObjectPayload;
    use mdbx_core::model::Commit;

    struct FailingWriter {
        written: usize,
        fail_after: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.written >= self.fail_after {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "simulated destination failure",
                ));
            }
            let allowed = (self.fail_after - self.written).min(buf.len());
            self.written += allowed;
            Ok(allowed)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn sample_bundle() -> SyncBundle {
        SyncBundle {
            exported_at: "2026-05-21T00:00:00Z".to_string(),
            source_device_id: "test-device".to_string(),
            vault_id: "test-vault".to_string(),
            commits: vec![SerializedCommit {
                commit: Commit {
                    commit_id: "commit-1".to_string(),
                    commit_kind: mdbx_core::model::CommitKind::Change,
                    change_scope: mdbx_core::model::ChangeScope::Entry,
                    device_id: "test-device".to_string(),
                    local_seq: 1,
                    changed_object_ids_ct: vec![],
                    vector_clock: r#"{"counter":1}"#.to_string(),
                    message_ct: None,
                    created_at: "2026-05-21T00:00:00Z".to_string(),
                    integrity_tag: vec![],
                },
                operation: None,
                parent_ids: vec!["genesis".to_string()],
                tombstones: vec![],
                object_payloads: vec![ObjectPayload {
                    object_type: "entry".to_string(),
                    object_id: "entry-1".to_string(),
                    ciphertext: b"encrypted-bytes".to_vec(),
                    associated_data: b"entry:entry-1:payload".to_vec(),
                }],
            }],
        }
    }

    fn legacy_bundle_bytes() -> Vec<u8> {
        let current = sample_bundle();
        let legacy = LegacySyncBundleV1 {
            exported_at: current.exported_at,
            source_device_id: current.source_device_id,
            vault_id: current.vault_id,
            commits: current
                .commits
                .into_iter()
                .map(|commit| LegacySerializedCommitV1 {
                    commit: commit.commit,
                    parent_ids: commit.parent_ids,
                    tombstones: commit.tombstones,
                    object_payloads: commit.object_payloads,
                })
                .collect(),
        };
        let payload = bincode::serde::encode_to_vec(legacy, bincode::config::standard()).unwrap();
        let hash = Sha256::digest(&payload);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&LEGACY_BUNDLE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&[0_u8; 20]);
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&hash);
        bytes
    }

    fn previous_v2_bundle_bytes() -> Vec<u8> {
        let payload =
            bincode::serde::encode_to_vec(sample_bundle(), bincode::config::standard()).unwrap();
        let hash = Sha256::digest(&payload);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&PREVIOUS_BUNDLE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&[0_u8; BUNDLE_RESERVED_BYTES]);
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&hash);
        bytes
    }

    fn declared_payload_len(bytes: &[u8]) -> u64 {
        let mut value = [0u8; 8];
        value.copy_from_slice(&bytes[12..20]);
        u64::from_le_bytes(value)
    }

    #[test]
    fn test_bundle_roundtrip() {
        let bundle = sample_bundle();
        let bytes = bundle_to_bytes(&bundle).unwrap();
        assert!(bytes.len() > 64);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 3);
        assert_eq!(declared_payload_len(&bytes) as usize, bytes.len() - 64);

        let restored = bundle_from_bytes(&bytes).unwrap();
        assert_eq!(restored.vault_id, bundle.vault_id);
        assert_eq!(restored.source_device_id, bundle.source_device_id);
        assert_eq!(restored.commits.len(), 1);
        assert_eq!(restored.commits[0].commit.commit_id, "commit-1");
    }

    #[test]
    fn test_legacy_v1_bundle_is_upgraded_without_operation_metadata() {
        let restored = bundle_from_bytes(&legacy_bundle_bytes()).unwrap();
        assert_eq!(restored.commits.len(), 1);
        assert!(restored.commits[0].operation.is_none());
        assert_eq!(restored.commits[0].commit.commit_id, "commit-1");
    }

    #[test]
    fn test_previous_v2_bundle_remains_readable() {
        let restored = bundle_from_bytes(&previous_v2_bundle_bytes()).unwrap();
        assert_eq!(restored.commits.len(), 1);
        assert_eq!(restored.commits[0].commit.commit_id, "commit-1");
    }

    #[test]
    fn bounded_bundle_v3_rejects_declared_length_before_allocation() {
        let limits = BundleReadLimits::new(64).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_VERSION.to_le_bytes());
        let mut reserved = [0u8; BUNDLE_RESERVED_BYTES];
        reserved[..8].copy_from_slice(&65_u64.to_le_bytes());
        bytes.extend_from_slice(&reserved);

        let error = read_bundle_with_limits(&mut std::io::Cursor::new(bytes), limits).unwrap_err();

        assert!(matches!(
            error,
            SyncError::ResourceLimit {
                actual: 65,
                limit: 64,
                ..
            }
        ));
    }

    #[test]
    fn bounded_bundle_v3_enforces_custom_limit_and_accepts_exact_size() {
        let bytes = bundle_to_bytes(&sample_bundle()).unwrap();
        let payload_len = declared_payload_len(&bytes);
        let too_small = BundleReadLimits::new(payload_len - 1).unwrap();
        assert!(matches!(
            read_bundle_with_limits(&mut std::io::Cursor::new(&bytes), too_small),
            Err(SyncError::ResourceLimit { .. })
        ));

        let exact = BundleReadLimits::new(payload_len).unwrap();
        let restored = read_bundle_with_limits(&mut std::io::Cursor::new(bytes), exact).unwrap();
        assert_eq!(restored.commits[0].commit.commit_id, "commit-1");
    }

    #[test]
    fn bounded_bundle_legacy_reader_stops_at_configured_limit() {
        let bytes = previous_v2_bundle_bytes();
        let limits = BundleReadLimits::new(16).unwrap();

        let error = read_bundle_with_limits(&mut std::io::Cursor::new(bytes), limits).unwrap_err();

        assert!(matches!(
            error,
            SyncError::ResourceLimit {
                actual: 17,
                limit: 16,
                ..
            }
        ));
    }

    #[test]
    fn bounded_bundle_v3_rejects_reserved_and_trailing_bytes() {
        let bytes = bundle_to_bytes(&sample_bundle()).unwrap();
        let mut reserved = bytes.clone();
        reserved[20] = 1;
        assert!(bundle_from_bytes(&reserved)
            .unwrap_err()
            .to_string()
            .contains("reserved"));

        let mut trailing = bytes;
        trailing.push(0);
        assert!(bundle_from_bytes(&trailing)
            .unwrap_err()
            .to_string()
            .contains("trailing bytes"));
    }

    #[test]
    fn bounded_bundle_limits_reject_invalid_configuration() {
        assert!(BundleReadLimits::new(0).is_err());
        assert!(BundleReadLimits::new(HARD_MAX_BUNDLE_PAYLOAD_BYTES + 1).is_err());
        assert_eq!(
            BundleReadLimits::desktop().max_payload_bytes(),
            DESKTOP_MAX_BUNDLE_PAYLOAD_BYTES
        );
    }

    #[test]
    fn bounded_bundle_streaming_write_preserves_destination_errors() {
        let mut writer = FailingWriter {
            written: 0,
            fail_after: 32,
        };

        let error = write_bundle(&sample_bundle(), &mut writer).unwrap_err();

        assert!(matches!(
            error,
            SyncError::IoError(ref inner)
                if inner.kind() == std::io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn bounded_bundle_counting_writer_stops_before_exceeding_limit() {
        let mut writer = LimitedCountingWriter::new(4);
        assert_eq!(writer.write(b"1234").unwrap(), 4);
        assert!(writer.write(b"5").is_err());
        assert_eq!(writer.bytes_written(), 4);
        assert_eq!(writer.exceeded_at(), Some(5));
    }

    #[test]
    fn test_magic_validation() {
        let mut bytes = bundle_to_bytes(&sample_bundle()).unwrap();
        bytes[0] = b'X';
        let result = bundle_from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_version_validation() {
        let mut bytes = bundle_to_bytes(&sample_bundle()).unwrap();
        bytes[8] = 99;
        let result = bundle_from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_tamper_detection() {
        let mut bytes = bundle_to_bytes(&sample_bundle()).unwrap();
        let tamper_idx = 40;
        bytes[tamper_idx] ^= 0xFF;
        let result = bundle_from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_commits() {
        let bundle = SyncBundle {
            exported_at: "2026-05-21T00:00:00Z".to_string(),
            source_device_id: "device".to_string(),
            vault_id: "vault".to_string(),
            commits: vec![],
        };

        let bytes = bundle_to_bytes(&bundle).unwrap();
        let restored = bundle_from_bytes(&bytes).unwrap();
        assert!(restored.commits.is_empty());
    }

    #[test]
    fn test_multiple_commits() {
        let commits: Vec<SerializedCommit> = (0..100)
            .map(|i| SerializedCommit {
                commit: Commit {
                    commit_id: format!("commit-{}", i),
                    commit_kind: mdbx_core::model::CommitKind::Change,
                    change_scope: mdbx_core::model::ChangeScope::Entry,
                    device_id: "device".to_string(),
                    local_seq: i,
                    changed_object_ids_ct: vec![],
                    vector_clock: r#"{"counter":1}"#.to_string(),
                    message_ct: None,
                    created_at: "2026-05-21T00:00:00Z".to_string(),
                    integrity_tag: vec![],
                },
                operation: None,
                parent_ids: vec![],
                tombstones: vec![],
                object_payloads: vec![],
            })
            .collect();

        let bundle = SyncBundle {
            exported_at: "2026-05-21T00:00:00Z".to_string(),
            source_device_id: "device".to_string(),
            vault_id: "vault".to_string(),
            commits,
        };

        let bytes = bundle_to_bytes(&bundle).unwrap();
        let restored = bundle_from_bytes(&bytes).unwrap();
        assert_eq!(restored.commits.len(), 100);
    }
}
