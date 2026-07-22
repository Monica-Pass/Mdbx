use rusqlite::types::Type;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use mdbx_core::model::{ObjectSummary, ObjectSummaryPage, ObjectTypeId};

use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};
use crate::repo::entry::EntryRepo;

pub const MAX_OBJECT_SUMMARY_PAGE_SIZE: usize = 200;
const OBJECT_SUMMARY_CURSOR_VERSION: u8 = 1;
const MAX_OBJECT_SUMMARY_CURSOR_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ObjectSummaryCursor {
    version: u8,
    collection_id: String,
    object_type_id: Option<String>,
    updated_at: String,
    object_id: String,
}

#[derive(Debug)]
struct RawObjectSummary {
    object_id: String,
    collection_id: String,
    object_type_id: String,
    title_ct: Option<Vec<u8>>,
    payload_schema_version: u32,
    head_commit_id: String,
    deleted: bool,
    updated_at: String,
}

/// 通用对象的有界元数据分页查询。
pub struct ObjectSummaryRepo;

impl ObjectSummaryRepo {
    /// Read one object's display metadata without touching its encrypted payload.
    ///
    /// Deleted objects remain visible so callers can render tombstone state without
    /// falling back to the plaintext-bearing legacy entry read API.
    pub fn get(conn: &VaultConnection, object_id: &str) -> StorageResult<Option<ObjectSummary>> {
        let raw = conn
            .inner()
            .query_row(
                "SELECT entry_id, project_id, entry_type, title_ct,
                        payload_schema_version, head_commit_id, deleted, updated_at
                 FROM entries WHERE entry_id = ?1",
                [object_id],
                read_raw_summary,
            )
            .optional()
            .map_err(StorageError::Database)?;
        raw.map(|row| decode_summary(conn, row)).transpose()
    }

    pub fn list(
        conn: &VaultConnection,
        collection_id: &str,
        object_type_id: Option<&ObjectTypeId>,
        page_size: usize,
        cursor: Option<&str>,
    ) -> StorageResult<ObjectSummaryPage> {
        if page_size == 0 || page_size > MAX_OBJECT_SUMMARY_PAGE_SIZE {
            return Err(StorageError::Validation(format!(
                "object summary page size must be between 1 and {MAX_OBJECT_SUMMARY_PAGE_SIZE}"
            )));
        }
        let object_type_value = object_type_id.map(ObjectTypeId::as_str);
        let cursor = cursor
            .map(|value| parse_cursor(value, collection_id, object_type_value))
            .transpose()?;
        let mut stmt = conn.inner().prepare(
            "SELECT entry_id, project_id, entry_type, title_ct,
                    payload_schema_version, head_commit_id, deleted, updated_at
             FROM entries
             WHERE deleted = 0 AND project_id = ?1
               AND (?2 IS NULL OR entry_type = ?2)
               AND (?3 IS NULL OR updated_at < ?3
                    OR (updated_at = ?3 AND entry_id < ?4))
             ORDER BY updated_at DESC, entry_id DESC
             LIMIT ?5",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![
                collection_id,
                object_type_value,
                cursor.as_ref().map(|cursor| cursor.updated_at.as_str()),
                cursor.as_ref().map(|cursor| cursor.object_id.as_str()),
                (page_size + 1) as i64,
            ],
            read_raw_summary,
        )?;
        let mut raw_items = Vec::with_capacity(page_size + 1);
        for row in rows.take(page_size + 1) {
            raw_items.push(row?);
        }
        let has_next = raw_items.len() > page_size;
        if has_next {
            raw_items.pop();
        }
        let next_cursor = if has_next {
            raw_items.last().map(|row| {
                encode_cursor(row, collection_id, object_type_value)
                    .expect("object summary cursor serialization cannot fail")
            })
        } else {
            None
        };
        let items = raw_items
            .into_iter()
            .map(|row| decode_summary(conn, row))
            .collect::<StorageResult<Vec<_>>>()?;
        Ok(ObjectSummaryPage { items, next_cursor })
    }
}

fn read_raw_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawObjectSummary> {
    let payload_schema_version = row.get::<_, i64>(4)?;
    Ok(RawObjectSummary {
        object_id: row.get(0)?,
        collection_id: row.get(1)?,
        object_type_id: row.get(2)?,
        title_ct: row.get(3)?,
        payload_schema_version: u32::try_from(payload_schema_version).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(4, Type::Integer, Box::new(error))
        })?,
        head_commit_id: row.get(5)?,
        deleted: row.get::<_, i32>(6)? != 0,
        updated_at: row.get(7)?,
    })
}

fn decode_summary(conn: &VaultConnection, row: RawObjectSummary) -> StorageResult<ObjectSummary> {
    let object_type_id = row
        .object_type_id
        .parse::<ObjectTypeId>()
        .map_err(StorageError::Validation)?;
    let title = row
        .title_ct
        .as_deref()
        .map(|ciphertext| EntryRepo::decrypt_metadata(conn, &row.object_id, "title", ciphertext))
        .transpose()?;
    Ok(ObjectSummary {
        object_id: row.object_id,
        collection_id: row.collection_id,
        object_type_id,
        title,
        payload_schema_version: row.payload_schema_version,
        head_commit_id: row.head_commit_id,
        deleted: row.deleted,
        updated_at: row.updated_at,
    })
}

fn encode_cursor(
    row: &RawObjectSummary,
    collection_id: &str,
    object_type_id: Option<&str>,
) -> StorageResult<String> {
    serde_json::to_string(&ObjectSummaryCursor {
        version: OBJECT_SUMMARY_CURSOR_VERSION,
        collection_id: collection_id.to_string(),
        object_type_id: object_type_id.map(str::to_string),
        updated_at: row.updated_at.clone(),
        object_id: row.object_id.clone(),
    })
    .map_err(|error| StorageError::Validation(error.to_string()))
}

fn parse_cursor(
    value: &str,
    collection_id: &str,
    object_type_id: Option<&str>,
) -> StorageResult<ObjectSummaryCursor> {
    if value.len() > MAX_OBJECT_SUMMARY_CURSOR_BYTES {
        return Err(StorageError::Validation(format!(
            "object summary cursor exceeds {MAX_OBJECT_SUMMARY_CURSOR_BYTES} bytes"
        )));
    }
    let cursor: ObjectSummaryCursor = serde_json::from_str(value).map_err(|error| {
        StorageError::Validation(format!("invalid object summary cursor: {error}"))
    })?;
    if cursor.version != OBJECT_SUMMARY_CURSOR_VERSION {
        return Err(StorageError::Validation(format!(
            "unsupported object summary cursor version {}",
            cursor.version
        )));
    }
    if cursor.collection_id != collection_id || cursor.object_type_id.as_deref() != object_type_id {
        return Err(StorageError::Validation(
            "object summary cursor does not match the requested collection and type".to_string(),
        ));
    }
    if cursor.updated_at.is_empty() || cursor.object_id.is_empty() {
        return Err(StorageError::Validation(
            "object summary cursor position is incomplete".to_string(),
        ));
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{initialize_vault, VaultInitParams};
    use crate::repo::{CommitContext, EntryRepo, ProjectRepo};
    use crate::unlock::UnlockService;

    fn setup() -> (VaultConnection, CommitContext, String, String) {
        let mut conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        UnlockService::setup_password(&mut conn, "object summary password").unwrap();
        let ctx = CommitContext::new("summary-device".to_string());
        let first = ProjectRepo::create(&conn, &ctx, "First", None, None).unwrap();
        let second = ProjectRepo::create(&conn, &ctx, "Second", None, None).unwrap();
        (conn, ctx, first.project_id, second.project_id)
    }

    #[test]
    fn object_summary_pages_are_stable_filtered_and_payload_free() {
        let (conn, ctx, collection_id, other_collection_id) = setup();
        let custom_type = ObjectTypeId::custom("com.monica.mail.message").unwrap();
        let mut expected_ids = Vec::new();
        for index in 0..5 {
            let object = EntryRepo::create_with_payload_schema_version(
                &conn,
                &ctx,
                &collection_id,
                custom_type.clone(),
                Some(&format!("Message {index}")),
                &serde_json::json!({"body": format!("secret body {index}")}),
                3,
            )
            .unwrap();
            expected_ids.push(object.entry_id);
        }
        EntryRepo::create(
            &conn,
            &ctx,
            &collection_id,
            ObjectTypeId::Login,
            Some("Login"),
            &serde_json::json!({"password": "secret"}),
        )
        .unwrap();
        EntryRepo::create(
            &conn,
            &ctx,
            &other_collection_id,
            custom_type.clone(),
            Some("Other"),
            &serde_json::json!({"body": "other"}),
        )
        .unwrap();
        conn.inner()
            .execute(
                "UPDATE entries SET updated_at = '2026-07-20T00:00:00Z'
                 WHERE project_id = ?1 AND entry_type = ?2",
                rusqlite::params![collection_id, custom_type.as_str()],
            )
            .unwrap();
        expected_ids.sort_by(|left, right| right.cmp(left));

        let mut cursor = None;
        let mut actual_ids = Vec::new();
        loop {
            let page = ObjectSummaryRepo::list(
                &conn,
                &collection_id,
                Some(&custom_type),
                2,
                cursor.as_deref(),
            )
            .unwrap();
            for item in &page.items {
                assert_eq!(item.collection_id, collection_id);
                assert_eq!(item.object_type_id, custom_type);
                assert_eq!(item.payload_schema_version, 3);
                assert!(!item.deleted);
                actual_ids.push(item.object_id.clone());
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        assert_eq!(actual_ids, expected_ids);
    }

    #[test]
    fn object_summary_does_not_read_corrupted_payload_ciphertext() {
        let (conn, ctx, collection_id, _) = setup();
        let object = EntryRepo::create(
            &conn,
            &ctx,
            &collection_id,
            ObjectTypeId::Login,
            Some("Visible title"),
            &serde_json::json!({"password": "secret"}),
        )
        .unwrap();
        conn.inner()
            .execute(
                "UPDATE entries SET payload_ct = X'00' WHERE entry_id = ?1",
                [&object.entry_id],
            )
            .unwrap();

        let page = ObjectSummaryRepo::list(&conn, &collection_id, None, 10, None).unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(
            page.items[0].title.as_deref(),
            Some(b"Visible title".as_slice())
        );
        assert!(EntryRepo::get_by_id(&conn, &object.entry_id).is_err());
    }

    #[test]
    fn object_summary_get_is_metadata_only_and_includes_deleted_objects() {
        let (conn, ctx, collection_id, _) = setup();
        let object = EntryRepo::create(
            &conn,
            &ctx,
            &collection_id,
            ObjectTypeId::Login,
            Some("Deleted title"),
            &serde_json::json!({"password": "secret"}),
        )
        .unwrap();
        EntryRepo::soft_delete(&conn, &ctx, &object.entry_id).unwrap();
        conn.inner()
            .execute(
                "UPDATE entries SET payload_ct = X'00' WHERE entry_id = ?1",
                [&object.entry_id],
            )
            .unwrap();

        let summary = ObjectSummaryRepo::get(&conn, &object.entry_id)
            .unwrap()
            .unwrap();
        assert_eq!(summary.object_id, object.entry_id);
        assert_eq!(summary.collection_id, collection_id);
        assert_eq!(summary.title.as_deref(), Some(b"Deleted title".as_slice()));
        assert!(summary.deleted);
        assert!(EntryRepo::get_by_id(&conn, &summary.object_id).is_err());
    }

    #[test]
    fn object_summary_cursor_is_bounded_and_query_bound() {
        let (conn, ctx, collection_id, other_collection_id) = setup();
        for title in ["A", "B"] {
            EntryRepo::create(
                &conn,
                &ctx,
                &collection_id,
                ObjectTypeId::Login,
                Some(title),
                &serde_json::json!({}),
            )
            .unwrap();
        }
        assert!(ObjectSummaryRepo::list(&conn, &collection_id, None, 0, None).is_err());
        assert!(ObjectSummaryRepo::list(
            &conn,
            &collection_id,
            None,
            MAX_OBJECT_SUMMARY_PAGE_SIZE + 1,
            None,
        )
        .is_err());
        assert!(ObjectSummaryRepo::list(
            &conn,
            &collection_id,
            None,
            1,
            Some(&"x".repeat(MAX_OBJECT_SUMMARY_CURSOR_BYTES + 1)),
        )
        .is_err());
        let first = ObjectSummaryRepo::list(&conn, &collection_id, None, 1, None).unwrap();
        let cursor = first.next_cursor.unwrap();
        let error = ObjectSummaryRepo::list(&conn, &other_collection_id, None, 1, Some(&cursor))
            .unwrap_err();
        assert!(error.to_string().contains("does not match"));
        let login = ObjectTypeId::Login;
        let error = ObjectSummaryRepo::list(&conn, &collection_id, Some(&login), 1, Some(&cursor))
            .unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }
}
