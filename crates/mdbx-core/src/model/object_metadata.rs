use serde::{Deserialize, Serialize};

use super::entry::validate_extension_id;
use crate::types::*;

/// Namespaced stable identifier describing the meaning of a directed relation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelationKindId(String);

impl RelationKindId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        value.into().parse()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RelationKindId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for RelationKindId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        validate_extension_id(value)?;
        if !value.contains('.') {
            return Err("relation kind ID must be namespaced".to_string());
        }
        Ok(Self(value.to_string()))
    }
}

impl Serialize for RelationKindId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelationKindId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Stable directed edge between two encrypted object records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectRelation {
    pub relation_id: ObjectRelationId,
    pub source_object_id: EntryId,
    pub target_object_id: EntryId,
    pub relation_kind: RelationKindId,
    pub payload_ct: CipherText,
    pub payload_schema_version: u32,
    pub object_clock: ObjectClock,
    pub head_commit_id: CommitId,
    pub deleted: bool,
    pub created_at: String,
    pub updated_at: String,
    pub created_by_device_id: DeviceId,
    pub updated_by_device_id: DeviceId,
}

/// Stable encrypted label definition scoped to one collection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectLabel {
    pub label_id: ObjectLabelId,
    pub collection_id: ProjectId,
    pub name_ct: CipherText,
    pub payload_ct: CipherText,
    pub payload_schema_version: u32,
    pub object_clock: ObjectClock,
    pub head_commit_id: CommitId,
    pub deleted: bool,
    pub created_at: String,
    pub updated_at: String,
    pub created_by_device_id: DeviceId,
    pub updated_by_device_id: DeviceId,
}

/// Stable many-to-many membership between an object and a label definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectLabelAssignment {
    pub assignment_id: ObjectLabelAssignmentId,
    pub object_id: EntryId,
    pub label_id: ObjectLabelId,
    pub object_clock: ObjectClock,
    pub head_commit_id: CommitId,
    pub deleted: bool,
    pub created_at: String,
    pub updated_at: String,
    pub created_by_device_id: DeviceId,
    pub updated_by_device_id: DeviceId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_kind_requires_a_valid_namespace() {
        let kind = RelationKindId::new("com.monica.mail.reply-to").unwrap();
        assert_eq!(kind.as_str(), "com.monica.mail.reply-to");
        assert!(RelationKindId::new("reply-to").is_err());
        assert!(RelationKindId::new("Com.Monica.Mail").is_err());
        assert!(RelationKindId::new("com.monica..mail").is_err());
    }

    #[test]
    fn relation_kind_serializes_as_its_exact_identifier() {
        let kind = RelationKindId::new("com.monica.bookmark.member-of").unwrap();
        let encoded = serde_json::to_string(&kind).unwrap();
        assert_eq!(encoded, r#""com.monica.bookmark.member-of""#);
        assert_eq!(
            serde_json::from_str::<RelationKindId>(&encoded).unwrap(),
            kind
        );
    }
}
