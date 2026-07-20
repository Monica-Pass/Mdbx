/// Compile-time capabilities present in the current MDBX build.
///
/// Security and compatibility invariants are intentionally absent from the
/// feature switch list: they are mandatory in every supported build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySet {
    pub mdbx1_compatibility: bool,
    pub authenticated_encryption: bool,
    pub tiga_policy: bool,
    pub key_epochs: bool,
    pub generic_objects: bool,
    pub generic_metadata: bool,
    pub collection_profiles: bool,
    pub payload_migrations: bool,
    pub commit_history: bool,
    pub conflicts: bool,
    pub snapshots: bool,
    pub recovery: bool,
    pub synchronization: bool,
    pub bounded_sync_state: bool,
    pub external_blob_references: bool,
    pub external_blob_lifecycle: bool,
    pub external_blob_transfer: bool,
    pub external_blob_replication: bool,
    pub filesystem_blob_store: bool,
    pub kdbx_import: bool,
    pub kdbx_export: bool,
    pub benchmarks: bool,
    pub derived_search_index: bool,
}

impl CapabilitySet {
    /// Returns the capabilities compiled into this library.
    pub const fn current() -> Self {
        Self {
            mdbx1_compatibility: true,
            authenticated_encryption: true,
            tiga_policy: true,
            key_epochs: true,
            generic_objects: true,
            generic_metadata: true,
            collection_profiles: true,
            payload_migrations: true,
            commit_history: true,
            conflicts: true,
            snapshots: true,
            recovery: true,
            synchronization: true,
            bounded_sync_state: true,
            external_blob_references: true,
            external_blob_lifecycle: true,
            external_blob_transfer: true,
            external_blob_replication: true,
            filesystem_blob_store: cfg!(feature = "filesystem-blob-store"),
            kdbx_import: cfg!(feature = "kdbx-import"),
            kdbx_export: cfg!(feature = "kdbx-export"),
            benchmarks: cfg!(feature = "benchmarks"),
            derived_search_index: cfg!(feature = "derived-search-index"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CapabilitySet;

    #[test]
    fn mandatory_database_invariants_are_present_in_every_build() {
        let capabilities = CapabilitySet::current();
        assert!(capabilities.mdbx1_compatibility);
        assert!(capabilities.authenticated_encryption);
        assert!(capabilities.tiga_policy);
        assert!(capabilities.key_epochs);
        assert!(capabilities.generic_objects);
        assert!(capabilities.generic_metadata);
        assert!(capabilities.collection_profiles);
        assert!(capabilities.payload_migrations);
        assert!(capabilities.commit_history);
        assert!(capabilities.conflicts);
        assert!(capabilities.snapshots);
        assert!(capabilities.recovery);
        assert!(capabilities.synchronization);
        assert!(capabilities.bounded_sync_state);
        assert!(capabilities.external_blob_references);
        assert!(capabilities.external_blob_lifecycle);
        assert!(capabilities.external_blob_transfer);
        assert!(capabilities.external_blob_replication);
    }

    #[test]
    fn optional_capabilities_match_cargo_features() {
        let capabilities = CapabilitySet::current();
        assert_eq!(
            capabilities.filesystem_blob_store,
            cfg!(feature = "filesystem-blob-store")
        );
        assert_eq!(capabilities.kdbx_import, cfg!(feature = "kdbx-import"));
        assert_eq!(capabilities.kdbx_export, cfg!(feature = "kdbx-export"));
        assert_eq!(capabilities.benchmarks, cfg!(feature = "benchmarks"));
        assert_eq!(
            capabilities.derived_search_index,
            cfg!(feature = "derived-search-index")
        );
    }
}
