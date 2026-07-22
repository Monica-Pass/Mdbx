use std::sync::{Arc, Mutex};

use mdbx_sync::{
    BlobChunkRequest, BlobChunkResponse, BlobManifestEntry, BlobManifestEntryState,
    BlobManifestPageRequest, BlobManifestPageResponse, BlobSyncPhase, BlobSyncResume, BranchHead,
    HelloRequest, HelloResponse, SyncClient, SyncMessage, SyncNegotiator, SyncWireFrame,
    SyncWireLimits, SyncWireResume, SyncWireSession,
};

use super::{MdbxAuthenticatedStateRootCheckpoint, MdbxFfiError};

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncBranchHead {
    pub branch_id: Option<String>,
    pub branch_name: String,
    pub head_commit_id: String,
}

impl From<BranchHead> for MdbxSyncBranchHead {
    fn from(value: BranchHead) -> Self {
        Self {
            branch_id: value.branch_id,
            branch_name: value.branch_name,
            head_commit_id: value.head_commit_id,
        }
    }
}

impl From<MdbxSyncBranchHead> for BranchHead {
    fn from(value: MdbxSyncBranchHead) -> Self {
        Self {
            branch_id: value.branch_id,
            branch_name: value.branch_name,
            head_commit_id: value.head_commit_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncHello {
    pub device_id: String,
    pub protocol_version: u32,
    pub heads: Vec<MdbxSyncBranchHead>,
    pub known_commit_ids: Vec<String>,
    pub capabilities: Vec<String>,
}

impl From<HelloRequest> for MdbxSyncHello {
    fn from(value: HelloRequest) -> Self {
        Self {
            device_id: value.device_id,
            protocol_version: value.protocol_version,
            heads: value.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: value.known_commit_ids,
            capabilities: value.capabilities,
        }
    }
}

impl From<HelloResponse> for MdbxSyncHello {
    fn from(value: HelloResponse) -> Self {
        Self {
            device_id: value.device_id,
            protocol_version: value.protocol_version,
            heads: value.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: value.known_commit_ids,
            capabilities: value.capabilities,
        }
    }
}

impl MdbxSyncHello {
    fn into_request(self) -> HelloRequest {
        HelloRequest {
            device_id: self.device_id,
            protocol_version: self.protocol_version,
            heads: self.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: self.known_commit_ids,
            capabilities: self.capabilities,
            authenticated_state_root: None,
        }
    }

    fn into_response(self) -> HelloResponse {
        HelloResponse {
            device_id: self.device_id,
            protocol_version: self.protocol_version,
            heads: self.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: self.known_commit_ids,
            capabilities: self.capabilities,
            authenticated_state_root: None,
        }
    }
}

/// Additive Hello shape for authenticated root exchange. Existing
/// `MdbxSyncHello` callers keep their original constructor unchanged.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxIntegrityRootSyncHello {
    pub device_id: String,
    pub protocol_version: u32,
    pub heads: Vec<MdbxSyncBranchHead>,
    pub known_commit_ids: Vec<String>,
    pub capabilities: Vec<String>,
    pub authenticated_state_root: Option<MdbxAuthenticatedStateRootCheckpoint>,
}

impl From<HelloRequest> for MdbxIntegrityRootSyncHello {
    fn from(value: HelloRequest) -> Self {
        Self {
            device_id: value.device_id,
            protocol_version: value.protocol_version,
            heads: value.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: value.known_commit_ids,
            capabilities: value.capabilities,
            authenticated_state_root: value.authenticated_state_root.map(Into::into),
        }
    }
}

impl From<HelloResponse> for MdbxIntegrityRootSyncHello {
    fn from(value: HelloResponse) -> Self {
        Self {
            device_id: value.device_id,
            protocol_version: value.protocol_version,
            heads: value.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: value.known_commit_ids,
            capabilities: value.capabilities,
            authenticated_state_root: value.authenticated_state_root.map(Into::into),
        }
    }
}

impl MdbxIntegrityRootSyncHello {
    fn into_request(self) -> Result<HelloRequest, MdbxFfiError> {
        let hello = HelloRequest {
            device_id: self.device_id,
            protocol_version: self.protocol_version,
            heads: self.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: self.known_commit_ids,
            capabilities: self.capabilities,
            authenticated_state_root: self
                .authenticated_state_root
                .map(MdbxAuthenticatedStateRootCheckpoint::into_core)
                .transpose()?,
        };
        hello.validate()?;
        Ok(hello)
    }

    fn into_response(self) -> Result<HelloResponse, MdbxFfiError> {
        let hello = HelloResponse {
            device_id: self.device_id,
            protocol_version: self.protocol_version,
            heads: self.heads.into_iter().map(Into::into).collect(),
            known_commit_ids: self.known_commit_ids,
            capabilities: self.capabilities,
            authenticated_state_root: self
                .authenticated_state_root
                .map(MdbxAuthenticatedStateRootCheckpoint::into_core)
                .transpose()?,
        };
        hello.validate()?;
        Ok(hello)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxBlobManifestEntryState {
    Available,
    SourceMissing,
    SourceSizeInvalid,
}

impl From<BlobManifestEntryState> for MdbxBlobManifestEntryState {
    fn from(value: BlobManifestEntryState) -> Self {
        match value {
            BlobManifestEntryState::Available => Self::Available,
            BlobManifestEntryState::SourceMissing => Self::SourceMissing,
            BlobManifestEntryState::SourceSizeInvalid => Self::SourceSizeInvalid,
        }
    }
}

impl From<MdbxBlobManifestEntryState> for BlobManifestEntryState {
    fn from(value: MdbxBlobManifestEntryState) -> Self {
        match value {
            MdbxBlobManifestEntryState::Available => Self::Available,
            MdbxBlobManifestEntryState::SourceMissing => Self::SourceMissing,
            MdbxBlobManifestEntryState::SourceSizeInvalid => Self::SourceSizeInvalid,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobManifestEntry {
    pub blob_id: String,
    pub total_size: Option<u64>,
    pub state: MdbxBlobManifestEntryState,
}

impl From<BlobManifestEntry> for MdbxBlobManifestEntry {
    fn from(value: BlobManifestEntry) -> Self {
        Self {
            blob_id: value.blob_id,
            total_size: value.total_size,
            state: value.state.into(),
        }
    }
}

impl From<MdbxBlobManifestEntry> for BlobManifestEntry {
    fn from(value: MdbxBlobManifestEntry) -> Self {
        Self {
            blob_id: value.blob_id,
            total_size: value.total_size,
            state: value.state.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobManifestPageRequest {
    pub namespace_id: String,
    pub checkpoint: Option<String>,
    pub cursor: Option<String>,
    pub page_size: u32,
}

impl From<BlobManifestPageRequest> for MdbxBlobManifestPageRequest {
    fn from(value: BlobManifestPageRequest) -> Self {
        Self {
            namespace_id: value.namespace_id,
            checkpoint: value.checkpoint,
            cursor: value.cursor,
            page_size: u32::from(value.page_size),
        }
    }
}

impl MdbxBlobManifestPageRequest {
    fn into_core(self) -> Result<BlobManifestPageRequest, MdbxFfiError> {
        BlobManifestPageRequest::new(
            self.namespace_id,
            self.checkpoint,
            self.cursor,
            usize::try_from(self.page_size).map_err(|_| MdbxFfiError::SyncProtocol {
                message: "Blob manifest page size cannot be represented locally".to_string(),
            })?,
        )
        .map_err(Into::into)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobManifestPageResponse {
    pub namespace_id: String,
    pub checkpoint: String,
    pub items: Vec<MdbxBlobManifestEntry>,
    pub next_cursor: Option<String>,
}

impl From<BlobManifestPageResponse> for MdbxBlobManifestPageResponse {
    fn from(value: BlobManifestPageResponse) -> Self {
        Self {
            namespace_id: value.namespace_id,
            checkpoint: value.checkpoint,
            items: value.items.into_iter().map(Into::into).collect(),
            next_cursor: value.next_cursor,
        }
    }
}

impl From<MdbxBlobManifestPageResponse> for BlobManifestPageResponse {
    fn from(value: MdbxBlobManifestPageResponse) -> Self {
        Self {
            namespace_id: value.namespace_id,
            checkpoint: value.checkpoint,
            items: value.items.into_iter().map(Into::into).collect(),
            next_cursor: value.next_cursor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobChunkRequest {
    pub namespace_id: String,
    pub blob_id: String,
    pub total_size: u64,
    pub offset: u64,
    pub max_bytes: u32,
}

impl From<BlobChunkRequest> for MdbxBlobChunkRequest {
    fn from(value: BlobChunkRequest) -> Self {
        Self {
            namespace_id: value.namespace_id,
            blob_id: value.blob_id,
            total_size: value.total_size,
            offset: value.offset,
            max_bytes: value.max_bytes,
        }
    }
}

impl MdbxBlobChunkRequest {
    fn into_core(self) -> Result<BlobChunkRequest, MdbxFfiError> {
        BlobChunkRequest::new(
            self.namespace_id,
            self.blob_id,
            self.total_size,
            self.offset,
            usize::try_from(self.max_bytes).map_err(|_| MdbxFfiError::SyncProtocol {
                message: "Blob chunk size cannot be represented locally".to_string(),
            })?,
        )
        .map_err(Into::into)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobChunkResponse {
    pub namespace_id: String,
    pub blob_id: String,
    pub total_size: u64,
    pub offset: u64,
    pub ciphertext: Vec<u8>,
    pub is_last: bool,
}

impl From<BlobChunkResponse> for MdbxBlobChunkResponse {
    fn from(value: BlobChunkResponse) -> Self {
        Self {
            namespace_id: value.namespace_id,
            blob_id: value.blob_id,
            total_size: value.total_size,
            offset: value.offset,
            ciphertext: value.ciphertext,
            is_last: value.is_last,
        }
    }
}

impl From<MdbxBlobChunkResponse> for BlobChunkResponse {
    fn from(value: MdbxBlobChunkResponse) -> Self {
        Self {
            namespace_id: value.namespace_id,
            blob_id: value.blob_id,
            total_size: value.total_size,
            offset: value.offset,
            ciphertext: value.ciphertext,
            is_last: value.is_last,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxBlobSyncResume {
    pub namespace_id: String,
    pub manifest_checkpoint: Option<String>,
    pub manifest_cursor: Option<String>,
    pub current_blob_id: Option<String>,
    pub total_size: u64,
    pub next_durable_offset: u64,
    pub manifest_complete: bool,
}

impl From<BlobSyncResume> for MdbxBlobSyncResume {
    fn from(value: BlobSyncResume) -> Self {
        Self {
            namespace_id: value.namespace_id,
            manifest_checkpoint: value.manifest_checkpoint,
            manifest_cursor: value.manifest_cursor,
            current_blob_id: value.current_blob_id,
            total_size: value.total_size,
            next_durable_offset: value.next_durable_offset,
            manifest_complete: value.manifest_complete,
        }
    }
}

impl From<MdbxBlobSyncResume> for BlobSyncResume {
    fn from(value: MdbxBlobSyncResume) -> Self {
        Self {
            namespace_id: value.namespace_id,
            manifest_checkpoint: value.manifest_checkpoint,
            manifest_cursor: value.manifest_cursor,
            current_blob_id: value.current_blob_id,
            total_size: value.total_size,
            next_durable_offset: value.next_durable_offset,
            manifest_complete: value.manifest_complete,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MdbxBlobSyncPhase {
    Disabled,
    Idle,
    Manifest,
    AwaitingManifestAcknowledgement,
    Chunk,
    AwaitingChunkAcknowledgement,
    Complete,
}

impl From<BlobSyncPhase> for MdbxBlobSyncPhase {
    fn from(value: BlobSyncPhase) -> Self {
        match value {
            BlobSyncPhase::Disabled => Self::Disabled,
            BlobSyncPhase::Idle => Self::Idle,
            BlobSyncPhase::Manifest => Self::Manifest,
            BlobSyncPhase::AwaitingManifestAcknowledgement => Self::AwaitingManifestAcknowledgement,
            BlobSyncPhase::Chunk => Self::Chunk,
            BlobSyncPhase::AwaitingChunkAcknowledgement => Self::AwaitingChunkAcknowledgement,
            BlobSyncPhase::Complete => Self::Complete,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct MdbxSyncWireResume {
    pub session_id: String,
    pub next_outbound_sequence: u64,
    pub next_inbound_sequence: u64,
}

impl From<SyncWireResume> for MdbxSyncWireResume {
    fn from(value: SyncWireResume) -> Self {
        Self {
            session_id: value.session_id,
            next_outbound_sequence: value.next_outbound_sequence,
            next_inbound_sequence: value.next_inbound_sequence,
        }
    }
}

impl MdbxSyncWireResume {
    fn into_core(self) -> SyncWireResume {
        SyncWireResume {
            session_id: self.session_id,
            next_outbound_sequence: self.next_outbound_sequence,
            next_inbound_sequence: self.next_inbound_sequence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncWireHello {
    pub sequence: u64,
    pub in_reply_to: Option<u64>,
    pub hello: MdbxSyncHello,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncWireIntegrityRootHello {
    pub sequence: u64,
    pub in_reply_to: Option<u64>,
    pub hello: MdbxIntegrityRootSyncHello,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncWireManifestPageRequest {
    pub sequence: u64,
    pub in_reply_to: Option<u64>,
    pub request: MdbxBlobManifestPageRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncWireManifestPageResponse {
    pub sequence: u64,
    pub in_reply_to: Option<u64>,
    pub response: MdbxBlobManifestPageResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncWireChunkRequest {
    pub sequence: u64,
    pub in_reply_to: Option<u64>,
    pub request: MdbxBlobChunkRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MdbxSyncWireChunkResponse {
    pub sequence: u64,
    pub in_reply_to: Option<u64>,
    pub response: MdbxBlobChunkResponse,
}

#[derive(uniffi::Object)]
pub struct MdbxSyncWireSession {
    wire: Mutex<SyncWireSession>,
    limits: SyncWireLimits,
}

/// Protocol-only Blob synchronization state for generated clients. The
/// application owns transport and Provider I/O, then calls acknowledgement
/// methods only after durable storage succeeds.
#[derive(uniffi::Object)]
pub struct MdbxBlobSyncSession {
    client: Mutex<SyncClient>,
}

/// Protocol-only authenticated root negotiation. The application persists the
/// last verified remote checkpoint outside the vault and owns transport.
#[derive(uniffi::Object)]
pub struct MdbxIntegrityRootSyncSession {
    negotiator: Mutex<SyncNegotiator>,
}

#[uniffi::export]
impl MdbxSyncWireSession {
    pub fn resume(&self) -> Result<MdbxSyncWireResume, MdbxFfiError> {
        let wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(wire.resume().clone().into())
    }

    pub fn restore_resume(&self, resume: MdbxSyncWireResume) -> Result<(), MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        *wire = SyncWireSession::restore(resume.into_core())?;
        Ok(())
    }

    pub fn pending_inbound_sequence(&self) -> Result<Option<u64>, MdbxFfiError> {
        let wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(wire.pending_inbound_sequence())
    }

    pub fn acknowledge_inbound(&self, sequence: u64) -> Result<(), MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        wire.acknowledge_inbound(sequence)?;
        Ok(())
    }

    pub fn discard_inbound(&self, sequence: u64) -> Result<(), MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        wire.discard_inbound(sequence)?;
        Ok(())
    }

    pub fn encode_hello(
        &self,
        hello: MdbxSyncHello,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(SyncMessage::Hello(hello.into_request()), in_reply_to)
    }

    pub fn encode_hello_ack(
        &self,
        hello: MdbxSyncHello,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(SyncMessage::HelloAck(hello.into_response()), in_reply_to)
    }

    pub fn encode_integrity_root_hello(
        &self,
        hello: MdbxIntegrityRootSyncHello,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(SyncMessage::Hello(hello.into_request()?), in_reply_to)
    }

    pub fn encode_integrity_root_hello_ack(
        &self,
        hello: MdbxIntegrityRootSyncHello,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(SyncMessage::HelloAck(hello.into_response()?), in_reply_to)
    }

    pub fn encode_blob_manifest_page_request(
        &self,
        request: MdbxBlobManifestPageRequest,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(
            SyncMessage::BlobManifestPageRequest(request.into_core()?),
            in_reply_to,
        )
    }

    pub fn encode_blob_manifest_page_response(
        &self,
        response: MdbxBlobManifestPageResponse,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(
            SyncMessage::BlobManifestPageResponse(response.into()),
            in_reply_to,
        )
    }

    pub fn encode_blob_chunk_request(
        &self,
        request: MdbxBlobChunkRequest,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(
            SyncMessage::BlobChunkRequest(request.into_core()?),
            in_reply_to,
        )
    }

    pub fn encode_blob_chunk_response(
        &self,
        response: MdbxBlobChunkResponse,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        self.encode(SyncMessage::BlobChunkResponse(response.into()), in_reply_to)
    }

    pub fn accept_hello(&self, bytes: Vec<u8>) -> Result<MdbxSyncWireHello, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::Hello(hello) if hello.authenticated_state_root.is_none() => {
                Ok(MdbxSyncWireHello {
                    sequence: frame.sequence,
                    in_reply_to: frame.in_reply_to,
                    hello: hello.into(),
                })
            }
            SyncMessage::Hello(_) => {
                self.reject_wrong_message(frame.sequence, "Hello without integrity root")
            }
            _ => self.reject_wrong_message(frame.sequence, "Hello"),
        }
    }

    pub fn accept_integrity_root_hello(
        &self,
        bytes: Vec<u8>,
    ) -> Result<MdbxSyncWireIntegrityRootHello, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::Hello(hello) => Ok(MdbxSyncWireIntegrityRootHello {
                sequence: frame.sequence,
                in_reply_to: frame.in_reply_to,
                hello: hello.into(),
            }),
            _ => self.reject_wrong_message(frame.sequence, "Hello"),
        }
    }

    pub fn accept_hello_ack(&self, bytes: Vec<u8>) -> Result<MdbxSyncWireHello, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::HelloAck(hello) if hello.authenticated_state_root.is_none() => {
                Ok(MdbxSyncWireHello {
                    sequence: frame.sequence,
                    in_reply_to: frame.in_reply_to,
                    hello: hello.into(),
                })
            }
            SyncMessage::HelloAck(_) => {
                self.reject_wrong_message(frame.sequence, "HelloAck without integrity root")
            }
            _ => self.reject_wrong_message(frame.sequence, "HelloAck"),
        }
    }

    pub fn accept_integrity_root_hello_ack(
        &self,
        bytes: Vec<u8>,
    ) -> Result<MdbxSyncWireIntegrityRootHello, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::HelloAck(hello) => Ok(MdbxSyncWireIntegrityRootHello {
                sequence: frame.sequence,
                in_reply_to: frame.in_reply_to,
                hello: hello.into(),
            }),
            _ => self.reject_wrong_message(frame.sequence, "HelloAck"),
        }
    }

    pub fn accept_blob_manifest_page_request(
        &self,
        bytes: Vec<u8>,
    ) -> Result<MdbxSyncWireManifestPageRequest, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::BlobManifestPageRequest(request) => Ok(MdbxSyncWireManifestPageRequest {
                sequence: frame.sequence,
                in_reply_to: frame.in_reply_to,
                request: request.into(),
            }),
            _ => self.reject_wrong_message(frame.sequence, "BlobManifestPageRequest"),
        }
    }

    pub fn accept_blob_manifest_page_response(
        &self,
        bytes: Vec<u8>,
    ) -> Result<MdbxSyncWireManifestPageResponse, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::BlobManifestPageResponse(response) => {
                Ok(MdbxSyncWireManifestPageResponse {
                    sequence: frame.sequence,
                    in_reply_to: frame.in_reply_to,
                    response: response.into(),
                })
            }
            _ => self.reject_wrong_message(frame.sequence, "BlobManifestPageResponse"),
        }
    }

    pub fn accept_blob_chunk_request(
        &self,
        bytes: Vec<u8>,
    ) -> Result<MdbxSyncWireChunkRequest, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::BlobChunkRequest(request) => Ok(MdbxSyncWireChunkRequest {
                sequence: frame.sequence,
                in_reply_to: frame.in_reply_to,
                request: request.into(),
            }),
            _ => self.reject_wrong_message(frame.sequence, "BlobChunkRequest"),
        }
    }

    pub fn accept_blob_chunk_response(
        &self,
        bytes: Vec<u8>,
    ) -> Result<MdbxSyncWireChunkResponse, MdbxFfiError> {
        let frame = self.accept(bytes)?;
        match frame.message {
            SyncMessage::BlobChunkResponse(response) => Ok(MdbxSyncWireChunkResponse {
                sequence: frame.sequence,
                in_reply_to: frame.in_reply_to,
                response: response.into(),
            }),
            _ => self.reject_wrong_message(frame.sequence, "BlobChunkResponse"),
        }
    }
}

impl MdbxSyncWireSession {
    fn encode(
        &self,
        message: SyncMessage,
        in_reply_to: Option<u64>,
    ) -> Result<Vec<u8>, MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(wire.encode_outbound(message, in_reply_to, self.limits)?)
    }

    fn accept(&self, bytes: Vec<u8>) -> Result<SyncWireFrame, MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(wire.accept_inbound_bytes(&bytes, self.limits)?)
    }

    fn reject_wrong_message<T>(&self, sequence: u64, expected: &str) -> Result<T, MdbxFfiError> {
        let mut wire = self.wire.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        wire.discard_inbound(sequence)?;
        Err(MdbxFfiError::SyncProtocol {
            message: format!("expected {expected} message in sync wire frame"),
        })
    }
}

#[uniffi::export]
impl MdbxIntegrityRootSyncSession {
    pub fn hello(&self) -> Result<MdbxIntegrityRootSyncHello, MdbxFfiError> {
        let negotiator = self
            .negotiator
            .lock()
            .map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(negotiator.local_hello()?.into())
    }

    pub fn accept_hello(
        &self,
        hello: MdbxIntegrityRootSyncHello,
    ) -> Result<MdbxIntegrityRootSyncHello, MdbxFfiError> {
        let hello = hello.into_request()?;
        let mut negotiator = self
            .negotiator
            .lock()
            .map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(negotiator.on_hello(&hello)?.into())
    }

    pub fn accept_hello_ack(&self, hello: MdbxIntegrityRootSyncHello) -> Result<(), MdbxFfiError> {
        let hello = hello.into_response()?;
        let mut negotiator = self
            .negotiator
            .lock()
            .map_err(|_| MdbxFfiError::LockPoisoned)?;
        negotiator.on_hello_ack(&hello)?;
        Ok(())
    }

    pub fn integrity_root_is_negotiated(&self) -> Result<bool, MdbxFfiError> {
        let negotiator = self
            .negotiator
            .lock()
            .map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(negotiator.authenticated_state_root_is_negotiated())
    }

    pub fn remote_integrity_root_checkpoint(
        &self,
    ) -> Result<Option<MdbxAuthenticatedStateRootCheckpoint>, MdbxFfiError> {
        let negotiator = self
            .negotiator
            .lock()
            .map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(negotiator
            .remote_authenticated_state_root()
            .cloned()
            .map(Into::into))
    }
}

#[uniffi::export]
impl MdbxBlobSyncSession {
    pub fn hello(&self) -> Result<MdbxSyncHello, MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.hello()?.into())
    }

    pub fn accept_hello(&self, hello: MdbxSyncHello) -> Result<MdbxSyncHello, MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.on_hello(&hello.into_request())?.into())
    }

    pub fn accept_hello_ack(&self, hello: MdbxSyncHello) -> Result<(), MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.on_hello_ack(&hello.into_response())?;
        Ok(())
    }

    pub fn blob_replication_is_negotiated(&self) -> Result<bool, MdbxFfiError> {
        let client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.blob_replication_is_negotiated())
    }

    pub fn begin_blob_sync(&self, namespace_id: String) -> Result<(), MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.begin_blob_sync(namespace_id)?;
        Ok(())
    }

    pub fn restore_blob_sync(&self, resume: MdbxBlobSyncResume) -> Result<(), MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.restore_blob_sync(resume.into())?;
        Ok(())
    }

    pub fn blob_resume(&self) -> Result<Option<MdbxBlobSyncResume>, MdbxFfiError> {
        let client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.blob_resume().cloned().map(Into::into))
    }

    pub fn blob_sync_phase(&self) -> Result<MdbxBlobSyncPhase, MdbxFfiError> {
        let client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.blob_sync_phase().into())
    }

    pub fn blob_manifest_request(
        &self,
        page_size: u32,
    ) -> Result<MdbxBlobManifestPageRequest, MdbxFfiError> {
        let page_size = usize::try_from(page_size).map_err(|_| MdbxFfiError::SyncProtocol {
            message: "Blob manifest page size cannot be represented locally".to_string(),
        })?;
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client.blob_manifest_request(page_size)?.into())
    }

    pub fn validate_blob_manifest_response(
        &self,
        response: MdbxBlobManifestPageResponse,
    ) -> Result<(), MdbxFfiError> {
        let response: BlobManifestPageResponse = response.into();
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.validate_blob_manifest_response(&response)?;
        Ok(())
    }

    pub fn acknowledge_blob_manifest_page(
        &self,
        response: MdbxBlobManifestPageResponse,
    ) -> Result<(), MdbxFfiError> {
        let response: BlobManifestPageResponse = response.into();
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.acknowledge_blob_manifest_page(&response)?;
        Ok(())
    }

    pub fn blob_chunk_request(
        &self,
        blob_id: String,
        total_size: u64,
        max_bytes: u32,
    ) -> Result<MdbxBlobChunkRequest, MdbxFfiError> {
        let max_bytes = usize::try_from(max_bytes).map_err(|_| MdbxFfiError::SyncProtocol {
            message: "Blob chunk size cannot be represented locally".to_string(),
        })?;
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(client
            .blob_chunk_request(blob_id, total_size, max_bytes)?
            .into())
    }

    pub fn validate_blob_chunk_response(
        &self,
        response: MdbxBlobChunkResponse,
    ) -> Result<(), MdbxFfiError> {
        let response: BlobChunkResponse = response.into();
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.validate_blob_chunk_response(&response)?;
        Ok(())
    }

    pub fn acknowledge_blob_chunk(
        &self,
        response: MdbxBlobChunkResponse,
    ) -> Result<(), MdbxFfiError> {
        let response: BlobChunkResponse = response.into();
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.acknowledge_blob_chunk(&response)?;
        Ok(())
    }

    pub fn restart_blob_transfer_after_abort(
        &self,
        blob_id: String,
        total_size: u64,
    ) -> Result<(), MdbxFfiError> {
        let mut client = self.client.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        client.restart_blob_transfer_after_abort(&blob_id, total_size)?;
        Ok(())
    }
}

#[uniffi::export]
pub fn create_integrity_root_sync_session(
    device_id: String,
    checkpoint: MdbxAuthenticatedStateRootCheckpoint,
) -> Result<Arc<MdbxIntegrityRootSyncSession>, MdbxFfiError> {
    let mut negotiator = SyncNegotiator::new(&device_id, Vec::new(), Vec::new());
    negotiator.enable_authenticated_state_root_checkpoint(checkpoint.into_core()?)?;
    Ok(Arc::new(MdbxIntegrityRootSyncSession {
        negotiator: Mutex::new(negotiator),
    }))
}

#[uniffi::export]
pub fn create_blob_sync_session(
    device_id: String,
) -> Result<Arc<MdbxBlobSyncSession>, MdbxFfiError> {
    let mut negotiator = SyncNegotiator::new(&device_id, Vec::new(), Vec::new());
    negotiator.enable_blob_replication_capabilities()?;
    Ok(Arc::new(MdbxBlobSyncSession {
        client: Mutex::new(SyncClient::new(negotiator, None, None)),
    }))
}

#[uniffi::export]
pub fn default_sync_wire_payload_bytes() -> u64 {
    mdbx_sync::MAX_SYNC_WIRE_PAYLOAD_BYTES
}

#[uniffi::export]
pub fn create_sync_wire_session(
    session_id: String,
    max_payload_bytes: u64,
) -> Result<Arc<MdbxSyncWireSession>, MdbxFfiError> {
    let limits = SyncWireLimits::new(max_payload_bytes)?;
    Ok(Arc::new(MdbxSyncWireSession {
        wire: Mutex::new(SyncWireSession::new(session_id)?),
        limits,
    }))
}
