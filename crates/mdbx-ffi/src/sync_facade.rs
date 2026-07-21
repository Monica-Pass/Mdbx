use mdbx_sync::{
    BlobChunkResponse, BlobManifestPageResponse, SyncMessage, SyncWireFrame, SyncWireSession,
};

use super::{
    MdbxBlobChunkRequest, MdbxBlobChunkResponse, MdbxBlobManifestPageRequest,
    MdbxBlobManifestPageResponse, MdbxBlobSyncPhase, MdbxBlobSyncResume, MdbxBlobSyncSession,
    MdbxFfiError, MdbxSyncHello, MdbxSyncWireChunkRequest, MdbxSyncWireChunkResponse,
    MdbxSyncWireHello, MdbxSyncWireManifestPageRequest, MdbxSyncWireManifestPageResponse,
    MdbxSyncWireResume, MdbxSyncWireSession,
};

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
            SyncMessage::Hello(hello) => Ok(MdbxSyncWireHello {
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
            SyncMessage::HelloAck(hello) => Ok(MdbxSyncWireHello {
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
