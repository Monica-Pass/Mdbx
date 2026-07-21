use mdbx_core::tiga::{PolicyException, TigaMode, TigaPolicyOverride, TigaScope};
use mdbx_storage::error::StorageError;
use mdbx_storage::key_epoch::KeyEpochService;
use mdbx_storage::repo::CommitContext;
use mdbx_storage::tiga::TigaService;
use mdbx_storage::tiga_policy::TigaAuthorizationContext;
use mdbx_storage::unlock::UnlockService;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    conservative_ffi_device_context, unix_now, MdbxAuthorizationDecision, MdbxDeviceContext,
    MdbxFfiError, MdbxKeyEpochRotationResult, MdbxResolvedTigaPolicy, MdbxSecurityAuditEvent,
    MdbxSecurityAuditEventV2, MdbxSessionInfo, MdbxTigaMode, MdbxTigaOperation, MdbxTigaScope,
    MdbxTigaUnlockAssessment, MdbxUnlockMethod, MdbxVault,
};

#[uniffi::export]
impl MdbxVault {
    pub fn resolve_tiga_policy(
        &self,
        scope: MdbxTigaScope,
    ) -> Result<MdbxResolvedTigaPolicy, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let resolved = match scope.into_core()? {
            TigaScope::Vault => TigaService::resolve_vault_policy(&conn)?,
            TigaScope::Project { project_id } => {
                TigaService::resolve_policy_for_project(&conn, &project_id)?
            }
            TigaScope::Entry { entry_id } => {
                TigaService::resolve_policy_for_entry(&conn, &entry_id)?
            }
            TigaScope::Attachment { attachment_id } => {
                TigaService::resolve_policy_for_attachment(&conn, &attachment_id)?
            }
        };
        Ok(resolved.into())
    }

    pub fn authorize_tiga_operation(
        &self,
        scope: MdbxTigaScope,
        operation: MdbxTigaOperation,
        device: MdbxDeviceContext,
    ) -> Result<MdbxAuthorizationDecision, MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let scope = scope.into_core()?;
        let device = device.into_core(&self.device_id);
        let decision = TigaService::authorize_operation_with_active_session(
            &mut conn,
            &scope,
            operation.into(),
            &device,
            unix_now(),
        )?;
        Ok(decision.into())
    }

    pub fn active_session_info(&self) -> Result<Option<MdbxSessionInfo>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(conn.active_session().map(|session| MdbxSessionInfo {
            session_id: session.session_id.clone(),
            unlock_method: session.unlock_method.into(),
            authenticated_at_unix_secs: session.assurance.authenticated_at_unix_secs,
            last_activity_at_unix_secs: session.assurance.last_activity_at_unix_secs,
        }))
    }

    pub fn list_unlock_methods(&self) -> Result<Vec<MdbxUnlockMethod>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(UnlockService::list_methods(&conn)?
            .into_iter()
            .map(|method| MdbxUnlockMethod {
                method_id: method.method_id,
                method_type: method.method_type.into(),
                created_at: method.created_at,
                updated_at: method.updated_at,
            })
            .collect())
    }

    pub fn rotate_key_epoch(
        &self,
        device: MdbxDeviceContext,
    ) -> Result<MdbxKeyEpochRotationResult, MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let session = conn.active_session().cloned();
        let device = device.into_core(&self.device_id);
        let ctx = CommitContext::new(self.device_id.clone());
        Ok(KeyEpochService::rotate_authorized(
            &mut conn,
            &ctx,
            TigaAuthorizationContext {
                session: session.as_ref(),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?
        .into())
    }

    pub fn assess_tiga_unlock_policy(&self) -> Result<MdbxTigaUnlockAssessment, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let mode = TigaService::get_global_default(&conn)?;
        Ok(UnlockService::assess_tiga_unlock_policy(&conn, mode)?.into())
    }

    pub fn list_security_audit_events(
        &self,
        limit: u32,
    ) -> Result<Vec<MdbxSecurityAuditEvent>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(
            TigaService::list_security_audit_events(&conn, limit as usize)?
                .into_iter()
                .map(Into::into)
                .collect(),
        )
    }

    pub fn list_security_audit_events_v2(
        &self,
        limit: u32,
    ) -> Result<Vec<MdbxSecurityAuditEventV2>, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        Ok(
            TigaService::list_security_audit_events(&conn, limit as usize)?
                .into_iter()
                .map(Into::into)
                .collect(),
        )
    }

    pub fn set_tiga_profile(
        &self,
        mode: MdbxTigaMode,
        weakening_reason: Option<String>,
        exception_expires_at_unix_secs: Option<i64>,
        device: MdbxDeviceContext,
    ) -> Result<MdbxResolvedTigaPolicy, MdbxFfiError> {
        let conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let target_mode: TigaMode = mode.into();
        let current_mode = TigaService::get_global_default(&conn)?;
        let exception = if target_mode < current_mode {
            let reason = weakening_reason
                .filter(|reason| !reason.trim().is_empty())
                .ok_or_else(|| {
                    MdbxFfiError::from(StorageError::Validation(
                        "a non-empty reason is required when weakening the Tiga profile"
                            .to_string(),
                    ))
                })?;
            Some(PolicyException {
                exception_id: Uuid::new_v4().to_string(),
                target: TigaScope::Vault,
                approved_override: TigaPolicyOverride::for_vault_profile(target_mode),
                reason,
                expires_at_unix_secs: exception_expires_at_unix_secs,
            })
        } else {
            None
        };
        let session = conn.active_session().cloned();
        let device = device.into_core(&self.device_id);
        let now = unix_now();
        let ctx = CommitContext::new(self.device_id.clone());
        TigaService::set_vault_profile_authorized(
            &conn,
            &ctx,
            target_mode,
            exception.as_ref(),
            TigaAuthorizationContext {
                session: session.as_ref(),
                device: &device,
                now_unix_secs: now,
            },
        )?;
        Ok(TigaService::resolve_vault_policy(&conn)?.into())
    }

    pub fn setup_local_security_key_unlock(
        &self,
        key_material: Vec<u8>,
    ) -> Result<(), MdbxFfiError> {
        self.setup_local_security_key_unlock_with_device_context(
            key_material,
            conservative_ffi_device_context(),
        )
    }

    pub fn setup_local_security_key_unlock_with_device_context(
        &self,
        key_material: Vec<u8>,
        device: MdbxDeviceContext,
    ) -> Result<(), MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let key_material = Zeroizing::new(key_material);
        let session = conn.active_session().cloned().ok_or_else(|| {
            MdbxFfiError::from(StorageError::Validation(
                "adding a security key requires an active unlock session".to_string(),
            ))
        })?;
        let device = device.into_core(&self.device_id);
        UnlockService::setup_security_key_authorized(
            &mut conn,
            key_material.as_slice(),
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?;
        Ok(())
    }

    pub fn setup_password_security_key_unlock(
        &self,
        password: String,
        key_material: Vec<u8>,
        device: MdbxDeviceContext,
    ) -> Result<(), MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let password = Zeroizing::new(password);
        let key_material = Zeroizing::new(key_material);
        let session = conn.active_session().cloned().ok_or_else(|| {
            MdbxFfiError::from(StorageError::Validation(
                "adding a combined unlock method requires an active unlock session".to_string(),
            ))
        })?;
        let mode = TigaService::get_global_default(&conn)?;
        let device = device.into_core(&self.device_id);
        UnlockService::setup_password_security_key_authorized(
            &mut conn,
            password.as_str(),
            key_material.as_slice(),
            mode,
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?;
        Ok(())
    }

    pub fn remove_unlock_method(
        &self,
        method_id: String,
        device: MdbxDeviceContext,
    ) -> Result<(), MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let session = conn.active_session().cloned().ok_or_else(|| {
            MdbxFfiError::from(StorageError::Validation(
                "removing an unlock method requires an active unlock session".to_string(),
            ))
        })?;
        let device = device.into_core(&self.device_id);
        UnlockService::remove_method_authorized(
            &mut conn,
            &method_id,
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?;
        Ok(())
    }

    pub fn reset_master_password(&self, new_password: String) -> Result<(), MdbxFfiError> {
        self.reset_master_password_with_tiga_mode(new_password, MdbxTigaMode::Multi)
    }

    pub fn reset_master_password_with_tiga_mode(
        &self,
        new_password: String,
        mode: MdbxTigaMode,
    ) -> Result<(), MdbxFfiError> {
        self.reset_master_password_with_tiga_mode_and_device_context(
            new_password,
            mode,
            conservative_ffi_device_context(),
        )
    }

    pub fn reset_master_password_with_tiga_mode_and_device_context(
        &self,
        new_password: String,
        mode: MdbxTigaMode,
        device: MdbxDeviceContext,
    ) -> Result<(), MdbxFfiError> {
        let mut conn = self.conn.lock().map_err(|_| MdbxFfiError::LockPoisoned)?;
        let new_password = Zeroizing::new(new_password);
        let session = conn.active_session().cloned().ok_or_else(|| {
            MdbxFfiError::from(StorageError::Validation(
                "resetting the password requires an active unlock session".to_string(),
            ))
        })?;
        let device = device.into_core(&self.device_id);
        UnlockService::reset_password_authorized(
            &mut conn,
            new_password.as_str(),
            mode.into(),
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: unix_now(),
            },
        )?;
        Ok(())
    }
}
