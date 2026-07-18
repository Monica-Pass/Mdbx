use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use mdbx_core::model::VaultSession;
use mdbx_core::tiga::{
    AuthorizationConstraint, AuthorizationContext, AuthorizationDecision, AuthorizationOutcome,
    AuthorizationReason, DeviceContext, PolicyCompliance, PolicyException, PolicyResolutionError,
    ResolvedTigaPolicy, TigaOperation, TigaPolicyOverride, TigaPolicyResolver, TigaScope,
    TIGA_POLICY_VERSION,
};
use mdbx_crypto::integrity::hmac_sha256;

use crate::connection::VaultConnection;
use crate::error::{StorageError, StorageResult};
use crate::repo::commit_ctx::CommitContext;
use crate::repo::entry::EntryRepo;
use crate::repo::object_version::ObjectVersionRepo;
use crate::repo::project::ProjectRepo;
use crate::tiga::{bump_clock, current_device_head, TigaService};

const STATUS_COMPLIANT: &str = "compliant";
const STATUS_EXCEPTION: &str = "exception";
const STATUS_REMEDIATION: &str = "remediation-required";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TigaPolicyState {
    pub policy_version: u32,
    pub compliance: PolicyCompliance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityAuditEvent {
    pub event_id: String,
    pub occurred_at: String,
    pub operation: TigaOperation,
    pub outcome: AuthorizationOutcome,
    pub scope: TigaScope,
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub reasons: Vec<AuthorizationReason>,
    pub constraints: Vec<AuthorizationConstraint>,
    pub exception_id: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct TigaAuthorizationContext<'a> {
    pub session: Option<&'a VaultSession>,
    pub device: &'a DeviceContext,
    pub now_unix_secs: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct StoredPolicyOverride {
    pub policy_override: TigaPolicyOverride,
    pub exception_id: Option<String>,
}

pub(crate) struct TigaPolicyStore;

impl TigaPolicyStore {
    pub(crate) fn get_override(
        conn: &VaultConnection,
        scope: &TigaScope,
    ) -> StorageResult<Option<StoredPolicyOverride>> {
        let (scope_type, scope_id) = scope_parts(scope);
        conn.inner()
            .query_row(
                "SELECT policy_json, exception_id FROM tiga_policy_overrides
                 WHERE scope_type = ?1 AND scope_id = ?2",
                params![scope_type, scope_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .map(|(json, exception_id)| {
                let policy_override = serde_json::from_str(&json).map_err(|e| {
                    StorageError::Validation(format!("invalid stored Tiga policy override: {e}"))
                })?;
                Ok(StoredPolicyOverride {
                    policy_override,
                    exception_id,
                })
            })
            .transpose()
    }

    pub(crate) fn put_override(
        conn: &VaultConnection,
        scope: &TigaScope,
        policy_override: &TigaPolicyOverride,
        exception_id: Option<&str>,
        device_id: &str,
        integrity_tag: Option<&[u8]>,
    ) -> StorageResult<()> {
        let (scope_type, scope_id) = scope_parts(scope);
        let json = serde_json::to_string(policy_override)
            .map_err(|e| StorageError::Validation(format!("cannot encode Tiga policy: {e}")))?;
        conn.inner().execute(
            "INSERT INTO tiga_policy_overrides
                (scope_type, scope_id, policy_json, exception_id, updated_at,
                 updated_by_device_id, integrity_tag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(scope_type, scope_id) DO UPDATE SET
                policy_json = excluded.policy_json,
                exception_id = excluded.exception_id,
                updated_at = excluded.updated_at,
                updated_by_device_id = excluded.updated_by_device_id,
                integrity_tag = excluded.integrity_tag",
            params![
                scope_type,
                scope_id,
                json,
                exception_id,
                chrono::Utc::now().to_rfc3339(),
                device_id,
                integrity_tag,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn delete_override(conn: &VaultConnection, scope: &TigaScope) -> StorageResult<()> {
        let (scope_type, scope_id) = scope_parts(scope);
        conn.inner().execute(
            "DELETE FROM tiga_policy_overrides WHERE scope_type = ?1 AND scope_id = ?2",
            params![scope_type, scope_id],
        )?;
        Ok(())
    }

    pub(crate) fn put_exception(
        conn: &VaultConnection,
        exception: &PolicyException,
        created_by_session_id: Option<&str>,
        integrity_tag: Option<&[u8]>,
    ) -> StorageResult<()> {
        let (target_scope, target_id) = scope_parts(&exception.target);
        let json = serde_json::to_string(&exception.approved_override).map_err(|e| {
            StorageError::Validation(format!("cannot encode Tiga policy exception: {e}"))
        })?;
        conn.inner().execute(
            "INSERT INTO tiga_policy_exceptions
                (exception_id, target_scope, target_id, approved_override_json, reason,
                 expires_at_unix_secs, created_at, created_by_session_id, revoked_at,
                 integrity_tag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9)
             ON CONFLICT(exception_id) DO UPDATE SET
                target_scope = excluded.target_scope,
                target_id = excluded.target_id,
                approved_override_json = excluded.approved_override_json,
                reason = excluded.reason,
                expires_at_unix_secs = excluded.expires_at_unix_secs,
                created_by_session_id = excluded.created_by_session_id,
                revoked_at = NULL,
                integrity_tag = excluded.integrity_tag",
            params![
                exception.exception_id,
                target_scope,
                target_id,
                json,
                exception.reason,
                exception.expires_at_unix_secs,
                chrono::Utc::now().to_rfc3339(),
                created_by_session_id,
                integrity_tag,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn get_exception(
        conn: &VaultConnection,
        exception_id: &str,
    ) -> StorageResult<Option<PolicyException>> {
        conn.inner()
            .query_row(
                "SELECT target_scope, target_id, approved_override_json, reason,
                        expires_at_unix_secs
                 FROM tiga_policy_exceptions
                 WHERE exception_id = ?1 AND revoked_at IS NULL",
                params![exception_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(scope_type, scope_id, json, reason, expires_at_unix_secs)| {
                    let approved_override = serde_json::from_str(&json).map_err(|e| {
                        StorageError::Validation(format!("invalid stored Tiga exception: {e}"))
                    })?;
                    Ok(PolicyException {
                        exception_id: exception_id.to_string(),
                        target: parse_scope(&scope_type, &scope_id)?,
                        approved_override,
                        reason,
                        expires_at_unix_secs,
                    })
                },
            )
            .transpose()
    }

    pub(crate) fn find_exception(
        conn: &VaultConnection,
        scope: &TigaScope,
        policy_override: &TigaPolicyOverride,
        now_unix_secs: i64,
    ) -> StorageResult<Option<PolicyException>> {
        let (scope_type, scope_id) = scope_parts(scope);
        let mut stmt = conn.inner().prepare(
            "SELECT exception_id FROM tiga_policy_exceptions
             WHERE target_scope = ?1 AND target_id = ?2 AND revoked_at IS NULL
             ORDER BY created_at DESC, exception_id DESC",
        )?;
        let rows = stmt.query_map(params![scope_type, scope_id], |row| row.get::<_, String>(0))?;
        for row in rows {
            let exception_id = row?;
            if let Some(exception) = Self::get_exception(conn, &exception_id)? {
                if exception.is_valid_for(scope, policy_override, now_unix_secs) {
                    return Ok(Some(exception));
                }
            }
        }
        Ok(None)
    }

    pub(crate) fn record_audit_event(
        conn: &VaultConnection,
        event: &SecurityAuditEvent,
        integrity_tag: Option<&[u8]>,
    ) -> StorageResult<()> {
        let (scope_type, scope_id) = scope_parts(&event.scope);
        conn.inner().execute(
            "INSERT INTO security_audit_events
                (event_id, occurred_at, operation, outcome, scope_type, scope_id,
                 session_id, device_id, reason_codes_json, constraints_json,
                 exception_id, integrity_tag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                event.event_id,
                event.occurred_at,
                enum_storage_value(&event.operation)?,
                enum_storage_value(&event.outcome)?,
                scope_type,
                scope_id,
                event.session_id,
                event.device_id,
                serde_json::to_string(&event.reasons)
                    .map_err(|e| StorageError::Validation(e.to_string()))?,
                serde_json::to_string(&event.constraints)
                    .map_err(|e| StorageError::Validation(e.to_string()))?,
                event.exception_id,
                integrity_tag,
            ],
        )?;
        Ok(())
    }
}

impl TigaService {
    pub fn get_policy_state(conn: &VaultConnection) -> StorageResult<TigaPolicyState> {
        conn.inner()
            .query_row(
                "SELECT tiga_policy_version, tiga_compliance_status FROM vault_meta",
                [],
                |row| Ok((row.get::<_, i64>(0)? as u32, row.get::<_, String>(1)?)),
            )
            .map_err(StorageError::Database)
            .and_then(|(policy_version, status)| {
                if policy_version != TIGA_POLICY_VERSION {
                    return Err(StorageError::Validation(format!(
                        "unsupported Tiga policy version {policy_version}; expected {TIGA_POLICY_VERSION}"
                    )));
                }
                Ok(TigaPolicyState {
                    policy_version,
                    compliance: parse_compliance(&status)?,
                })
            })
    }

    pub fn resolve_vault_policy(conn: &VaultConnection) -> StorageResult<ResolvedTigaPolicy> {
        let base = Self::get_global_default(conn)?.policy();
        let resolved = ResolvedTigaPolicy {
            policy: base,
            compliance: Self::get_policy_state(conn)?.compliance,
            exception_id: None,
            warnings: Vec::new(),
        };
        apply_stored_override(conn, resolved, TigaScope::Vault)
    }

    pub fn resolve_policy_for_project(
        conn: &VaultConnection,
        project_id: &str,
    ) -> StorageResult<ResolvedTigaPolicy> {
        let project = ProjectRepo::get_by_id(conn, project_id)?
            .ok_or_else(|| StorageError::NotFound(project_id.to_string()))?;
        let scope = TigaScope::Project {
            project_id: project_id.to_string(),
        };
        let mut resolved = Self::resolve_vault_policy(conn)?;
        if let Some(mode) = project.tiga_mode_override {
            resolved = apply_profile_override(conn, resolved, scope.clone(), mode)?;
        }
        apply_stored_override(conn, resolved, scope)
    }

    pub fn resolve_policy_for_entry(
        conn: &VaultConnection,
        entry_id: &str,
    ) -> StorageResult<ResolvedTigaPolicy> {
        let entry = EntryRepo::get_by_id(conn, entry_id)?
            .ok_or_else(|| StorageError::NotFound(entry_id.to_string()))?;
        let scope = TigaScope::Entry {
            entry_id: entry_id.to_string(),
        };
        let mut resolved = Self::resolve_policy_for_project(conn, &entry.project_id)?;
        if let Some(mode) = entry.tiga_mode_override {
            resolved = apply_profile_override(conn, resolved, scope.clone(), mode)?;
        }
        apply_stored_override(conn, resolved, scope)
    }

    pub fn list_security_audit_events(
        conn: &VaultConnection,
        limit: usize,
    ) -> StorageResult<Vec<SecurityAuditEvent>> {
        let mut stmt = conn.inner().prepare(
            "SELECT event_id, occurred_at, operation, outcome, scope_type, scope_id,
                    session_id, device_id, reason_codes_json, constraints_json, exception_id
             FROM security_audit_events
             ORDER BY occurred_at DESC, event_id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.min(i64::MAX as usize) as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, Option<String>>(10)?,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (
                event_id,
                occurred_at,
                operation,
                outcome,
                scope_type,
                scope_id,
                session_id,
                device_id,
                reasons,
                constraints,
                exception_id,
            ) = row?;
            events.push(SecurityAuditEvent {
                event_id,
                occurred_at,
                operation: parse_enum_storage_value(&operation)?,
                outcome: parse_enum_storage_value(&outcome)?,
                scope: parse_scope(&scope_type, &scope_id)?,
                session_id,
                device_id,
                reasons: serde_json::from_str(&reasons)
                    .map_err(|e| StorageError::Validation(e.to_string()))?,
                constraints: serde_json::from_str(&constraints)
                    .map_err(|e| StorageError::Validation(e.to_string()))?,
                exception_id,
            });
        }
        Ok(events)
    }

    pub fn evaluate_operation(
        conn: &VaultConnection,
        scope: &TigaScope,
        operation: TigaOperation,
        context: TigaAuthorizationContext<'_>,
    ) -> StorageResult<AuthorizationDecision> {
        let mut resolved = resolve_scope_policy(conn, scope)?;
        if operation == TigaOperation::ChangeUnlockMethods
            && resolved.compliance == PolicyCompliance::RemediationRequired
        {
            resolved.policy.unlock.minimum_auth_factors = 1;
            resolved.policy.unlock.security_key_required = false;
            resolved.policy.administration.minimum_auth_factors = 1;
            resolved.policy.minimum_device_assurance = mdbx_core::tiga::DeviceAssurance::Standard;
        }
        Ok(resolved.policy.authorize(
            operation,
            AuthorizationContext {
                session: context.session.map(|session| &session.assurance),
                device: context.device,
                now_unix_secs: context.now_unix_secs,
            },
        ))
    }

    /// Evaluate an operation and persist its audit event before the caller
    /// performs any client-owned action such as reveal or clipboard access.
    pub fn authorize_operation(
        conn: &VaultConnection,
        scope: &TigaScope,
        operation: TigaOperation,
        context: TigaAuthorizationContext<'_>,
    ) -> StorageResult<AuthorizationDecision> {
        let decision = Self::evaluate_operation(conn, scope, operation, context)?;
        if decision.audit_required {
            conn.with_immediate_transaction(|| {
                record_authorization_event(conn, scope, operation, context, &decision, None)
            })?;
        }
        Ok(decision)
    }

    /// Authorize a client-owned operation using the connection's active
    /// session. A successful decision renews only the idle-activity timestamp;
    /// the original authentication time and absolute lifetime are unchanged.
    pub fn authorize_operation_with_active_session(
        conn: &mut VaultConnection,
        scope: &TigaScope,
        operation: TigaOperation,
        device: &DeviceContext,
        now_unix_secs: i64,
    ) -> StorageResult<AuthorizationDecision> {
        let session = conn.active_session().cloned();
        let context = TigaAuthorizationContext {
            session: session.as_ref(),
            device,
            now_unix_secs,
        };
        let decision = Self::authorize_operation(conn, scope, operation, context)?;
        if decision_allows(&decision) && operation != TigaOperation::SyncCiphertext {
            conn.touch_active_session(now_unix_secs);
        }
        Ok(decision)
    }

    pub(crate) fn execute_authorized<T>(
        conn: &VaultConnection,
        scope: &TigaScope,
        operation: TigaOperation,
        context: TigaAuthorizationContext<'_>,
        action: impl FnOnce() -> StorageResult<T>,
    ) -> StorageResult<(T, AuthorizationDecision)> {
        let decision = Self::evaluate_operation(conn, scope, operation, context)?;
        if !decision_allows(&decision) {
            conn.with_immediate_transaction(|| {
                record_authorization_event(conn, scope, operation, context, &decision, None)
            })?;
            return Err(StorageError::Authorization(decision));
        }
        conn.with_immediate_transaction(|| {
            let value = action()?;
            if decision.audit_required {
                record_authorization_event(conn, scope, operation, context, &decision, None)?;
            }
            Ok((value, decision))
        })
    }

    pub(crate) fn execute_authorized_mut<T>(
        conn: &mut VaultConnection,
        scope: &TigaScope,
        operation: TigaOperation,
        context: TigaAuthorizationContext<'_>,
        action: impl FnOnce(&mut VaultConnection) -> StorageResult<T>,
    ) -> StorageResult<(T, AuthorizationDecision)> {
        let decision = Self::evaluate_operation(conn, scope, operation, context)?;
        if !decision_allows(&decision) {
            conn.with_immediate_transaction(|| {
                record_authorization_event(conn, scope, operation, context, &decision, None)
            })?;
            return Err(StorageError::Authorization(decision));
        }
        conn.with_immediate_transaction_mut(|conn| {
            let value = action(conn)?;
            if decision.audit_required {
                record_authorization_event(conn, scope, operation, context, &decision, None)?;
            }
            Ok((value, decision))
        })
    }

    pub fn set_vault_profile_authorized(
        conn: &VaultConnection,
        ctx: &CommitContext,
        mode: mdbx_core::tiga::TigaMode,
        exception: Option<&PolicyException>,
        context: TigaAuthorizationContext<'_>,
    ) -> StorageResult<()> {
        let scope = TigaScope::Vault;
        let decision = authorize_mutation(conn, &scope, context)?;
        let current_mode = Self::get_global_default(conn)?;
        let policy_override = TigaPolicyOverride::for_vault_profile(mode);
        let resolved = match TigaPolicyResolver::resolve(
            &current_mode.policy(),
            scope.clone(),
            &policy_override,
            exception,
            context.now_unix_secs,
        ) {
            Ok(resolved) => resolved,
            Err(error) => {
                record_resolution_denial(conn, &scope, context, &error)?;
                return Err(policy_error(error));
            }
        };
        let override_tag = if resolved.compliance == PolicyCompliance::Exception {
            Some(integrity_tag(
                conn,
                b"tiga-policy-override",
                &policy_override,
            )?)
        } else {
            None
        };

        conn.with_immediate_transaction(|| {
            if let Some(exception) = exception {
                persist_exception(conn, exception, context)?;
            }
            record_authorization_event(
                conn,
                &scope,
                TigaOperation::ChangeSecurityPolicy,
                context,
                &decision,
                resolved.exception_id.as_deref(),
            )?;
            if resolved.compliance == PolicyCompliance::Exception {
                TigaPolicyStore::put_override(
                    conn,
                    &scope,
                    &policy_override,
                    resolved.exception_id.as_deref(),
                    ctx.device_id.as_str(),
                    override_tag.as_deref(),
                )?;
                track_scope_policy_change(conn, ctx, &scope)?;
            } else {
                TigaPolicyStore::delete_override(conn, &scope)?;
                Self::set_global_default(conn, ctx, mode)?;
            }
            conn.inner().execute(
                "UPDATE vault_meta SET tiga_policy_version = ?1,
                 tiga_compliance_status = ?2",
                params![
                    TIGA_POLICY_VERSION,
                    compliance_storage_value(resolved.compliance)
                ],
            )?;
            Ok(())
        })
    }

    pub fn set_project_profile_authorized(
        conn: &VaultConnection,
        ctx: &CommitContext,
        project_id: &str,
        mode: Option<mdbx_core::tiga::TigaMode>,
        exception: Option<&PolicyException>,
        context: TigaAuthorizationContext<'_>,
    ) -> StorageResult<()> {
        let scope = TigaScope::Project {
            project_id: project_id.to_string(),
        };
        let decision = authorize_mutation(conn, &scope, context)?;
        let exception_id = if let Some(mode) = mode {
            let parent = Self::resolve_vault_policy(conn)?;
            let policy_override = TigaPolicyOverride::for_resource_profile(mode);
            match TigaPolicyResolver::resolve(
                &parent.policy,
                scope.clone(),
                &policy_override,
                exception,
                context.now_unix_secs,
            ) {
                Ok(resolved) => resolved.exception_id,
                Err(error) => {
                    record_resolution_denial(conn, &scope, context, &error)?;
                    return Err(policy_error(error));
                }
            }
        } else {
            None
        };

        conn.with_immediate_transaction(|| {
            if let Some(exception) = exception {
                persist_exception(conn, exception, context)?;
            }
            record_authorization_event(
                conn,
                &scope,
                TigaOperation::ChangeSecurityPolicy,
                context,
                &decision,
                exception_id.as_deref(),
            )?;
            Self::set_project_override(conn, ctx, project_id, mode)
        })
    }

    pub fn set_entry_profile_authorized(
        conn: &VaultConnection,
        ctx: &CommitContext,
        entry_id: &str,
        mode: Option<mdbx_core::tiga::TigaMode>,
        exception: Option<&PolicyException>,
        context: TigaAuthorizationContext<'_>,
    ) -> StorageResult<()> {
        let entry = EntryRepo::get_by_id(conn, entry_id)?
            .ok_or_else(|| StorageError::NotFound(entry_id.to_string()))?;
        let scope = TigaScope::Entry {
            entry_id: entry_id.to_string(),
        };
        let decision = authorize_mutation(conn, &scope, context)?;
        let exception_id = if let Some(mode) = mode {
            let parent = Self::resolve_policy_for_project(conn, &entry.project_id)?;
            let policy_override = TigaPolicyOverride::for_resource_profile(mode);
            match TigaPolicyResolver::resolve(
                &parent.policy,
                scope.clone(),
                &policy_override,
                exception,
                context.now_unix_secs,
            ) {
                Ok(resolved) => resolved.exception_id,
                Err(error) => {
                    record_resolution_denial(conn, &scope, context, &error)?;
                    return Err(policy_error(error));
                }
            }
        } else {
            None
        };

        conn.with_immediate_transaction(|| {
            if let Some(exception) = exception {
                persist_exception(conn, exception, context)?;
            }
            record_authorization_event(
                conn,
                &scope,
                TigaOperation::ChangeSecurityPolicy,
                context,
                &decision,
                exception_id.as_deref(),
            )?;
            Self::set_entry_override(conn, ctx, entry_id, mode)
        })
    }

    pub fn set_policy_override_authorized(
        conn: &VaultConnection,
        ctx: &CommitContext,
        scope: TigaScope,
        policy_override: TigaPolicyOverride,
        exception: Option<&PolicyException>,
        context: TigaAuthorizationContext<'_>,
    ) -> StorageResult<ResolvedTigaPolicy> {
        let decision = authorize_mutation(conn, &scope, context)?;
        let parent = resolve_parent_policy(conn, &scope)?;
        let resolved = match TigaPolicyResolver::resolve(
            &parent.policy,
            scope.clone(),
            &policy_override,
            exception,
            context.now_unix_secs,
        ) {
            Ok(resolved) => combine_resolution(parent, resolved),
            Err(error) => {
                record_resolution_denial(conn, &scope, context, &error)?;
                return Err(policy_error(error));
            }
        };
        let override_tag = integrity_tag(conn, b"tiga-policy-override", &policy_override)?;

        conn.with_immediate_transaction(|| {
            if let Some(exception) = exception {
                persist_exception(conn, exception, context)?;
            }
            TigaPolicyStore::put_override(
                conn,
                &scope,
                &policy_override,
                resolved.exception_id.as_deref(),
                ctx.device_id.as_str(),
                Some(&override_tag),
            )?;
            track_scope_policy_change(conn, ctx, &scope)?;
            record_authorization_event(
                conn,
                &scope,
                TigaOperation::ChangeSecurityPolicy,
                context,
                &decision,
                resolved.exception_id.as_deref(),
            )?;
            Ok(())
        })?;
        Ok(resolved)
    }

    pub fn clear_policy_override_authorized(
        conn: &VaultConnection,
        ctx: &CommitContext,
        scope: TigaScope,
        context: TigaAuthorizationContext<'_>,
    ) -> StorageResult<()> {
        let decision = authorize_mutation(conn, &scope, context)?;
        conn.with_immediate_transaction(|| {
            TigaPolicyStore::delete_override(conn, &scope)?;
            track_scope_policy_change(conn, ctx, &scope)?;
            record_authorization_event(
                conn,
                &scope,
                TigaOperation::ChangeSecurityPolicy,
                context,
                &decision,
                None,
            )
        })
    }
}

fn resolve_scope_policy(
    conn: &VaultConnection,
    scope: &TigaScope,
) -> StorageResult<ResolvedTigaPolicy> {
    match scope {
        TigaScope::Vault => TigaService::resolve_vault_policy(conn),
        TigaScope::Project { project_id } => {
            TigaService::resolve_policy_for_project(conn, project_id)
        }
        TigaScope::Entry { entry_id } => TigaService::resolve_policy_for_entry(conn, entry_id),
    }
}

fn resolve_parent_policy(
    conn: &VaultConnection,
    scope: &TigaScope,
) -> StorageResult<ResolvedTigaPolicy> {
    match scope {
        TigaScope::Vault => Ok(ResolvedTigaPolicy {
            policy: TigaService::get_global_default(conn)?.policy(),
            compliance: PolicyCompliance::Compliant,
            exception_id: None,
            warnings: Vec::new(),
        }),
        TigaScope::Project { .. } => TigaService::resolve_vault_policy(conn),
        TigaScope::Entry { entry_id } => {
            let entry = EntryRepo::get_by_id(conn, entry_id)?
                .ok_or_else(|| StorageError::NotFound(entry_id.to_string()))?;
            TigaService::resolve_policy_for_project(conn, &entry.project_id)
        }
    }
}

fn authorize_mutation(
    conn: &VaultConnection,
    scope: &TigaScope,
    context: TigaAuthorizationContext<'_>,
) -> StorageResult<AuthorizationDecision> {
    let decision =
        TigaService::evaluate_operation(conn, scope, TigaOperation::ChangeSecurityPolicy, context)?;
    if !decision_allows(&decision) {
        conn.with_immediate_transaction(|| {
            record_authorization_event(
                conn,
                scope,
                TigaOperation::ChangeSecurityPolicy,
                context,
                &decision,
                None,
            )
        })?;
        return Err(StorageError::Authorization(decision));
    }
    if context.session.is_none() || conn.keyring().is_none() {
        return Err(StorageError::Validation(
            "security policy mutations require an unlocked vault session".to_string(),
        ));
    }
    Ok(decision)
}

fn decision_allows(decision: &AuthorizationDecision) -> bool {
    matches!(
        decision.outcome,
        AuthorizationOutcome::Allow | AuthorizationOutcome::AllowWithConstraints
    )
}

fn record_resolution_denial(
    conn: &VaultConnection,
    scope: &TigaScope,
    context: TigaAuthorizationContext<'_>,
    error: &PolicyResolutionError,
) -> StorageResult<()> {
    let reason = match error {
        PolicyResolutionError::WeakeningNotAuthorized { .. } => {
            AuthorizationReason::PolicyWeakeningNotAuthorized
        }
        PolicyResolutionError::InvalidException => AuthorizationReason::PolicyExceptionInvalid,
        PolicyResolutionError::InvalidOverride(_) => AuthorizationReason::OperationDisabled,
    };
    let decision = AuthorizationDecision {
        outcome: AuthorizationOutcome::Deny,
        reasons: vec![reason],
        constraints: Vec::new(),
        audit_required: true,
    };
    conn.with_immediate_transaction(|| {
        record_authorization_event(
            conn,
            scope,
            TigaOperation::ChangeSecurityPolicy,
            context,
            &decision,
            None,
        )
    })
}

fn persist_exception(
    conn: &VaultConnection,
    exception: &PolicyException,
    context: TigaAuthorizationContext<'_>,
) -> StorageResult<()> {
    let tag = integrity_tag(conn, b"tiga-policy-exception", exception)?;
    TigaPolicyStore::put_exception(
        conn,
        exception,
        context.session.map(|session| session.session_id.as_str()),
        Some(&tag),
    )
}

fn record_authorization_event(
    conn: &VaultConnection,
    scope: &TigaScope,
    operation: TigaOperation,
    context: TigaAuthorizationContext<'_>,
    decision: &AuthorizationDecision,
    exception_id: Option<&str>,
) -> StorageResult<()> {
    let event = SecurityAuditEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        occurred_at: chrono::DateTime::from_timestamp(context.now_unix_secs, 0)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339(),
        operation,
        outcome: decision.outcome,
        scope: scope.clone(),
        session_id: context.session.map(|session| session.session_id.clone()),
        device_id: context.device.device_id.clone(),
        reasons: decision.reasons.clone(),
        constraints: decision.constraints.clone(),
        exception_id: exception_id.map(str::to_string),
    };
    let tag = optional_integrity_tag(conn, b"tiga-security-audit", &event)?;
    TigaPolicyStore::record_audit_event(conn, &event, tag.as_deref())
}

fn integrity_tag<T: Serialize>(
    conn: &VaultConnection,
    domain: &[u8],
    value: &T,
) -> StorageResult<Vec<u8>> {
    optional_integrity_tag(conn, domain, value)?.ok_or_else(|| {
        StorageError::Validation("vault must be unlocked to authenticate Tiga records".to_string())
    })
}

fn optional_integrity_tag<T: Serialize>(
    conn: &VaultConnection,
    domain: &[u8],
    value: &T,
) -> StorageResult<Option<Vec<u8>>> {
    let Some(keyring) = conn.keyring() else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(value).map_err(|e| StorageError::Validation(e.to_string()))?;
    hmac_sha256(&keyring.integrity_subkey, &[domain, &encoded])
        .map(Some)
        .map_err(StorageError::Crypto)
}

fn track_scope_policy_change(
    conn: &VaultConnection,
    ctx: &CommitContext,
    scope: &TigaScope,
) -> StorageResult<()> {
    match scope {
        TigaScope::Vault => {
            ctx.create_commit(
                conn,
                "change",
                "vault-meta",
                &["vault-meta:tiga-policy".to_string()],
                &current_device_head(conn, ctx)?
                    .into_iter()
                    .collect::<Vec<_>>(),
            )?;
            conn.inner().execute(
                "UPDATE vault_meta SET updated_at = ?1",
                params![chrono::Utc::now().to_rfc3339()],
            )?;
        }
        TigaScope::Project { project_id } => {
            let project = ProjectRepo::get_by_id(conn, project_id)?
                .ok_or_else(|| StorageError::NotFound(project_id.clone()))?;
            if project.deleted {
                return Err(StorageError::ConstraintViolation(
                    "cannot change Tiga policy on a deleted project".to_string(),
                ));
            }
            let commit_id =
                ctx.commit_object_change(conn, "projects", project_id, "change", "project")?;
            conn.inner().execute(
                "UPDATE projects SET object_clock = ?1, head_commit_id = ?2,
                 updated_at = ?3, updated_by_device_id = ?4 WHERE project_id = ?5",
                params![
                    bump_clock(&project.object_clock),
                    commit_id,
                    chrono::Utc::now().to_rfc3339(),
                    ctx.device_id,
                    project_id,
                ],
            )?;
            ObjectVersionRepo::record_project_current(conn, &commit_id, project_id)?;
        }
        TigaScope::Entry { entry_id } => {
            let entry = EntryRepo::get_by_id(conn, entry_id)?
                .ok_or_else(|| StorageError::NotFound(entry_id.clone()))?;
            if entry.deleted {
                return Err(StorageError::ConstraintViolation(
                    "cannot change Tiga policy on a deleted entry".to_string(),
                ));
            }
            let commit_id =
                ctx.commit_object_change(conn, "entries", entry_id, "change", "entry")?;
            conn.inner().execute(
                "UPDATE entries SET object_clock = ?1, head_commit_id = ?2,
                 updated_at = ?3, updated_by_device_id = ?4 WHERE entry_id = ?5",
                params![
                    bump_clock(&entry.object_clock),
                    commit_id,
                    chrono::Utc::now().to_rfc3339(),
                    ctx.device_id,
                    entry_id,
                ],
            )?;
            ObjectVersionRepo::record_entry_current(conn, &commit_id, entry_id)?;
        }
    }
    Ok(())
}

fn compliance_storage_value(compliance: PolicyCompliance) -> &'static str {
    match compliance {
        PolicyCompliance::Compliant => STATUS_COMPLIANT,
        PolicyCompliance::Exception => STATUS_EXCEPTION,
        PolicyCompliance::RemediationRequired => STATUS_REMEDIATION,
    }
}

fn apply_profile_override(
    conn: &VaultConnection,
    parent: ResolvedTigaPolicy,
    scope: TigaScope,
    mode: mdbx_core::tiga::TigaMode,
) -> StorageResult<ResolvedTigaPolicy> {
    let policy_override = TigaPolicyOverride::for_resource_profile(mode);
    let now = chrono::Utc::now().timestamp();
    let exception = TigaPolicyStore::find_exception(conn, &scope, &policy_override, now)?;
    let next = match TigaPolicyResolver::resolve(
        &parent.policy,
        scope,
        &policy_override,
        exception.as_ref(),
        now,
    ) {
        Ok(resolved) => resolved,
        Err(_error)
            if parent.compliance == PolicyCompliance::RemediationRequired
                && exception.is_none() =>
        {
            TigaPolicyResolver::resolve_legacy(&parent.policy, &policy_override)
                .map_err(policy_error)?
        }
        Err(error) => return Err(policy_error(error)),
    };
    Ok(combine_resolution(parent, next))
}

fn apply_stored_override(
    conn: &VaultConnection,
    parent: ResolvedTigaPolicy,
    scope: TigaScope,
) -> StorageResult<ResolvedTigaPolicy> {
    let Some(stored) = TigaPolicyStore::get_override(conn, &scope)? else {
        return Ok(parent);
    };
    let exception = stored
        .exception_id
        .as_deref()
        .map(|id| TigaPolicyStore::get_exception(conn, id))
        .transpose()?
        .flatten();
    let next = TigaPolicyResolver::resolve(
        &parent.policy,
        scope,
        &stored.policy_override,
        exception.as_ref(),
        chrono::Utc::now().timestamp(),
    )
    .map_err(policy_error)?;
    Ok(combine_resolution(parent, next))
}

fn combine_resolution(
    mut parent: ResolvedTigaPolicy,
    mut child: ResolvedTigaPolicy,
) -> ResolvedTigaPolicy {
    child.compliance = stricter_compliance(parent.compliance, child.compliance);
    if child.exception_id.is_none() {
        child.exception_id = parent.exception_id.take();
    }
    parent.warnings.append(&mut child.warnings);
    child.warnings = parent.warnings;
    child
}

fn stricter_compliance(a: PolicyCompliance, b: PolicyCompliance) -> PolicyCompliance {
    use PolicyCompliance::*;
    match (a, b) {
        (RemediationRequired, _) | (_, RemediationRequired) => RemediationRequired,
        (Exception, _) | (_, Exception) => Exception,
        _ => Compliant,
    }
}

fn policy_error(error: impl std::fmt::Display) -> StorageError {
    StorageError::ConstraintViolation(error.to_string())
}

pub(crate) fn scope_parts(scope: &TigaScope) -> (&'static str, &str) {
    match scope {
        TigaScope::Vault => ("vault", ""),
        TigaScope::Project { project_id } => ("project", project_id),
        TigaScope::Entry { entry_id } => ("entry", entry_id),
    }
}

fn parse_scope(scope_type: &str, scope_id: &str) -> StorageResult<TigaScope> {
    match scope_type {
        "vault" if scope_id.is_empty() => Ok(TigaScope::Vault),
        "project" if !scope_id.is_empty() => Ok(TigaScope::Project {
            project_id: scope_id.to_string(),
        }),
        "entry" if !scope_id.is_empty() => Ok(TigaScope::Entry {
            entry_id: scope_id.to_string(),
        }),
        _ => Err(StorageError::Validation(format!(
            "invalid Tiga scope {scope_type}:{scope_id}"
        ))),
    }
}

fn parse_compliance(value: &str) -> StorageResult<PolicyCompliance> {
    match value {
        STATUS_COMPLIANT => Ok(PolicyCompliance::Compliant),
        STATUS_EXCEPTION => Ok(PolicyCompliance::Exception),
        STATUS_REMEDIATION => Ok(PolicyCompliance::RemediationRequired),
        _ => Err(StorageError::Validation(format!(
            "invalid Tiga compliance status: {value}"
        ))),
    }
}

fn enum_storage_value<T: Serialize>(value: &T) -> StorageResult<String> {
    match serde_json::to_value(value).map_err(|e| StorageError::Validation(e.to_string()))? {
        serde_json::Value::String(value) => Ok(value),
        _ => Err(StorageError::Validation(
            "Tiga enum did not serialize as a string".to_string(),
        )),
    }
}

fn parse_enum_storage_value<T: for<'de> Deserialize<'de>>(value: &str) -> StorageResult<T> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .map_err(|e| StorageError::Validation(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{initialize_vault, VaultInitParams};
    use crate::repo::commit_ctx::CommitContext;
    use crate::repo::entry::EntryRepo;
    use crate::repo::project::ProjectRepo;
    use mdbx_core::model::EntryType;
    use mdbx_core::model::{UnlockMethodType, VaultSession};
    use mdbx_core::tiga::{AuditLevel, DeviceAssurance, DeviceContext, SessionAssurance, TigaMode};
    use mdbx_crypto::keyring::Keyring;

    fn setup() -> (VaultConnection, CommitContext, String, String) {
        let mut conn = VaultConnection::open_in_memory().unwrap();
        initialize_vault(&conn, &VaultInitParams::default()).unwrap();
        unlock_for_tests(&mut conn);
        let ctx = CommitContext::new("device-1".to_string());
        let project = ProjectRepo::create(&conn, &ctx, "project", None, None).unwrap();
        let entry = EntryRepo::create(
            &conn,
            &ctx,
            &project.project_id,
            EntryType::Login,
            Some("entry"),
            &serde_json::json!({"password": "secret"}),
        )
        .unwrap();
        (conn, ctx, project.project_id, entry.entry_id)
    }

    fn unlock_for_tests(conn: &mut VaultConnection) {
        conn.attach_keyring(Keyring::from_vault_key(&[7_u8; 32], b"tiga-policy-test").unwrap());
    }

    fn session(method: UnlockMethodType, now: i64) -> VaultSession {
        VaultSession {
            session_id: "session-1".to_string(),
            unlock_method: method,
            created_at: chrono::DateTime::from_timestamp(now, 0)
                .unwrap()
                .to_rfc3339(),
            assurance: SessionAssurance::from_unlock_method(method, now),
        }
    }

    fn standard_device() -> DeviceContext {
        DeviceContext {
            device_id: Some("device-1".to_string()),
            assurance: DeviceAssurance::Standard,
            secure_clipboard_available: true,
            screen_capture_protection_available: false,
            secure_temp_files_available: true,
        }
    }

    fn trusted_device() -> DeviceContext {
        DeviceContext {
            device_id: Some("device-1".to_string()),
            assurance: DeviceAssurance::TrustedHardware,
            secure_clipboard_available: true,
            screen_capture_protection_available: true,
            secure_temp_files_available: true,
        }
    }

    #[test]
    fn initialized_vault_has_tiga2_compliant_policy_state() {
        let (conn, _, _, _) = setup();
        let state = TigaService::get_policy_state(&conn).unwrap();
        assert_eq!(state.policy_version, TIGA_POLICY_VERSION);
        assert_eq!(state.compliance, PolicyCompliance::Compliant);
        let resolved = TigaService::resolve_vault_policy(&conn).unwrap();
        assert_eq!(resolved.policy.profile, TigaMode::Multi);
    }

    #[test]
    fn unknown_policy_version_fails_closed() {
        let (conn, _, _, _) = setup();
        conn.inner()
            .execute(
                "UPDATE vault_meta SET tiga_policy_version = ?1",
                params![i64::from(TIGA_POLICY_VERSION + 1)],
            )
            .unwrap();

        let error = TigaService::get_policy_state(&conn).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported Tiga policy version"));
    }

    #[test]
    fn active_session_authorization_renews_idle_but_not_absolute_lifetime() {
        let (mut conn, _, _, _) = setup();
        conn.attach_session(session(UnlockMethodType::Password, 100));
        let device = standard_device();

        let first = TigaService::authorize_operation_with_active_session(
            &mut conn,
            &TigaScope::Vault,
            TigaOperation::DecryptAttachment,
            &device,
            200,
        )
        .unwrap();
        assert!(decision_allows(&first));
        let assurance = &conn.active_session().unwrap().assurance;
        assert_eq!(assurance.authenticated_at_unix_secs, 100);
        assert_eq!(assurance.last_activity_at_unix_secs, 200);

        let renewed = TigaService::authorize_operation_with_active_session(
            &mut conn,
            &TigaScope::Vault,
            TigaOperation::DecryptAttachment,
            &device,
            750,
        )
        .unwrap();
        assert!(decision_allows(&renewed));

        let expired = TigaService::authorize_operation_with_active_session(
            &mut conn,
            &TigaScope::Vault,
            TigaOperation::DecryptAttachment,
            &device,
            7_300,
        )
        .unwrap();
        assert_eq!(
            expired.outcome,
            AuthorizationOutcome::RequireFreshAuthentication
        );
        assert_eq!(
            conn.active_session()
                .unwrap()
                .assurance
                .last_activity_at_unix_secs,
            750
        );
    }

    #[test]
    fn strict_resource_profile_resolves_over_parent() {
        let (conn, ctx, project_id, _) = setup();
        TigaService::set_project_override(&conn, &ctx, &project_id, Some(TigaMode::Power)).unwrap();
        let resolved = TigaService::resolve_policy_for_project(&conn, &project_id).unwrap();
        assert_eq!(resolved.policy.profile, TigaMode::Power);
        assert!(!resolved.policy.egress.export_allowed);
        assert_eq!(resolved.compliance, PolicyCompliance::Compliant);
    }

    #[test]
    fn unexcepted_resource_profile_weakening_is_rejected() {
        let (conn, ctx, project_id, _) = setup();
        TigaService::set_global_default(&conn, &ctx, TigaMode::Power).unwrap();
        TigaService::set_project_override(&conn, &ctx, &project_id, Some(TigaMode::Sky)).unwrap();
        let error = TigaService::resolve_policy_for_project(&conn, &project_id).unwrap_err();
        assert!(error.to_string().contains("weakens parent fields"));
    }

    #[test]
    fn sparse_policy_override_roundtrips_and_resolves() {
        let (conn, _, _, entry_id) = setup();
        let scope = TigaScope::Entry {
            entry_id: entry_id.clone(),
        };
        TigaPolicyStore::put_override(
            &conn,
            &scope,
            &TigaPolicyOverride {
                clipboard_allowed: Some(false),
                audit_level: Some(AuditLevel::AllDecisions),
                ..Default::default()
            },
            None,
            "device-1",
            None,
        )
        .unwrap();
        let resolved = TigaService::resolve_policy_for_entry(&conn, &entry_id).unwrap();
        assert!(!resolved.policy.disclosure.clipboard_allowed);
        assert_eq!(resolved.policy.audit_level, AuditLevel::AllDecisions);
    }

    #[test]
    fn exact_exception_is_persisted_and_applied() {
        let (conn, ctx, project_id, _) = setup();
        TigaService::set_global_default(&conn, &ctx, TigaMode::Power).unwrap();
        let scope = TigaScope::Project {
            project_id: project_id.clone(),
        };
        let policy_override = TigaPolicyOverride::for_resource_profile(TigaMode::Sky);
        let exception = PolicyException {
            exception_id: "exception-1".to_string(),
            target: scope,
            approved_override: policy_override,
            reason: "legacy access compatibility".to_string(),
            expires_at_unix_secs: None,
        };
        TigaPolicyStore::put_exception(&conn, &exception, Some("session-1"), None).unwrap();
        TigaService::set_project_override(&conn, &ctx, &project_id, Some(TigaMode::Sky)).unwrap();
        let resolved = TigaService::resolve_policy_for_project(&conn, &project_id).unwrap();
        assert_eq!(resolved.policy.profile, TigaMode::Sky);
        assert_eq!(resolved.compliance, PolicyCompliance::Exception);
        assert_eq!(resolved.exception_id.as_deref(), Some("exception-1"));
    }

    #[test]
    fn audit_events_store_only_typed_metadata() {
        let (conn, _, _, _) = setup();
        let event = SecurityAuditEvent {
            event_id: "event-1".to_string(),
            occurred_at: "2026-07-19T00:00:00Z".to_string(),
            operation: TigaOperation::CopySecret,
            outcome: AuthorizationOutcome::AllowWithConstraints,
            scope: TigaScope::Vault,
            session_id: Some("session-1".to_string()),
            device_id: Some("device-1".to_string()),
            reasons: Vec::new(),
            constraints: vec![AuthorizationConstraint::ClearClipboardAfterSeconds(30)],
            exception_id: None,
        };
        TigaPolicyStore::record_audit_event(&conn, &event, None).unwrap();
        assert_eq!(
            TigaService::list_security_audit_events(&conn, 10).unwrap(),
            vec![event]
        );
    }

    #[test]
    fn deleting_sparse_override_restores_parent_policy() {
        let (conn, _, project_id, _) = setup();
        let scope = TigaScope::Project {
            project_id: project_id.clone(),
        };
        TigaPolicyStore::put_override(
            &conn,
            &scope,
            &TigaPolicyOverride {
                clipboard_allowed: Some(false),
                ..Default::default()
            },
            None,
            "device-1",
            None,
        )
        .unwrap();
        TigaPolicyStore::delete_override(&conn, &scope).unwrap();
        let resolved = TigaService::resolve_policy_for_project(&conn, &project_id).unwrap();
        assert!(resolved.policy.disclosure.clipboard_allowed);
    }

    #[test]
    fn authorized_sparse_override_is_committed_authenticated_and_audited() {
        let (conn, ctx, _, entry_id) = setup();
        let session = session(UnlockMethodType::Password, 1_000);
        let device = standard_device();
        let before = EntryRepo::get_by_id(&conn, &entry_id)
            .unwrap()
            .unwrap()
            .head_commit_id;

        TigaService::set_policy_override_authorized(
            &conn,
            &ctx,
            TigaScope::Entry {
                entry_id: entry_id.clone(),
            },
            TigaPolicyOverride {
                clipboard_allowed: Some(false),
                ..Default::default()
            },
            None,
            TigaAuthorizationContext {
                session: Some(&session),
                device: &device,
                now_unix_secs: 1_010,
            },
        )
        .unwrap();

        let after = EntryRepo::get_by_id(&conn, &entry_id)
            .unwrap()
            .unwrap()
            .head_commit_id;
        assert_ne!(before, after);
        let integrity_len: i64 = conn
            .inner()
            .query_row(
                "SELECT length(integrity_tag) FROM tiga_policy_overrides
                 WHERE scope_type = 'entry' AND scope_id = ?1",
                params![entry_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(integrity_len, 32);
        let events = TigaService::list_security_audit_events(&conn, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, TigaOperation::ChangeSecurityPolicy);
        assert_eq!(events[0].outcome, AuthorizationOutcome::Allow);
    }

    #[test]
    fn missing_session_denial_is_audited_and_does_not_write_policy() {
        let (conn, ctx, project_id, _) = setup();
        let device = standard_device();
        let error = TigaService::set_policy_override_authorized(
            &conn,
            &ctx,
            TigaScope::Project {
                project_id: project_id.clone(),
            },
            TigaPolicyOverride {
                clipboard_allowed: Some(false),
                ..Default::default()
            },
            None,
            TigaAuthorizationContext {
                session: None,
                device: &device,
                now_unix_secs: 1_010,
            },
        )
        .unwrap_err();
        assert!(matches!(error, StorageError::Authorization(_)));
        assert!(TigaPolicyStore::get_override(
            &conn,
            &TigaScope::Project {
                project_id: project_id.clone()
            }
        )
        .unwrap()
        .is_none());
        let events = TigaService::list_security_audit_events(&conn, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].outcome,
            AuthorizationOutcome::RequireFreshAuthentication
        );
    }

    #[test]
    fn power_to_sky_requires_exact_exception_and_strong_current_session() {
        let (conn, ctx, _, _) = setup();
        let standard_session = session(UnlockMethodType::Password, 1_000);
        let standard_device = standard_device();
        TigaService::set_vault_profile_authorized(
            &conn,
            &ctx,
            TigaMode::Power,
            None,
            TigaAuthorizationContext {
                session: Some(&standard_session),
                device: &standard_device,
                now_unix_secs: 1_010,
            },
        )
        .unwrap();

        let strong_session = session(UnlockMethodType::PasswordSecurityKey, 1_020);
        let trusted_device = trusted_device();
        let context = TigaAuthorizationContext {
            session: Some(&strong_session),
            device: &trusted_device,
            now_unix_secs: 1_030,
        };
        let error =
            TigaService::set_vault_profile_authorized(&conn, &ctx, TigaMode::Sky, None, context)
                .unwrap_err();
        assert!(error.to_string().contains("weakens parent fields"));

        let exception = PolicyException {
            exception_id: "vault-downgrade".to_string(),
            target: TigaScope::Vault,
            approved_override: TigaPolicyOverride::for_vault_profile(TigaMode::Sky),
            reason: "user approved a temporary portability exception".to_string(),
            expires_at_unix_secs: None,
        };
        TigaService::set_vault_profile_authorized(
            &conn,
            &ctx,
            TigaMode::Sky,
            Some(&exception),
            context,
        )
        .unwrap();
        assert_eq!(
            TigaService::get_global_default(&conn).unwrap(),
            TigaMode::Power
        );
        let resolved = TigaService::resolve_vault_policy(&conn).unwrap();
        assert_eq!(resolved.policy.profile, TigaMode::Sky);
        assert_eq!(resolved.exception_id.as_deref(), Some("vault-downgrade"));
        assert_eq!(
            TigaService::get_policy_state(&conn).unwrap().compliance,
            PolicyCompliance::Exception
        );
        let tag_len: i64 = conn
            .inner()
            .query_row(
                "SELECT length(integrity_tag) FROM tiga_policy_exceptions
                 WHERE exception_id = 'vault-downgrade'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tag_len, 32);
    }

    #[test]
    fn expired_vault_profile_exception_fails_closed_against_preserved_baseline() {
        let (conn, ctx, _, _) = setup();
        let standard_session = session(UnlockMethodType::Password, 1_000);
        let standard_device = standard_device();
        TigaService::set_vault_profile_authorized(
            &conn,
            &ctx,
            TigaMode::Power,
            None,
            TigaAuthorizationContext {
                session: Some(&standard_session),
                device: &standard_device,
                now_unix_secs: 1_010,
            },
        )
        .unwrap();

        let strong_session = session(UnlockMethodType::PasswordSecurityKey, 1_020);
        let trusted_device = trusted_device();
        let exception = PolicyException {
            exception_id: "expired-vault-downgrade".to_string(),
            target: TigaScope::Vault,
            approved_override: TigaPolicyOverride::for_vault_profile(TigaMode::Sky),
            reason: "temporary downgrade".to_string(),
            expires_at_unix_secs: Some(2_000),
        };
        TigaService::set_vault_profile_authorized(
            &conn,
            &ctx,
            TigaMode::Sky,
            Some(&exception),
            TigaAuthorizationContext {
                session: Some(&strong_session),
                device: &trusted_device,
                now_unix_secs: 1_030,
            },
        )
        .unwrap();

        assert_eq!(
            TigaService::get_global_default(&conn).unwrap(),
            TigaMode::Power
        );
        let error = TigaService::resolve_vault_policy(&conn).unwrap_err();
        assert!(error.to_string().contains("invalid, expired"));
    }
}
