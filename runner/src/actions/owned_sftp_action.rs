//! Unregistered compiled consumer: one authenticated resource, one receipt-owned
//! output. No Action/descriptor/catalog entry or raw admission deserializer exists.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::json;

use super::{
    authorize_path, begin_receipt, commit_receipt, receipt_paths, ActionContext, ActionFailure,
    ActionOutcome,
};
use crate::contract::{ErrorRecord, NetworkDestination, ReviewedOperationIdentity, TaskStatus};
use crate::owned_sftp::{self, Cleanup, Issue, Request, Retrieval, VerifiedSftpAdmission};

const DESTINATION: &str = "staged/sftp.jsonl";

fn preflight(
    context: &ActionContext<'_>,
    admission: &VerifiedSftpAdmission,
    request: &Request,
) -> Result<(), ActionFailure> {
    // The ordinary runner must already have authenticated and checked its
    // manifest/profile. That context still cannot mint the private admission.
    let manifest = context.manifest;
    let selected = manifest.reviewed_operation.as_ref().ok_or_else(|| {
        ActionFailure::refused(
            "sftp_review_required",
            "SFTP requires an exact reviewed operation.",
        )
    })?;
    let reviewed = context.profile.reviewed_execution.as_ref().ok_or_else(|| {
        ActionFailure::refused(
            "sftp_review_required",
            "SFTP requires reviewed execution authority.",
        )
    })?;
    let operation = ReviewedOperationIdentity {
        step_id: manifest.step_id.clone(),
        behavior_id: manifest.behavior_id.clone(),
        action_id: manifest.action_id.clone(),
        execution_binding_digest: None,
    };
    if manifest.action_id != owned_sftp::METHOD
        || manifest.behavior_id != owned_sftp::METHOD
        || manifest.execution_binding.is_some()
        || manifest.provider_binding.is_some()
        || selected.authorization_digest != reviewed.authorization_digest
        || selected.step_id != operation.step_id
        || selected.behavior_id != operation.behavior_id
        || selected.action_id != operation.action_id
        || selected.execution_binding_digest.is_some()
        || !reviewed.operations.contains(&operation)
        || !context
            .profile
            .allowed_actions
            .contains(&owned_sftp::METHOD.to_owned())
    {
        return Err(ActionFailure::refused(
            "sftp_review_required",
            "The SFTP operation differs from its reviewed scope.",
        ));
    }
    admission
        .check_operation(&operation, &reviewed.authorization_digest)
        .map_err(|_| {
            ActionFailure::refused(
                "sftp_admission_unresolved",
                "The private SFTP admission does not bind this exact reviewed operation.",
            )
        })?;
    admission
        .check_scope(
            &manifest.request_hash,
            &context.profile.profile_id,
            &context.root.workspace_id(),
        )
        .map_err(|_| {
            ActionFailure::refused(
                "sftp_admission_unresolved",
                "The private SFTP admission differs from this request, profile or workspace.",
            )
        })?;
    admission.check_request(request).map_err(|_| {
        ActionFailure::refused(
            "sftp_prerequisite_changed",
            "Current SFTP prerequisites differ from the private admission.",
        )
    })?;
    crate::safety::ensure_network_authorized(
        manifest,
        context.profile,
        &NetworkDestination {
            host: "127.0.0.1".into(),
            port: admission.port(),
        },
    )
    .map_err(|_| {
        ActionFailure::refused(
            "sftp_endpoint_blocked",
            "The owned SFTP endpoint is outside the exact network scope.",
        )
    })?;
    authorize_path(context, DESTINATION, false)?;
    if manifest.limits.max_files < 1
        || manifest.limits.max_artifact_bytes < request.expected_size
        || manifest.limits.max_stdout_bytes < owned_sftp::MAX_DIAGNOSTIC
        || manifest.limits.max_stderr_bytes < owned_sftp::MAX_DIAGNOSTIC
    {
        return Err(ActionFailure::refused(
            "sftp_limit",
            "The SFTP output exceeds its approved artifact limits.",
        ));
    }
    let remaining = manifest
        .expires_at
        .signed_duration_since(crate::contract::utc_now())
        .to_std()
        .map_err(|_| ActionFailure::timed_out("sftp_timeout", "The SFTP manifest expired."))?
        .min(Duration::from_millis(manifest.limits.timeout_ms))
        .min(Duration::from_secs(30));
    let now = Instant::now();
    if admission.deadline() <= now
        || admission.deadline().saturating_duration_since(now) > remaining
    {
        return Err(ActionFailure::timed_out(
            "sftp_timeout",
            "The SFTP admission exceeds the remaining operation deadline.",
        ));
    }
    Ok(())
}

fn failed_result(result: &Retrieval, issue: Issue) -> ActionOutcome {
    let mut outcome = ActionOutcome::success(json!({
        "tool_executed": result.executed, "exit_code": result.exit_code,
        "diagnostic_bytes": result.diagnostics_bytes,
        "client_group_cleanup": match result.cleanup {
            Cleanup::NotStarted => "not_started", Cleanup::ReapedClientGroupAbsent => "reaped_group_absent", Cleanup::Unknown => "unknown"
        }, "artifact_published": false, "artifact_available": false
    }));
    outcome.status = match issue {
        Issue::Cancelled => TaskStatus::Failed,
        Issue::Deadline => TaskStatus::TimedOut,
        _ => TaskStatus::Failed,
    };
    outcome.error = Some(ErrorRecord { code: format!("sftp_{issue:?}").to_ascii_lowercase(),
        message: "The owned SFTP retrieval did not yield complete verified output; inspect execution and cleanup evidence.".into() });
    outcome
}

fn publication_failure(
    result: &Retrieval,
    receipt: &str,
    destination: &str,
    published: bool,
) -> ActionOutcome {
    let mut failure = failed_result(result, Issue::Io).with_receipt(receipt.into());
    failure.output["artifact"] = json!(destination);
    failure.output["publication_intent_retained"] = json!(true);
    // write_new can fail after no-replace publication or a final sync. A
    // successful write_new followed by commit failure proves the publication,
    // but cannot prove whether the commit marker persisted before its error.
    failure.output["artifact_published"] = if published { json!(true) } else { json!(null) };
    failure.output["receipt_committed"] = if published { json!(null) } else { json!(false) };
    failure.output["publication_state"] = json!(if published {
        "published_commit_unknown"
    } else {
        "unknown"
    });
    failure
}

/// This API cannot be reached from a registered action or a raw request. The
/// missing authenticated resolver and empty compiled build table keep it closed.
/// `cancelled` is cancellation only, never execution or cleanup authority.
pub fn consume(
    context: &ActionContext<'_>,
    admission: VerifiedSftpAdmission,
    request: &Request,
    cancelled: &AtomicBool,
) -> Result<ActionOutcome, ActionFailure> {
    preflight(context, &admission, request)?;
    owned_sftp::check_execution_admission(&admission, request, cancelled).map_err(|issue| {
        match issue {
            Issue::Cancelled => ActionFailure::blocked(
                "sftp_cancelled",
                "SFTP was cancelled before input inspection.",
            ),
            Issue::Deadline => ActionFailure::timed_out(
                "sftp_timeout",
                "The SFTP admission expired before input inspection.",
            ),
            _ => ActionFailure::refused(
                "sftp_unavailable",
                "SFTP requires current private admissions and an exact reviewed protected build.",
            ),
        }
    })?;
    // Pure admission/build gates above do no input I/O. The following path may
    // read/hash protected images even if exec is never reached. Match the
    // existing runner's attempted-input-inspection progress semantics.
    context.mark_execution_started();
    let result = owned_sftp::retrieve(&admission, request, cancelled).map_err(|issue| {
        match issue {
            Issue::Cancelled => ActionFailure::failed("sftp_cancelled_after_inspection", "SFTP was cancelled on the admitted input-inspection path before an execution result."),
            Issue::Deadline => ActionFailure::timed_out("sftp_timeout", "The SFTP deadline elapsed before execution."),
            _ => ActionFailure::failed("sftp_acquisition_failed", "The admitted SFTP input inspection or setup failed before a client execution result."),
        }
    })?;
    publish(context, &admission, request, result, cancelled)
}

fn publish(
    context: &ActionContext<'_>,
    admission: &VerifiedSftpAdmission,
    request: &Request,
    result: Retrieval,
    cancelled: &AtomicBool,
) -> Result<ActionOutcome, ActionFailure> {
    if let Some(issue) = result.issue {
        return Ok(failed_result(&result, issue));
    }
    if !result.executed
        || result.cleanup != Cleanup::ReapedClientGroupAbsent
        || owned_sftp::verify_bytes(admission, &result.bytes).is_err()
    {
        return Ok(failed_result(&result, Issue::ContentMismatch));
    }
    if cancelled.load(Ordering::Acquire) {
        return Ok(failed_result(&result, Issue::Cancelled));
    }
    if Instant::now() >= admission.deadline()
        || crate::contract::utc_now() >= context.manifest.expires_at
    {
        return Ok(failed_result(&result, Issue::Deadline));
    }
    // No disk path exists for partial downloads. The successful anonymous bytes
    // are now published through exactly the existing crash-recoverable receipt
    // protocol: durable intent, synced staging inode, no-replace publication,
    // commit. Publication failure retains the durable intent for recovery.
    let target = match context.root.prepare_new_file(DESTINATION) {
        Ok(target) => target,
        Err(_) => return Ok(failed_result(&result, Issue::Io)),
    };
    let intent = match begin_receipt(
        context,
        receipt_paths(
            target.relative.clone(),
            &result.bytes,
            &target.created_directories,
        ),
    ) {
        Ok(intent) => intent,
        Err(_) => return Ok(failed_result(&result, Issue::Io)),
    };
    if let Err(_error) = context.root.write_new(&target, &result.bytes, &intent) {
        return Ok(publication_failure(
            &result,
            intent.id(),
            &target.relative,
            false,
        ));
    }
    let receipt = match commit_receipt(context, &intent) {
        Ok(receipt) => receipt,
        Err(_) => {
            return Ok(publication_failure(
                &result,
                intent.id(),
                &target.relative,
                true,
            ));
        }
    };
    let mut outcome = ActionOutcome::success(json!({
        "artifact": target.relative, "size": result.bytes.len(),
        "sha256": crate::contract::sha256_hex(&result.bytes), "tool_executed": true,
        "bundle_digest": request.bundle_digest, "resource_ref": request.references.resource_ref,
        "resource_generation": request.references.resource_generation,
        "source_sha256": request.references.source_content_sha256,
        "client_group_cleanup": "reaped_group_absent", "artifact_published": true,
        "artifact_available": true, "receipt_committed": true
    }))
    .with_receipt(receipt);
    // A cancellation/deadline during the durable publication cannot erase its
    // receipt or its actual effects. Keep the artifact fact for cleanup/recovery.
    retain_publication_interruption(&mut outcome, context, admission.deadline(), cancelled);
    Ok(outcome)
}

fn retain_publication_interruption(
    outcome: &mut ActionOutcome,
    context: &ActionContext<'_>,
    deadline: Instant,
    cancelled: &AtomicBool,
) {
    if cancelled.load(Ordering::Acquire)
        || Instant::now() >= deadline
        || crate::contract::utc_now() >= context.manifest.expires_at
    {
        outcome.status = if cancelled.load(Ordering::Acquire) {
            TaskStatus::Partial
        } else {
            TaskStatus::TimedOut
        };
        outcome.error = Some(ErrorRecord { code: "sftp_publication_interrupted".into(),
            message: "SFTP publication completed during cancellation/expiry; the owned receipt is retained for cleanup.".into() });
        outcome.output["artifact_available"] = json!(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{ExecutionManifest, Platform, RunnerProfile};
    use crate::safety::SafeRoot;
    use std::cell::Cell;
    use std::fs;

    #[test]
    fn post_publication_errors_never_claim_artifact_absence_or_missing_commit() {
        let result = Retrieval {
            bytes: Vec::new(),
            issue: None,
            cleanup: Cleanup::ReapedClientGroupAbsent,
            executed: true,
            exit_code: Some(0),
            diagnostics_bytes: 0,
        };
        let write = publication_failure(&result, "durable-intent", DESTINATION, false);
        assert!(write.output["artifact_published"].is_null());
        assert_eq!(write.output["publication_state"], "unknown");
        let commit = publication_failure(&result, "durable-intent", DESTINATION, true);
        assert_eq!(commit.output["artifact_published"], true);
        assert!(commit.output["receipt_committed"].is_null());
        for failure in [write, commit] {
            assert_eq!(failure.output["tool_executed"], true);
            assert_eq!(failure.output["artifact"], DESTINATION);
            assert_eq!(failure.receipt_ids, vec!["durable-intent".to_owned()]);
            assert_eq!(failure.output["publication_intent_retained"], true);
            assert_eq!(failure.output["artifact_available"], false);
        }
    }

    #[test]
    fn publication_preserves_existing_path_and_cancellation_leaves_no_disk_effects() {
        publication_case(true, false);
        publication_case(false, true);
    }

    #[test]
    fn verified_publication_commits_existing_receipt_protocol_and_rejects_retry() {
        publication_case(false, false);
    }

    fn publication_case(existing: bool, cancelled: bool) {
        let path = std::env::temp_dir().join(format!(
            "bf-sftp-pub-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        let root = SafeRoot::open(&path).unwrap();
        let scope = json!({"filesystem":["staged"],"network":[]});
        let limits = json!({"timeout_ms":30000,"max_stdout_bytes":8192,"max_stderr_bytes":8192,
            "max_artifact_bytes":1048576,"max_files":4});
        let profile: RunnerProfile = serde_json::from_value(json!({
            "schema_version":crate::contract::PROFILE_SCHEMA_VERSION,
            "profile_id":"profile:test","runner_id":"runner:test","platform":Platform::current(),
            "sandbox_root":path,"allowed_actions":[owned_sftp::METHOD],
            "capabilities":["filesystem_read","filesystem_write","process_spawn"],
            "max_safety_tier":"controlled","target_scope":scope,"limits":limits,
            "policy_digest":"a".repeat(64)
        }))
        .unwrap();
        let now = crate::contract::utc_now();
        let manifest: ExecutionManifest = serde_json::from_value(json!({
            "schema_version":crate::contract::MANIFEST_SCHEMA_VERSION,
            "request_id":"request:test","run_id":"run:test","step_id":"step:retrieve",
            "behavior_id":owned_sftp::METHOD,"action_id":owned_sftp::METHOD,"mode":"execute",
            "runner_id":profile.runner_id,"runner_profile_id":profile.profile_id,
            "platform":Platform::current(),"requested_at":now,"expires_at":now+chrono::Duration::minutes(1),
            "params":{},"target_scope":scope,"required_capabilities":["filesystem_read","filesystem_write","process_spawn"],
            "safety_tier":"controlled","limits":limits,"cleanup_action_id":"sandbox.cleanup.v1",
            "policy_digest":profile.policy_digest,"request_hash":"b".repeat(64)
        })).unwrap();
        let context = ActionContext {
            manifest: &manifest,
            profile: &profile,
            root: &root,
            execution_started: Cell::new(false),
        };
        let admission =
            VerifiedSftpAdmission::authored_fixture("/owned/reports/reconciliation.jsonl");
        let reference =
            |label: &str| format!("sha256:{}", crate::contract::sha256_hex(label.as_bytes()));
        let request = Request {
            references: crate::owned_sftp::CurrentReferences {
                endpoint_binding_ref: reference("endpoint"),
                server_preparation_ref: reference("server"),
                resource_ref: reference("/owned/reports/reconciliation.jsonl"),
                resource_generation: reference("generation"),
                source_content_sha256: reference("generated-public-data"),
                host_key_ref: reference("host-key"),
                reader_identity_ref: reference("reader"),
                access_observation_ref: reference("fresh-access"),
                session_prerequisite_ref: reference("new-session"),
            },
            bundle_digest: reference("synthetic-not-approved-bundle"),
            expected_size: b"generated-public-data".len() as u64,
        };
        if existing {
            fs::create_dir(path.join("staged")).unwrap();
            fs::write(path.join(DESTINATION), b"owned prior file").unwrap();
        }
        let retrieved = || Retrieval {
            bytes: b"generated-public-data".to_vec(),
            issue: None,
            cleanup: Cleanup::ReapedClientGroupAbsent,
            executed: true,
            exit_code: Some(0),
            diagnostics_bytes: 0,
        };
        let refusal = consume(
            &context,
            VerifiedSftpAdmission::authored_fixture("/owned/reports/reconciliation.jsonl"),
            &request,
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert_eq!(refusal.code, "sftp_review_required");
        assert!(!context.execution_started.get());
        assert!(!path.join(".bluefire").exists());
        let outcome = publish(
            &context,
            &admission,
            &request,
            retrieved(),
            &AtomicBool::new(cancelled),
        )
        .unwrap();
        assert_eq!(outcome.output["tool_executed"], true);
        if cancelled {
            assert!(outcome.receipt_ids.is_empty());
            assert!(!path.join("staged").exists());
        } else if existing {
            assert_eq!(outcome.status, TaskStatus::Failed);
            assert_eq!(
                fs::read(path.join(DESTINATION)).unwrap(),
                b"owned prior file"
            );
            assert!(!path.join(".bluefire").exists());
        } else {
            assert_eq!(outcome.status, TaskStatus::Success);
            let receipt = outcome.receipt_ids[0].clone();
            assert!(root.receipt_commit_exists(&receipt).unwrap());
            assert_eq!(
                fs::read(path.join(DESTINATION)).unwrap(),
                b"generated-public-data"
            );
            let mut interrupted = outcome;
            retain_publication_interruption(
                &mut interrupted,
                &context,
                admission.deadline(),
                &AtomicBool::new(true),
            );
            assert_eq!(interrupted.status, TaskStatus::Partial);
            assert_eq!(interrupted.output["artifact_published"], true);
            assert_eq!(interrupted.output["artifact_available"], false);
            assert_eq!(interrupted.receipt_ids[0], receipt);
            assert!(root.receipt_commit_exists(&receipt).unwrap());
            let retry = publish(
                &context,
                &admission,
                &request,
                retrieved(),
                &AtomicBool::new(false),
            )
            .unwrap();
            assert_eq!(retry.status, TaskStatus::Failed);
            assert!(root.receipt_commit_exists(&receipt).unwrap());
        }
        drop(root);
        fs::remove_dir_all(path).unwrap();
    }
}
