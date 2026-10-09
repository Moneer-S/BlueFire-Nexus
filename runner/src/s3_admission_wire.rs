//! Closed native S3 approval and configured-host binding validation.

use chrono::{DateTime, FixedOffset};
use serde_json::Value;

use super::{VerifiedS3Admission, REFUSAL, S3_ACTION_ID};
use crate::canonical::{canonical_hash, canonical_json};
use crate::contract::{
    expected_manifest_hash, expected_profile_digest, Capability, ExecutionManifest, Platform,
    RunMode, RunnerProfile, MANIFEST_SCHEMA_VERSION, PROFILE_SCHEMA_VERSION,
};
use crate::s3_access_binding::S3WorkerBinding;

fn require(ok: bool) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}
fn fields(value: &Value, names: &str) -> Result<(), String> {
    let object = value.as_object().ok_or(REFUSAL)?;
    require(
        object.len() == names.split_whitespace().count()
            && names.split_whitespace().all(|key| object.contains_key(key)),
    )
}
fn text(value: &Value) -> Result<&str, String> {
    value.as_str().ok_or_else(|| REFUSAL.into())
}
fn identifier(value: &Value) -> Result<&str, String> {
    let value = text(value)?;
    require(
        (1..=128).contains(&value.len())
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
    )?;
    Ok(value)
}
fn digest(value: &Value) -> Result<(), String> {
    require(text(value)?.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }))
}
fn path(value: &Value) -> Result<String, String> {
    let value = text(value)?;
    require(
        value.len() <= 4096
            && value.starts_with('/')
            && !value.contains(['\\', '\0'])
            && !value
                .split('/')
                .skip(1)
                .any(|part| part.is_empty() || part == "." || part == ".."),
    )?;
    Ok(value.into())
}
fn time(value: &Value) -> Result<DateTime<FixedOffset>, String> {
    let value = text(value)?;
    require(value.is_ascii() && value.len() <= 27 && value.ends_with('Z'))?;
    DateTime::parse_from_rfc3339(value).map_err(|_| REFUSAL.into())
}

pub(super) fn validate(
    admission: &Value,
    expected_issuer: &Value,
    manifest: &Value,
    profile: &Value,
    now: DateTime<FixedOffset>,
) -> Result<VerifiedS3Admission, String> {
    fields(admission, "schema_version issuer manifest_digest profile_digest request_digest approval_digest host native_runner_digest credential_digest issued_at expires_at")?;
    require(admission["schema_version"] == "bluefire.s3-access-admission.v1")?;
    fields(
        expected_issuer,
        "runner_id client_id enrollment_generation peer_fingerprint",
    )?;
    fields(
        &admission["issuer"],
        "runner_id client_id enrollment_generation peer_fingerprint server_instance_id",
    )?;
    let mut issuer = admission["issuer"].clone();
    identifier(&issuer["server_instance_id"])?;
    issuer
        .as_object_mut()
        .ok_or(REFUSAL)?
        .remove("server_instance_id");
    require(issuer == *expected_issuer)?;
    identifier(&issuer["runner_id"])?;
    identifier(&issuer["client_id"])?;
    digest(&issuer["enrollment_generation"])?;
    digest(&issuer["peer_fingerprint"])?;
    digest(&admission["native_runner_digest"])?;
    digest(&admission["credential_digest"])?;
    let typed_manifest: ExecutionManifest =
        serde_json::from_value(manifest.clone()).map_err(|_| REFUSAL)?;
    let typed_profile: RunnerProfile =
        serde_json::from_value(profile.clone()).map_err(|_| REFUSAL)?;
    let approval = typed_manifest.approval.as_ref().ok_or(REFUSAL)?;
    fields(&manifest["params"], "worker_request workflow_approval")?;
    let binding = S3WorkerBinding::from_json(
        canonical_json(&manifest["params"]["worker_request"]).as_bytes(),
    )?;
    let workflow = &manifest["params"]["workflow_approval"];
    fields(workflow, "schema_version workflow_job_id operation_job_id environment_id scope_digest request_digest phase reviewed_by review_digest expected_workflow_revision prior_run_ids policy_change_digest")?;
    require(workflow["schema_version"] == "bluefire.s3-workflow-approval.v1")?;
    for field in ["workflow_job_id", "operation_job_id", "environment_id"] {
        identifier(&workflow[field])?;
    }
    let reviewer = text(&workflow["reviewed_by"])?;
    require(
        (1..=100).contains(&reviewer.chars().count())
            && reviewer.trim() == reviewer
            && reviewer.chars().all(|character| character as u32 >= 32),
    )?;
    digest(&workflow["review_digest"])?;
    let revision = workflow["expected_workflow_revision"]
        .as_u64()
        .filter(|n| *n <= 1_000_000)
        .ok_or(REFUSAL)?;
    let runs = workflow["prior_run_ids"]
        .as_array()
        .filter(|runs| runs.len() <= 32)
        .ok_or(REFUSAL)?;
    let mut unique = std::collections::BTreeSet::new();
    for run in runs {
        require(unique.insert(identifier(run)?))?;
    }
    let phase = text(&workflow["phase"])?;
    let operations: &[&str] = match phase {
        "inspect" => &["inspect_policy"],
        "baseline" | "retest" => &["probe_read", "legitimate_read"],
        "apply" => &["apply_policy"],
        "rollback" => &["rollback_policy"],
        "reconcile" => &["reconcile_policy"],
        _ => return Err(REFUSAL.into()),
    };
    require(operations.contains(&binding.operation()))?;
    let change = binding.policy_change_digest()?;
    require(workflow["policy_change_digest"] == change.map_or(Value::Null, Value::String))?;
    require(
        workflow["scope_digest"] == binding.scope_digest()
            && workflow["request_digest"] == binding.digest(),
    )?;
    let host = &admission["host"];
    fields(host, "environment_id scope_digest runtime_digest worker_generation ledger_root runtime_root owner_uid")?;
    let owner_uid = host["owner_uid"]
        .as_u64()
        .filter(|uid| (1..u32::MAX as u64).contains(uid))
        .ok_or(REFUSAL)? as u32;
    require(
        host["environment_id"] == workflow["environment_id"]
            && host["scope_digest"] == binding.scope_digest()
            && host["runtime_digest"] == binding.runtime_digest()
            && host["worker_generation"] == binding.worker_generation(),
    )?;
    let issued = time(&admission["issued_at"])?;
    let expires = time(&admission["expires_at"])?;
    require(
        issued <= now
            && now < expires
            && expires <= binding.deadline()?
            && (expires - issued).num_seconds() <= 60,
    )?;
    require(
        admission["manifest_digest"] == canonical_hash(manifest)
            && admission["profile_digest"] == canonical_hash(profile)
            && admission["request_digest"] == binding.digest()
            && admission["approval_digest"] == canonical_hash(workflow)
            && typed_manifest.schema_version == MANIFEST_SCHEMA_VERSION
            && typed_profile.schema_version == PROFILE_SCHEMA_VERSION
            && typed_manifest.action_id == S3_ACTION_ID
            && typed_manifest.mode == RunMode::Execute
            && typed_manifest.platform == Platform::Linux
            && typed_profile.platform == Platform::Linux
            && typed_manifest.runner_id == typed_profile.runner_id
            && typed_manifest.runner_profile_id == typed_profile.profile_id
            && issuer["runner_id"] == typed_profile.runner_id
            && typed_manifest.request_hash == expected_manifest_hash(&typed_manifest)
            && typed_profile.policy_digest == expected_profile_digest(&typed_profile)
            && typed_manifest.policy_digest == typed_profile.policy_digest
            && approval.request_hash == typed_manifest.request_hash
            && approval.approved_at <= now
            && now < approval.expires_at
            && typed_manifest.requested_at <= now
            && now < typed_manifest.expires_at
            && expires <= typed_manifest.expires_at
            && expires <= approval.expires_at
            && typed_manifest.required_capabilities == [Capability::CloudAwsS3Access]
            && typed_profile
                .capabilities
                .contains(&Capability::CloudAwsS3Access)
            && typed_profile.allowed_actions.contains(&S3_ACTION_ID.into())
            && !typed_profile
                .control_blocked_actions
                .contains(&S3_ACTION_ID.into())
            && typed_manifest.safety_tier.rank() <= typed_profile.max_safety_tier.rank()
            && typed_manifest.limits.timeout_ms > 0
            && typed_manifest.limits.timeout_ms <= 60_000
            && typed_manifest.limits.timeout_ms <= typed_profile.limits.timeout_ms
            && typed_profile.file_access_binding.is_none()
            && typed_manifest.execution_binding.is_none()
            && typed_manifest.provider_binding.is_none()
            && typed_manifest.reviewed_operation.is_none()
            && typed_manifest.grant_attempt.is_none()
            && typed_manifest.grant_cleanup.is_none(),
    )?;
    Ok(VerifiedS3Admission {
        manifest: typed_manifest,
        profile: typed_profile,
        binding,
        enrollment_digest: canonical_hash(expected_issuer),
        approval_digest: text(&admission["approval_digest"])?.into(),
        workflow_id: text(&workflow["workflow_job_id"])?.into(),
        operation_id: text(&workflow["operation_job_id"])?.into(),
        environment_id: text(&workflow["environment_id"])?.into(),
        phase: phase.into(),
        revision,
        owner_uid,
        ledger_root: path(&host["ledger_root"])?,
        runtime_root: path(&host["runtime_root"])?,
        expires_at: expires,
        #[cfg(target_os = "linux")]
        credentials: None,
    })
}
