use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{Duration as ChronoDuration, Utc};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::actions::{find_action, ActionContext, ActionDescriptor, ActionFailure, ActionOutcome};
use crate::contract::{
    canonical_hash, evidence_id, expected_manifest_hash, expected_profile_digest,
    unique_capabilities, utc_now, validate_identifier, BoundedOutput, ErrorRecord, EvidenceKind,
    EvidenceRecord, ExecutionLimits, ExecutionManifest, RunMode, RunnerProfile, TaskResult,
    TaskStatus, MANIFEST_SCHEMA_VERSION, PROFILE_SCHEMA_VERSION, RESULT_SCHEMA_VERSION,
};
use crate::safety::{normalize_relative, scope_is_subset, validate_loopback_destination, SafeRoot};

pub const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_NODES: usize = 4096;
const MAX_JSON_STRING_BYTES: usize = 16 * 1024;
const MAX_REQUEST_LIFETIME_MINUTES: i64 = 60;

#[derive(Debug)]
pub struct RunnerError(pub String);

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RunnerError {}

#[derive(Debug, Clone)]
pub struct Runner {
    executable: PathBuf,
}

impl Runner {
    pub fn new() -> Result<Self, RunnerError> {
        let executable = std::env::current_exe().map_err(|error| {
            RunnerError(format!("cannot identify the runner executable: {error}"))
        })?;
        Ok(Self { executable })
    }

    /// Test and embedding hook. The selected executable still receives only
    /// the private fixed transform subcommand and its fixed typed arguments.
    pub fn with_executable(executable: PathBuf) -> Self {
        Self { executable }
    }

    pub fn execute(&self, manifest: ExecutionManifest, profile: RunnerProfile) -> TaskResult {
        let started_at = utc_now();

        let action = match find_action(&manifest.action_id) {
            Some(action) => action,
            None => {
                return failure_result(
                    &manifest,
                    &profile,
                    started_at,
                    ActionFailure {
                        status: TaskStatus::Refused,
                        code: "unknown_action",
                        message: "action ID is not present in the static runner registry"
                            .to_string(),
                    },
                )
            }
        };

        if let Err(failure) = validate_policy(&manifest, &profile, action.descriptor()) {
            return failure_result(&manifest, &profile, started_at, failure);
        }

        let prepared = match action.prepare(manifest.params.clone()) {
            Ok(prepared) => prepared,
            Err(failure) => return failure_result(&manifest, &profile, started_at, failure),
        };
        let root = match SafeRoot::open(&profile.sandbox_root) {
            Ok(root) => root,
            Err(message) => {
                return failure_result(
                    &manifest,
                    &profile,
                    started_at,
                    ActionFailure {
                        status: TaskStatus::ControlBlocked,
                        code: "sandbox_root_blocked",
                        message,
                    },
                )
            }
        };
        let context = ActionContext {
            manifest: &manifest,
            profile: &profile,
            root: &root,
            runner_executable: &self.executable,
        };
        match prepared.execute(&context) {
            Ok(outcome) => outcome_result(&manifest, &profile, started_at, outcome),
            Err(failure) => failure_result(&manifest, &profile, started_at, failure),
        }
    }
}

fn validate_limits(
    requested: &ExecutionLimits,
    maximum: &ExecutionLimits,
) -> Result<(), ActionFailure> {
    if requested.timeout_ms == 0
        || requested.max_stdout_bytes == 0
        || requested.max_stderr_bytes == 0
        || requested.max_artifact_bytes == 0
        || requested.max_files == 0
    {
        return Err(blocked(
            "invalid_resource_limits",
            "all execution limits must be greater than zero",
        ));
    }
    if requested.timeout_ms > maximum.timeout_ms
        || requested.max_stdout_bytes > maximum.max_stdout_bytes
        || requested.max_stderr_bytes > maximum.max_stderr_bytes
        || requested.max_artifact_bytes > maximum.max_artifact_bytes
        || requested.max_files > maximum.max_files
    {
        return Err(blocked(
            "resource_limit_blocked",
            "manifest limits exceed the runner profile",
        ));
    }
    Ok(())
}

fn validate_json_shape(value: &Value) -> Result<(), ActionFailure> {
    fn visit(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), String> {
        *nodes = nodes.saturating_add(1);
        if *nodes > MAX_JSON_NODES {
            return Err("parameter document contains too many JSON nodes".to_string());
        }
        if depth > MAX_JSON_DEPTH {
            return Err("parameter document exceeds the nesting limit".to_string());
        }
        match value {
            Value::String(value) if value.len() > MAX_JSON_STRING_BYTES => {
                Err("parameter string exceeds its byte limit".to_string())
            }
            Value::Array(values) => {
                for value in values {
                    visit(value, depth + 1, nodes)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                for (key, value) in values {
                    if key.len() > 128 {
                        return Err("parameter key exceeds its byte limit".to_string());
                    }
                    visit(value, depth + 1, nodes)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    let mut nodes = 0;
    visit(value, 0, &mut nodes).map_err(|error| blocked("parameter_bounds_blocked", error))
}

fn validate_profile(profile: &RunnerProfile) -> Result<(), ActionFailure> {
    if profile.schema_version != PROFILE_SCHEMA_VERSION {
        return Err(blocked(
            "unsupported_profile_schema",
            "profile schema version is unsupported",
        ));
    }
    validate_identifier("profile_id", &profile.profile_id)
        .map_err(|error| blocked("invalid_profile", error))?;
    validate_identifier("runner_id", &profile.runner_id)
        .map_err(|error| blocked("invalid_profile", error))?;
    if expected_profile_digest(profile) != profile.policy_digest {
        return Err(blocked(
            "policy_digest_mismatch",
            "profile policy digest does not match its contents",
        ));
    }
    unique_capabilities(&profile.capabilities)
        .map_err(|error| blocked("invalid_profile", error))?;
    let allowed = profile.allowed_actions.iter().collect::<BTreeSet<_>>();
    if allowed.len() != profile.allowed_actions.len() {
        return Err(blocked(
            "invalid_profile",
            "allowed_actions contains duplicates",
        ));
    }
    let blocked_actions = profile
        .control_blocked_actions
        .iter()
        .collect::<BTreeSet<_>>();
    if blocked_actions.len() != profile.control_blocked_actions.len() {
        return Err(blocked(
            "invalid_profile",
            "control_blocked_actions contains duplicates",
        ));
    }
    for action_id in profile
        .allowed_actions
        .iter()
        .chain(profile.control_blocked_actions.iter())
    {
        if find_action(action_id).is_none() {
            return Err(blocked(
                "invalid_profile",
                format!("profile names unknown action {action_id}"),
            ));
        }
    }
    for path in &profile.target_scope.filesystem {
        normalize_relative(path, true).map_err(|error| blocked("invalid_profile_scope", error))?;
    }
    for destination in &profile.target_scope.network {
        validate_loopback_destination(destination)
            .map_err(|error| blocked("invalid_profile_scope", error))?;
    }
    validate_limits(&profile.limits, &profile.limits)
}

fn validate_policy(
    manifest: &ExecutionManifest,
    profile: &RunnerProfile,
    descriptor: &ActionDescriptor,
) -> Result<(), ActionFailure> {
    validate_profile(profile)?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(blocked(
            "unsupported_manifest_schema",
            "manifest schema version is unsupported",
        ));
    }
    for (kind, value) in [
        ("request_id", manifest.request_id.as_str()),
        ("run_id", manifest.run_id.as_str()),
        ("step_id", manifest.step_id.as_str()),
        ("behavior_id", manifest.behavior_id.as_str()),
        ("action_id", manifest.action_id.as_str()),
        ("runner_id", manifest.runner_id.as_str()),
        ("runner_profile_id", manifest.runner_profile_id.as_str()),
    ] {
        validate_identifier(kind, value).map_err(|error| blocked("invalid_manifest", error))?;
    }
    if manifest.mode != RunMode::Execute {
        return Err(blocked(
            "mode_blocked",
            "the execution runner accepts Execute manifests only; Simulate stays in the control plane",
        ));
    }
    if manifest.request_hash.len() != 71
        || !manifest.request_hash.starts_with("sha256:")
        || !manifest.request_hash[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || expected_manifest_hash(manifest) != manifest.request_hash
    {
        return Err(blocked(
            "request_hash_mismatch",
            "manifest request hash does not match its normalized contents",
        ));
    }
    let now = utc_now();
    if manifest.requested_at > now + ChronoDuration::minutes(5)
        || manifest.expires_at <= now
        || manifest.expires_at <= manifest.requested_at
        || manifest.expires_at - manifest.requested_at
            > ChronoDuration::minutes(MAX_REQUEST_LIFETIME_MINUTES)
    {
        return Err(blocked(
            "request_time_blocked",
            "manifest time window is invalid, expired, or too long",
        ));
    }
    if manifest.runner_id != profile.runner_id || manifest.runner_profile_id != profile.profile_id {
        return Err(blocked(
            "runner_profile_mismatch",
            "manifest is routed to a different runner or profile",
        ));
    }
    if manifest.policy_digest != profile.policy_digest {
        return Err(blocked(
            "policy_digest_mismatch",
            "manifest is bound to a different runner policy",
        ));
    }
    if manifest.cleanup_action_id != "sandbox.cleanup.v1" {
        return Err(blocked(
            "cleanup_action_blocked",
            "manifest must bind cleanup to sandbox.cleanup.v1",
        ));
    }
    let actual_platform = crate::contract::Platform::current();
    if manifest.platform != actual_platform
        || profile.platform != actual_platform
        || !descriptor.platforms.contains(&actual_platform)
    {
        return Err(blocked(
            "platform_blocked",
            "manifest, profile, action, and actual host platform do not agree",
        ));
    }
    if !descriptor
        .behavior_ids
        .contains(&manifest.behavior_id.as_str())
    {
        return Err(blocked(
            "behavior_action_mismatch",
            "action is not registered for the requested behavior",
        ));
    }
    if profile
        .control_blocked_actions
        .contains(&manifest.action_id)
    {
        return Err(blocked(
            "action_control_blocked",
            "runner profile explicitly blocks this action",
        ));
    }
    if !profile.allowed_actions.contains(&manifest.action_id) {
        return Err(blocked(
            "action_not_allowed",
            "runner profile does not allow this action",
        ));
    }

    let requested_capabilities = unique_capabilities(&manifest.required_capabilities)
        .map_err(|error| blocked("capability_blocked", error))?;
    let descriptor_capabilities = descriptor
        .capabilities
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if requested_capabilities != descriptor_capabilities {
        return Err(blocked(
            "capability_declaration_mismatch",
            "manifest capabilities must exactly match the action descriptor",
        ));
    }
    let profile_capabilities = unique_capabilities(&profile.capabilities)
        .map_err(|error| blocked("invalid_profile", error))?;
    if !descriptor_capabilities.is_subset(&profile_capabilities) {
        return Err(blocked(
            "capability_blocked",
            "runner profile lacks a required action capability",
        ));
    }
    if manifest.safety_tier != descriptor.safety_tier
        || descriptor.safety_tier.rank() > profile.max_safety_tier.rank()
    {
        return Err(blocked(
            "safety_tier_blocked",
            "action safety tier is misstated or exceeds the profile",
        ));
    }
    if let Some(threshold) = profile.approval_required_at_or_above {
        if descriptor.safety_tier.rank() >= threshold.rank() {
            let approval = manifest.approval.as_ref().ok_or_else(|| {
                blocked(
                    "approval_required",
                    "profile requires a bound approval for this action",
                )
            })?;
            if approval.approved_by.is_empty()
                || approval.approved_at > now + ChronoDuration::minutes(5)
                || approval.expires_at <= now
                || approval.expires_at <= approval.approved_at
                || approval.request_hash != manifest.request_hash
            {
                return Err(blocked(
                    "approval_invalid",
                    "approval is invalid, expired, or bound to another request",
                ));
            }
        }
    }
    if !scope_is_subset(&manifest.target_scope, &profile.target_scope)
        .map_err(|error| blocked("target_scope_blocked", error))?
    {
        return Err(blocked(
            "target_scope_blocked",
            "manifest target scope expands beyond the profile",
        ));
    }
    for destination in &manifest.target_scope.network {
        validate_loopback_destination(destination)
            .map_err(|error| blocked("target_scope_blocked", error))?;
    }
    validate_limits(&manifest.limits, &profile.limits)?;
    validate_json_shape(&manifest.params)?;
    for reference in &manifest.evidence_refs {
        validate_identifier("evidence reference", reference)
            .map_err(|error| blocked("invalid_evidence_reference", error))?;
    }
    Ok(())
}

fn blocked(code: &'static str, message: impl Into<String>) -> ActionFailure {
    ActionFailure {
        status: TaskStatus::ControlBlocked,
        code,
        message: message.into(),
    }
}

fn make_evidence(
    manifest: &ExecutionManifest,
    profile: &RunnerProfile,
    kind: EvidenceKind,
    details: Value,
) -> EvidenceRecord {
    let mut evidence = EvidenceRecord {
        evidence_id: String::new(),
        kind,
        producer: "bluefire-rust-runner".to_string(),
        request_hash: manifest.request_hash.clone(),
        policy_digest: profile.policy_digest.clone(),
        action_id: manifest.action_id.clone(),
        behavior_id: manifest.behavior_id.clone(),
        runner_id: profile.runner_id.clone(),
        runner_profile_id: profile.profile_id.clone(),
        platform: crate::contract::Platform::current(),
        recorded_at: utc_now(),
        references: manifest.evidence_refs.clone(),
        details,
    };
    evidence.evidence_id = evidence_id(&evidence);
    evidence
}

fn failure_result(
    manifest: &ExecutionManifest,
    profile: &RunnerProfile,
    started_at: chrono::DateTime<Utc>,
    failure: ActionFailure,
) -> TaskResult {
    let kind = if matches!(
        failure.status,
        TaskStatus::Refused | TaskStatus::ControlBlocked
    ) {
        EvidenceKind::ControlBlocked
    } else {
        EvidenceKind::Executed
    };
    let error = ErrorRecord {
        code: failure.code.to_string(),
        message: failure.message,
    };
    let details = json!({
        "status": failure.status,
        "error": &error,
        "side_effects_started": kind == EvidenceKind::Executed,
    });
    let evidence = make_evidence(manifest, profile, kind, details);
    TaskResult {
        schema_version: RESULT_SCHEMA_VERSION.to_string(),
        request_id: manifest.request_id.clone(),
        run_id: manifest.run_id.clone(),
        step_id: manifest.step_id.clone(),
        behavior_id: manifest.behavior_id.clone(),
        action_id: manifest.action_id.clone(),
        status: failure.status,
        runner_id: profile.runner_id.clone(),
        runner_profile_id: profile.profile_id.clone(),
        platform: crate::contract::Platform::current(),
        request_hash: manifest.request_hash.clone(),
        policy_digest: profile.policy_digest.clone(),
        started_at,
        finished_at: utc_now(),
        output: Value::Null,
        stdout: BoundedOutput::default(),
        stderr: BoundedOutput::default(),
        receipt_ids: Vec::new(),
        cleanup: None,
        evidence: vec![evidence],
        error: Some(error),
        limitations: Vec::new(),
    }
}

fn outcome_result(
    manifest: &ExecutionManifest,
    profile: &RunnerProfile,
    started_at: chrono::DateTime<Utc>,
    outcome: ActionOutcome,
) -> TaskResult {
    let details = json!({
        "status": outcome.status,
        "output_hash": canonical_hash(&outcome.output),
        "receipt_ids": &outcome.receipt_ids,
        "stdout_total_bytes": outcome.stdout.total_bytes,
        "stderr_total_bytes": outcome.stderr.total_bytes,
    });
    let evidence = make_evidence(manifest, profile, EvidenceKind::Executed, details);
    TaskResult {
        schema_version: RESULT_SCHEMA_VERSION.to_string(),
        request_id: manifest.request_id.clone(),
        run_id: manifest.run_id.clone(),
        step_id: manifest.step_id.clone(),
        behavior_id: manifest.behavior_id.clone(),
        action_id: manifest.action_id.clone(),
        status: outcome.status,
        runner_id: profile.runner_id.clone(),
        runner_profile_id: profile.profile_id.clone(),
        platform: crate::contract::Platform::current(),
        request_hash: manifest.request_hash.clone(),
        policy_digest: profile.policy_digest.clone(),
        started_at,
        finished_at: utc_now(),
        output: outcome.output,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
        receipt_ids: outcome.receipt_ids,
        cleanup: outcome.cleanup,
        evidence: vec![evidence],
        error: outcome.error,
        limitations: outcome.limitations,
    }
}

fn read_document<T: DeserializeOwned>(path: &Path) -> Result<T, RunnerError> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| RunnerError(format!("cannot inspect {}: {error}", path.display())))?;
    if !metadata.is_file() || metadata.len() > MAX_DOCUMENT_BYTES {
        return Err(RunnerError(format!(
            "{} is not a regular JSON file within the {} byte limit",
            path.display(),
            MAX_DOCUMENT_BYTES
        )));
    }
    let file = File::open(path)
        .map_err(|error| RunnerError(format!("cannot open {}: {error}", path.display())))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_DOCUMENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| RunnerError(format!("cannot read {}: {error}", path.display())))?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(RunnerError(
            "JSON document grew beyond its byte limit".to_string(),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        RunnerError(format!(
            "{} has an invalid strict schema: {error}",
            path.display()
        ))
    })
}

pub fn execute_files(manifest_path: &Path, profile_path: &Path) -> Result<TaskResult, RunnerError> {
    let manifest: ExecutionManifest = read_document(manifest_path)?;
    let profile: RunnerProfile = read_document(profile_path)?;
    Ok(Runner::new()?.execute(manifest, profile))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_depth_is_bounded() {
        let mut value = Value::Null;
        for _ in 0..=MAX_JSON_DEPTH + 1 {
            value = json!([value]);
        }
        assert!(validate_json_shape(&value).is_err());
    }

    #[test]
    fn resource_limits_cannot_expand_profile() {
        let maximum = ExecutionLimits {
            timeout_ms: 100,
            max_stdout_bytes: 100,
            max_stderr_bytes: 100,
            max_artifact_bytes: 100,
            max_files: 2,
        };
        let mut requested = maximum.clone();
        requested.timeout_ms = 101;
        assert!(validate_limits(&requested, &maximum).is_err());
        requested.timeout_ms = 0;
        assert!(validate_limits(&requested, &maximum).is_err());
    }
}
