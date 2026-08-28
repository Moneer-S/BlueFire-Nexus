use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use chrono::{Duration as ChronoDuration, Utc};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::actions::{
    find_action, Action, ActionContext, ActionDescriptor, ActionFailure, ActionOutcome,
    ActionReadiness,
};
use crate::contract::{
    canonical_hash, evidence_id, expected_manifest_hash, expected_profile_digest,
    unique_capabilities, utc_now, validate_identifier, BoundedOutput, ErrorRecord, EvidenceKind,
    EvidenceRecord, ExecutionBinding, ExecutionLimits, ExecutionManifest, ProviderExecutionBinding,
    RunMode, RunnerProfile, TaskResult, TaskStatus, ACTION_PROGRAM_ADAPTER,
    ACTION_PROGRAM_SCHEMA_VERSION, EXECUTION_BINDING_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION,
    PROFILE_SCHEMA_VERSION, RESULT_SCHEMA_VERSION,
};
use crate::provider_action::{
    execute_provider_action, provider_artifact_bytes, validate_provider_binding,
    validate_provider_parameters, validate_provider_profile, ProviderActionExecution,
};
use crate::providers::ProviderError;
use crate::safety::{normalize_relative, scope_is_subset, validate_loopback_destination, SafeRoot};

pub const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_JSON_DEPTH: usize = 16;
const MAX_JSON_NODES: usize = 4096;
const MAX_JSON_STRING_BYTES: usize = 16 * 1024;
const MAX_REQUEST_LIFETIME_MINUTES: i64 = 60;
const MAX_ACTION_BINDINGS: usize = 512;
const MAX_BINDING_CONSTANTS: usize = 32;

#[derive(Debug)]
pub struct RunnerError(pub String);

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RunnerError {}

#[derive(Debug, Clone, Default)]
pub struct Runner;

enum ValidatedExecution<'a> {
    Registered {
        action: &'static dyn Action,
        package_alias: bool,
    },
    Provider {
        binding: &'a ProviderExecutionBinding,
        artifact: Vec<u8>,
    },
}

impl Runner {
    pub fn new() -> Result<Self, RunnerError> {
        Ok(Self)
    }

    pub fn execute(&self, manifest: ExecutionManifest, profile: RunnerProfile) -> TaskResult {
        let started_at = utc_now();
        let execution = match validate_policy(&manifest, &profile) {
            Ok(execution) => execution,
            Err(failure) => return failure_result(&manifest, &profile, started_at, failure),
        };

        match execution {
            ValidatedExecution::Registered { action, .. } => {
                let prepared = match action.prepare(manifest.params.clone()) {
                    Ok(prepared) => prepared,
                    Err(failure) => {
                        return failure_result(&manifest, &profile, started_at, failure)
                    }
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
                };
                match prepared.execute(&context) {
                    Ok(outcome) => outcome_result(&manifest, &profile, started_at, outcome),
                    Err(failure) => failure_result(&manifest, &profile, started_at, failure),
                }
            }
            ValidatedExecution::Provider { binding, artifact } => {
                match execute_provider_action(&manifest, binding, &artifact) {
                    Ok(execution) => provider_result(&manifest, &profile, started_at, execution),
                    Err(error) => {
                        failure_result(&manifest, &profile, started_at, provider_failure(error))
                    }
                }
            }
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

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_package_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut separator = false;
    for byte in bytes.iter().copied().skip(1) {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            separator = false;
        } else if matches!(byte, b'.' | b'_' | b'-') && !separator {
            separator = true;
        } else {
            return false;
        }
    }
    !separator
}

fn is_stable_id(value: &str) -> bool {
    let Some((namespace, version)) = value.rsplit_once(".v") else {
        return false;
    };
    is_package_identifier(namespace)
        && !version.is_empty()
        && version.as_bytes()[0].is_ascii_digit()
        && version.as_bytes()[0] != b'0'
        && version.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_semver(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return false;
    }
    let mut build_split = value.split('+');
    let Some(without_build) = build_split.next() else {
        return false;
    };
    let build = build_split.next();
    if build_split.next().is_some() {
        return false;
    }
    let mut prerelease_split = without_build.splitn(2, '-');
    let Some(core) = prerelease_split.next() else {
        return false;
    };
    let prerelease = prerelease_split.next();
    let core_parts = core.split('.').collect::<Vec<_>>();
    if core_parts.len() != 3
        || core_parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
                || part.parse::<u64>().is_err()
        })
    {
        return false;
    }
    for (section, reject_numeric_leading_zero) in [(prerelease, true), (build, false)] {
        if let Some(section) = section {
            if section.is_empty()
                || section.split('.').any(|part| {
                    part.is_empty()
                        || !part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                        || (reject_numeric_leading_zero
                            && part.bytes().all(|byte| byte.is_ascii_digit())
                            && part.len() > 1
                            && part.starts_with('0'))
                })
            {
                return false;
            }
        }
    }
    true
}

fn reviewed_program_constants(opcode: &str) -> Option<BTreeMap<String, Value>> {
    let constants = match opcode {
        "sandbox.archive.tar.v1" => BTreeMap::from([(
            "archive_format".to_string(),
            Value::String("ustar".to_string()),
        )]),
        "sandbox.fixture.create.v1" => BTreeMap::from([(
            "content_template".to_string(),
            Value::String("telemetry-seed".to_string()),
        )]),
        "sandbox.network.loopback.v1" => {
            BTreeMap::from([("method".to_string(), Value::String("POST".to_string()))])
        }
        "sandbox.restricted.persistence-marker.v1" => BTreeMap::from([(
            "marker_kind".to_string(),
            Value::String("detection-canary".to_string()),
        )]),
        "endpoint.discovery.processes.v1"
        | "endpoint.discovery.system.v1"
        | "sandbox.cleanup.v1"
        | "sandbox.collection.stage.v1"
        | "sandbox.discovery.list.v1"
        | "sandbox.discovery.metadata.v1"
        | "sandbox.discovery.recursive.v1"
        | "sandbox.export.local.v1"
        | "sandbox.fixture.transform.v1" => BTreeMap::new(),
        _ => return None,
    };
    Some(constants)
}

fn program_digest(binding: &ExecutionBinding) -> String {
    canonical_hash(&json!({
        "schema_version": ACTION_PROGRAM_SCHEMA_VERSION,
        "steps": [{
            "opcode": &binding.runner_opcode,
            "adapter": ACTION_PROGRAM_ADAPTER,
            "constants": &binding.constants,
        }],
    }))
}

fn descriptor_digest(descriptor: &ActionDescriptor) -> String {
    canonical_hash(
        &serde_json::to_value(descriptor)
            .expect("static action descriptor serialization cannot fail"),
    )
}

fn validate_execution_binding(binding: &ExecutionBinding) -> Result<&'static dyn Action, String> {
    if binding.schema_version != EXECUTION_BINDING_SCHEMA_VERSION {
        return Err("execution binding schema version is unsupported".to_string());
    }
    if binding.catalog_generation == 0 || binding.catalog_generation > i64::MAX as u64 {
        return Err("execution binding catalog generation is invalid".to_string());
    }
    for (kind, digest) in [
        ("catalog", binding.catalog_digest.as_str()),
        ("package", binding.package_digest.as_str()),
        ("content", binding.content_digest.as_str()),
        ("program", binding.program_digest.as_str()),
        ("opcode contract", binding.opcode_contract_digest.as_str()),
    ] {
        if !is_sha256_digest(digest) {
            return Err(format!(
                "execution binding {kind} digest must be exact lowercase SHA-256"
            ));
        }
    }
    if !is_stable_id(&binding.logical_behavior_id)
        || !is_stable_id(&binding.logical_action_id)
        || !is_package_identifier(&binding.package_id)
        || !is_semver(&binding.package_version)
        || !is_stable_id(&binding.runner_opcode)
    {
        return Err("execution binding identity is invalid".to_string());
    }
    if find_action(&binding.logical_action_id).is_some() {
        return Err("execution binding cannot shadow a static action".to_string());
    }
    if binding.constants.len() > MAX_BINDING_CONSTANTS {
        return Err("execution binding contains too many constants".to_string());
    }
    let expected_constants = reviewed_program_constants(&binding.runner_opcode)
        .ok_or_else(|| "execution binding selects an unreviewed runner opcode".to_string())?;
    if binding.constants != expected_constants {
        return Err("execution binding constants do not match the reviewed opcode".to_string());
    }
    if binding.program_digest != program_digest(binding) {
        return Err("execution binding program digest does not match its program".to_string());
    }
    let action = find_action(&binding.runner_opcode)
        .ok_or_else(|| "execution binding runner opcode is unavailable".to_string())?;
    let descriptor = action.descriptor();
    if binding.opcode_contract_digest != descriptor_digest(descriptor) {
        return Err(
            "execution binding opcode contract digest does not match the runner".to_string(),
        );
    }
    Ok(action)
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
    if profile
        .action_bindings
        .len()
        .checked_add(profile.provider_bindings.len())
        .is_none_or(|count| count > MAX_ACTION_BINDINGS)
    {
        return Err(blocked(
            "invalid_profile",
            "action and provider bindings exceed the runner profile limit",
        ));
    }
    validate_provider_profile(&profile.provider_bindings, &profile.provider_artifacts)
        .map_err(|error| blocked("invalid_profile", error))?;
    let mut binding_pairs = BTreeSet::new();
    let mut catalog_identity: Option<(u64, &str)> = None;
    let mut previous_binding_pair: Option<(&str, &str)> = None;
    for binding in &profile.action_bindings {
        validate_execution_binding(binding).map_err(|error| blocked("invalid_profile", error))?;
        let pair = (
            binding.logical_behavior_id.as_str(),
            binding.logical_action_id.as_str(),
        );
        if !binding_pairs.insert(pair) {
            return Err(blocked(
                "invalid_profile",
                "action_bindings contains a duplicate logical behavior/action pair",
            ));
        }
        if previous_binding_pair.is_some_and(|previous| previous >= pair) {
            return Err(blocked(
                "invalid_profile",
                "action_bindings must be ordered by logical behavior/action pair",
            ));
        }
        previous_binding_pair = Some(pair);
        let candidate_identity = (binding.catalog_generation, binding.catalog_digest.as_str());
        if let Some(expected_identity) = catalog_identity {
            if candidate_identity != expected_identity {
                return Err(blocked(
                    "invalid_profile",
                    "action_bindings span more than one catalog generation",
                ));
            }
        } else {
            catalog_identity = Some(candidate_identity);
        }
        if !profile.allowed_actions.contains(&binding.logical_action_id) {
            return Err(blocked(
                "invalid_profile",
                "action binding logical action is not in allowed_actions",
            ));
        }
        if !profile.allowed_actions.contains(&binding.runner_opcode)
            || profile
                .control_blocked_actions
                .contains(&binding.runner_opcode)
        {
            return Err(blocked(
                "invalid_profile",
                "action binding cannot bypass backing opcode policy",
            ));
        }
    }
    for binding in &profile.provider_bindings {
        let pair = (
            binding.logical_behavior_id.as_str(),
            binding.logical_action_id.as_str(),
        );
        if !binding_pairs.insert(pair) {
            return Err(blocked(
                "invalid_profile",
                "action and provider bindings contain a duplicate logical pair",
            ));
        }
        let candidate_identity = (binding.catalog_generation, binding.catalog_digest.as_str());
        if let Some(expected_identity) = catalog_identity {
            if candidate_identity != expected_identity {
                return Err(blocked(
                    "invalid_profile",
                    "action and provider bindings span more than one catalog generation",
                ));
            }
        } else {
            catalog_identity = Some(candidate_identity);
        }
        if find_action(&binding.logical_action_id).is_some() {
            return Err(blocked(
                "invalid_profile",
                "provider binding cannot shadow a registered action",
            ));
        }
        if !profile.allowed_actions.contains(&binding.logical_action_id) {
            return Err(blocked(
                "invalid_profile",
                "provider binding logical action is not in allowed_actions",
            ));
        }
    }
    for action_id in profile
        .allowed_actions
        .iter()
        .chain(profile.control_blocked_actions.iter())
    {
        if find_action(action_id).is_none()
            && !profile
                .action_bindings
                .iter()
                .any(|binding| binding.logical_action_id == *action_id)
            && !profile
                .provider_bindings
                .iter()
                .any(|binding| binding.logical_action_id == *action_id)
        {
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

fn validate_policy<'a>(
    manifest: &'a ExecutionManifest,
    profile: &'a RunnerProfile,
) -> Result<ValidatedExecution<'a>, ActionFailure> {
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
    let execution = match (
        manifest.execution_binding.as_ref(),
        manifest.provider_binding.as_ref(),
    ) {
        (Some(_), Some(_)) => {
            return Err(blocked(
                "execution_binding_mismatch",
                "manifest cannot select both a native alias and a provider action",
            ))
        }
        (Some(binding), None) => {
            let action = validate_execution_binding(binding)
                .map_err(|error| blocked("execution_binding_mismatch", error))?;
            if binding.logical_behavior_id != manifest.behavior_id
                || binding.logical_action_id != manifest.action_id
            {
                return Err(blocked(
                    "execution_binding_mismatch",
                    "execution binding does not match the manifest logical identity",
                ));
            }
            let profile_binding = profile.action_bindings.iter().find(|candidate| {
                candidate.logical_behavior_id == manifest.behavior_id
                    && candidate.logical_action_id == manifest.action_id
            });
            if profile_binding != Some(binding) {
                return Err(blocked(
                    "execution_binding_mismatch",
                    "manifest execution binding does not exactly match the sealed profile",
                ));
            }
            let parameter_object = manifest.params.as_object();
            for (name, constant) in &binding.constants {
                if let Some(parameter) = parameter_object.and_then(|params| params.get(name)) {
                    if parameter != constant {
                        return Err(blocked(
                            "execution_binding_mismatch",
                            "manifest parameter conflicts with a reviewed program constant",
                        ));
                    }
                }
            }
            ValidatedExecution::Registered {
                action,
                package_alias: true,
            }
        }
        (None, Some(binding)) => {
            validate_provider_binding(binding)
                .map_err(|error| blocked("provider_binding_mismatch", error))?;
            if binding.logical_behavior_id != manifest.behavior_id
                || binding.logical_action_id != manifest.action_id
            {
                return Err(blocked(
                    "provider_binding_mismatch",
                    "provider binding does not match the manifest logical identity",
                ));
            }
            if find_action(&binding.logical_action_id).is_some() {
                return Err(blocked(
                    "provider_binding_mismatch",
                    "provider binding cannot shadow a registered action",
                ));
            }
            let profile_binding = profile.provider_bindings.iter().find(|candidate| {
                candidate.logical_behavior_id == manifest.behavior_id
                    && candidate.logical_action_id == manifest.action_id
            });
            if profile_binding != Some(binding) {
                return Err(blocked(
                    "provider_binding_mismatch",
                    "manifest provider binding does not exactly match the sealed profile",
                ));
            }
            let artifact = provider_artifact_bytes(profile, binding)
                .map_err(|error| blocked("provider_artifact_blocked", error))?;
            ValidatedExecution::Provider { binding, artifact }
        }
        (None, None) => {
            let action = find_action(&manifest.action_id).ok_or_else(|| ActionFailure {
                status: TaskStatus::Refused,
                code: "unknown_action",
                message: "action ID is not present in the static runner registry".to_string(),
            })?;
            ValidatedExecution::Registered {
                action,
                package_alias: false,
            }
        }
    };

    let actual_platform = crate::contract::Platform::current();
    if manifest.platform != actual_platform || profile.platform != actual_platform {
        return Err(blocked(
            "platform_blocked",
            "manifest, profile, and actual host platform do not agree",
        ));
    }
    let (target_capabilities, target_safety_tier) = match &execution {
        ValidatedExecution::Registered {
            action,
            package_alias,
        } => {
            let descriptor = action.descriptor();
            ensure_action_ready(descriptor)?;
            if !descriptor.platforms.contains(&actual_platform) {
                return Err(blocked(
                    "platform_blocked",
                    "registered action does not support the actual host platform",
                ));
            }
            if !package_alias
                && !descriptor
                    .behavior_ids
                    .contains(&manifest.behavior_id.as_str())
            {
                return Err(blocked(
                    "behavior_action_mismatch",
                    "action is not registered for the requested behavior",
                ));
            }
            (
                descriptor
                    .capabilities
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>(),
                descriptor.safety_tier,
            )
        }
        ValidatedExecution::Provider { binding, .. } => {
            if !binding.platforms.contains(&actual_platform) {
                return Err(blocked(
                    "platform_blocked",
                    "provider action does not support the actual host platform",
                ));
            }
            if !manifest.target_scope.filesystem.is_empty()
                || !manifest.target_scope.network.is_empty()
            {
                return Err(blocked(
                    "provider_scope_blocked",
                    "provider ABI v1 receives no filesystem or network scope",
                ));
            }
            validate_provider_parameters(binding, &manifest.params)
                .map_err(|error| blocked("provider_parameters_blocked", error))?;
            (
                binding
                    .capabilities
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>(),
                binding.safety_tier,
            )
        }
    };
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
    if requested_capabilities != target_capabilities {
        return Err(blocked(
            "capability_declaration_mismatch",
            "manifest capabilities must exactly match the selected action contract",
        ));
    }
    let profile_capabilities = unique_capabilities(&profile.capabilities)
        .map_err(|error| blocked("invalid_profile", error))?;
    if !target_capabilities.is_subset(&profile_capabilities) {
        return Err(blocked(
            "capability_blocked",
            "runner profile lacks a required action capability",
        ));
    }
    if manifest.safety_tier != target_safety_tier
        || target_safety_tier.rank() > profile.max_safety_tier.rank()
    {
        return Err(blocked(
            "safety_tier_blocked",
            "action safety tier is misstated or exceeds the profile",
        ));
    }
    if let Some(threshold) = profile.approval_required_at_or_above {
        if target_safety_tier.rank() >= threshold.rank() {
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
    Ok(execution)
}

fn ensure_action_ready(descriptor: &ActionDescriptor) -> Result<(), ActionFailure> {
    if matches!(descriptor.readiness, ActionReadiness::Ready) {
        return Ok(());
    }
    Err(blocked(
        "action_not_ready",
        "selected action is not ready for execution",
    ))
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

fn provider_failure(error: ProviderError) -> ActionFailure {
    match error {
        ProviderError::FuelExhausted => ActionFailure {
            status: TaskStatus::TimedOut,
            code: "provider_fuel_exhausted",
            message: "isolated provider execution exhausted its fuel limit".to_string(),
        },
        ProviderError::InvalidLimits(_)
        | ProviderError::InvalidArtifactDigest
        | ProviderError::ArtifactDigestMismatch
        | ProviderError::ArtifactTooLarge { .. }
        | ProviderError::UnsupportedAbi(_)
        | ProviderError::InputEncoding(_)
        | ProviderError::InputTooLarge { .. } => ActionFailure {
            status: TaskStatus::ControlBlocked,
            code: "provider_contract_blocked",
            message: "provider artifact or invocation contract was refused before execution"
                .to_string(),
        },
        ProviderError::InvalidArtifact(_)
        | ProviderError::ImportForbidden { .. }
        | ProviderError::InvalidExport(_)
        | ProviderError::MemoryLimitExceeded
        | ProviderError::ExecutionTrap(_)
        | ProviderError::OutputTooLarge { .. }
        | ProviderError::OutputOutOfBounds
        | ProviderError::InvalidOutput(_)
        | ProviderError::NonCanonicalOutput => ActionFailure {
            status: TaskStatus::Failed,
            code: "provider_runtime_failed",
            message: "isolated provider execution failed its bounded runtime contract".to_string(),
        },
    }
}

fn provider_result(
    manifest: &ExecutionManifest,
    profile: &RunnerProfile,
    started_at: chrono::DateTime<Utc>,
    execution: ProviderActionExecution,
) -> TaskResult {
    let details = json!({
        "status": TaskStatus::Success,
        "output_hash": canonical_hash(&execution.output),
        "receipt_ids": [],
        "provider_execution": {
            "artifact_sha256": &execution.artifact_sha256,
            "fuel_consumed": execution.fuel_consumed,
            "memory_bytes": execution.memory_bytes,
            "output_bytes": execution.output_bytes,
            "no_host_imports": true,
        },
    });
    let evidence = make_evidence(manifest, profile, EvidenceKind::Executed, details);
    TaskResult {
        schema_version: RESULT_SCHEMA_VERSION.to_string(),
        request_id: manifest.request_id.clone(),
        run_id: manifest.run_id.clone(),
        step_id: manifest.step_id.clone(),
        behavior_id: manifest.behavior_id.clone(),
        action_id: manifest.action_id.clone(),
        status: TaskStatus::Success,
        runner_id: profile.runner_id.clone(),
        runner_profile_id: profile.profile_id.clone(),
        platform: crate::contract::Platform::current(),
        request_hash: manifest.request_hash.clone(),
        policy_digest: profile.policy_digest.clone(),
        started_at,
        finished_at: utc_now(),
        output: execution.output,
        stdout: BoundedOutput::default(),
        stderr: BoundedOutput::default(),
        receipt_ids: Vec::new(),
        cleanup: None,
        evidence: vec![evidence],
        error: None,
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
#[path = "runner_tests.rs"]
mod tests;
