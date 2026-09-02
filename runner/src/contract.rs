use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::SystemTime;

use chrono::{DateTime, Timelike, Utc};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const MANIFEST_SCHEMA_VERSION: &str = "bluefire.runner-manifest.v1";
pub const PROFILE_SCHEMA_VERSION: &str = "bluefire.runner-profile.v1";
pub const RESULT_SCHEMA_VERSION: &str = "bluefire.runner-result.v1";
pub const INVENTORY_SCHEMA_VERSION: &str = "bluefire.runner-inventory.v1";
pub const EXECUTION_BINDING_SCHEMA_VERSION: &str = "bluefire.runner-execution-binding.v1";
pub const PROVIDER_EXECUTION_BINDING_SCHEMA_VERSION: &str =
    "bluefire.runner-provider-execution-binding.v1";
pub const ACTION_PROGRAM_SCHEMA_VERSION: &str = "bluefire.action-program.v1";
pub const ACTION_PROGRAM_ADAPTER: &str = "bluefire.builtin-runner-adapter.v1";

fn normalize_wire_datetime(value: DateTime<Utc>) -> DateTime<Utc> {
    value
        .with_nanosecond((value.nanosecond() / 1_000) * 1_000)
        .expect("microsecond normalization preserves valid nanoseconds")
}

pub fn utc_now() -> DateTime<Utc> {
    normalize_wire_datetime(DateTime::<Utc>::from(SystemTime::now()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Linux,
    Macos,
}

impl Platform {
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Self::Macos
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        compile_error!("bluefire-runner supports Windows, Linux, and macOS only");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    Simulate,
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    NativeExecution,
    FilesystemRead,
    FilesystemWrite,
    ProcessSpawn,
    ProcessDiscovery,
    SystemDiscovery,
    NetworkLoopback,
    ExportLocal,
    SandboxRestricted,
    Cleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SafetyTier {
    Safe,
    Controlled,
    Restricted,
}

impl SafetyTier {
    pub fn rank(self) -> u8 {
        match self {
            Self::Safe => 1,
            Self::Controlled => 2,
            Self::Restricted => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkDestination {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetScope {
    #[serde(default)]
    pub filesystem: Vec<String>,
    #[serde(default)]
    pub network: Vec<NetworkDestination>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLimits {
    pub timeout_ms: u64,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub max_artifact_bytes: u64,
    pub max_files: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub approved_by: String,
    pub approved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Binds the approval to the normalized manifest. This value is excluded
    /// while calculating the request hash to avoid a circular hash.
    pub request_hash: String,
}

fn deserialize_constants<'de, D>(deserializer: D) -> Result<BTreeMap<String, Value>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ConstantsVisitor;

    impl<'de> Visitor<'de> for ConstantsVisitor {
        type Value = BTreeMap<String, Value>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a canonical object of reviewed action constants")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut constants = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, Value>()? {
                if constants.insert(key.clone(), value).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate execution-binding constant {key}"
                    )));
                }
            }
            Ok(constants)
        }
    }

    deserializer.deserialize_map(ConstantsVisitor)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBinding {
    pub schema_version: String,
    pub catalog_generation: u64,
    pub catalog_digest: String,
    pub logical_behavior_id: String,
    pub logical_action_id: String,
    pub package_id: String,
    pub package_version: String,
    pub package_digest: String,
    pub content_digest: String,
    pub program_digest: String,
    pub runner_opcode: String,
    pub opcode_contract_digest: String,
    #[serde(deserialize_with = "deserialize_constants")]
    pub constants: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderParameterType {
    String,
    Integer,
    Number,
    Boolean,
    StringList,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderArtifactSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub artifact_type: String,
    pub required: bool,
    pub multiple: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderParameterSpec {
    pub name: String,
    #[serde(rename = "type")]
    pub parameter_type: ProviderParameterType,
    pub required: bool,
    pub default: Value,
    #[serde(rename = "enum")]
    pub enum_values: Vec<Value>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub minimum: Option<serde_json::Number>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub maximum: Option<serde_json::Number>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderActionLimits {
    pub max_module_bytes: usize,
    pub max_memory_bytes: usize,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub fuel: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionBinding {
    pub schema_version: String,
    pub catalog_generation: u64,
    pub catalog_digest: String,
    pub logical_behavior_id: String,
    pub logical_action_id: String,
    pub package_id: String,
    pub package_version: String,
    pub package_digest: String,
    pub content_digest: String,
    pub program_digest: String,
    pub provider_id: String,
    pub abi_version: String,
    pub artifact_sha256: String,
    pub artifact_size: usize,
    pub action_contract_digest: String,
    pub runtime_contract_digest: String,
    pub provider_runtime_contract_digest: String,
    pub inputs: Vec<ProviderArtifactSpec>,
    pub outputs: Vec<ProviderArtifactSpec>,
    pub parameters: Vec<ProviderParameterSpec>,
    pub capabilities: Vec<Capability>,
    pub safety_tier: SafetyTier,
    pub platforms: Vec<Platform>,
    pub mutates: bool,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub cleanup_action_id: Option<String>,
    pub limits: ProviderActionLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderArtifact {
    pub artifact_sha256: String,
    pub artifact_size: usize,
    pub artifact_hex: String,
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn deserialize_execution_binding<'de, D>(
    deserializer: D,
) -> Result<Option<ExecutionBinding>, D::Error>
where
    D: Deserializer<'de>,
{
    ExecutionBinding::deserialize(deserializer).map(Some)
}

fn deserialize_provider_binding<'de, D>(
    deserializer: D,
) -> Result<Option<ProviderExecutionBinding>, D::Error>
where
    D: Deserializer<'de>,
{
    ProviderExecutionBinding::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionManifest {
    pub schema_version: String,
    pub request_id: String,
    pub run_id: String,
    pub step_id: String,
    pub behavior_id: String,
    pub action_id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_execution_binding",
        skip_serializing_if = "Option::is_none"
    )]
    pub execution_binding: Option<ExecutionBinding>,
    #[serde(
        default,
        deserialize_with = "deserialize_provider_binding",
        skip_serializing_if = "Option::is_none"
    )]
    pub provider_binding: Option<ProviderExecutionBinding>,
    pub mode: RunMode,
    pub runner_id: String,
    pub runner_profile_id: String,
    pub platform: Platform,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub params: Value,
    pub target_scope: TargetScope,
    pub required_capabilities: Vec<Capability>,
    pub safety_tier: SafetyTier,
    pub limits: ExecutionLimits,
    pub cleanup_action_id: String,
    pub policy_digest: String,
    #[serde(default)]
    pub approval: Option<Approval>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub request_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerProfile {
    pub schema_version: String,
    pub profile_id: String,
    pub runner_id: String,
    pub platform: Platform,
    pub sandbox_root: PathBuf,
    pub allowed_actions: Vec<String>,
    #[serde(default)]
    pub control_blocked_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub action_bindings: Vec<ExecutionBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_bindings: Vec<ProviderExecutionBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_artifacts: Vec<ProviderArtifact>,
    pub capabilities: Vec<Capability>,
    pub max_safety_tier: SafetyTier,
    #[serde(default)]
    pub approval_required_at_or_above: Option<SafetyTier>,
    pub target_scope: TargetScope,
    pub limits: ExecutionLimits,
    pub policy_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Success,
    Failed,
    Partial,
    Refused,
    ControlBlocked,
    TimedOut,
    CleanupFailed,
}

impl TaskStatus {
    pub fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Executed,
    ControlBlocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub producer: String,
    pub request_hash: String,
    pub policy_digest: String,
    pub action_id: String,
    pub behavior_id: String,
    pub runner_id: String,
    pub runner_profile_id: String,
    pub platform: Platform,
    pub recorded_at: DateTime<Utc>,
    pub references: Vec<String>,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BoundedOutput {
    pub text: String,
    pub total_bytes: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorRecord {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CleanupReport {
    pub requested_receipts: usize,
    pub removed_paths: Vec<String>,
    pub already_absent_receipts: Vec<String>,
    pub retained_paths: Vec<String>,
    pub errors: Vec<String>,
    pub verification_performed: bool,
    pub verified_removed_paths: usize,
    pub verified_absent_paths: usize,
    pub verified_receipts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskResult {
    pub schema_version: String,
    pub request_id: String,
    pub run_id: String,
    pub step_id: String,
    pub behavior_id: String,
    pub action_id: String,
    pub status: TaskStatus,
    pub runner_id: String,
    pub runner_profile_id: String,
    pub platform: Platform,
    pub request_hash: String,
    pub policy_digest: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub output: Value,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
    pub receipt_ids: Vec<String>,
    #[serde(default)]
    pub cleanup: Option<CleanupReport>,
    pub evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub error: Option<ErrorRecord>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("serializing a JSON string"),
        Value::Array(values) => {
            let body = values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{body}]")
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let body = keys
                .into_iter()
                .map(|key| {
                    let encoded_key =
                        serde_json::to_string(key).expect("serializing a JSON object key");
                    format!("{encoded_key}:{}", canonical_json(&values[key]))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn canonical_hash(value: &Value) -> String {
    format!("sha256:{}", sha256_hex(canonical_json(value).as_bytes()))
}

fn manifest_hash_value(manifest: &ExecutionManifest) -> Value {
    let mut value = serde_json::to_value(manifest).expect("manifest serialization cannot fail");
    if let Value::Object(root) = &mut value {
        root.insert("request_hash".to_string(), Value::String(String::new()));
        if let Some(Value::Object(approval)) = root.get_mut("approval") {
            approval.insert("request_hash".to_string(), Value::String(String::new()));
        }
    }
    value
}

pub fn expected_manifest_hash(manifest: &ExecutionManifest) -> String {
    canonical_hash(&manifest_hash_value(manifest))
}

pub fn seal_manifest(manifest: &mut ExecutionManifest) {
    manifest.request_hash.clear();
    if let Some(approval) = manifest.approval.as_mut() {
        approval.request_hash.clear();
    }
    let digest = expected_manifest_hash(manifest);
    manifest.request_hash = digest.clone();
    if let Some(approval) = manifest.approval.as_mut() {
        approval.request_hash = digest;
    }
}

fn profile_hash_value(profile: &RunnerProfile) -> Value {
    let mut value = serde_json::to_value(profile).expect("profile serialization cannot fail");
    if let Value::Object(root) = &mut value {
        root.insert("policy_digest".to_string(), Value::String(String::new()));
    }
    value
}

pub fn expected_profile_digest(profile: &RunnerProfile) -> String {
    canonical_hash(&profile_hash_value(profile))
}

pub fn seal_profile(profile: &mut RunnerProfile) {
    profile.policy_digest.clear();
    profile.policy_digest = expected_profile_digest(profile);
}

pub fn validate_identifier(kind: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 {
        return Err(format!("{kind} must contain 1..=128 characters"));
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
    }) {
        return Err(format!("{kind} contains unsupported characters"));
    }
    Ok(())
}

pub fn unique_capabilities(values: &[Capability]) -> Result<BTreeSet<Capability>, String> {
    let set = values.iter().copied().collect::<BTreeSet<_>>();
    if set.len() != values.len() {
        return Err("capability lists must not contain duplicates".to_string());
    }
    Ok(set)
}

pub fn object_without_id(mut value: Value, id_field: &str) -> Value {
    if let Value::Object(ref mut map) = value {
        map.insert(id_field.to_string(), Value::String(String::new()));
    }
    value
}

pub fn evidence_id(record: &EvidenceRecord) -> String {
    let value = serde_json::to_value(record).expect("evidence serialization cannot fail");
    canonical_hash(&object_without_id(value, "evidence_id"))
}

pub fn json_object(entries: impl IntoIterator<Item = (String, Value)>) -> Value {
    Value::Object(entries.into_iter().collect::<Map<_, _>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_now_uses_microsecond_wire_precision() {
        let nanosecond_datetime =
            DateTime::<Utc>::from_timestamp(1_700_000_000, 123_456_789).unwrap();

        let normalized = normalize_wire_datetime(nanosecond_datetime);

        assert_eq!(normalized.timestamp_subsec_nanos(), 123_456_000);
        assert_eq!(
            serde_json::to_string(&normalized).unwrap(),
            r#""2023-11-14T22:13:20.123456Z""#
        );
        assert_eq!(utc_now().timestamp_subsec_nanos() % 1_000, 0);
    }

    #[test]
    fn canonical_json_sorts_object_keys_recursively() {
        let left: Value = serde_json::from_str(r#"{"z":1,"a":{"y":2,"x":3}}"#).unwrap();
        let right: Value = serde_json::from_str(r#"{"a":{"x":3,"y":2},"z":1}"#).unwrap();
        assert_eq!(canonical_json(&left), canonical_json(&right));
        assert_eq!(canonical_hash(&left), canonical_hash(&right));
    }

    #[test]
    fn canonical_hash_matches_the_control_plane_utf8_golden_vector() {
        let value: Value = serde_json::from_str(r#"{"z":[1,true,null],"a":"é"}"#).unwrap();
        assert_eq!(canonical_json(&value), r#"{"a":"é","z":[1,true,null]}"#);
        assert_eq!(
            canonical_hash(&value),
            "sha256:4ab501d6475772598121dfb387250b231f7173c861662d3e1350f4d3d814ccc9"
        );
    }

    #[test]
    fn boundary_enums_use_the_python_contract_spellings() {
        assert_eq!(
            serde_json::to_string(&RunMode::Execute).unwrap(),
            r#""execute""#
        );
        assert_eq!(
            serde_json::to_string(&Capability::NativeExecution).unwrap(),
            r#""native_execution""#
        );
        assert_eq!(
            serde_json::to_string(&Capability::FilesystemWrite).unwrap(),
            r#""filesystem_write""#
        );
        assert_eq!(
            serde_json::to_string(&Capability::SandboxRestricted).unwrap(),
            r#""sandbox_restricted""#
        );
        assert_eq!(
            serde_json::to_string(&SafetyTier::Controlled).unwrap(),
            r#""controlled""#
        );
    }

    #[test]
    fn duplicate_struct_field_is_rejected() {
        let duplicate = r#"{
            "host":"127.0.0.1",
            "host":"127.0.0.2",
            "port":8080
        }"#;
        assert!(serde_json::from_str::<NetworkDestination>(duplicate).is_err());
    }

    #[test]
    fn unknown_struct_field_is_rejected() {
        let unknown = r#"{"host":"127.0.0.1","port":8080,"url":"http://example"}"#;
        assert!(serde_json::from_str::<NetworkDestination>(unknown).is_err());
    }

    #[test]
    fn execution_binding_rejects_unknown_fields_and_duplicate_constants() {
        let unknown = format!(
            r#"{{
                "schema_version":"{EXECUTION_BINDING_SCHEMA_VERSION}",
                "catalog_generation":1,
                "catalog_digest":"sha256:{}",
                "logical_behavior_id":"acme.endpoint.profile.v1",
                "logical_action_id":"acme.endpoint.profile-action.v1",
                "package_id":"acme.endpoint-profile-pack",
                "package_version":"1.2.3",
                "package_digest":"sha256:{}",
                "content_digest":"sha256:{}",
                "program_digest":"sha256:{}",
                "runner_opcode":"endpoint.discovery.system.v1",
                "opcode_contract_digest":"sha256:{}",
                "constants":{{}},
                "entry_point":"forbidden"
            }}"#,
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            "5".repeat(64),
        );
        assert!(serde_json::from_str::<ExecutionBinding>(&unknown).is_err());

        let duplicate = unknown
            .replace(",\n                \"entry_point\":\"forbidden\"", "")
            .replace(
                "\"constants\":{}",
                "\"constants\":{\"method\":\"POST\",\"method\":\"GET\"}",
            );
        assert!(serde_json::from_str::<ExecutionBinding>(&duplicate).is_err());

        let missing_constants = unknown
            .replace(",\n                \"constants\":{}", "")
            .replace(",\n                \"entry_point\":\"forbidden\"", "");
        assert!(serde_json::from_str::<ExecutionBinding>(&missing_constants).is_err());
    }

    #[test]
    fn absent_binding_fields_remain_omitted_for_legacy_documents() {
        let profile: RunnerProfile = serde_json::from_value(serde_json::json!({
            "schema_version": PROFILE_SCHEMA_VERSION,
            "profile_id": "profile.test.v1",
            "runner_id": "runner.test.v1",
            "platform": Platform::current(),
            "sandbox_root": ".",
            "allowed_actions": [],
            "control_blocked_actions": [],
            "capabilities": [],
            "max_safety_tier": "safe",
            "approval_required_at_or_above": null,
            "target_scope": {"filesystem": [], "network": []},
            "limits": {
                "timeout_ms": 1,
                "max_stdout_bytes": 1,
                "max_stderr_bytes": 1,
                "max_artifact_bytes": 1,
                "max_files": 1
            },
            "policy_digest": "sha256:legacy"
        }))
        .unwrap();
        let serialized_profile = serde_json::to_value(profile).unwrap();
        assert!(serialized_profile.get("action_bindings").is_none());

        let manifest: ExecutionManifest = serde_json::from_value(serde_json::json!({
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "request_id": "request.test.v1",
            "run_id": "run.test.v1",
            "step_id": "step.test.v1",
            "behavior_id": "behavior.test.v1",
            "action_id": "action.test.v1",
            "mode": "execute",
            "runner_id": "runner.test.v1",
            "runner_profile_id": "profile.test.v1",
            "platform": Platform::current(),
            "requested_at": "2026-08-23T12:00:00Z",
            "expires_at": "2026-08-23T12:05:00Z",
            "params": {},
            "target_scope": {"filesystem": [], "network": []},
            "required_capabilities": [],
            "safety_tier": "safe",
            "limits": {
                "timeout_ms": 1,
                "max_stdout_bytes": 1,
                "max_stderr_bytes": 1,
                "max_artifact_bytes": 1,
                "max_files": 1
            },
            "cleanup_action_id": "sandbox.cleanup.v1",
            "policy_digest": "sha256:legacy",
            "approval": null,
            "evidence_refs": [],
            "request_hash": "sha256:legacy"
        }))
        .unwrap();
        let serialized_manifest = serde_json::to_value(manifest).unwrap();
        assert!(serialized_manifest.get("execution_binding").is_none());

        let mut explicit_null = serialized_manifest;
        explicit_null
            .as_object_mut()
            .unwrap()
            .insert("execution_binding".to_string(), Value::Null);
        assert!(serde_json::from_value::<ExecutionManifest>(explicit_null).is_err());
    }
}
