use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::contract::{
    BoundedOutput, Capability, CleanupReport, ErrorRecord, ExecutionManifest, NetworkDestination,
    Platform, RunnerProfile, SafetyTier, TaskStatus,
};
use crate::process::run_process_discovery;
use crate::safety::{
    ensure_network_authorized, ensure_path_authorized, hash_file, normalize_relative,
    owned_directories, owned_file, read_file_bounded, OwnedPath, ReceiptIntent, SafeRoot,
};

const ALL_PLATFORMS: &[Platform] = &[Platform::Windows, Platform::Linux, Platform::Macos];
pub const ACTION_SDK_SCHEMA_VERSION: &str = "bluefire.runner-action-sdk.v1";
const MAX_RECURSIVE_DEPTH: usize = 16;
const MAX_RECURSIVE_ENTRIES: usize = 4_096;
const MAX_RECURSIVE_ERRORS: usize = 64;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionReadiness {
    Ready,
    Structural,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ObservationHint {
    pub source: &'static str,
    pub signal: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct DeclaredLimits {
    pub timeout_ms: bool,
    pub max_stdout_bytes: bool,
    pub max_stderr_bytes: bool,
    pub max_artifact_bytes: bool,
    pub max_files: bool,
    pub max_depth: Option<usize>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ActionProvenance {
    pub source: &'static str,
    pub reference: &'static str,
    pub license: &'static str,
}

const BLUEFIRE_PROVENANCE: ActionProvenance = ActionProvenance {
    source: "BlueFire Nexus reviewed built-in action",
    reference: "runner static registry",
    license: "MIT",
};

const TASK_LIMITS: DeclaredLimits = DeclaredLimits {
    timeout_ms: true,
    max_stdout_bytes: true,
    max_stderr_bytes: true,
    max_artifact_bytes: true,
    max_files: true,
    max_depth: None,
};

const RECURSIVE_LIMITS: DeclaredLimits = DeclaredLimits {
    max_depth: Some(MAX_RECURSIVE_DEPTH),
    ..TASK_LIMITS
};

#[derive(Debug, Clone)]
pub struct ActionDescriptor {
    pub schema_version: &'static str,
    pub action_id: &'static str,
    pub action_version: &'static str,
    pub behavior_ids: &'static [&'static str],
    pub summary: &'static str,
    pub platforms: &'static [Platform],
    pub parameter_schema: fn() -> Value,
    pub capabilities: &'static [Capability],
    pub safety_tier: SafetyTier,
    pub target_types: &'static [&'static str],
    pub observation_hints: &'static [ObservationHint],
    pub cleanup_action_id: Option<&'static str>,
    pub declared_limits: DeclaredLimits,
    pub readiness: ActionReadiness,
    pub provenance: ActionProvenance,
    pub filesystem_effect: bool,
    pub network_effect: bool,
    pub process_effect: bool,
    pub cleanup_receipt: bool,
}

impl Serialize for ActionDescriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ActionDescriptor", 19)?;
        state.serialize_field("schema_version", self.schema_version)?;
        state.serialize_field("action_id", self.action_id)?;
        state.serialize_field("action_version", self.action_version)?;
        state.serialize_field("behavior_ids", self.behavior_ids)?;
        state.serialize_field("summary", self.summary)?;
        state.serialize_field("platforms", self.platforms)?;
        state.serialize_field("parameter_schema", &(self.parameter_schema)())?;
        state.serialize_field("capabilities", self.capabilities)?;
        state.serialize_field("safety_tier", &self.safety_tier)?;
        state.serialize_field("target_types", self.target_types)?;
        state.serialize_field("observation_hints", self.observation_hints)?;
        state.serialize_field("cleanup_action_id", &self.cleanup_action_id)?;
        state.serialize_field("declared_limits", &self.declared_limits)?;
        state.serialize_field("readiness", &self.readiness)?;
        state.serialize_field("provenance", &self.provenance)?;
        state.serialize_field("filesystem_effect", &self.filesystem_effect)?;
        state.serialize_field("network_effect", &self.network_effect)?;
        state.serialize_field("process_effect", &self.process_effect)?;
        state.serialize_field("cleanup_receipt", &self.cleanup_receipt)?;
        state.end()
    }
}

pub struct ActionContext<'a> {
    pub manifest: &'a ExecutionManifest,
    pub profile: &'a RunnerProfile,
    pub root: &'a SafeRoot,
}

#[derive(Debug)]
pub struct ActionOutcome {
    pub status: TaskStatus,
    pub output: Value,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
    pub receipt_ids: Vec<String>,
    pub cleanup: Option<CleanupReport>,
    pub error: Option<ErrorRecord>,
    pub limitations: Vec<String>,
}

impl ActionOutcome {
    fn success(output: Value) -> Self {
        Self {
            status: TaskStatus::Success,
            output,
            stdout: BoundedOutput::default(),
            stderr: BoundedOutput::default(),
            receipt_ids: Vec::new(),
            cleanup: None,
            error: None,
            limitations: Vec::new(),
        }
    }

    fn with_receipt(mut self, receipt_id: String) -> Self {
        self.receipt_ids.push(receipt_id);
        self
    }
}

#[derive(Debug)]
pub struct ActionFailure {
    pub status: TaskStatus,
    pub code: &'static str,
    pub message: String,
}

impl ActionFailure {
    fn refused(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: TaskStatus::Refused,
            code,
            message: message.into(),
        }
    }

    fn blocked(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: TaskStatus::ControlBlocked,
            code,
            message: message.into(),
        }
    }

    fn failed(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: TaskStatus::Failed,
            code,
            message: message.into(),
        }
    }

    fn timed_out(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: TaskStatus::TimedOut,
            code,
            message: message.into(),
        }
    }
}

pub trait PreparedAction: Send {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure>;
}

pub trait Action: Sync {
    fn descriptor(&self) -> &'static ActionDescriptor;
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure>;
}

fn parse_params<T: DeserializeOwned>(params: Value) -> Result<T, ActionFailure> {
    serde_json::from_value(params)
        .map_err(|error| ActionFailure::refused("invalid_action_params", error.to_string()))
}

fn authorize_path(
    context: &ActionContext<'_>,
    path: &str,
    allow_root: bool,
) -> Result<String, ActionFailure> {
    let normalized = normalize_relative(path, allow_root)
        .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
    ensure_path_authorized(context.manifest, &normalized)
        .map_err(|error| ActionFailure::blocked("filesystem_scope_blocked", error))?;
    Ok(normalized)
}

fn begin_receipt(
    context: &ActionContext<'_>,
    paths: Vec<OwnedPath>,
) -> Result<ReceiptIntent, ActionFailure> {
    context
        .root
        .begin_receipt(context.manifest, context.profile, paths)
        .map_err(|error| ActionFailure::failed("receipt_persistence_failed", error))
}

fn commit_receipt(
    context: &ActionContext<'_>,
    intent: &ReceiptIntent,
) -> Result<String, ActionFailure> {
    context
        .root
        .commit_receipt(intent, context.profile)
        .map_err(|error| ActionFailure::failed("receipt_commit_failed", error))
}

fn receipt_paths(relative: String, bytes: &[u8], directories: &[String]) -> Vec<OwnedPath> {
    let mut paths = vec![owned_file(relative, bytes)];
    paths.extend(owned_directories(directories));
    paths
}

fn fixture_create_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["path", "content_template"],
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "content_template": {
                "type": "string",
                "enum": ["telemetry-seed", "harmless-document", "empty"]
            }
        }
    })
}

fn fixture_transform_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["input", "output", "transform"],
        "properties": {
            "input": {"type": "string", "minLength": 1},
            "output": {"type": "string", "minLength": 1},
            "transform": {"type": "string", "enum": ["uppercase-ascii", "reverse-bytes"]}
        }
    })
}

fn discovery_list_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["path", "max_entries"],
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "max_entries": {"type": "integer", "minimum": 1}
        }
    })
}

fn discovery_metadata_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["path"],
        "properties": {"path": {"type": "string", "minLength": 1}}
    })
}

fn collection_stage_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["inputs", "destination_directory"],
        "properties": {
            "inputs": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
            "destination_directory": {"type": "string", "minLength": 1}
        }
    })
}

fn network_loopback_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["artifact", "destination"],
        "properties": {
            "artifact": {"type": "string", "minLength": 1},
            "destination": {
                "type": "object",
                "additionalProperties": false,
                "required": ["host", "port"],
                "properties": {
                    "host": {"type": "string", "enum": ["127.0.0.1", "::1"]},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535}
                }
            }
        }
    })
}

fn export_local_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["source", "destination"],
        "properties": {
            "source": {"type": "string", "minLength": 1},
            "destination": {"type": "string", "minLength": 1}
        }
    })
}

fn restricted_persistence_marker_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["label"],
        "properties": {
            "label": {
                "type": "string",
                "enum": ["persistence_detection_canary", "control_validation"]
            }
        }
    })
}

fn cleanup_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["receipt_ids"],
        "properties": {
            "receipt_ids": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": true,
                "items": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
            }
        }
    })
}

fn system_discovery_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": {}
    })
}

fn process_discovery_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["max_entries"],
        "properties": {"max_entries": {"type": "integer", "minimum": 1}}
    })
}

fn recursive_discovery_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["path", "max_entries", "max_depth"],
        "properties": {
            "path": {"type": "string", "minLength": 1},
            "max_entries": {"type": "integer", "minimum": 1, "maximum": MAX_RECURSIVE_ENTRIES},
            "max_depth": {"type": "integer", "minimum": 1, "maximum": MAX_RECURSIVE_DEPTH}
        }
    })
}

fn archive_tar_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["inputs", "destination"],
        "properties": {
            "inputs": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": true,
                "items": {"type": "string", "minLength": 1, "maxLength": 100}
            },
            "destination": {"type": "string", "minLength": 1}
        }
    })
}

macro_rules! reviewed_descriptor {
    (
        id: $id:literal,
        behavior_ids: $behavior_ids:expr,
        summary: $summary:literal,
        schema: $schema:expr,
        capabilities: $capabilities:expr,
        tier: $tier:expr,
        targets: $targets:expr,
        hints: $hints:expr,
        cleanup: $cleanup:expr,
        limits: $limits:expr,
        effects: ($filesystem:expr, $network:expr, $process:expr),
        receipt: $receipt:expr $(,)?
    ) => {
        ActionDescriptor {
            schema_version: ACTION_SDK_SCHEMA_VERSION,
            action_id: $id,
            action_version: "1.0.0",
            behavior_ids: $behavior_ids,
            summary: $summary,
            platforms: ALL_PLATFORMS,
            parameter_schema: $schema,
            capabilities: $capabilities,
            safety_tier: $tier,
            target_types: $targets,
            observation_hints: $hints,
            cleanup_action_id: $cleanup,
            declared_limits: $limits,
            readiness: ActionReadiness::Ready,
            provenance: BLUEFIRE_PROVENANCE,
            filesystem_effect: $filesystem,
            network_effect: $network,
            process_effect: $process,
            cleanup_receipt: $receipt,
        }
    };
}

// -------------------------------------------------------------------------
// sandbox.fixture.create.v1

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum FixtureTemplate {
    TelemetrySeed,
    HarmlessDocument,
    Empty,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCreateParams {
    path: String,
    content_template: FixtureTemplate,
}

struct FixtureCreatePrepared(FixtureCreateParams);

impl PreparedAction for FixtureCreatePrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let path = authorize_path(context, &self.0.path, false)?;
        let bytes: &[u8] = match self.0.content_template {
            FixtureTemplate::TelemetrySeed => b"bluefire-fixture-v1\nkind=telemetry-seed\n",
            FixtureTemplate::HarmlessDocument => b"BlueFire Nexus disposable sandbox fixture.\n",
            FixtureTemplate::Empty => b"",
        };
        if bytes.len() as u64 > context.manifest.limits.max_artifact_bytes {
            return Err(ActionFailure::blocked(
                "artifact_limit_blocked",
                "compiled-in fixture exceeds the manifest artifact limit",
            ));
        }
        let target = context
            .root
            .prepare_new_file(&path)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let intent = begin_receipt(
            context,
            receipt_paths(target.relative.clone(), bytes, &target.created_directories),
        )?;
        context
            .root
            .write_new(&target, bytes, &intent)
            .map_err(|error| ActionFailure::failed("fixture_write_failed", error))?;
        let receipt_id = commit_receipt(context, &intent)?;
        Ok(ActionOutcome::success(json!({
            "artifact": target.relative,
            "sha256": crate::contract::sha256_hex(bytes),
            "size": bytes.len(),
            "template": match self.0.content_template {
                FixtureTemplate::TelemetrySeed => "telemetry-seed",
                FixtureTemplate::HarmlessDocument => "harmless-document",
                FixtureTemplate::Empty => "empty",
            }
        }))
        .with_receipt(receipt_id))
    }
}

struct FixtureCreateAction;
static FIXTURE_CREATE_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.fixture.create.v1",
        behavior_ids: &["sandbox.fixture.create.v1"],
        summary: "Create one deterministic fixture inside the runner-owned sandbox.",
        schema: fixture_create_schema,
        capabilities: &[Capability::FilesystemWrite],
        tier: SafetyTier::Safe,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "file_create" }],
        cleanup: Some("sandbox.cleanup.v1"),
        limits: TASK_LIMITS,
        effects: (true, false, false),
        receipt: true,
    }
};
impl Action for FixtureCreateAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &FIXTURE_CREATE_DESCRIPTOR
    }
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(FixtureCreatePrepared(parse_params(params)?)))
    }
}

// -------------------------------------------------------------------------
// sandbox.fixture.transform.v1

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TransformKind {
    UppercaseAscii,
    ReverseBytes,
}

impl TransformKind {
    fn as_arg(&self) -> &'static str {
        match self {
            Self::UppercaseAscii => "uppercase-ascii",
            Self::ReverseBytes => "reverse-bytes",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureTransformParams {
    input: String,
    output: String,
    transform: TransformKind,
}

struct FixtureTransformPrepared(FixtureTransformParams);

impl PreparedAction for FixtureTransformPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let started = Instant::now();
        let deadline = Duration::from_millis(context.manifest.limits.timeout_ms);
        let input = authorize_path(context, &self.0.input, false)?;
        let output = authorize_path(context, &self.0.output, false)?;
        if input == output {
            return Err(ActionFailure::blocked(
                "path_rejected",
                "transform input and output must be different",
            ));
        }
        let input_path = context
            .root
            .resolve_existing(&input)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let mut bytes = read_file_bounded(&input_path, context.manifest.limits.max_artifact_bytes)
            .map_err(|error| ActionFailure::blocked("artifact_limit_blocked", error))?;
        match self.0.transform {
            TransformKind::UppercaseAscii => bytes.make_ascii_uppercase(),
            TransformKind::ReverseBytes => bytes.reverse(),
        }
        if started.elapsed() >= deadline {
            return Err(ActionFailure {
                status: TaskStatus::TimedOut,
                code: "transform_timeout",
                message: "the bounded in-process transform exceeded its deadline".to_string(),
            });
        }
        let target = context
            .root
            .prepare_new_file(&output)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let intent = begin_receipt(
            context,
            receipt_paths(target.relative.clone(), &bytes, &target.created_directories),
        )?;
        context
            .root
            .write_new(&target, &bytes, &intent)
            .map_err(|error| ActionFailure::failed("transform_write_failed", error))?;
        let receipt_id = commit_receipt(context, &intent)?;
        let timed_out = started.elapsed() >= deadline;
        let status = if timed_out {
            TaskStatus::TimedOut
        } else {
            TaskStatus::Success
        };
        Ok(ActionOutcome {
            status,
            output: json!({
                "artifact": output,
                "sha256": crate::contract::sha256_hex(&bytes),
                "size": bytes.len(),
                "transform": self.0.transform.as_arg(),
                "implementation": "in_process_reviewed_transform",
            }),
            stdout: BoundedOutput::default(),
            stderr: BoundedOutput::default(),
            receipt_ids: vec![receipt_id],
            cleanup: None,
            error: timed_out.then(|| ErrorRecord {
                code: "transform_timeout".to_string(),
                message: "the completed bounded transform exceeded its deadline".to_string(),
            }),
            limitations: vec![
                "The transform is compiled into the runner and exposes no process subcommand."
                    .to_string(),
            ],
        })
    }
}

struct FixtureTransformAction;
static FIXTURE_TRANSFORM_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.fixture.transform.v1",
        behavior_ids: &["sandbox.fixture.transform.v1"],
        summary: "Apply one compiled in-process transform to a bounded sandbox file.",
        schema: fixture_transform_schema,
        capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite],
        tier: SafetyTier::Safe,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "file_create" }],
        cleanup: Some("sandbox.cleanup.v1"),
        limits: TASK_LIMITS,
        effects: (true, false, false),
        receipt: true,
    }
};
impl Action for FixtureTransformAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &FIXTURE_TRANSFORM_DESCRIPTOR
    }
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(FixtureTransformPrepared(parse_params(params)?)))
    }
}

// -------------------------------------------------------------------------
// sandbox.discovery.list.v1 and sandbox.discovery.metadata.v1

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryListParams {
    path: String,
    max_entries: usize,
}

struct DiscoveryListPrepared(DiscoveryListParams);

impl PreparedAction for DiscoveryListPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let path = authorize_path(context, &self.0.path, true)?;
        if self.0.max_entries == 0 || self.0.max_entries > context.manifest.limits.max_files {
            return Err(ActionFailure::blocked(
                "file_count_limit_blocked",
                "max_entries is zero or exceeds the manifest file limit",
            ));
        }
        let directory = context
            .root
            .resolve_existing(&path)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        if !fs::metadata(&directory)
            .map_err(|error| ActionFailure::failed("discovery_failed", error.to_string()))?
            .is_dir()
        {
            return Err(ActionFailure::refused(
                "invalid_action_params",
                "discovery list path is not a directory",
            ));
        }
        let mut entries = Vec::new();
        let iterator = fs::read_dir(&directory)
            .map_err(|error| ActionFailure::failed("discovery_failed", error.to_string()))?;
        for entry in iterator {
            if entries.len() == self.0.max_entries {
                break;
            }
            let entry = entry
                .map_err(|error| ActionFailure::failed("discovery_failed", error.to_string()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == ".bluefire" {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| ActionFailure::failed("discovery_failed", error.to_string()))?;
            let kind = if metadata.file_type().is_symlink() {
                "link-blocked"
            } else if metadata.is_file() {
                "file"
            } else if metadata.is_dir() {
                "directory"
            } else {
                "other"
            };
            entries.push(json!({"name": name, "kind": kind, "size": metadata.len()}));
        }
        entries.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
        Ok(ActionOutcome::success(
            json!({"path": path, "entries": entries}),
        ))
    }
}

struct DiscoveryListAction;
static DISCOVERY_LIST_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.discovery.list.v1",
        behavior_ids: &["sandbox.discovery.list.v1"],
        summary: "List one sandbox directory without recursion.",
        schema: discovery_list_schema,
        capabilities: &[Capability::FilesystemRead],
        tier: SafetyTier::Safe,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "directory_enumeration" }],
        cleanup: None,
        limits: TASK_LIMITS,
        effects: (false, false, false),
        receipt: false,
    }
};
impl Action for DiscoveryListAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &DISCOVERY_LIST_DESCRIPTOR
    }
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(DiscoveryListPrepared(parse_params(params)?)))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryMetadataParams {
    path: String,
}

struct DiscoveryMetadataPrepared(DiscoveryMetadataParams);

impl PreparedAction for DiscoveryMetadataPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let path = authorize_path(context, &self.0.path, true)?;
        let absolute = context
            .root
            .resolve_existing(&path)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let metadata = fs::metadata(&absolute)
            .map_err(|error| ActionFailure::failed("metadata_failed", error.to_string()))?;
        let mut limitations = Vec::new();
        let digest = if metadata.is_file()
            && metadata.len() <= context.manifest.limits.max_artifact_bytes
        {
            Some(
                hash_file(&absolute, context.manifest.limits.max_artifact_bytes)
                    .map_err(|error| ActionFailure::failed("metadata_hash_failed", error))?,
            )
        } else {
            if metadata.is_file() {
                limitations.push(
                    "File hash omitted because the file exceeds the artifact limit.".to_string(),
                );
            }
            None
        };
        let mut outcome = ActionOutcome::success(json!({
            "path": path,
            "kind": if metadata.is_file() { "file" } else if metadata.is_dir() { "directory" } else { "other" },
            "size": metadata.len(),
            "readonly": metadata.permissions().readonly(),
            "sha256": digest,
        }));
        outcome.limitations = limitations;
        Ok(outcome)
    }
}

struct DiscoveryMetadataAction;
static DISCOVERY_METADATA_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.discovery.metadata.v1",
        behavior_ids: &["sandbox.discovery.metadata.v1"],
        summary: "Inspect metadata and optionally hash one bounded sandbox file.",
        schema: discovery_metadata_schema,
        capabilities: &[Capability::FilesystemRead],
        tier: SafetyTier::Safe,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "file_read" }],
        cleanup: None,
        limits: TASK_LIMITS,
        effects: (false, false, false),
        receipt: false,
    }
};
impl Action for DiscoveryMetadataAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &DISCOVERY_METADATA_DESCRIPTOR
    }
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(DiscoveryMetadataPrepared(parse_params(params)?)))
    }
}

// -------------------------------------------------------------------------
// endpoint.discovery.system.v1

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemDiscoveryParams {}

struct SystemDiscoveryPrepared;

impl PreparedAction for SystemDiscoveryPrepared {
    fn execute(
        self: Box<Self>,
        _context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let byte_order = if cfg!(target_endian = "little") {
            "little"
        } else {
            "big"
        };
        Ok(ActionOutcome::success(json!({
            "operating_system": std::env::consts::OS,
            "architecture": std::env::consts::ARCH,
            "family": std::env::consts::FAMILY,
            "logical_processors": std::thread::available_parallelism().map(|value| value.get()).unwrap_or(1),
            "pointer_width_bits": usize::BITS,
            "byte_order": byte_order,
        })))
    }
}

struct SystemDiscoveryAction;
static SYSTEM_DISCOVERY_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "endpoint.discovery.system.v1",
        behavior_ids: &["endpoint.discovery.system.v1"],
        summary: "Report bounded operating-system and architecture facts from compiled Rust APIs.",
        schema: system_discovery_schema,
        capabilities: &[Capability::SystemDiscovery],
        tier: SafetyTier::Safe,
        targets: &["endpoint", "sandbox", "container"],
        hints: &[ObservationHint { source: "runner", signal: "system_discovery" }],
        cleanup: None,
        limits: TASK_LIMITS,
        effects: (false, false, false),
        receipt: false,
    }
};
impl Action for SystemDiscoveryAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &SYSTEM_DISCOVERY_DESCRIPTOR
    }

    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        let _: SystemDiscoveryParams = parse_params(params)?;
        Ok(Box::new(SystemDiscoveryPrepared))
    }
}

// -------------------------------------------------------------------------
// endpoint.discovery.processes.v1

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessDiscoveryParams {
    max_entries: usize,
}

struct ProcessDiscoveryPrepared(ProcessDiscoveryParams);

fn parse_tasklist_csv(line: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '"' if quoted && characters.peek() == Some(&'"') => {
                current.push('"');
                characters.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                values.push(current);
                current = String::new();
            }
            _ => current.push(character),
        }
    }
    values.push(current);
    values
}

fn process_record(line: &str, format: &str) -> Value {
    if format == "tasklist-csv" {
        let values = parse_tasklist_csv(line);
        return json!({
            "name": values.first().cloned().unwrap_or_default(),
            "pid": values.get(1).cloned().unwrap_or_default(),
        });
    }
    let mut values = line.split_whitespace();
    json!({
        "pid": values.next().unwrap_or_default(),
        "parent_pid": values.next().unwrap_or_default(),
        "name": values.collect::<Vec<_>>().join(" "),
    })
}

impl PreparedAction for ProcessDiscoveryPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        if self.0.max_entries == 0 || self.0.max_entries > context.manifest.limits.max_files {
            return Err(ActionFailure::blocked(
                "process_count_limit_blocked",
                "max_entries is zero or exceeds the manifest file/item limit",
            ));
        }
        let process = run_process_discovery(&context.manifest.limits, self.0.max_entries)
            .map_err(|error| ActionFailure::failed("process_discovery_failed", error))?;
        let mut lines = process
            .stdout
            .text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        let records = lines
            .by_ref()
            .take(self.0.max_entries)
            .map(|line| process_record(line, process.output_format))
            .collect::<Vec<_>>();
        let entry_limit_reached = lines.next().is_some();
        let status = if process.timed_out {
            TaskStatus::TimedOut
        } else if process.exit_code != Some(0) {
            TaskStatus::Failed
        } else if process.stdout.truncated || entry_limit_reached {
            TaskStatus::Partial
        } else {
            TaskStatus::Success
        };
        Ok(ActionOutcome {
            status,
            output: json!({
                "format": process.output_format,
                "entries": records,
                "truncated": process.stdout.truncated || entry_limit_reached,
                "exit_code": process.exit_code,
            }),
            stdout: process.stdout,
            stderr: process.stderr,
            receipt_ids: Vec::new(),
            cleanup: None,
            error: match status {
                TaskStatus::Success | TaskStatus::Partial => None,
                TaskStatus::TimedOut => Some(ErrorRecord {
                    code: "process_discovery_timeout".to_string(),
                    message: "the reviewed process inventory exceeded its deadline".to_string(),
                }),
                _ => Some(ErrorRecord {
                    code: "process_discovery_exit".to_string(),
                    message: format!("the reviewed process inventory exited with {:?}", process.exit_code),
                }),
            },
            limitations: vec![
                "The executable and argument vector are selected by the compiled runner for the current platform."
                    .to_string(),
            ],
        })
    }
}

struct ProcessDiscoveryAction;
static PROCESS_DISCOVERY_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "endpoint.discovery.processes.v1",
        behavior_ids: &["endpoint.discovery.processes.v1"],
        summary: "Enumerate bounded process identity fields through one compiled platform adapter.",
        schema: process_discovery_schema,
        capabilities: &[Capability::ProcessDiscovery, Capability::ProcessSpawn],
        tier: SafetyTier::Safe,
        targets: &["endpoint", "sandbox", "container"],
        hints: &[ObservationHint { source: "process", signal: "process_inventory" }],
        cleanup: None,
        limits: TASK_LIMITS,
        effects: (false, false, true),
        receipt: false,
    }
};
impl Action for ProcessDiscoveryAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &PROCESS_DISCOVERY_DESCRIPTOR
    }

    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(ProcessDiscoveryPrepared(parse_params(params)?)))
    }
}

// -------------------------------------------------------------------------
// sandbox.discovery.recursive.v1

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecursiveDiscoveryParams {
    path: String,
    max_entries: usize,
    max_depth: usize,
}

struct RecursiveDiscoveryPrepared(RecursiveDiscoveryParams);

fn record_recursive_error(errors: &mut Vec<String>, suppressed: &mut usize, error: String) {
    if errors.len() < MAX_RECURSIVE_ERRORS {
        errors.push(error);
    } else {
        *suppressed = suppressed.saturating_add(1);
    }
}

impl PreparedAction for RecursiveDiscoveryPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let root_relative = authorize_path(context, &self.0.path, true)?;
        if self.0.max_entries == 0
            || self.0.max_entries > context.manifest.limits.max_files
            || self.0.max_entries > MAX_RECURSIVE_ENTRIES
        {
            return Err(ActionFailure::blocked(
                "file_count_limit_blocked",
                "max_entries is zero or exceeds a manifest or runner limit",
            ));
        }
        if self.0.max_depth == 0 || self.0.max_depth > MAX_RECURSIVE_DEPTH {
            return Err(ActionFailure::blocked(
                "directory_depth_limit_blocked",
                "max_depth is zero or exceeds the runner recursion limit",
            ));
        }
        let root = context
            .root
            .resolve_existing(&root_relative)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        if !fs::metadata(&root)
            .map_err(|error| ActionFailure::failed("discovery_failed", error.to_string()))?
            .is_dir()
        {
            return Err(ActionFailure::refused(
                "invalid_action_params",
                "recursive discovery path is not a directory",
            ));
        }

        let started = Instant::now();
        let deadline = Duration::from_millis(context.manifest.limits.timeout_ms);
        let mut queue = VecDeque::from([(root_relative.clone(), 0_usize)]);
        let mut records = Vec::new();
        let mut errors = Vec::new();
        let mut suppressed_errors = 0_usize;
        let mut skipped_names = 0_usize;
        let mut truncated = false;
        let mut timed_out = false;

        'walk: while let Some((directory_relative, depth)) = queue.pop_front() {
            if started.elapsed() >= deadline {
                timed_out = true;
                break;
            }
            let directory = match context.root.resolve_existing(&directory_relative) {
                Ok(path) => path,
                Err(error) => {
                    record_recursive_error(
                        &mut errors,
                        &mut suppressed_errors,
                        format!("{directory_relative}: {error}"),
                    );
                    continue;
                }
            };
            let iterator = match fs::read_dir(directory) {
                Ok(iterator) => iterator,
                Err(error) => {
                    record_recursive_error(
                        &mut errors,
                        &mut suppressed_errors,
                        format!("{directory_relative}: {error}"),
                    );
                    continue;
                }
            };
            if records.len() == self.0.max_entries {
                truncated = true;
                break;
            }
            let retained_limit = self
                .0
                .max_entries
                .saturating_sub(records.len())
                .saturating_add(1);
            let mut entries = BTreeMap::new();
            for entry in iterator {
                if started.elapsed() >= deadline {
                    timed_out = true;
                    break 'walk;
                }
                match entry {
                    Ok(entry) => {
                        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                            skipped_names = skipped_names.saturating_add(1);
                            continue;
                        };
                        if name.eq_ignore_ascii_case(".bluefire") {
                            continue;
                        }
                        entries.insert(name, entry);
                        if entries.len() > retained_limit {
                            entries.pop_last();
                            truncated = true;
                        }
                    }
                    Err(error) => record_recursive_error(
                        &mut errors,
                        &mut suppressed_errors,
                        format!("{directory_relative}: {error}"),
                    ),
                }
            }
            for (name, entry) in entries {
                if records.len() == self.0.max_entries {
                    truncated = true;
                    break 'walk;
                }
                let child_raw = if directory_relative == "." {
                    name
                } else {
                    format!("{directory_relative}/{name}")
                };
                let child_relative = match normalize_relative(&child_raw, false) {
                    Ok(value) => value,
                    Err(_) => {
                        skipped_names = skipped_names.saturating_add(1);
                        continue;
                    }
                };
                let metadata = match fs::symlink_metadata(entry.path()) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        record_recursive_error(
                            &mut errors,
                            &mut suppressed_errors,
                            format!("{child_relative}: {error}"),
                        );
                        continue;
                    }
                };
                let child_depth = depth.saturating_add(1);
                let kind = if metadata.file_type().is_symlink() {
                    "link_blocked"
                } else if metadata.is_file() {
                    "file"
                } else if metadata.is_dir() {
                    "directory"
                } else {
                    "other"
                };
                records.push(json!({
                    "path": child_relative,
                    "kind": kind,
                    "size": metadata.len(),
                    "depth": child_depth,
                }));
                if metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && child_depth < self.0.max_depth
                {
                    queue.push_back((child_relative, child_depth));
                }
            }
        }

        let status = if timed_out && records.is_empty() {
            TaskStatus::TimedOut
        } else if timed_out || !errors.is_empty() || suppressed_errors != 0 {
            TaskStatus::Partial
        } else {
            TaskStatus::Success
        };
        Ok(ActionOutcome {
            status,
            output: json!({
                "path": root_relative,
                "entries": records,
                "truncated": truncated,
                "skipped_unsupported_names": skipped_names,
                "errors": errors,
                "suppressed_errors": suppressed_errors,
            }),
            stdout: BoundedOutput::default(),
            stderr: BoundedOutput::default(),
            receipt_ids: Vec::new(),
            cleanup: None,
            error: (status != TaskStatus::Success).then(|| ErrorRecord {
                code: if timed_out {
                    "recursive_discovery_timeout"
                } else {
                    "recursive_discovery_partial"
                }
                .to_string(),
                message: "recursive discovery returned a bounded partial result".to_string(),
            }),
            limitations: Vec::new(),
        })
    }
}

struct RecursiveDiscoveryAction;
static RECURSIVE_DISCOVERY_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.discovery.recursive.v1",
        behavior_ids: &["sandbox.discovery.recursive.v1"],
        summary: "Recursively enumerate one authorized sandbox subtree with explicit count and depth bounds.",
        schema: recursive_discovery_schema,
        capabilities: &[Capability::FilesystemRead],
        tier: SafetyTier::Safe,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "recursive_directory_enumeration" }],
        cleanup: None,
        limits: RECURSIVE_LIMITS,
        effects: (false, false, false),
        receipt: false,
    }
};
impl Action for RecursiveDiscoveryAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &RECURSIVE_DISCOVERY_DESCRIPTOR
    }

    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(RecursiveDiscoveryPrepared(parse_params(params)?)))
    }
}

// -------------------------------------------------------------------------
// sandbox.archive.tar.v1

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveTarParams {
    inputs: Vec<String>,
    destination: String,
}

struct ArchiveTarPrepared(ArchiveTarParams);

fn write_tar_octal(field: &mut [u8], value: u64) -> Result<(), String> {
    let width = field
        .len()
        .checked_sub(1)
        .ok_or_else(|| "tar numeric field has no terminator space".to_string())?;
    let encoded = format!("{value:0width$o}", width = width);
    if encoded.len() > width {
        return Err("tar numeric field exceeds its deterministic width".to_string());
    }
    field[..width].copy_from_slice(encoded.as_bytes());
    field[width] = 0;
    Ok(())
}

fn tar_header(name: &str, size: usize) -> Result<[u8; 512], String> {
    if name.len() > 100 {
        return Err("archive input path exceeds the deterministic ustar name limit".to_string());
    }
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_tar_octal(&mut header[100..108], 0o644)?;
    write_tar_octal(&mut header[108..116], 0)?;
    write_tar_octal(&mut header[116..124], 0)?;
    write_tar_octal(&mut header[124..136], size as u64)?;
    write_tar_octal(&mut header[136..148], 0)?;
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[265..273].copy_from_slice(b"bluefire");
    header[297..305].copy_from_slice(b"bluefire");
    let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
    let encoded = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(encoded.as_bytes());
    Ok(header)
}

fn build_deterministic_tar(files: &[(String, Vec<u8>)], max_bytes: u64) -> Result<Vec<u8>, String> {
    let mut archive = Vec::new();
    for (name, bytes) in files {
        let padded = bytes.len().div_ceil(512).saturating_mul(512);
        let projected = archive
            .len()
            .saturating_add(512)
            .saturating_add(padded)
            .saturating_add(1_024);
        if projected as u64 > max_bytes {
            return Err("deterministic archive exceeds the artifact byte limit".to_string());
        }
        archive.extend_from_slice(&tar_header(name, bytes.len())?);
        archive.extend_from_slice(bytes);
        archive.resize(archive.len() + padded.saturating_sub(bytes.len()), 0);
    }
    archive.resize(archive.len() + 1_024, 0);
    Ok(archive)
}

impl PreparedAction for ArchiveTarPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        if self.0.inputs.is_empty() || self.0.inputs.len() > context.manifest.limits.max_files {
            return Err(ActionFailure::blocked(
                "file_count_limit_blocked",
                "archive inputs are empty or exceed the manifest file limit",
            ));
        }
        let destination = authorize_path(context, &self.0.destination, false)?;
        let mut normalized = Vec::new();
        let mut unique = BTreeSet::new();
        for input in &self.0.inputs {
            let input = authorize_path(context, input, false)?;
            if input == destination {
                return Err(ActionFailure::blocked(
                    "path_rejected",
                    "archive destination cannot also be an input",
                ));
            }
            if !unique.insert(input.clone()) {
                return Err(ActionFailure::refused(
                    "invalid_action_params",
                    "archive inputs must not contain duplicates",
                ));
            }
            normalized.push(input);
        }
        normalized.sort();

        let mut files = Vec::new();
        let mut input_total = 0_u64;
        for input in normalized {
            let path = context
                .root
                .resolve_existing(&input)
                .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
            let remaining = context
                .manifest
                .limits
                .max_artifact_bytes
                .saturating_sub(input_total);
            let bytes = read_file_bounded(&path, remaining)
                .map_err(|error| ActionFailure::blocked("artifact_limit_blocked", error))?;
            input_total = input_total.saturating_add(bytes.len() as u64);
            files.push((input, bytes));
        }
        let archive = build_deterministic_tar(&files, context.manifest.limits.max_artifact_bytes)
            .map_err(|error| ActionFailure::blocked("artifact_limit_blocked", error))?;
        let target = context
            .root
            .prepare_new_file(&destination)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let intent = begin_receipt(
            context,
            receipt_paths(
                target.relative.clone(),
                &archive,
                &target.created_directories,
            ),
        )?;
        context
            .root
            .write_new(&target, &archive, &intent)
            .map_err(|error| ActionFailure::failed("archive_write_failed", error))?;
        let receipt_id = commit_receipt(context, &intent)?;
        Ok(ActionOutcome::success(json!({
            "artifact": target.relative,
            "format": "ustar",
            "entry_count": files.len(),
            "input_bytes": input_total,
            "size": archive.len(),
            "sha256": crate::contract::sha256_hex(&archive),
        }))
        .with_receipt(receipt_id))
    }
}

struct ArchiveTarAction;
static ARCHIVE_TAR_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.archive.tar.v1",
        behavior_ids: &["sandbox.archive.tar.v1"],
        summary: "Create a deterministic uncompressed ustar archive from bounded sandbox files.",
        schema: archive_tar_schema,
        capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite],
        tier: SafetyTier::Controlled,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "archive_create" }],
        cleanup: Some("sandbox.cleanup.v1"),
        limits: TASK_LIMITS,
        effects: (true, false, false),
        receipt: true,
    }
};
impl Action for ArchiveTarAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &ARCHIVE_TAR_DESCRIPTOR
    }

    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(ArchiveTarPrepared(parse_params(params)?)))
    }
}

// -------------------------------------------------------------------------
// sandbox.collection.stage.v1

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectionStageParams {
    inputs: Vec<String>,
    destination_directory: String,
}

struct CollectionStagePrepared(CollectionStageParams);

impl PreparedAction for CollectionStagePrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        if self.0.inputs.is_empty() || self.0.inputs.len() > context.manifest.limits.max_files {
            return Err(ActionFailure::blocked(
                "file_count_limit_blocked",
                "collection inputs are empty or exceed the manifest file limit",
            ));
        }
        let destination = authorize_path(context, &self.0.destination_directory, false)?;
        let probe_path = format!("{destination}/.bluefire-stage-probe");
        let probe = context
            .root
            .prepare_new_file(&probe_path)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let created_directories = probe.created_directories;

        let mut plans = Vec::new();
        let mut errors = Vec::new();
        let mut planned_bytes = 0_u64;
        for (index, input) in self.0.inputs.iter().enumerate() {
            let normalized = match authorize_path(context, input, false) {
                Ok(path) => path,
                Err(error) => {
                    errors.push(format!("{input}: {}", error.message));
                    continue;
                }
            };
            let source = match context.root.resolve_existing(&normalized) {
                Ok(path) => path,
                Err(error) => {
                    errors.push(format!("{normalized}: {error}"));
                    continue;
                }
            };
            let remaining = context
                .manifest
                .limits
                .max_artifact_bytes
                .saturating_sub(planned_bytes);
            let bytes = match read_file_bounded(&source, remaining) {
                Ok(bytes) => bytes,
                Err(error) => {
                    errors.push(format!("{normalized}: {error}"));
                    continue;
                }
            };
            let name = normalized.rsplit('/').next().unwrap_or("artifact");
            let staged_relative = format!("{destination}/{index:03}-{name}");
            let target = match context.root.prepare_new_file(&staged_relative) {
                Ok(target) => target,
                Err(error) => {
                    errors.push(format!("{normalized}: {error}"));
                    continue;
                }
            };
            planned_bytes = planned_bytes.saturating_add(bytes.len() as u64);
            plans.push((normalized, target, bytes));
        }
        let mut owned = plans
            .iter()
            .map(|(_, target, bytes)| owned_file(target.relative.clone(), bytes))
            .collect::<Vec<_>>();
        owned.extend(owned_directories(&created_directories));
        let intent = if owned.is_empty() {
            None
        } else {
            Some(begin_receipt(context, owned)?)
        };

        let mut staged = Vec::new();
        let mut total_bytes = 0_u64;
        for (normalized, target, bytes) in plans {
            let Some(intent) = intent.as_ref() else {
                return Err(ActionFailure::failed(
                    "receipt_persistence_failed",
                    "collection mutation has no durable receipt intent",
                ));
            };
            if let Err(error) = context.root.write_new(&target, &bytes, intent) {
                errors.push(format!("{normalized}: {error}"));
                continue;
            }
            total_bytes = total_bytes.saturating_add(bytes.len() as u64);
            staged.push(json!({
                "source": normalized,
                "artifact": target.relative,
                "sha256": crate::contract::sha256_hex(&bytes),
                "size": bytes.len(),
            }));
        }
        let receipt_id = match intent.as_ref() {
            Some(intent) => Some(commit_receipt(context, intent)?),
            None => None,
        };
        let status = if errors.is_empty() {
            TaskStatus::Success
        } else if !staged.is_empty() || !created_directories.is_empty() {
            TaskStatus::Partial
        } else {
            TaskStatus::Failed
        };
        Ok(ActionOutcome {
            status,
            output: json!({"staged": staged, "errors": errors, "total_bytes": total_bytes}),
            stdout: BoundedOutput::default(),
            stderr: BoundedOutput::default(),
            receipt_ids: receipt_id.into_iter().collect(),
            cleanup: None,
            error: if status == TaskStatus::Success {
                None
            } else {
                Some(ErrorRecord {
                    code: "collection_incomplete".to_string(),
                    message: "one or more requested artifacts could not be staged".to_string(),
                })
            },
            limitations: Vec::new(),
        })
    }
}

struct CollectionStageAction;
static COLLECTION_STAGE_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.collection.stage.v1",
        behavior_ids: &["sandbox.collection.stage.v1"],
        summary: "Copy a bounded set of sandbox files into a deterministic staging directory.",
        schema: collection_stage_schema,
        capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite],
        tier: SafetyTier::Controlled,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "file_create" }],
        cleanup: Some("sandbox.cleanup.v1"),
        limits: TASK_LIMITS,
        effects: (true, false, false),
        receipt: true,
    }
};
impl Action for CollectionStageAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &COLLECTION_STAGE_DESCRIPTOR
    }
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(CollectionStagePrepared(parse_params(params)?)))
    }
}

// -------------------------------------------------------------------------
// sandbox.network.loopback.v1

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkLoopbackParams {
    artifact: String,
    destination: NetworkDestination,
}

struct NetworkLoopbackPrepared(NetworkLoopbackParams);

const LOOPBACK_RECEIVER_CHALLENGE_SCHEMA_VERSION: &str = "bluefire.loopback-receiver-challenge.v1";
const LOOPBACK_RECEIVER_REQUEST_SCHEMA_VERSION: &str = "bluefire.loopback-receiver-request.v1";
const LOOPBACK_RECEIVER_RESULT_SCHEMA_VERSION: &str = "bluefire.loopback-receiver-result.v2";
const LOOPBACK_RECEIVER_CHALLENGE_PATH: &str = "/bluefire/v1/challenge";
const LOOPBACK_RECEIVER_ARTIFACT_PATH: &str = "/bluefire/v1/artifact";
const LOOPBACK_RECEIVER_TASK_ID_ENV: &str = "BLUEFIRE_RECEIVER_TASK_ID";
const LOOPBACK_RECEIVER_TASK_KEY_ENV: &str = "BLUEFIRE_RECEIVER_TASK_KEY";
const LOOPBACK_RECEIVER_CHALLENGE_DOMAIN: &[u8] = b"bluefire.loopback-receiver.challenge.v1\0";
const LOOPBACK_RECEIVER_REQUEST_DOMAIN: &[u8] = b"bluefire.loopback-receiver.request.v1\0";
const LOOPBACK_RECEIVER_RESPONSE_DOMAIN: &[u8] = b"bluefire.loopback-receiver.response.v1\0";
const LOOPBACK_RECEIVER_PROTOCOL_LIMIT: usize = 32 * 1024;

type HmacSha256 = Hmac<Sha256>;

struct LoopbackReceiverTaskAuthentication {
    task_id: String,
    task_key: [u8; 32],
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoopbackReceiverChallenge {
    schema_version: String,
    task_id: String,
    session_id: String,
    nonce: String,
    host: String,
    port: u16,
    sha256: String,
    content_length: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoopbackReceiverResult {
    schema_version: String,
    accepted: bool,
    task_id: String,
    session_id: String,
    bytes_received: u64,
    sha256: String,
    stored: bool,
}

struct StrictLoopbackResponse {
    status_code: u16,
    body: Vec<u8>,
    authentication: String,
}

fn valid_receiver_task_id(value: &str) -> bool {
    (1..=200).contains(&value.len())
        && value.is_ascii()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

fn valid_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn receiver_task_authentication() -> Result<LoopbackReceiverTaskAuthentication, ActionFailure> {
    let task_id = env::var_os(LOOPBACK_RECEIVER_TASK_ID_ENV);
    let task_key = env::var_os(LOOPBACK_RECEIVER_TASK_KEY_ENV);
    // These are one-task capabilities. Remove them as soon as this process has
    // copied and validated both values so child processes cannot inherit them.
    env::remove_var(LOOPBACK_RECEIVER_TASK_ID_ENV);
    env::remove_var(LOOPBACK_RECEIVER_TASK_KEY_ENV);
    let (task_id, task_key) = match (task_id, task_key) {
        (Some(task_id), Some(task_key)) => match (task_id.into_string(), task_key.into_string()) {
            (Ok(task_id), Ok(task_key)) => (task_id, task_key),
            _ => {
                return Err(ActionFailure::blocked(
                    "receiver_authentication_unavailable",
                    "managed receiver authentication is unavailable",
                ))
            }
        },
        _ => {
            return Err(ActionFailure::blocked(
                "receiver_authentication_unavailable",
                "managed receiver authentication is unavailable",
            ))
        }
    };
    if !valid_receiver_task_id(&task_id) || !valid_lower_hex_32(&task_key) {
        return Err(ActionFailure::blocked(
            "receiver_authentication_unavailable",
            "managed receiver authentication is unavailable",
        ));
    }
    let decoded = hex::decode(task_key).map_err(|_| {
        ActionFailure::blocked(
            "receiver_authentication_unavailable",
            "managed receiver authentication is unavailable",
        )
    })?;
    let task_key: [u8; 32] = decoded.try_into().map_err(|_| {
        ActionFailure::blocked(
            "receiver_authentication_unavailable",
            "managed receiver authentication is unavailable",
        )
    })?;
    Ok(LoopbackReceiverTaskAuthentication { task_id, task_key })
}

fn receiver_authentication_value(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts a 32-byte key");
    mac.update(domain);
    mac.update(payload);
    format!("sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

fn verify_receiver_authentication(
    key: &[u8; 32],
    domain: &[u8],
    payloads: &[&[u8]],
    authentication: &str,
) -> bool {
    let Some(encoded) = authentication.strip_prefix("sha256:") else {
        return false;
    };
    if !valid_lower_hex_32(encoded) {
        return false;
    }
    let Ok(candidate) = hex::decode(encoded) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts a 32-byte key");
    mac.update(domain);
    for payload in payloads {
        mac.update(payload);
    }
    mac.verify_slice(&candidate).is_ok()
}

fn remaining_deadline(started: Instant, budget: Duration) -> Result<Duration, String> {
    budget
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "the network action exceeded its monotonic deadline".to_string())
}

fn write_socket_with_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    started: Instant,
    budget: Duration,
) -> Result<(), ActionFailure> {
    while !bytes.is_empty() {
        let remaining = remaining_deadline(started, budget)
            .map_err(|error| ActionFailure::timed_out("loopback_timeout", error))?;
        stream.set_write_timeout(Some(remaining)).map_err(|error| {
            ActionFailure::failed("loopback_timeout_setup_failed", error.to_string())
        })?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(ActionFailure::failed(
                    "loopback_write_failed",
                    "loopback socket stopped accepting bytes",
                ));
            }
            Ok(count) => bytes = &bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ActionFailure::timed_out(
                    "loopback_timeout",
                    "the loopback write exceeded its monotonic deadline",
                ));
            }
            Err(error) => {
                return Err(ActionFailure::failed(
                    "loopback_write_failed",
                    error.to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn read_socket_bounded(
    stream: &mut TcpStream,
    limit: usize,
    started: Instant,
    budget: Duration,
) -> Result<(Vec<u8>, BoundedOutput, bool), String> {
    let mut retained = Vec::with_capacity(limit.min(16 * 1024));
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    let mut timed_out = false;
    loop {
        let remaining = match remaining_deadline(started, budget) {
            Ok(remaining) => remaining,
            Err(_) => {
                timed_out = true;
                break;
            }
        };
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|error| format!("cannot update loopback read deadline: {error}"))?;
        let retained_remaining = limit.saturating_sub(retained.len());
        let read_limit = if retained_remaining == 0 {
            1
        } else {
            retained_remaining.min(buffer.len())
        };
        match stream.read(&mut buffer[..read_limit]) {
            Ok(0) => break,
            Ok(count) => {
                total = total.saturating_add(count as u64);
                let remaining = limit.saturating_sub(retained.len());
                retained.extend_from_slice(&buffer[..count.min(remaining)]);
                if retained.len() == limit {
                    let probe_remaining = remaining_deadline(started, budget);
                    if let Ok(probe_remaining) = probe_remaining {
                        stream
                            .set_read_timeout(Some(probe_remaining))
                            .map_err(|error| {
                                format!("cannot update loopback read deadline: {error}")
                            })?;
                        match stream.read(&mut buffer[..1]) {
                            Ok(0) => {}
                            Ok(count) => total = total.saturating_add(count as u64),
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) =>
                            {
                                timed_out = true;
                            }
                            Err(error) => {
                                return Err(format!("cannot read loopback response: {error}"))
                            }
                        }
                    } else {
                        timed_out = true;
                    }
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                timed_out = true;
                break;
            }
            Err(error) => return Err(format!("cannot read loopback response: {error}")),
        }
    }
    let output = BoundedOutput {
        text: String::from_utf8_lossy(&retained).into_owned(),
        total_bytes: total,
        truncated: total > retained.len() as u64,
    };
    Ok((retained, output, timed_out))
}

fn loopback_response_status(response: &[u8]) -> Option<u16> {
    let line_end = response.windows(2).position(|window| window == b"\r\n")?;
    let status_line = std::str::from_utf8(&response[..line_end]).ok()?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next()?;
    let status_text = parts.next()?;
    let reason = parts.next()?;
    if version != "HTTP/1.1"
        || status_text.len() != 3
        || !status_text.bytes().all(|byte| byte.is_ascii_digit())
        || reason.is_empty()
        || reason.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    status_text.parse::<u16>().ok()
}

fn valid_http_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn parse_authenticated_loopback_response(
    response: &[u8],
    truncated: bool,
) -> Result<StrictLoopbackResponse, String> {
    if truncated {
        return Err("response exceeded the bounded output limit".to_string());
    }
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "response did not contain a complete HTTP header".to_string())?;
    let header = std::str::from_utf8(&response[..separator])
        .map_err(|_| "response header was not valid ASCII".to_string())?;
    let header_bytes = header.as_bytes();
    let invalid_line_break = header_bytes.iter().enumerate().any(|(index, byte)| {
        (*byte == b'\r' && header_bytes.get(index + 1) != Some(&b'\n'))
            || (*byte == b'\n'
                && index
                    .checked_sub(1)
                    .and_then(|prior| header_bytes.get(prior))
                    != Some(&b'\r'))
    });
    if !header.is_ascii() || invalid_line_break {
        return Err("response header was invalid".to_string());
    }
    let body = response[separator + 4..].to_vec();
    let status_code = loopback_response_status(response)
        .ok_or_else(|| "response status line was invalid".to_string())?;

    let mut headers = BTreeMap::new();
    for line in header.split("\r\n").skip(1) {
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return Err("response contained an invalid header".to_string());
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "response contained an invalid header".to_string())?;
        if !valid_http_header_name(name) {
            return Err("response contained an invalid header".to_string());
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches(' ');
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == 0x7f)
            || headers.insert(name, value.to_string()).is_some()
        {
            return Err("response contained an invalid header".to_string());
        }
    }
    let expected_names = BTreeSet::from([
        "cache-control".to_string(),
        "connection".to_string(),
        "content-length".to_string(),
        "content-type".to_string(),
        "x-bluefire-authentication".to_string(),
        "x-content-type-options".to_string(),
    ]);
    if headers.keys().cloned().collect::<BTreeSet<_>>() != expected_names {
        return Err("response header set was invalid".to_string());
    }
    if headers.get("content-type").map(String::as_str) != Some("application/json; charset=utf-8")
        || headers.get("cache-control").map(String::as_str) != Some("no-store")
        || headers.get("x-content-type-options").map(String::as_str) != Some("nosniff")
        || headers.get("connection").map(String::as_str) != Some("close")
    {
        return Err("response security headers were invalid".to_string());
    }
    let content_length_text = headers
        .get("content-length")
        .ok_or_else(|| "response Content-Length was missing".to_string())?;
    if content_length_text.is_empty()
        || !content_length_text
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        || (content_length_text.len() > 1 && content_length_text.starts_with('0'))
    {
        return Err("response Content-Length was invalid".to_string());
    }
    let content_length = content_length_text
        .parse::<usize>()
        .map_err(|_| "response Content-Length was invalid".to_string())?;
    if content_length != body.len() {
        return Err("response Content-Length did not match the body".to_string());
    }
    let authentication = headers
        .remove("x-bluefire-authentication")
        .ok_or_else(|| "response authentication was missing".to_string())?;
    Ok(StrictLoopbackResponse {
        status_code,
        body,
        authentication,
    })
}

fn parse_canonical_json(body: &[u8], context: &str) -> Result<Value, String> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| format!("{context} was not strict JSON"))?;
    if crate::contract::canonical_json(&value).as_bytes() != body {
        return Err(format!("{context} was not canonical JSON"));
    }
    Ok(value)
}

fn validate_loopback_challenge(
    response: &[u8],
    truncated: bool,
    authentication: &LoopbackReceiverTaskAuthentication,
    destination: &NetworkDestination,
) -> Result<LoopbackReceiverChallenge, String> {
    let response = parse_authenticated_loopback_response(response, truncated)?;
    if response.status_code != 200 {
        return Err("receiver challenge did not return 200".to_string());
    }
    let value = parse_canonical_json(&response.body, "receiver challenge")?;
    if !verify_receiver_authentication(
        &authentication.task_key,
        LOOPBACK_RECEIVER_CHALLENGE_DOMAIN,
        &[&response.body],
        &response.authentication,
    ) {
        return Err("receiver challenge authentication failed".to_string());
    }
    let challenge: LoopbackReceiverChallenge = serde_json::from_value(value)
        .map_err(|_| "receiver challenge schema was invalid".to_string())?;
    if challenge.schema_version != LOOPBACK_RECEIVER_CHALLENGE_SCHEMA_VERSION
        || challenge.task_id != authentication.task_id
        || !valid_lower_hex_32(&challenge.session_id)
        || !valid_lower_hex_32(&challenge.nonce)
        || challenge.host != destination.host
        || challenge.port != destination.port
    {
        return Err("receiver challenge binding did not match".to_string());
    }
    Ok(challenge)
}

fn validate_loopback_acknowledgement(
    response: &[u8],
    truncated: bool,
    authentication: &LoopbackReceiverTaskAuthentication,
    request_authentication: &str,
    challenge: &LoopbackReceiverChallenge,
    expected_sha256: &str,
    expected_bytes: usize,
) -> Result<LoopbackReceiverResult, String> {
    let response = parse_authenticated_loopback_response(response, truncated)?;
    if !matches!(response.status_code, 200 | 201) {
        return Err("receiver did not return an authenticated success status".to_string());
    }
    let value = parse_canonical_json(&response.body, "receiver acknowledgement")?;
    if !verify_receiver_authentication(
        &authentication.task_key,
        LOOPBACK_RECEIVER_RESPONSE_DOMAIN,
        &[request_authentication.as_bytes(), b"\0", &response.body],
        &response.authentication,
    ) {
        return Err("receiver acknowledgement authentication failed".to_string());
    }

    let acknowledgement: LoopbackReceiverResult = serde_json::from_value(value)
        .map_err(|_| "response body was not the strict receiver JSON schema".to_string())?;
    if acknowledgement.schema_version != LOOPBACK_RECEIVER_RESULT_SCHEMA_VERSION {
        return Err("receiver acknowledgement schema version did not match".to_string());
    }
    if !acknowledgement.accepted {
        return Err("receiver did not acknowledge the artifact".to_string());
    }
    if acknowledgement.task_id != authentication.task_id
        || acknowledgement.session_id != challenge.session_id
    {
        return Err("receiver acknowledgement task or session did not match".to_string());
    }
    if acknowledgement.sha256 != expected_sha256 {
        return Err("receiver acknowledgement digest did not match".to_string());
    }
    if acknowledgement.bytes_received != expected_bytes as u64 {
        return Err("receiver acknowledgement byte count did not match".to_string());
    }
    if (response.status_code == 201) != acknowledgement.stored {
        return Err("receiver acknowledgement storage status did not match".to_string());
    }
    Ok(acknowledgement)
}

fn loopback_authority(destination: &NetworkDestination) -> String {
    if destination.host.contains(':') {
        format!("[{}]:{}", destination.host, destination.port)
    } else {
        format!("{}:{}", destination.host, destination.port)
    }
}

fn exchange_loopback_request(
    socket: SocketAddr,
    request_header: &[u8],
    request_body: &[u8],
    response_limit: usize,
    started: Instant,
    budget: Duration,
) -> Result<(Vec<u8>, BoundedOutput, bool), ActionFailure> {
    let mut stream = TcpStream::connect_timeout(
        &socket,
        remaining_deadline(started, budget)
            .map_err(|error| ActionFailure::timed_out("loopback_timeout", error))?,
    )
    .map_err(|error| {
        if matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ) {
            ActionFailure::timed_out("loopback_timeout", "the loopback connect timed out")
        } else {
            ActionFailure::failed("loopback_connect_failed", "loopback connection failed")
        }
    })?;
    write_socket_with_deadline(&mut stream, request_header, started, budget)?;
    write_socket_with_deadline(&mut stream, request_body, started, budget)?;
    let flush_budget = remaining_deadline(started, budget)
        .map_err(|error| ActionFailure::timed_out("loopback_timeout", error))?;
    stream.set_write_timeout(Some(flush_budget)).map_err(|_| {
        ActionFailure::failed(
            "loopback_timeout_setup_failed",
            "loopback timeout setup failed",
        )
    })?;
    stream.flush().map_err(|_| {
        ActionFailure::failed("loopback_write_failed", "loopback socket write failed")
    })?;
    remaining_deadline(started, budget)
        .map_err(|error| ActionFailure::timed_out("loopback_timeout", error))?;
    let _ = stream.shutdown(Shutdown::Write);
    read_socket_bounded(&mut stream, response_limit, started, budget)
        .map_err(|_| ActionFailure::failed("loopback_read_failed", "loopback response failed"))
}

impl PreparedAction for NetworkLoopbackPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let started = Instant::now();
        let budget = Duration::from_millis(context.manifest.limits.timeout_ms);
        let artifact = authorize_path(context, &self.0.artifact, false)?;
        // This authorization intentionally occurs before constructing or
        // connecting a socket. A refused destination has no network effect.
        let ip = ensure_network_authorized(context.manifest, context.profile, &self.0.destination)
            .map_err(|error| ActionFailure::blocked("network_scope_blocked", error))?;
        // The transport/watchdog supplies this exact pair through a scrubbed
        // child environment. Missing, partial, malformed, or mismatched
        // material blocks the action before the first connection attempt.
        let receiver_authentication = receiver_task_authentication()?;
        let artifact_path = context
            .root
            .resolve_existing(&artifact)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let body = read_file_bounded(&artifact_path, context.manifest.limits.max_artifact_bytes)
            .map_err(|error| ActionFailure::blocked("artifact_limit_blocked", error))?;
        let body_sha256 = crate::contract::sha256_hex(&body);
        let socket = SocketAddr::new(ip, self.0.destination.port);
        let authority = loopback_authority(&self.0.destination);
        let response_limit = context
            .manifest
            .limits
            .max_stdout_bytes
            .min(LOOPBACK_RECEIVER_PROTOCOL_LIMIT);

        let challenge_request = format!(
            "GET {LOOPBACK_RECEIVER_CHALLENGE_PATH} HTTP/1.1\r\nHost: {authority}\r\nX-BlueFire-Task-ID: {}\r\nX-BlueFire-SHA256: {body_sha256}\r\nX-BlueFire-Content-Length: {}\r\nConnection: close\r\n\r\n",
            receiver_authentication.task_id,
            body.len(),
        );
        let (challenge_bytes, challenge_output, challenge_timed_out) = exchange_loopback_request(
            socket,
            challenge_request.as_bytes(),
            &[],
            response_limit,
            started,
            budget,
        )?;
        if challenge_timed_out {
            return Err(ActionFailure::timed_out(
                "loopback_timeout",
                "the authenticated receiver challenge exceeded its monotonic deadline",
            ));
        }
        let challenge = validate_loopback_challenge(
            &challenge_bytes,
            challenge_output.truncated,
            &receiver_authentication,
            &self.0.destination,
        )
        .map_err(|_| {
            ActionFailure::failed(
                "receiver_authentication_failed",
                "the loopback receiver did not prove the expected managed session identity",
            )
        })?;
        if challenge.sha256 != body_sha256 || challenge.content_length != body.len() {
            return Err(ActionFailure::failed(
                "receiver_authentication_failed",
                "the loopback receiver challenge did not bind the exact artifact",
            ));
        }

        let request_document = json!({
            "schema_version": LOOPBACK_RECEIVER_REQUEST_SCHEMA_VERSION,
            "method": "POST",
            "path": LOOPBACK_RECEIVER_ARTIFACT_PATH,
            "task_id": receiver_authentication.task_id,
            "session_id": challenge.session_id,
            "nonce": challenge.nonce,
            "host": self.0.destination.host,
            "port": self.0.destination.port,
            "sha256": body_sha256,
            "content_length": body.len(),
        });
        let request_document = crate::contract::canonical_json(&request_document);
        let request_authentication = receiver_authentication_value(
            &receiver_authentication.task_key,
            LOOPBACK_RECEIVER_REQUEST_DOMAIN,
            request_document.as_bytes(),
        );
        let artifact_request = format!(
            "POST {LOOPBACK_RECEIVER_ARTIFACT_PATH} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/octet-stream\r\nX-BlueFire-SHA256: {body_sha256}\r\nX-BlueFire-Task-ID: {}\r\nX-BlueFire-Session-ID: {}\r\nX-BlueFire-Nonce: {}\r\nX-BlueFire-Authentication: {request_authentication}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            receiver_authentication.task_id,
            challenge.session_id,
            challenge.nonce,
            body.len(),
        );
        let (response_bytes, response, timed_out) = exchange_loopback_request(
            socket,
            artifact_request.as_bytes(),
            &body,
            response_limit,
            started,
            budget,
        )?;
        let status_code = loopback_response_status(&response_bytes);
        let acknowledgement = if timed_out {
            None
        } else {
            Some(validate_loopback_acknowledgement(
                &response_bytes,
                response.truncated,
                &receiver_authentication,
                &request_authentication,
                &challenge,
                &body_sha256,
                body.len(),
            ))
        };
        let receiver_stored = acknowledgement
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|result| result.stored);
        let status = if timed_out {
            TaskStatus::TimedOut
        } else if acknowledgement.as_ref().is_some_and(Result::is_ok) {
            TaskStatus::Success
        } else {
            TaskStatus::Failed
        };
        Ok(ActionOutcome {
            status,
            output: json!({
                "destination": self.0.destination,
                "artifact": artifact,
                "bytes_sent": body.len(),
                "sha256": body_sha256,
                "http_status": status_code,
                "receiver_acknowledged": status == TaskStatus::Success,
                "receiver_stored": receiver_stored,
            }),
            stdout: response,
            stderr: BoundedOutput::default(),
            receipt_ids: Vec::new(),
            cleanup: None,
            error: match status {
                TaskStatus::Success => None,
                TaskStatus::TimedOut => Some(ErrorRecord {
                    code: "loopback_timeout".to_string(),
                    message: "the loopback action exceeded its monotonic deadline".to_string(),
                }),
                _ => Some(ErrorRecord {
                    code: "loopback_response_failed".to_string(),
                    message: format!(
                        "loopback receiver acknowledgement failed: {}",
                        acknowledgement
                            .as_ref()
                            .and_then(|result| result.as_ref().err())
                            .map(String::as_str)
                            .unwrap_or("response was invalid")
                    ),
                }),
            },
            limitations: vec![
                "Literal loopback IP only; DNS, redirects, and proxy environment variables are not used."
                    .to_string(),
                "Success requires an active managed enrollment, an exact per-task HMAC capability, an authenticated ephemeral receiver session, a one-time challenge, and a digest- and length-bound acknowledgement."
                    .to_string(),
                "This same-user loopback protocol is not remote transport and does not authorize a different host, port, task, or receiver session."
                    .to_string(),
            ],
        })
    }
}

struct NetworkLoopbackAction;
static NETWORK_LOOPBACK_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.network.loopback.v1",
        behavior_ids: &["sandbox.network.loopback.v1"],
        summary: "Send one bounded artifact to an exact literal loopback HTTP sink.",
        schema: network_loopback_schema,
        capabilities: &[Capability::FilesystemRead, Capability::NetworkLoopback],
        tier: SafetyTier::Controlled,
        targets: &["sandbox", "loopback_service"],
        hints: &[ObservationHint { source: "network_fixture", signal: "http_request" }],
        cleanup: None,
        limits: TASK_LIMITS,
        effects: (false, true, false),
        receipt: false,
    }
};
impl Action for NetworkLoopbackAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &NETWORK_LOOPBACK_DESCRIPTOR
    }
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(NetworkLoopbackPrepared(parse_params(params)?)))
    }
}

// -------------------------------------------------------------------------
// sandbox.export.local.v1

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportLocalParams {
    source: String,
    destination: String,
}

struct ExportLocalPrepared(ExportLocalParams);

impl PreparedAction for ExportLocalPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let source = authorize_path(context, &self.0.source, false)?;
        let destination = authorize_path(context, &self.0.destination, false)?;
        let source_path = context
            .root
            .resolve_existing(&source)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let bytes = read_file_bounded(&source_path, context.manifest.limits.max_artifact_bytes)
            .map_err(|error| ActionFailure::blocked("artifact_limit_blocked", error))?;
        let target = context
            .root
            .prepare_new_file(&destination)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let intent = begin_receipt(
            context,
            receipt_paths(target.relative.clone(), &bytes, &target.created_directories),
        )?;
        context
            .root
            .write_new(&target, &bytes, &intent)
            .map_err(|error| ActionFailure::failed("export_write_failed", error))?;
        let receipt_id = commit_receipt(context, &intent)?;
        Ok(ActionOutcome::success(json!({
            "source": source,
            "artifact": target.relative,
            "size": bytes.len(),
            "sha256": crate::contract::sha256_hex(&bytes),
        }))
        .with_receipt(receipt_id))
    }
}

struct ExportLocalAction;
static EXPORT_LOCAL_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.export.local.v1",
        behavior_ids: &["sandbox.export.local.v1"],
        summary: "Copy one bounded artifact into an approved sandbox-local export path.",
        schema: export_local_schema,
        capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite, Capability::ExportLocal],
        tier: SafetyTier::Controlled,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "file_create" }],
        cleanup: Some("sandbox.cleanup.v1"),
        limits: TASK_LIMITS,
        effects: (true, false, false),
        receipt: true,
    }
};
impl Action for ExportLocalAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &EXPORT_LOCAL_DESCRIPTOR
    }
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(ExportLocalPrepared(parse_params(params)?)))
    }
}

// -------------------------------------------------------------------------
// sandbox.restricted.persistence-marker.v1

const PERSISTENCE_MARKER_PATH: &str = "restricted/persistence-marker.json";

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistenceMarkerLabel {
    PersistenceDetectionCanary,
    ControlValidation,
}

impl PersistenceMarkerLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::PersistenceDetectionCanary => "persistence_detection_canary",
            Self::ControlValidation => "control_validation",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestrictedPersistenceMarkerParams {
    label: PersistenceMarkerLabel,
}

struct RestrictedPersistenceMarkerPrepared(RestrictedPersistenceMarkerParams);

impl PreparedAction for RestrictedPersistenceMarkerPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let destination = authorize_path(context, PERSISTENCE_MARKER_PATH, false)?;
        let document = json!({
            "schema_version": "bluefire.persistence-detection-canary/v1",
            "kind": "non_executable_marker",
            "label": self.0.label.as_str(),
            "executable": false,
        });
        let bytes = format!("{}\n", crate::contract::canonical_json(&document)).into_bytes();
        if bytes.len() as u64 > context.manifest.limits.max_artifact_bytes {
            return Err(ActionFailure::blocked(
                "artifact_limit_blocked",
                "the deterministic persistence marker exceeds the manifest artifact limit",
            ));
        }
        let target = context
            .root
            .prepare_new_file(&destination)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let intent = begin_receipt(
            context,
            receipt_paths(target.relative.clone(), &bytes, &target.created_directories),
        )?;
        context
            .root
            .write_new(&target, &bytes, &intent)
            .map_err(|error| ActionFailure::failed("persistence_marker_write_failed", error))?;
        let receipt_id = commit_receipt(context, &intent)?;
        Ok(ActionOutcome::success(json!({
            "artifact": PERSISTENCE_MARKER_PATH,
            "sha256": format!("sha256:{}", crate::contract::sha256_hex(&bytes)),
            "label": self.0.label.as_str(),
            "executable": false,
        }))
        .with_receipt(receipt_id))
    }
}

struct RestrictedPersistenceMarkerAction;
static RESTRICTED_PERSISTENCE_MARKER_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.restricted.persistence-marker.v1",
        behavior_ids: &["sandbox.restricted.persistence-marker.v1"],
        summary: "Create one deterministic non-executable persistence-detection canary inside the sandbox.",
        schema: restricted_persistence_marker_schema,
        capabilities: &[Capability::FilesystemWrite, Capability::SandboxRestricted],
        tier: SafetyTier::Restricted,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "persistence_marker_create" }],
        cleanup: Some("sandbox.cleanup.v1"),
        limits: TASK_LIMITS,
        effects: (true, false, false),
        receipt: true,
    }
};
impl Action for RestrictedPersistenceMarkerAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &RESTRICTED_PERSISTENCE_MARKER_DESCRIPTOR
    }

    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(RestrictedPersistenceMarkerPrepared(parse_params(
            params,
        )?)))
    }
}

// -------------------------------------------------------------------------
// sandbox.cleanup.v1

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupParams {
    receipt_ids: Vec<String>,
}

struct CleanupPrepared(CleanupParams);

impl PreparedAction for CleanupPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        if self.0.receipt_ids.is_empty()
            || self.0.receipt_ids.len() > context.manifest.limits.max_files
        {
            return Err(ActionFailure::blocked(
                "cleanup_limit_blocked",
                "cleanup receipt count is empty or exceeds the manifest file limit",
            ));
        }
        let mut report = CleanupReport {
            requested_receipts: self.0.receipt_ids.len(),
            ..CleanupReport::default()
        };
        let mut loaded = Vec::new();
        let mut seen = BTreeSet::new();
        for receipt_id in &self.0.receipt_ids {
            if !seen.insert(receipt_id.clone()) {
                report.errors.push(format!(
                    "{receipt_id}: cleanup receipt IDs must not contain duplicates"
                ));
                continue;
            }
            let record = match context.root.load_receipt(receipt_id) {
                Ok(Some(record)) => record,
                Ok(None) => {
                    report.already_absent_receipts.push(receipt_id.clone());
                    if let Err(error) = context.root.delete_receipt(receipt_id) {
                        report.errors.push(format!("{receipt_id}: {error}"));
                    }
                    continue;
                }
                Err(error) => {
                    report.errors.push(format!("{receipt_id}: {error}"));
                    continue;
                }
            };
            if record.runner_profile_id != context.profile.profile_id {
                report.errors.push(format!(
                    "{receipt_id}: receipt belongs to another runner profile"
                ));
                continue;
            }
            loaded.push((receipt_id.clone(), record));
        }
        loaded.sort_by(|left, right| {
            right
                .1
                .created_at
                .cmp(&left.1.created_at)
                .then_with(|| right.0.cmp(&left.0))
        });
        for (receipt_id, record) in loaded {
            let mut receipt_failed = false;
            for owned in &record.paths {
                match context.root.remove_owned(owned) {
                    Ok(Some(path)) => report.removed_paths.push(path),
                    Ok(None) => {}
                    Err(error) => {
                        receipt_failed = true;
                        report.retained_paths.push(owned.relative_path.clone());
                        report
                            .errors
                            .push(format!("{}: {error}", owned.relative_path));
                    }
                }
                if let Err(error) = context.root.remove_staging_for_owned(&receipt_id, owned) {
                    receipt_failed = true;
                    report
                        .errors
                        .push(format!("{} staging: {error}", owned.relative_path));
                }
            }
            if !receipt_failed {
                if let Err(error) = context.root.delete_receipt(&receipt_id) {
                    report.errors.push(format!("{receipt_id}: {error}"));
                }
            }
        }
        let status = if report.errors.is_empty() {
            TaskStatus::Success
        } else if report.removed_paths.is_empty() {
            TaskStatus::CleanupFailed
        } else {
            TaskStatus::Partial
        };
        Ok(ActionOutcome {
            status,
            output: serde_json::to_value(&report)
                .expect("cleanup report serialization cannot fail"),
            stdout: BoundedOutput::default(),
            stderr: BoundedOutput::default(),
            receipt_ids: Vec::new(),
            cleanup: Some(report),
            error: if status == TaskStatus::Success {
                None
            } else {
                Some(ErrorRecord {
                    code: "cleanup_incomplete".to_string(),
                    message: "one or more receipt-owned paths were retained".to_string(),
                })
            },
            limitations: Vec::new(),
        })
    }
}

struct CleanupAction;
static CLEANUP_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    ..reviewed_descriptor! {
        id: "sandbox.cleanup.v1",
        behavior_ids: &["sandbox.cleanup.v1"],
        summary: "Remove only hash-checked objects named by runner-owned receipts.",
        schema: cleanup_schema,
        capabilities: &[Capability::FilesystemWrite, Capability::Cleanup],
        tier: SafetyTier::Safe,
        targets: &["sandbox"],
        hints: &[ObservationHint { source: "filesystem", signal: "file_delete" }],
        cleanup: None,
        limits: TASK_LIMITS,
        effects: (true, false, false),
        receipt: false,
    }
};
impl Action for CleanupAction {
    fn descriptor(&self) -> &'static ActionDescriptor {
        &CLEANUP_DESCRIPTOR
    }
    fn prepare(&self, params: Value) -> Result<Box<dyn PreparedAction>, ActionFailure> {
        Ok(Box::new(CleanupPrepared(parse_params(params)?)))
    }
}

static FIXTURE_CREATE: FixtureCreateAction = FixtureCreateAction;
static FIXTURE_TRANSFORM: FixtureTransformAction = FixtureTransformAction;
static DISCOVERY_LIST: DiscoveryListAction = DiscoveryListAction;
static DISCOVERY_METADATA: DiscoveryMetadataAction = DiscoveryMetadataAction;
static SYSTEM_DISCOVERY: SystemDiscoveryAction = SystemDiscoveryAction;
static PROCESS_DISCOVERY: ProcessDiscoveryAction = ProcessDiscoveryAction;
static RECURSIVE_DISCOVERY: RecursiveDiscoveryAction = RecursiveDiscoveryAction;
static ARCHIVE_TAR: ArchiveTarAction = ArchiveTarAction;
static COLLECTION_STAGE: CollectionStageAction = CollectionStageAction;
static NETWORK_LOOPBACK: NetworkLoopbackAction = NetworkLoopbackAction;
static EXPORT_LOCAL: ExportLocalAction = ExportLocalAction;
static RESTRICTED_PERSISTENCE_MARKER: RestrictedPersistenceMarkerAction =
    RestrictedPersistenceMarkerAction;
static CLEANUP: CleanupAction = CleanupAction;

static REGISTRY: [&'static dyn Action; 13] = [
    &FIXTURE_CREATE,
    &FIXTURE_TRANSFORM,
    &DISCOVERY_LIST,
    &DISCOVERY_METADATA,
    &SYSTEM_DISCOVERY,
    &PROCESS_DISCOVERY,
    &RECURSIVE_DISCOVERY,
    &ARCHIVE_TAR,
    &COLLECTION_STAGE,
    &NETWORK_LOOPBACK,
    &EXPORT_LOCAL,
    &RESTRICTED_PERSISTENCE_MARKER,
    &CLEANUP,
];

pub fn registered_actions() -> &'static [&'static dyn Action] {
    &REGISTRY
}

pub fn find_action(action_id: &str) -> Option<&'static dyn Action> {
    REGISTRY
        .iter()
        .copied()
        .find(|action| action.descriptor().action_id == action_id)
}

pub fn inventory() -> Vec<ActionDescriptor> {
    REGISTRY
        .iter()
        .map(|action| action.descriptor().clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn registry_contains_exactly_the_reviewed_action_ids() {
        let actual = inventory()
            .into_iter()
            .map(|descriptor| descriptor.action_id)
            .collect::<BTreeSet<_>>();
        let expected = BTreeSet::from([
            "sandbox.fixture.create.v1",
            "sandbox.fixture.transform.v1",
            "sandbox.discovery.list.v1",
            "sandbox.discovery.metadata.v1",
            "endpoint.discovery.system.v1",
            "endpoint.discovery.processes.v1",
            "sandbox.discovery.recursive.v1",
            "sandbox.archive.tar.v1",
            "sandbox.collection.stage.v1",
            "sandbox.network.loopback.v1",
            "sandbox.export.local.v1",
            "sandbox.restricted.persistence-marker.v1",
            "sandbox.cleanup.v1",
        ]);
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), registered_actions().len());
    }

    #[test]
    fn inventory_exposes_versioned_machine_readable_sdk_contracts() {
        for descriptor in inventory() {
            let value = serde_json::to_value(&descriptor).unwrap();
            assert_eq!(value["schema_version"], ACTION_SDK_SCHEMA_VERSION);
            assert_eq!(value["action_version"], "1.0.0");
            assert_eq!(value["parameter_schema"]["type"], "object");
            assert_eq!(value["parameter_schema"]["additionalProperties"], false);
            assert!(value["target_types"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()));
            assert!(value["observation_hints"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty()));
            assert_eq!(value["readiness"], "ready");
            assert_eq!(value["provenance"]["license"], "MIT");
        }
    }

    #[test]
    fn deterministic_tar_has_ustar_header_and_stable_bytes() {
        let files = vec![
            ("fixtures/a.txt".to_string(), b"alpha".to_vec()),
            ("fixtures/b.txt".to_string(), b"beta".to_vec()),
        ];
        let first = build_deterministic_tar(&files, 16 * 1024).unwrap();
        let second = build_deterministic_tar(&files, 16 * 1024).unwrap();
        assert_eq!(first, second);
        assert_eq!(&first[257..263], b"ustar\0");
        assert_eq!(first.len() % 512, 0);
        assert!(first[first.len() - 1_024..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn arbitrary_execution_fields_are_rejected() {
        let action = find_action("sandbox.fixture.transform.v1").unwrap();
        let error = action
            .prepare(json!({
                "input": "a",
                "output": "b",
                "transform": "uppercase-ascii",
                "command": "whoami"
            }))
            .err()
            .expect("unknown command field must be rejected");
        assert_eq!(error.code, "invalid_action_params");
    }
}
