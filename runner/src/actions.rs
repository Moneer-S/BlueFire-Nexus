use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::contract::{
    BoundedOutput, Capability, CleanupReport, ErrorRecord, ExecutionManifest, NetworkDestination,
    Platform, RunnerProfile, SafetyTier, TaskStatus,
};
use crate::process::run_fixed_transform;
use crate::safety::{
    ensure_network_authorized, ensure_path_authorized, hash_file, normalize_relative,
    owned_directories, owned_file, read_file_bounded, OwnedPath, SafeRoot,
};

const ALL_PLATFORMS: &[Platform] = &[Platform::Windows, Platform::Linux, Platform::Macos];

#[derive(Debug, Clone, Serialize)]
pub struct ActionDescriptor {
    pub action_id: &'static str,
    pub behavior_ids: &'static [&'static str],
    pub platforms: &'static [Platform],
    pub capabilities: &'static [Capability],
    pub safety_tier: SafetyTier,
    pub filesystem_effect: bool,
    pub network_effect: bool,
    pub process_effect: bool,
    pub cleanup_receipt: bool,
}

pub struct ActionContext<'a> {
    pub manifest: &'a ExecutionManifest,
    pub profile: &'a RunnerProfile,
    pub root: &'a SafeRoot,
    pub runner_executable: &'a Path,
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

fn store_receipt(
    context: &ActionContext<'_>,
    paths: Vec<OwnedPath>,
) -> Result<String, ActionFailure> {
    context
        .root
        .store_receipt(context.manifest, context.profile, paths.clone())
        .map_err(|error| {
            // The newly-created objects are known by exact path and hash. If
            // durable receipt storage fails, make a guarded best-effort rollback.
            for path in &paths {
                let _ = context.root.remove_owned(path);
            }
            ActionFailure::failed("receipt_persistence_failed", error)
        })
}

fn receipt_paths(relative: String, bytes: &[u8], directories: &[String]) -> Vec<OwnedPath> {
    let mut paths = vec![owned_file(relative, bytes)];
    paths.extend(owned_directories(directories));
    paths
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
        context
            .root
            .write_new(&target, bytes)
            .map_err(|error| ActionFailure::failed("fixture_write_failed", error))?;
        let receipt_id = store_receipt(
            context,
            receipt_paths(target.relative.clone(), bytes, &target.created_directories),
        )?;
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
    action_id: "sandbox.fixture.create.v1",
    behavior_ids: &["sandbox.fixture.create.v1"],
    platforms: ALL_PLATFORMS,
    capabilities: &[Capability::FilesystemWrite],
    safety_tier: SafetyTier::Safe,
    filesystem_effect: true,
    network_effect: false,
    process_effect: false,
    cleanup_receipt: true,
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
        let input_metadata = fs::metadata(&input_path)
            .map_err(|error| ActionFailure::failed("input_metadata_failed", error.to_string()))?;
        if !input_metadata.is_file()
            || input_metadata.len() > context.manifest.limits.max_artifact_bytes
        {
            return Err(ActionFailure::blocked(
                "artifact_limit_blocked",
                "transform input is not a bounded regular file",
            ));
        }
        let target = context
            .root
            .prepare_new_file(&output)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;

        let process = match run_fixed_transform(
            context.runner_executable,
            context.root.path(),
            &input,
            &output,
            self.0.transform.as_arg(),
            &context.manifest.limits,
        ) {
            Ok(process) => process,
            Err(error) => {
                context.root.rollback_prepared(&target);
                return Err(ActionFailure::failed("fixed_process_failed", error));
            }
        };

        let mut receipt_ids = Vec::new();
        let mut output_bytes = None;
        if let Ok(path) = context.root.resolve_existing(&output) {
            let bytes = match read_file_bounded(&path, context.manifest.limits.max_artifact_bytes) {
                Ok(bytes) => bytes,
                Err(error) => {
                    context.root.rollback_prepared(&target);
                    return Err(ActionFailure::failed("transform_output_invalid", error));
                }
            };
            let receipt_id = store_receipt(
                context,
                receipt_paths(target.relative.clone(), &bytes, &target.created_directories),
            )?;
            receipt_ids.push(receipt_id);
            output_bytes = Some(bytes);
        } else if !target.created_directories.is_empty() {
            let receipt_id =
                store_receipt(context, owned_directories(&target.created_directories))?;
            receipt_ids.push(receipt_id);
        }

        let status = if process.timed_out {
            TaskStatus::TimedOut
        } else if process.exit_code == Some(0) && output_bytes.is_some() {
            TaskStatus::Success
        } else if output_bytes.is_some() {
            TaskStatus::Partial
        } else {
            TaskStatus::Failed
        };
        let error = match status {
            TaskStatus::Success => None,
            TaskStatus::TimedOut => Some(ErrorRecord {
                code: "fixed_process_timeout".to_string(),
                message: "the fixed transform exceeded its deadline".to_string(),
            }),
            _ => Some(ErrorRecord {
                code: "fixed_process_exit".to_string(),
                message: format!("fixed transform exited with {:?}", process.exit_code),
            }),
        };
        Ok(ActionOutcome {
            status,
            output: json!({
                "artifact": output_bytes.as_ref().map(|_| output),
                "sha256": output_bytes.as_ref().map(|bytes| crate::contract::sha256_hex(bytes)),
                "size": output_bytes.as_ref().map(Vec::len),
                "exit_code": process.exit_code,
                "transform": self.0.transform.as_arg(),
            }),
            stdout: process.stdout,
            stderr: process.stderr,
            receipt_ids,
            cleanup: None,
            error,
            limitations: vec![
                "The action can spawn only this runner's private fixed transform helper."
                    .to_string(),
            ],
        })
    }
}

struct FixtureTransformAction;
static FIXTURE_TRANSFORM_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    action_id: "sandbox.fixture.transform.v1",
    behavior_ids: &["sandbox.fixture.transform.v1"],
    platforms: ALL_PLATFORMS,
    capabilities: &[
        Capability::FilesystemRead,
        Capability::FilesystemWrite,
        Capability::ProcessSpawn,
    ],
    safety_tier: SafetyTier::Safe,
    filesystem_effect: true,
    network_effect: false,
    process_effect: true,
    cleanup_receipt: true,
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
    action_id: "sandbox.discovery.list.v1",
    behavior_ids: &["sandbox.discovery.list.v1"],
    platforms: ALL_PLATFORMS,
    capabilities: &[Capability::FilesystemRead],
    safety_tier: SafetyTier::Safe,
    filesystem_effect: false,
    network_effect: false,
    process_effect: false,
    cleanup_receipt: false,
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
    action_id: "sandbox.discovery.metadata.v1",
    behavior_ids: &["sandbox.discovery.metadata.v1"],
    platforms: ALL_PLATFORMS,
    capabilities: &[Capability::FilesystemRead],
    safety_tier: SafetyTier::Safe,
    filesystem_effect: false,
    network_effect: false,
    process_effect: false,
    cleanup_receipt: false,
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

        let mut owned = Vec::new();
        let mut staged = Vec::new();
        let mut errors = Vec::new();
        let mut total_bytes = 0_u64;
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
                .saturating_sub(total_bytes);
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
            if let Err(error) = context.root.write_new(&target, &bytes) {
                errors.push(format!("{normalized}: {error}"));
                continue;
            }
            total_bytes = total_bytes.saturating_add(bytes.len() as u64);
            owned.push(owned_file(target.relative.clone(), &bytes));
            staged.push(json!({
                "source": normalized,
                "artifact": target.relative,
                "sha256": crate::contract::sha256_hex(&bytes),
                "size": bytes.len(),
            }));
        }
        owned.extend(owned_directories(&created_directories));
        let receipt_id = if owned.is_empty() {
            None
        } else {
            Some(store_receipt(context, owned)?)
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
    action_id: "sandbox.collection.stage.v1",
    behavior_ids: &["sandbox.collection.stage.v1"],
    platforms: ALL_PLATFORMS,
    capabilities: &[Capability::FilesystemRead, Capability::FilesystemWrite],
    safety_tier: SafetyTier::Controlled,
    filesystem_effect: true,
    network_effect: false,
    process_effect: false,
    cleanup_receipt: true,
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

fn read_socket_bounded(stream: &mut TcpStream, limit: usize) -> Result<BoundedOutput, String> {
    let mut retained = Vec::with_capacity(limit.min(16 * 1024));
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                total = total.saturating_add(count as u64);
                let remaining = limit.saturating_sub(retained.len());
                retained.extend_from_slice(&buffer[..count.min(remaining)]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break
            }
            Err(error) => return Err(format!("cannot read loopback response: {error}")),
        }
    }
    Ok(BoundedOutput {
        text: String::from_utf8_lossy(&retained).into_owned(),
        total_bytes: total,
        truncated: total > retained.len() as u64,
    })
}

impl PreparedAction for NetworkLoopbackPrepared {
    fn execute(
        self: Box<Self>,
        context: &ActionContext<'_>,
    ) -> Result<ActionOutcome, ActionFailure> {
        let artifact = authorize_path(context, &self.0.artifact, false)?;
        // This authorization intentionally occurs before constructing or
        // connecting a socket. A refused destination has no network effect.
        let ip = ensure_network_authorized(context.manifest, context.profile, &self.0.destination)
            .map_err(|error| ActionFailure::blocked("network_scope_blocked", error))?;
        let artifact_path = context
            .root
            .resolve_existing(&artifact)
            .map_err(|error| ActionFailure::blocked("path_rejected", error))?;
        let body = read_file_bounded(&artifact_path, context.manifest.limits.max_artifact_bytes)
            .map_err(|error| ActionFailure::blocked("artifact_limit_blocked", error))?;
        let timeout = Duration::from_millis(context.manifest.limits.timeout_ms);
        let socket = SocketAddr::new(ip, self.0.destination.port);
        let mut stream = TcpStream::connect_timeout(&socket, timeout)
            .map_err(|error| ActionFailure::failed("loopback_connect_failed", error.to_string()))?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|_| stream.set_write_timeout(Some(timeout)))
            .map_err(|error| {
                ActionFailure::failed("loopback_timeout_setup_failed", error.to_string())
            })?;
        let request = format!(
            "POST /bluefire/v1/artifact HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/octet-stream\r\nX-BlueFire-SHA256: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.0.destination.host,
            self.0.destination.port,
            crate::contract::sha256_hex(&body),
            body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .and_then(|_| stream.write_all(&body))
            .and_then(|_| stream.flush())
            .map_err(|error| ActionFailure::failed("loopback_write_failed", error.to_string()))?;
        let _ = stream.shutdown(Shutdown::Write);
        let response = read_socket_bounded(&mut stream, context.manifest.limits.max_stdout_bytes)
            .map_err(|error| ActionFailure::failed("loopback_read_failed", error))?;
        let status_code = response
            .text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok());
        let status = if status_code.is_some_and(|code| (200..300).contains(&code)) {
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
                "sha256": crate::contract::sha256_hex(&body),
                "http_status": status_code,
            }),
            stdout: response,
            stderr: BoundedOutput::default(),
            receipt_ids: Vec::new(),
            cleanup: None,
            error: if status == TaskStatus::Success {
                None
            } else {
                Some(ErrorRecord {
                    code: "loopback_response_failed".to_string(),
                    message: "loopback receiver did not return a 2xx response".to_string(),
                })
            },
            limitations: vec![
                "Literal loopback IP only; DNS, redirects, and proxy environment variables are not used."
                    .to_string(),
            ],
        })
    }
}

struct NetworkLoopbackAction;
static NETWORK_LOOPBACK_DESCRIPTOR: ActionDescriptor = ActionDescriptor {
    action_id: "sandbox.network.loopback.v1",
    behavior_ids: &["sandbox.network.loopback.v1"],
    platforms: ALL_PLATFORMS,
    capabilities: &[Capability::FilesystemRead, Capability::NetworkLoopback],
    safety_tier: SafetyTier::Controlled,
    filesystem_effect: false,
    network_effect: true,
    process_effect: false,
    cleanup_receipt: false,
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
        context
            .root
            .write_new(&target, &bytes)
            .map_err(|error| ActionFailure::failed("export_write_failed", error))?;
        let receipt_id = store_receipt(
            context,
            receipt_paths(target.relative.clone(), &bytes, &target.created_directories),
        )?;
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
    action_id: "sandbox.export.local.v1",
    behavior_ids: &["sandbox.export.local.v1"],
    platforms: ALL_PLATFORMS,
    capabilities: &[
        Capability::FilesystemRead,
        Capability::FilesystemWrite,
        Capability::ExportLocal,
    ],
    safety_tier: SafetyTier::Controlled,
    filesystem_effect: true,
    network_effect: false,
    process_effect: false,
    cleanup_receipt: true,
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
        for receipt_id in &self.0.receipt_ids {
            let record = match context.root.load_receipt(receipt_id) {
                Ok(Some(record)) => record,
                Ok(None) => {
                    report.already_absent_receipts.push(receipt_id.clone());
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
            }
            if !receipt_failed {
                if let Err(error) = context.root.delete_receipt(receipt_id) {
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
    action_id: "sandbox.cleanup.v1",
    behavior_ids: &["sandbox.cleanup.v1"],
    platforms: ALL_PLATFORMS,
    capabilities: &[Capability::FilesystemWrite, Capability::Cleanup],
    safety_tier: SafetyTier::Safe,
    filesystem_effect: true,
    network_effect: false,
    process_effect: false,
    cleanup_receipt: false,
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
static COLLECTION_STAGE: CollectionStageAction = CollectionStageAction;
static NETWORK_LOOPBACK: NetworkLoopbackAction = NetworkLoopbackAction;
static EXPORT_LOCAL: ExportLocalAction = ExportLocalAction;
static CLEANUP: CleanupAction = CleanupAction;

static REGISTRY: [&'static dyn Action; 8] = [
    &FIXTURE_CREATE,
    &FIXTURE_TRANSFORM,
    &DISCOVERY_LIST,
    &DISCOVERY_METADATA,
    &COLLECTION_STAGE,
    &NETWORK_LOOPBACK,
    &EXPORT_LOCAL,
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
            "sandbox.collection.stage.v1",
            "sandbox.network.loopback.v1",
            "sandbox.export.local.v1",
            "sandbox.cleanup.v1",
        ]);
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), registered_actions().len());
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
