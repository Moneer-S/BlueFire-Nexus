use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use bluefire_runner::contract::{
    canonical_json, sha256_hex, MANIFEST_SCHEMA_VERSION, PROFILE_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
};
use bluefire_runner::safety::{owned_directories, owned_file, SafeRoot};
use bluefire_runner::{
    inventory, seal_manifest, seal_profile, utc_now, Approval, Capability, EvidenceKind,
    ExecutionLimits, ExecutionManifest, NetworkDestination, Platform, RunMode, Runner,
    RunnerProfile, SafetyTier, TargetScope, TaskResult, TaskStatus,
};
use chrono::Duration;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static RECEIVER_ENV_LOCK: Mutex<()> = Mutex::new(());
const RECEIVER_TASK_ID: &str =
    "execute-1111111111111111111111111111111111111111111111111111111111111111";
const RECEIVER_TASK_KEY: [u8; 32] = [0x42; 32];

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> std::io::Result<Self> {
        for _attempt in 0..100 {
            let suffix = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "bluefire-runner-test-{}-{suffix}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate an isolated runner test directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn assert_no_workspace_artifacts(root: &Path) {
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        assert_eq!(
            entry.file_name().to_string_lossy(),
            ".bluefire",
            "unexpected workspace artifact remained at {}",
            entry.path().display()
        );
        let metadata = fs::symlink_metadata(entry.path()).unwrap();
        assert!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "runner state is not a real directory"
        );
        for child in fs::read_dir(entry.path()).unwrap() {
            let child = child.unwrap();
            let name = child.file_name().to_string_lossy().into_owned();
            assert!(
                matches!(name.as_str(), "receipts" | "receipt-commits" | "staging"),
                "unexpected runner state entry remained at {}",
                child.path().display()
            );
            let metadata = fs::symlink_metadata(child.path()).unwrap();
            assert!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "runner state child is not a real directory: {}",
                child.path().display()
            );
            assert!(
                fs::read_dir(child.path()).unwrap().next().is_none(),
                "runner state child retained a file: {}",
                child.path().display()
            );
        }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn directory_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(target, link)
    }
}

fn runner_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bluefire-runner"))
}

fn runner() -> Runner {
    Runner::new().unwrap()
}

fn limits() -> ExecutionLimits {
    ExecutionLimits {
        timeout_ms: 5_000,
        max_stdout_bytes: 8 * 1024,
        max_stderr_bytes: 8 * 1024,
        max_artifact_bytes: 1024 * 1024,
        max_files: 32,
    }
}

fn profile(root: &TempDir, network: Vec<NetworkDestination>) -> RunnerProfile {
    let mut profile = RunnerProfile {
        schema_version: PROFILE_SCHEMA_VERSION.to_string(),
        profile_id: "profile:test".to_string(),
        runner_id: "runner:test".to_string(),
        platform: Platform::current(),
        sandbox_root: root.path().to_path_buf(),
        allowed_actions: inventory()
            .into_iter()
            .map(|descriptor| descriptor.action_id.to_string())
            .collect(),
        control_blocked_actions: Vec::new(),
        action_bindings: Vec::new(),
        provider_bindings: Vec::new(),
        provider_artifacts: Vec::new(),
        capabilities: vec![
            Capability::FilesystemRead,
            Capability::FilesystemWrite,
            Capability::ProcessSpawn,
            Capability::ProcessDiscovery,
            Capability::SystemDiscovery,
            Capability::NetworkLoopback,
            Capability::ExportLocal,
            Capability::SandboxRestricted,
            Capability::Cleanup,
        ],
        max_safety_tier: SafetyTier::Restricted,
        approval_required_at_or_above: None,
        target_scope: TargetScope {
            filesystem: vec![".".to_string()],
            network,
        },
        limits: limits(),
        policy_digest: String::new(),
    };
    seal_profile(&mut profile);
    profile
}

fn manifest(profile: &RunnerProfile, action_id: &str, params: Value) -> ExecutionManifest {
    let descriptor = inventory()
        .into_iter()
        .find(|descriptor| descriptor.action_id == action_id)
        .expect("test action is registered");
    let requested_at = utc_now() - Duration::seconds(1);
    let mut manifest = ExecutionManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        request_id: format!("request:{}", action_id.replace('.', "-")),
        run_id: "run:test".to_string(),
        step_id: format!("step:{}", action_id.replace('.', "-")),
        behavior_id: descriptor.behavior_ids[0].to_string(),
        action_id: action_id.to_string(),
        execution_binding: None,
        provider_binding: None,
        mode: RunMode::Execute,
        runner_id: profile.runner_id.clone(),
        runner_profile_id: profile.profile_id.clone(),
        platform: Platform::current(),
        requested_at,
        expires_at: requested_at + Duration::minutes(10),
        params,
        target_scope: profile.target_scope.clone(),
        required_capabilities: descriptor.capabilities.to_vec(),
        safety_tier: descriptor.safety_tier,
        limits: limits(),
        cleanup_action_id: "sandbox.cleanup.v1".to_string(),
        policy_digest: profile.policy_digest.clone(),
        approval: None,
        evidence_refs: vec![format!("sha256:{}", "1".repeat(64))],
        request_hash: String::new(),
    };
    seal_manifest(&mut manifest);
    manifest
}

fn bind_to_profile(manifest: &mut ExecutionManifest, profile: &RunnerProfile) {
    manifest.runner_id = profile.runner_id.clone();
    manifest.runner_profile_id = profile.profile_id.clone();
    manifest.platform = profile.platform;
    manifest.policy_digest = profile.policy_digest.clone();
    seal_manifest(manifest);
}

fn create_fixture(_root: &TempDir, profile: &RunnerProfile, path: &str) -> TaskResult {
    let request = manifest(
        profile,
        "sandbox.fixture.create.v1",
        json!({"path": path, "content_template": "telemetry-seed", "record_count": 1}),
    );
    runner().execute(request, profile.clone())
}

#[test]
fn valid_fixture_has_structured_provenance_and_receipt() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let result = create_fixture(&root, &profile, "artifacts/seed.txt");
    assert_eq!(result.schema_version, RESULT_SCHEMA_VERSION);
    assert_eq!(result.status, TaskStatus::Success, "{result:#?}");
    assert!(root.path().join("artifacts/seed.txt").is_file());
    assert_eq!(result.receipt_ids.len(), 1);
    let receipt_id = &result.receipt_ids[0];
    let receipt: Value = serde_json::from_slice(
        &fs::read(
            root.path()
                .join(".bluefire/receipts")
                .join(format!("{receipt_id}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["schema_version"], "bluefire.receipt/v1");
    assert_eq!(receipt["receipt_id"], *receipt_id);
    assert!(receipt["workspace_id"].as_str().is_some());
    let commit: Value = serde_json::from_slice(
        &fs::read(
            root.path()
                .join(".bluefire/receipt-commits")
                .join(format!("{receipt_id}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(commit["schema_version"], "bluefire.receipt-commit/v1");
    assert_eq!(commit["receipt_id"], *receipt_id);
    assert!(result.request_hash.starts_with("sha256:"));
    assert_eq!(result.policy_digest, profile.policy_digest);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.evidence[0].kind, EvidenceKind::Executed);
    assert!(result.evidence[0].evidence_id.starts_with("sha256:"));
    assert_eq!(result.evidence[0].references.len(), 1);
}

#[test]
fn fixture_record_count_is_bounded_and_creates_exact_deterministic_jsonl_records() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let result = runner().execute(
        manifest(
            &profile,
            "sandbox.fixture.create.v1",
            json!({
                "path": "fixtures/three.jsonl",
                "content_template": "telemetry-seed",
                "record_count": 3
            }),
        ),
        profile.clone(),
    );
    assert_eq!(result.status, TaskStatus::Success);
    assert_eq!(result.output["record_count"], 3);
    assert_eq!(result.output["format"], "jsonl");
    let records = fs::read_to_string(root.path().join("fixtures/three.jsonl")).unwrap();
    let parsed = records
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed[0]["record_id"], "synthetic-001");
    assert_eq!(parsed[2]["value"], "telemetry-value-003");

    for (record_count, path) in [(0, "fixtures/zero.jsonl"), (101, "fixtures/too-many.jsonl")] {
        let blocked = runner().execute(
            manifest(
                &profile,
                "sandbox.fixture.create.v1",
                json!({
                    "path": path,
                    "content_template": "telemetry-seed",
                    "record_count": record_count
                }),
            ),
            profile.clone(),
        );
        assert_eq!(blocked.status, TaskStatus::ControlBlocked);
        assert!(!root.path().join(path).exists());
    }
}

#[test]
fn simulate_unknown_action_and_unknown_parameter_never_execute() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());

    let mut simulate = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "simulate.txt", "content_template": "empty", "record_count": 1}),
    );
    simulate.mode = RunMode::Simulate;
    seal_manifest(&mut simulate);
    let result = runner().execute(simulate, profile.clone());
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert!(!root.path().join("simulate.txt").exists());

    let mut unknown = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "unknown.txt", "content_template": "empty", "record_count": 1}),
    );
    unknown.action_id = "sandbox.not-registered.v1".to_string();
    unknown.behavior_id = "behavior.sandbox.unknown.v1".to_string();
    unknown.required_capabilities.clear();
    seal_manifest(&mut unknown);
    let result = runner().execute(unknown, profile.clone());
    assert_eq!(result.status, TaskStatus::Refused);
    assert!(!root.path().join("unknown.txt").exists());

    let command = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({
            "path": "command.txt",
            "content_template": "empty",
            "record_count": 1,
            "command": "whoami"
        }),
    );
    let result = runner().execute(command, profile);
    assert_eq!(result.status, TaskStatus::Refused);
    assert!(!root.path().join("command.txt").exists());
}

#[test]
fn platform_capability_tier_allowlist_and_control_block_are_authoritative() {
    let root = TempDir::new().unwrap();
    let base_profile = profile(&root, Vec::new());
    let base_manifest = manifest(
        &base_profile,
        "sandbox.fixture.create.v1",
        json!({"path": "blocked.txt", "content_template": "empty", "record_count": 1}),
    );

    let mut wrong_platform = base_manifest.clone();
    wrong_platform.platform = match Platform::current() {
        Platform::Windows => Platform::Linux,
        Platform::Linux | Platform::Macos => Platform::Windows,
    };
    seal_manifest(&mut wrong_platform);
    assert_eq!(
        runner()
            .execute(wrong_platform, base_profile.clone())
            .status,
        TaskStatus::ControlBlocked
    );

    let mut missing_declared_capability = base_manifest.clone();
    missing_declared_capability.required_capabilities.clear();
    seal_manifest(&mut missing_declared_capability);
    assert_eq!(
        runner()
            .execute(missing_declared_capability, base_profile.clone())
            .status,
        TaskStatus::ControlBlocked
    );

    let mut weak_profile = base_profile.clone();
    weak_profile
        .capabilities
        .retain(|capability| *capability != Capability::FilesystemWrite);
    seal_profile(&mut weak_profile);
    let mut weak_manifest = base_manifest.clone();
    bind_to_profile(&mut weak_manifest, &weak_profile);
    assert_eq!(
        runner().execute(weak_manifest, weak_profile).status,
        TaskStatus::ControlBlocked
    );

    let mut wrong_tier = base_manifest.clone();
    wrong_tier.safety_tier = SafetyTier::Controlled;
    seal_manifest(&mut wrong_tier);
    assert_eq!(
        runner().execute(wrong_tier, base_profile.clone()).status,
        TaskStatus::ControlBlocked
    );

    let mut not_allowed_profile = base_profile.clone();
    not_allowed_profile
        .allowed_actions
        .retain(|action| action != "sandbox.fixture.create.v1");
    seal_profile(&mut not_allowed_profile);
    let mut not_allowed_manifest = base_manifest.clone();
    bind_to_profile(&mut not_allowed_manifest, &not_allowed_profile);
    assert_eq!(
        runner()
            .execute(not_allowed_manifest, not_allowed_profile)
            .status,
        TaskStatus::ControlBlocked
    );

    let mut blocked_profile = base_profile.clone();
    blocked_profile
        .control_blocked_actions
        .push("sandbox.fixture.create.v1".to_string());
    seal_profile(&mut blocked_profile);
    let mut blocked_manifest = base_manifest;
    bind_to_profile(&mut blocked_manifest, &blocked_profile);
    let result = runner().execute(blocked_manifest, blocked_profile);
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "action_control_blocked");
    assert!(!root.path().join("blocked.txt").exists());
}

#[test]
fn target_scope_path_traversal_and_resource_expansion_are_blocked() {
    let root = TempDir::new().unwrap();
    let mut profile = profile(&root, Vec::new());
    profile.target_scope.filesystem = vec!["approved".to_string()];
    profile.limits.timeout_ms = 100;
    seal_profile(&mut profile);

    let mut expanded_scope = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "approved/a.txt", "content_template": "empty", "record_count": 1}),
    );
    expanded_scope.target_scope.filesystem = vec![".".to_string()];
    seal_manifest(&mut expanded_scope);
    assert_eq!(
        runner().execute(expanded_scope, profile.clone()).status,
        TaskStatus::ControlBlocked
    );

    let mut traversal = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "../escape.txt", "content_template": "empty", "record_count": 1}),
    );
    traversal.target_scope.filesystem = vec!["approved".to_string()];
    traversal.limits.timeout_ms = 100;
    seal_manifest(&mut traversal);
    assert_eq!(
        runner().execute(traversal, profile.clone()).status,
        TaskStatus::ControlBlocked
    );

    let mut timeout = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "approved/timeout.txt", "content_template": "empty", "record_count": 1}),
    );
    timeout.limits.timeout_ms = 101;
    seal_manifest(&mut timeout);
    assert_eq!(
        runner().execute(timeout, profile).status,
        TaskStatus::ControlBlocked
    );
    assert!(!root.path().join("approved/timeout.txt").exists());
}

#[test]
fn approval_is_bound_to_the_normalized_request() {
    let root = TempDir::new().unwrap();
    let mut profile = profile(&root, Vec::new());
    profile.approval_required_at_or_above = Some(SafetyTier::Safe);
    seal_profile(&mut profile);

    let request = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "approved.txt", "content_template": "empty", "record_count": 1}),
    );
    assert_eq!(
        runner().execute(request.clone(), profile.clone()).status,
        TaskStatus::ControlBlocked
    );

    let now = utc_now();
    let mut approved = request;
    approved.approval = Some(Approval {
        approved_by: "operator:test".to_string(),
        approved_at: now - Duration::seconds(1),
        expires_at: now + Duration::minutes(5),
        request_hash: String::new(),
    });
    seal_manifest(&mut approved);
    assert_eq!(
        runner().execute(approved, profile).status,
        TaskStatus::Success
    );
}

#[cfg(unix)]
#[test]
fn symlink_escape_is_blocked_without_following_the_link() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("secret.txt"), b"outside").unwrap();
    symlink(
        outside.path().join("secret.txt"),
        root.path().join("link.txt"),
    )
    .unwrap();
    let profile = profile(&root, Vec::new());
    let request = manifest(
        &profile,
        "sandbox.discovery.metadata.v1",
        json!({"path": "link.txt"}),
    );
    let result = runner().execute(request, profile);
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(
        fs::read(outside.path().join("secret.txt")).unwrap(),
        b"outside"
    );
}

#[test]
fn fixed_transform_is_in_process_and_has_no_caller_executable() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    assert_eq!(
        create_fixture(&root, &profile, "input.txt").status,
        TaskStatus::Success
    );
    let mut request = manifest(
        &profile,
        "sandbox.fixture.transform.v1",
        json!({
            "input": "input.txt",
            "output": "output.txt",
            "redact_values": true
        }),
    );
    seal_manifest(&mut request);
    let result = runner().execute(request, profile);
    assert_eq!(result.status, TaskStatus::Success);
    assert!(result.stdout.text.is_empty());
    assert_eq!(
        result.output["implementation"],
        "in_process_reviewed_jsonl_transform"
    );
    let bytes = fs::read(root.path().join("output.txt")).unwrap();
    assert_eq!(
        bytes,
        b"{\"record_id\":\"synthetic-001\",\"synthetic\":true,\"template\":\"telemetry-seed\",\"value\":\"synthetic-redacted\"}\n"
    );
}

#[test]
fn fixed_transform_false_canonicalizes_and_preserves_synthetic_values() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    assert_eq!(
        create_fixture(&root, &profile, "input.jsonl").status,
        TaskStatus::Success
    );
    let original = fs::read(root.path().join("input.jsonl")).unwrap();
    let result = runner().execute(
        manifest(
            &profile,
            "sandbox.fixture.transform.v1",
            json!({
                "input": "input.jsonl",
                "output": "preserved.jsonl",
                "redact_values": false
            }),
        ),
        profile,
    );
    assert_eq!(result.status, TaskStatus::Success);
    assert_eq!(result.output["redact_values"], false);
    assert_eq!(result.output["redacted_value_count"], 0);
    assert_eq!(
        fs::read(root.path().join("preserved.jsonl")).unwrap(),
        original
    );
}

#[test]
fn transform_rejects_non_generated_values_and_misaligned_record_ids_before_writing() {
    for (name, bytes) in [
        (
            "malicious-value",
            b"{\"record_id\":\"synthetic-001\",\"synthetic\":true,\"template\":\"telemetry-seed\",\"value\":\"REAL_SECRET\"}\n".as_slice(),
        ),
        (
            "misaligned-id",
            b"{\"record_id\":\"synthetic-100\",\"synthetic\":true,\"template\":\"telemetry-seed\",\"value\":\"telemetry-value-100\"}\n".as_slice(),
        ),
    ] {
        let root = TempDir::new().unwrap();
        fs::write(root.path().join("input.jsonl"), bytes).unwrap();
        let profile = profile(&root, Vec::new());
        let result = runner().execute(
            manifest(
                &profile,
                "sandbox.fixture.transform.v1",
                json!({
                    "input": "input.jsonl",
                    "output": format!("{name}.jsonl"),
                    "redact_values": true
                }),
            ),
            profile,
        );
        assert_eq!(result.status, TaskStatus::Failed);
        assert!(!root.path().join(format!("{name}.jsonl")).exists());
        assert!(result.receipt_ids.is_empty());
    }
}

#[test]
fn transform_and_collection_reject_mixed_fixture_identity_before_writing() {
    for (name, bytes) in [
        (
            "mixed-template",
            concat!(
                "{\"record_id\":\"synthetic-001\",\"synthetic\":true,\"template\":\"telemetry-seed\",\"value\":\"telemetry-value-001\"}\n",
                "{\"record_id\":\"synthetic-002\",\"synthetic\":true,\"template\":\"harmless-document\",\"value\":\"document-value-002\"}\n"
            ),
        ),
        (
            "mixed-redaction",
            concat!(
                "{\"record_id\":\"synthetic-001\",\"synthetic\":true,\"template\":\"telemetry-seed\",\"value\":\"telemetry-value-001\"}\n",
                "{\"record_id\":\"synthetic-002\",\"synthetic\":true,\"template\":\"telemetry-seed\",\"value\":\"synthetic-redacted\"}\n"
            ),
        ),
    ] {
        let root = TempDir::new().unwrap();
        fs::write(root.path().join("input.jsonl"), bytes).unwrap();
        let profile = profile(&root, Vec::new());
        let transformed = runner().execute(
            manifest(
                &profile,
                "sandbox.fixture.transform.v1",
                json!({
                    "input": "input.jsonl",
                    "output": format!("{name}-transform.jsonl"),
                    "redact_values": true
                }),
            ),
            profile.clone(),
        );
        assert_eq!(transformed.status, TaskStatus::Failed);
        assert!(!root
            .path()
            .join(format!("{name}-transform.jsonl"))
            .exists());

        let collected = runner().execute(
            manifest(
                &profile,
                "sandbox.collection.stage.v1",
                json!({
                    "inputs": ["input.jsonl"],
                    "destination_directory": format!("{name}-stage"),
                    "bundle_format": "jsonl"
                }),
            ),
            profile,
        );
        assert_eq!(collected.status, TaskStatus::Failed);
        assert!(!root
            .path()
            .join(format!("{name}-stage/bundle.jsonl"))
            .exists());
    }
}

#[test]
fn transform_blocks_more_than_one_hundred_records_before_writing() {
    let root = TempDir::new().unwrap();
    let mut bytes = String::new();
    for index in 1..=101 {
        bytes.push_str(&format!(
            "{{\"record_id\":\"synthetic-{index:03}\",\"synthetic\":true,\"template\":\"telemetry-seed\",\"value\":\"telemetry-value-{index:03}\"}}\n"
        ));
    }
    fs::write(root.path().join("input.jsonl"), bytes).unwrap();
    let profile = profile(&root, Vec::new());
    let result = runner().execute(
        manifest(
            &profile,
            "sandbox.fixture.transform.v1",
            json!({"input": "input.jsonl", "output": "output.jsonl", "redact_values": true}),
        ),
        profile,
    );
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert!(!root.path().join("output.jsonl").exists());
    assert!(result.receipt_ids.is_empty());
}

#[test]
fn legacy_private_transform_subcommand_is_not_an_invokable_bypass() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("input.txt"), b"caller-controlled").unwrap();
    let output = Command::new(runner_binary())
        .arg("__private-transform")
        .arg(root.path())
        .arg("input.txt")
        .arg("output.txt")
        .arg("uppercase-ascii")
        .env("BLUEFIRE_RUNNER_PRIVATE_TRANSFORM", "v1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!root.path().join("output.txt").exists());
}

#[test]
fn collection_invalid_input_fails_closed_without_artifact_or_receipt() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    assert_eq!(
        create_fixture(&root, &profile, "input.jsonl").status,
        TaskStatus::Success
    );
    fs::write(
        root.path().join("input.jsonl"),
        b"{\"record_id\":\"synthetic-001\",\"synthetic\":true,\"template\":\"telemetry-seed\",\"value\":\"not-generated\"}\n",
    )
    .unwrap();
    let request = manifest(
        &profile,
        "sandbox.collection.stage.v1",
        json!({
            "inputs": ["input.jsonl"],
            "destination_directory": "stage",
            "bundle_format": "jsonl"
        }),
    );
    let result = runner().execute(request, profile);
    assert_eq!(result.status, TaskStatus::Failed);
    assert!(result.receipt_ids.is_empty());
    assert!(!root.path().join("stage/bundle.jsonl").exists());
}

#[test]
fn exact_metadata_and_collection_materialize_each_bundle_format() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    assert_eq!(
        create_fixture(&root, &profile, "fixtures/b.jsonl").status,
        TaskStatus::Success
    );
    assert_eq!(
        create_fixture(&root, &profile, "fixtures/a.jsonl").status,
        TaskStatus::Success
    );

    let metadata = runner().execute(
        manifest(
            &profile,
            "sandbox.discovery.metadata.v1",
            json!({"path": "fixtures/a.jsonl"}),
        ),
        profile.clone(),
    );
    assert_eq!(metadata.status, TaskStatus::Success);
    assert_eq!(metadata.output["returned_entries"], 1);
    assert_eq!(metadata.output["entries"][0]["path"], "fixtures/a.jsonl");

    let jsonl = runner().execute(
        manifest(
            &profile,
            "sandbox.collection.stage.v1",
            json!({
                "inputs": ["fixtures/a.jsonl"],
                "destination_directory": "stage-jsonl",
                "bundle_format": "jsonl"
            }),
        ),
        profile.clone(),
    );
    assert_eq!(jsonl.status, TaskStatus::Success);
    assert_eq!(jsonl.output["artifact"], "stage-jsonl/bundle.jsonl");
    assert_eq!(jsonl.output["record_count"], 1);
    assert_eq!(jsonl.output["complete"], true);
    assert_eq!(
        fs::read_to_string(root.path().join("stage-jsonl/bundle.jsonl"))
            .unwrap()
            .lines()
            .count(),
        1
    );

    let json = runner().execute(
        manifest(
            &profile,
            "sandbox.collection.stage.v1",
            json!({
                "inputs": ["fixtures/b.jsonl"],
                "destination_directory": "stage-json",
                "bundle_format": "json"
            }),
        ),
        profile.clone(),
    );
    assert_eq!(json.status, TaskStatus::Success);
    assert_eq!(json.output["artifact"], "stage-json/bundle.json");
    assert_eq!(json.output["complete"], true);
    let document: Value =
        serde_json::from_slice(&fs::read(root.path().join("stage-json/bundle.json")).unwrap())
            .unwrap();
    assert_eq!(document["schema_version"], "bluefire.synthetic-bundle.v1");
    assert_eq!(document["records"].as_array().unwrap().len(), 1);

    for label in ["ephemeral", "review"] {
        let exported = runner().execute(
            manifest(
                &profile,
                "sandbox.export.local.v1",
                json!({
                    "source": "stage-jsonl/bundle.jsonl",
                    "retention_label": label
                }),
            ),
            profile.clone(),
        );
        assert_eq!(exported.status, TaskStatus::Success);
        assert_eq!(exported.output["retention_label"], label);
        assert_eq!(
            exported.output["artifact"],
            format!("exports/{label}/bundle.bin")
        );
        assert!(root
            .path()
            .join(format!("exports/{label}/bundle.bin"))
            .is_file());
    }
}

#[test]
fn system_process_recursive_and_archive_actions_are_bounded_and_typed() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());

    let system = runner().execute(
        manifest(&profile, "endpoint.discovery.system.v1", json!({})),
        profile.clone(),
    );
    assert_eq!(system.status, TaskStatus::Success);
    assert_eq!(system.output["operating_system"], std::env::consts::OS);
    assert!(system.output["logical_processors"].as_u64().unwrap() >= 1);

    let processes = runner().execute(
        manifest(
            &profile,
            "endpoint.discovery.processes.v1",
            json!({"max_entries": 4}),
        ),
        profile.clone(),
    );
    assert!(matches!(
        processes.status,
        TaskStatus::Success | TaskStatus::Partial
    ));
    assert!(processes.output["entries"]
        .as_array()
        .is_some_and(|entries| !entries.is_empty() && entries.len() <= 4));

    let first = create_fixture(&root, &profile, "tree/a.txt");
    let second = create_fixture(&root, &profile, "tree/deep/b.txt");
    assert_eq!(first.status, TaskStatus::Success);
    assert_eq!(second.status, TaskStatus::Success);

    let recursive = runner().execute(
        manifest(
            &profile,
            "sandbox.discovery.recursive.v1",
            json!({"path": "tree", "max_entries": 8, "max_depth": 3}),
        ),
        profile.clone(),
    );
    assert_eq!(recursive.status, TaskStatus::Success);
    let paths = recursive.output["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["path"].as_str())
        .collect::<Vec<_>>();
    assert!(paths.contains(&"tree/a.txt"));
    assert!(paths.contains(&"tree/deep/b.txt"));

    let shallow = runner().execute(
        manifest(
            &profile,
            "sandbox.discovery.recursive.v1",
            json!({"path": "tree", "max_entries": 8, "max_depth": 1}),
        ),
        profile.clone(),
    );
    assert_eq!(shallow.status, TaskStatus::Success);
    assert!(shallow.output["entries"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["depth"].as_u64().is_some_and(|depth| depth <= 1)));
    assert!(!shallow.output["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["path"] == "tree/deep/b.txt"));

    let count_limited = runner().execute(
        manifest(
            &profile,
            "sandbox.discovery.recursive.v1",
            json!({"path": "tree", "max_entries": 1, "max_depth": 3}),
        ),
        profile.clone(),
    );
    assert_eq!(count_limited.status, TaskStatus::Success);
    assert_eq!(count_limited.output["entries"].as_array().unwrap().len(), 1);
    assert_eq!(count_limited.output["truncated"], true);

    let archived = runner().execute(
        manifest(
            &profile,
            "sandbox.archive.tar.v1",
            json!({
                "inputs": ["tree/deep/b.txt", "tree/a.txt"],
                "destination": "archives/tree.tar"
            }),
        ),
        profile,
    );
    assert_eq!(archived.status, TaskStatus::Success);
    assert_eq!(archived.output["format"], "ustar");
    assert_eq!(archived.output["entry_count"], 2);
    assert_eq!(archived.receipt_ids.len(), 1);
    let archive = fs::read(root.path().join("archives/tree.tar")).unwrap();
    assert_eq!(&archive[257..263], b"ustar\0");
    assert_eq!(archive.len() % 512, 0);
}

#[test]
fn receipt_cleanup_is_idempotent_and_refuses_tampered_files() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let created = create_fixture(&root, &profile, "owned.txt");
    let receipt = created.receipt_ids[0].clone();
    let cleanup = manifest(
        &profile,
        "sandbox.cleanup.v1",
        json!({"receipt_ids": [receipt.clone()]}),
    );
    let result = runner().execute(cleanup.clone(), profile.clone());
    assert_eq!(result.status, TaskStatus::Success, "{result:#?}");
    assert!(!root.path().join("owned.txt").exists());
    assert_eq!(
        runner().execute(cleanup, profile.clone()).status,
        TaskStatus::Success
    );

    let created = create_fixture(&root, &profile, "tampered.txt");
    fs::write(root.path().join("tampered.txt"), b"changed after receipt").unwrap();
    let cleanup = manifest(
        &profile,
        "sandbox.cleanup.v1",
        json!({"receipt_ids": [created.receipt_ids[0].clone()]}),
    );
    let result = runner().execute(cleanup, profile);
    assert_eq!(result.status, TaskStatus::CleanupFailed);
    assert!(root.path().join("tampered.txt").exists());
    assert!(!result.cleanup.unwrap().retained_paths.is_empty());
}

#[test]
fn cleanup_refuses_a_receipt_whose_owned_path_metadata_was_rewritten() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let created = create_fixture(&root, &profile, "intent-owner.txt");
    assert_eq!(created.status, TaskStatus::Success);
    let receipt_id = &created.receipt_ids[0];
    let receipt_path = root
        .path()
        .join(".bluefire/receipts")
        .join(format!("{receipt_id}.json"));
    let owner_bytes = fs::read(root.path().join("intent-owner.txt")).unwrap();
    fs::write(root.path().join("unowned-victim.txt"), &owner_bytes).unwrap();

    let mut receipt: Value = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    receipt["paths"][0]["relative_path"] = json!("unowned-victim.txt");
    fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    let cleaned = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": [receipt_id]}),
        ),
        profile,
    );
    assert_eq!(cleaned.status, TaskStatus::CleanupFailed);
    assert!(root.path().join("intent-owner.txt").exists());
    assert!(root.path().join("unowned-victim.txt").exists());
    assert!(cleaned
        .cleanup
        .unwrap()
        .errors
        .iter()
        .any(|error| error.contains("content digest is invalid")));
}

#[test]
fn cleanup_refuses_missing_receipt_intent_when_durable_commit_remains() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let created = create_fixture(&root, &profile, "orphan-guard.jsonl");
    assert_eq!(created.status, TaskStatus::Success);
    let receipt_id = created.receipt_ids[0].clone();
    let receipt_path = root
        .path()
        .join(".bluefire/receipts")
        .join(format!("{receipt_id}.json"));
    let commit_path = root
        .path()
        .join(".bluefire/receipt-commits")
        .join(format!("{receipt_id}.json"));
    fs::remove_file(receipt_path).unwrap();
    assert!(commit_path.is_file());

    let result = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": [receipt_id]}),
        ),
        profile,
    );
    assert_eq!(result.status, TaskStatus::CleanupFailed);
    assert!(root.path().join("orphan-guard.jsonl").is_file());
    assert!(commit_path.is_file());
    assert_eq!(result.cleanup.as_ref().unwrap().verified_receipts, 0);
}

#[test]
fn cleanup_recovers_a_valid_object_left_in_receipt_bound_quarantine() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let relative = "recoverable-quarantine.jsonl";
    let created = create_fixture(&root, &profile, relative);
    assert_eq!(created.status, TaskStatus::Success);
    let receipt_id = created.receipt_ids[0].clone();
    let quarantine_identity = sha256_hex(format!("{receipt_id}\0{relative}").as_bytes());
    let quarantine = root
        .path()
        .join(".bluefire/staging")
        .join(format!("cleanup-{quarantine_identity}.quarantine"));
    fs::rename(root.path().join(relative), &quarantine).unwrap();

    let result = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": [receipt_id.clone()]}),
        ),
        profile,
    );
    assert_eq!(result.status, TaskStatus::Success);
    assert!(!root.path().join(relative).exists());
    assert!(!quarantine.exists());
    assert!(!root
        .path()
        .join(".bluefire/receipts")
        .join(format!("{receipt_id}.json"))
        .exists());
    assert_eq!(result.cleanup.as_ref().unwrap().verified_receipts, 1);
}

#[test]
fn cleanup_restores_a_changed_quarantined_object_and_retains_recovery_evidence() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let relative = "changed-quarantine.jsonl";
    let created = create_fixture(&root, &profile, relative);
    assert_eq!(created.status, TaskStatus::Success);
    let receipt_id = created.receipt_ids[0].clone();
    let quarantine_identity = sha256_hex(format!("{receipt_id}\0{relative}").as_bytes());
    let quarantine = root
        .path()
        .join(".bluefire/staging")
        .join(format!("cleanup-{quarantine_identity}.quarantine"));
    fs::rename(root.path().join(relative), &quarantine).unwrap();
    fs::write(&quarantine, b"changed after quarantine").unwrap();

    let result = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": [receipt_id.clone()]}),
        ),
        profile,
    );
    assert_eq!(result.status, TaskStatus::CleanupFailed);
    assert_eq!(
        fs::read(root.path().join(relative)).unwrap(),
        b"changed after quarantine"
    );
    assert!(!quarantine.exists());
    assert!(root
        .path()
        .join(".bluefire/receipts")
        .join(format!("{receipt_id}.json"))
        .exists());
    assert!(root
        .path()
        .join(".bluefire/receipt-commits")
        .join(format!("{receipt_id}.json"))
        .exists());
    assert!(result
        .cleanup
        .as_ref()
        .unwrap()
        .errors
        .iter()
        .any(|error| error.contains("restored without overwrite and retained")));
}

#[test]
fn cleanup_never_follows_a_replaced_source_parent_to_a_matching_external_file() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let relative = "replaced-parent/owned.jsonl";
    let created = create_fixture(&root, &profile, relative);
    assert_eq!(created.status, TaskStatus::Success);
    let expected = fs::read(root.path().join(relative)).unwrap();

    fs::remove_file(root.path().join(relative)).unwrap();
    fs::remove_dir(root.path().join("replaced-parent")).unwrap();
    fs::write(outside.path().join("owned.jsonl"), &expected).unwrap();
    if let Err(error) = directory_symlink(outside.path(), &root.path().join("replaced-parent")) {
        #[cfg(windows)]
        if error.raw_os_error() == Some(1314) {
            // Windows hosts without Developer Mode cannot create this attack
            // fixture. The handle-lock unit test still exercises the Windows
            // parent-swap defense without requiring symlink privilege.
            return;
        }
        panic!("cannot create source-parent attack link: {error}");
    }

    let result = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": created.receipt_ids}),
        ),
        profile,
    );
    assert_eq!(result.status, TaskStatus::CleanupFailed, "{result:#?}");
    assert_eq!(
        fs::read(outside.path().join("owned.jsonl")).unwrap(),
        expected
    );
}

#[test]
fn cleanup_never_follows_a_replaced_staging_parent() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let created = create_fixture(&root, &profile, "staging-parent-guard.jsonl");
    assert_eq!(created.status, TaskStatus::Success);
    let outside_sentinel = outside.path().join("sentinel.bin");
    fs::write(&outside_sentinel, b"outside-staging-sentinel").unwrap();

    let staging = root.path().join(".bluefire/staging");
    fs::remove_dir(&staging).unwrap();
    if let Err(error) = directory_symlink(outside.path(), &staging) {
        #[cfg(windows)]
        if error.raw_os_error() == Some(1314) {
            return;
        }
        panic!("cannot create staging-parent attack link: {error}");
    }

    let result = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": created.receipt_ids}),
        ),
        profile,
    );
    assert_eq!(result.status, TaskStatus::CleanupFailed, "{result:#?}");
    assert_eq!(
        fs::read(outside_sentinel).unwrap(),
        b"outside-staging-sentinel"
    );
    assert!(root.path().join("staging-parent-guard.jsonl").is_file());
}

#[test]
fn receipt_deletion_refuses_unreadable_staging_before_removing_recovery_metadata() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let created = create_fixture(&root, &profile, "staging-guard.jsonl");
    assert_eq!(created.status, TaskStatus::Success);
    let receipt_id = created.receipt_ids[0].clone();
    let staging = root.path().join(".bluefire/staging");
    fs::remove_dir(&staging).unwrap();
    fs::write(&staging, b"not a directory").unwrap();

    let safe_root = SafeRoot::open(root.path()).unwrap();
    assert!(safe_root.delete_receipt(&receipt_id).is_err());
    assert!(root
        .path()
        .join(".bluefire/receipts")
        .join(format!("{receipt_id}.json"))
        .exists());
    assert!(root
        .path()
        .join(".bluefire/receipt-commits")
        .join(format!("{receipt_id}.json"))
        .exists());
}

#[test]
fn receipt_deletion_retains_a_prefix_matching_stage_without_owned_path_proof() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let created = create_fixture(&root, &profile, "retained-unproven-stage.jsonl");
    assert_eq!(created.status, TaskStatus::Success);
    let receipt_id = &created.receipt_ids[0];
    let unproven = root
        .path()
        .join(".bluefire/staging")
        .join(format!("{receipt_id}-{}.stage", "f".repeat(64)));
    fs::write(&unproven, b"not named by an authenticated owned-path entry").unwrap();

    let safe_root = SafeRoot::open(root.path()).unwrap();
    safe_root.delete_receipt(receipt_id).unwrap();

    assert_eq!(
        fs::read(&unproven).unwrap(),
        b"not named by an authenticated owned-path entry"
    );
    assert!(!root
        .path()
        .join(".bluefire/receipts")
        .join(format!("{receipt_id}.json"))
        .exists());
    assert!(!root
        .path()
        .join(".bluefire/receipt-commits")
        .join(format!("{receipt_id}.json"))
        .exists());
}

#[test]
fn cleanup_refuses_a_valid_receipt_copied_into_another_workspace() {
    let source_root = TempDir::new().unwrap();
    let source_profile = profile(&source_root, Vec::new());
    let created = create_fixture(&source_root, &source_profile, "copied.txt");
    assert_eq!(created.status, TaskStatus::Success);
    let receipt_id = &created.receipt_ids[0];
    let source_receipt = source_root
        .path()
        .join(".bluefire/receipts")
        .join(format!("{receipt_id}.json"));

    let destination_root = TempDir::new().unwrap();
    let destination_profile = profile(&destination_root, Vec::new());
    fs::write(
        destination_root.path().join("copied.txt"),
        fs::read(source_root.path().join("copied.txt")).unwrap(),
    )
    .unwrap();
    fs::create_dir(destination_root.path().join(".bluefire")).unwrap();
    fs::create_dir(destination_root.path().join(".bluefire/receipts")).unwrap();
    fs::copy(
        source_receipt,
        destination_root
            .path()
            .join(".bluefire/receipts")
            .join(format!("{receipt_id}.json")),
    )
    .unwrap();

    let cleaned = runner().execute(
        manifest(
            &destination_profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": [receipt_id]}),
        ),
        destination_profile,
    );
    assert_eq!(cleaned.status, TaskStatus::CleanupFailed);
    assert!(destination_root.path().join("copied.txt").exists());
    assert!(cleaned
        .cleanup
        .unwrap()
        .errors
        .iter()
        .any(|error| error.contains("another workspace")));
}

#[test]
fn cleanup_rejects_a_receipt_missing_its_workspace_identity() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let created = create_fixture(&root, &profile, "missing-workspace.txt");
    assert_eq!(created.status, TaskStatus::Success);
    let receipt_id = &created.receipt_ids[0];
    let receipt_path = root
        .path()
        .join(".bluefire/receipts")
        .join(format!("{receipt_id}.json"));
    let mut receipt: Value = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    receipt
        .as_object_mut()
        .unwrap()
        .remove("workspace_id")
        .unwrap();
    fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();

    let cleaned = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": [receipt_id]}),
        ),
        profile,
    );
    assert_eq!(cleaned.status, TaskStatus::CleanupFailed);
    assert!(root.path().join("missing-workspace.txt").exists());
    assert!(cleaned
        .cleanup
        .unwrap()
        .errors
        .iter()
        .any(|error| error.contains("receipt schema is invalid")));
}

#[test]
fn receipt_commit_rejects_a_missing_owned_output() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let request = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({
            "path": "vanished/output.jsonl",
            "content_template": "telemetry-seed",
            "record_count": 1
        }),
    );
    let safe_root = SafeRoot::open(root.path()).unwrap();
    let bytes = b"owned-before-commit\n";
    let target = safe_root.prepare_new_file("vanished/output.jsonl").unwrap();
    let mut owned = vec![owned_file(target.relative.clone(), bytes)];
    owned.extend(owned_directories(&target.created_directories));
    let intent = safe_root.begin_receipt(&request, &profile, owned).unwrap();
    safe_root.write_new(&target, bytes, &intent).unwrap();
    fs::remove_file(&target.absolute).unwrap();

    let error = safe_root.commit_receipt(&intent, &profile).unwrap_err();
    assert!(error.contains("receipt-owned path is missing during commit"));
    assert!(!root
        .path()
        .join(".bluefire/receipt-commits")
        .join(format!("{}.json", intent.id()))
        .exists());
    assert!(root
        .path()
        .join(".bluefire/receipts")
        .join(format!("{}.json", intent.id()))
        .is_file());
}

#[test]
fn pending_wal_intent_is_discoverable_and_cleans_a_partially_published_action() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let request = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "partial/first.bin", "content_template": "empty", "record_count": 1}),
    );
    let safe_root = SafeRoot::open(root.path()).unwrap();
    let first_bytes = b"first-published-effect";
    let second_bytes = b"second-never-published";
    let first = safe_root.prepare_new_file("partial/first.bin").unwrap();
    let second = safe_root.prepare_new_file("partial/second.bin").unwrap();
    assert!(!root.path().join("partial").exists());
    let mut owned = vec![
        owned_file(first.relative.clone(), first_bytes),
        owned_file(second.relative.clone(), second_bytes),
    ];
    owned.extend(owned_directories(&first.created_directories));
    let intent = safe_root.begin_receipt(&request, &profile, owned).unwrap();
    let receipt_id = intent.id().to_string();
    assert!(!root.path().join("partial").exists());

    // Deterministically model a hard kill between two file publications: the
    // first exact effect exists, the second is absent, and no commit marker was
    // written. The pre-effect receipt must already be independently visible.
    safe_root.write_new(&first, first_bytes, &intent).unwrap();
    drop(safe_root);
    let receipt_path = root
        .path()
        .join(".bluefire/receipts")
        .join(format!("{receipt_id}.json"));
    let receipt: Value = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["schema_version"], "bluefire.receipt/v1");
    assert_eq!(receipt["receipt_id"], receipt_id);
    assert_eq!(receipt["runner_profile_id"], profile.profile_id);
    assert!(receipt["workspace_id"].as_str().is_some());
    assert!(!root
        .path()
        .join(".bluefire/receipt-commits")
        .join(format!("{receipt_id}.json"))
        .exists());
    assert!(root.path().join("partial/first.bin").exists());
    assert!(!root.path().join("partial/second.bin").exists());

    let cleaned = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": [receipt_id]}),
        ),
        profile,
    );
    assert_eq!(cleaned.status, TaskStatus::Success, "{cleaned:#?}");
    assert_no_workspace_artifacts(root.path());
}

#[test]
fn pending_wal_cleanup_removes_a_partial_runner_staging_effect() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let request = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "partial-stage/output.bin", "content_template": "empty", "record_count": 1}),
    );
    let safe_root = SafeRoot::open(root.path()).unwrap();
    let bytes = b"complete-intended-content";
    let target = safe_root
        .prepare_new_file("partial-stage/output.bin")
        .unwrap();
    let mut owned = vec![owned_file(target.relative.clone(), bytes)];
    owned.extend(owned_directories(&target.created_directories));
    let intent = safe_root.begin_receipt(&request, &profile, owned).unwrap();
    let receipt_id = intent.id().to_string();

    // Model termination after the durable intent and a partial staging write,
    // before atomic publication. Staging is runner-owned by receipt+path hash.
    fs::create_dir(root.path().join("partial-stage")).unwrap();
    let path_id = sha256_hex(target.relative.as_bytes());
    let staging = root
        .path()
        .join(".bluefire/staging")
        .join(format!("{receipt_id}-{path_id}.stage"));
    fs::write(&staging, &bytes[..8]).unwrap();
    drop(safe_root);

    let cleaned = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": [receipt_id]}),
        ),
        profile,
    );
    assert_eq!(cleaned.status, TaskStatus::Success, "{cleaned:#?}");
    assert!(!staging.exists());
    assert_no_workspace_artifacts(root.path());
}

#[test]
fn cleanup_enforces_receipt_lifo_even_when_the_request_is_oldest_first() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let parent = create_fixture(&root, &profile, "lifo/parent.txt");
    let child = create_fixture(&root, &profile, "lifo/child.txt");
    assert_eq!(parent.status, TaskStatus::Success);
    assert_eq!(child.status, TaskStatus::Success);

    let cleaned = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({
                "receipt_ids": [parent.receipt_ids[0], child.receipt_ids[0]]
            }),
        ),
        profile,
    );
    assert_eq!(cleaned.status, TaskStatus::Success, "{cleaned:#?}");
    assert_no_workspace_artifacts(root.path());
}

#[test]
fn network_scope_refusal_occurs_before_any_connect_attempt() {
    let root = TempDir::new().unwrap();
    let declared = NetworkDestination {
        host: "127.0.0.1".to_string(),
        port: 41_001,
    };
    let profile = profile(&root, vec![declared.clone()]);
    assert_eq!(
        create_fixture(&root, &profile, "network.txt").status,
        TaskStatus::Success
    );
    let request = manifest(
        &profile,
        "sandbox.network.loopback.v1",
        json!({
            "artifact": "network.txt",
            "destination": {"host": "127.0.0.1", "port": 41002}
        }),
    );
    let result = runner().execute(request, profile);
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "network_scope_blocked");
    assert_eq!(result.evidence[0].kind, EvidenceKind::ControlBlocked);
}

fn receiver_hmac(domain: &[u8], payloads: &[&[u8]]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&RECEIVER_TASK_KEY).unwrap();
    mac.update(domain);
    for payload in payloads {
        mac.update(payload);
    }
    format!("sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

fn request_header(request: &[u8], expected_name: &str) -> String {
    let separator = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let header = std::str::from_utf8(&request[..separator]).unwrap();
    header
        .split("\r\n")
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(expected_name)
                .then(|| value.trim().to_string())
        })
        .unwrap()
}

fn request_body(request: &[u8]) -> &[u8] {
    let offset = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    &request[offset..]
}

fn read_http_request(socket: &mut std::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    socket.read_to_end(&mut request).unwrap();
    request
}

fn authenticated_http_response(
    status_code: u16,
    reason: &str,
    body: &[u8],
    authentication: &str,
) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\nX-BlueFire-Authentication: {authentication}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn loopback_challenge(request: &[u8], port: u16, authentication_override: Option<&str>) -> Vec<u8> {
    let sha256 = request_header(request, "x-bluefire-sha256");
    let content_length = request_header(request, "x-bluefire-content-length")
        .parse::<usize>()
        .unwrap();
    loopback_challenge_bound(
        port,
        "127.0.0.1",
        RECEIVER_TASK_ID,
        &"1".repeat(64),
        &"2".repeat(64),
        (&sha256, content_length),
        authentication_override,
    )
}

fn loopback_challenge_bound(
    port: u16,
    host: &str,
    task_id: &str,
    session_id: &str,
    nonce: &str,
    artifact_binding: (&str, usize),
    authentication_override: Option<&str>,
) -> Vec<u8> {
    let (sha256, content_length) = artifact_binding;
    let document = json!({
        "schema_version": "bluefire.loopback-receiver-challenge.v1",
        "task_id": task_id,
        "session_id": session_id,
        "nonce": nonce,
        "host": host,
        "port": port,
        "sha256": sha256,
        "content_length": content_length,
    });
    let body = canonical_json(&document).into_bytes();
    let authentication = authentication_override
        .map(str::to_string)
        .unwrap_or_else(|| receiver_hmac(b"bluefire.loopback-receiver.challenge.v1\0", &[&body]));
    authenticated_http_response(200, "OK", &body, &authentication)
}

fn disposable_peer_process_id() -> u32 {
    // Protocol-only unit fixtures use a distinct synthetic PID. Release proof must use
    // the separately launched receiver process exercised by the platform E2E suite.
    let source = std::process::id();
    if source == u32::MAX {
        source - 1
    } else {
        source + 1
    }
}

fn disposable_peer_challenge_with_override(
    request: &[u8],
    port: u16,
    receiver_process_id: u32,
    field_override: Option<(&str, Value)>,
) -> Vec<u8> {
    let sha256 = request_header(request, "x-bluefire-sha256");
    let content_length = request_header(request, "x-bluefire-content-length")
        .parse::<usize>()
        .unwrap();
    let mut document = json!({
        "schema_version": "bluefire.loopback-receiver-challenge.v2",
        "task_id": RECEIVER_TASK_ID,
        "session_id": "1".repeat(64),
        "nonce": "2".repeat(64),
        "host": "127.0.0.1",
        "port": port,
        "sha256": sha256,
        "content_length": content_length,
        "receiver_process_id": receiver_process_id,
        "receiver_mode": "disposable_peer",
        "accepted_artifact_limit": 1,
        "storage_mode": "memory_only",
        "exit_after_accept": true,
    });
    if let Some((field, value)) = field_override {
        document[field] = value;
    }
    let body = canonical_json(&document).into_bytes();
    let authentication = receiver_hmac(b"bluefire.loopback-receiver.challenge.v1\0", &[&body]);
    authenticated_http_response(200, "OK", &body, &authentication)
}

fn disposable_peer_challenge(request: &[u8], port: u16, receiver_process_id: u32) -> Vec<u8> {
    disposable_peer_challenge_with_override(request, port, receiver_process_id, None)
}

fn loopback_acknowledgement(
    request: &[u8],
    status_code: u16,
    reason: &str,
    stored: bool,
    digest_override: Option<&str>,
    authentication_override: Option<&str>,
) -> Vec<u8> {
    let artifact = request_body(request);
    let task_id = request_header(request, "x-bluefire-task-id");
    let session_id = request_header(request, "x-bluefire-session-id");
    let request_authentication = request_header(request, "x-bluefire-authentication");
    let acknowledgement = canonical_json(&json!({
        "schema_version": "bluefire.loopback-receiver-result.v2",
        "accepted": true,
        "task_id": task_id,
        "session_id": session_id,
        "bytes_received": artifact.len(),
        "sha256": digest_override.map(str::to_string).unwrap_or_else(|| sha256_hex(artifact)),
        "stored": stored,
    }))
    .into_bytes();
    let authentication = authentication_override
        .map(str::to_string)
        .unwrap_or_else(|| {
            receiver_hmac(
                b"bluefire.loopback-receiver.response.v1\0",
                &[request_authentication.as_bytes(), b"\0", &acknowledgement],
            )
        });
    authenticated_http_response(status_code, reason, &acknowledgement, &authentication)
}

fn disposable_peer_acknowledgement_with_override(
    request: &[u8],
    receiver_process_id: u32,
    field_override: Option<(&str, Value)>,
) -> Vec<u8> {
    let artifact = request_body(request);
    let task_id = request_header(request, "x-bluefire-task-id");
    let session_id = request_header(request, "x-bluefire-session-id");
    let request_authentication = request_header(request, "x-bluefire-authentication");
    let mut acknowledgement = json!({
        "schema_version": "bluefire.loopback-receiver-result.v3",
        "accepted": true,
        "task_id": task_id,
        "session_id": session_id,
        "bytes_received": artifact.len(),
        "sha256": sha256_hex(artifact),
        "stored": false,
        "receiver_process_id": receiver_process_id,
        "receiver_mode": "disposable_peer",
        "terminal_disposition": "exit_after_response",
    });
    if let Some((field, value)) = field_override {
        acknowledgement[field] = value;
    }
    let acknowledgement = canonical_json(&acknowledgement).into_bytes();
    let authentication = receiver_hmac(
        b"bluefire.loopback-receiver.response.v1\0",
        &[request_authentication.as_bytes(), b"\0", &acknowledgement],
    );
    authenticated_http_response(200, "OK", &acknowledgement, &authentication)
}

fn disposable_peer_acknowledgement(request: &[u8], receiver_process_id: u32) -> Vec<u8> {
    disposable_peer_acknowledgement_with_override(request, receiver_process_id, None)
}

fn assert_authenticated_artifact_request(request: &[u8], port: u16) {
    let artifact = request_body(request);
    let digest = request_header(request, "x-bluefire-sha256");
    assert_eq!(digest, sha256_hex(artifact));
    let task_id = request_header(request, "x-bluefire-task-id");
    let session_id = request_header(request, "x-bluefire-session-id");
    let nonce = request_header(request, "x-bluefire-nonce");
    let content_length = request_header(request, "content-length")
        .parse::<usize>()
        .unwrap();
    assert_eq!(content_length, artifact.len());
    let document = canonical_json(&json!({
        "schema_version": "bluefire.loopback-receiver-request.v1",
        "method": "POST",
        "path": "/bluefire/v1/artifact",
        "task_id": task_id,
        "session_id": session_id,
        "nonce": nonce,
        "host": "127.0.0.1",
        "port": port,
        "sha256": digest,
        "content_length": content_length,
    }));
    assert_eq!(
        request_header(request, "x-bluefire-authentication"),
        receiver_hmac(
            b"bluefire.loopback-receiver.request.v1\0",
            &[document.as_bytes()],
        )
    );
}

struct ReceiverEnvironment {
    prior_task_id: Option<std::ffi::OsString>,
    prior_task_key: Option<std::ffi::OsString>,
}

impl Drop for ReceiverEnvironment {
    fn drop(&mut self) {
        match self.prior_task_id.take() {
            Some(value) => std::env::set_var("BLUEFIRE_RECEIVER_TASK_ID", value),
            None => std::env::remove_var("BLUEFIRE_RECEIVER_TASK_ID"),
        }
        match self.prior_task_key.take() {
            Some(value) => std::env::set_var("BLUEFIRE_RECEIVER_TASK_KEY", value),
            None => std::env::remove_var("BLUEFIRE_RECEIVER_TASK_KEY"),
        }
    }
}

fn execute_network_with_authentication(
    request: ExecutionManifest,
    profile: RunnerProfile,
    task_id: &str,
    task_key: &[u8; 32],
) -> TaskResult {
    let _lock = RECEIVER_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _environment = ReceiverEnvironment {
        prior_task_id: std::env::var_os("BLUEFIRE_RECEIVER_TASK_ID"),
        prior_task_key: std::env::var_os("BLUEFIRE_RECEIVER_TASK_KEY"),
    };
    std::env::set_var("BLUEFIRE_RECEIVER_TASK_ID", task_id);
    std::env::set_var("BLUEFIRE_RECEIVER_TASK_KEY", hex::encode(task_key));
    runner().execute(request, profile)
}

fn execute_authenticated_network(request: ExecutionManifest, profile: RunnerProfile) -> TaskResult {
    execute_network_with_authentication(request, profile, RECEIVER_TASK_ID, &RECEIVER_TASK_KEY)
}

fn execute_network_without_authentication(
    request: ExecutionManifest,
    profile: RunnerProfile,
    partial_key: Option<&str>,
) -> TaskResult {
    let _lock = RECEIVER_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _environment = ReceiverEnvironment {
        prior_task_id: std::env::var_os("BLUEFIRE_RECEIVER_TASK_ID"),
        prior_task_key: std::env::var_os("BLUEFIRE_RECEIVER_TASK_KEY"),
    };
    std::env::remove_var("BLUEFIRE_RECEIVER_TASK_ID");
    match partial_key {
        Some(value) => std::env::set_var("BLUEFIRE_RECEIVER_TASK_KEY", value),
        None => std::env::remove_var("BLUEFIRE_RECEIVER_TASK_KEY"),
    }
    runner().execute(request, profile)
}

fn network_case(port: u16) -> (TempDir, ExecutionManifest, RunnerProfile) {
    let root = TempDir::new().unwrap();
    let destination = NetworkDestination {
        host: "127.0.0.1".to_string(),
        port,
    };
    let profile = profile(&root, vec![destination.clone()]);
    assert_eq!(
        create_fixture(&root, &profile, "network-auth.txt").status,
        TaskStatus::Success
    );
    let request = manifest(
        &profile,
        "sandbox.network.loopback.v1",
        json!({"artifact": "network-auth.txt", "destination": destination}),
    );
    (root, request, profile)
}

fn peer_case(port: u16) -> (TempDir, ExecutionManifest, RunnerProfile) {
    let root = TempDir::new().unwrap();
    let destination = NetworkDestination {
        host: "127.0.0.1".to_string(),
        port,
    };
    let profile = profile(&root, vec![destination]);
    assert_eq!(
        create_fixture(&root, &profile, "fixtures/input.jsonl").status,
        TaskStatus::Success
    );
    let staged = runner().execute(
        manifest(
            &profile,
            "sandbox.collection.stage.v1",
            json!({
                "inputs": ["fixtures/input.jsonl"],
                "destination_directory": "staged",
                "bundle_format": "jsonl"
            }),
        ),
        profile.clone(),
    );
    assert_eq!(staged.status, TaskStatus::Success);
    let request = manifest(&profile, "sandbox.peer.handoff.v1", json!({"port": port}));
    (root, request, profile)
}

fn serve_authenticated_receiver(
    listener: TcpListener,
    status_code: u16,
    reason: &'static str,
    stored: bool,
    digest_override: Option<&'static str>,
) -> thread::JoinHandle<Vec<u8>> {
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut challenge_socket, peer) = listener.accept().unwrap();
        assert!(peer.ip().is_loopback());
        let challenge_request = read_http_request(&mut challenge_socket);
        assert!(challenge_request.starts_with(b"GET /bluefire/v1/challenge HTTP/1.1\r\n"));
        assert_eq!(
            request_header(&challenge_request, "x-bluefire-task-id"),
            RECEIVER_TASK_ID
        );
        challenge_socket
            .write_all(&loopback_challenge(&challenge_request, port, None))
            .unwrap();
        drop(challenge_socket);

        let (mut artifact_socket, peer) = listener.accept().unwrap();
        assert!(peer.ip().is_loopback());
        let artifact_request = read_http_request(&mut artifact_socket);
        assert!(artifact_request.starts_with(b"POST /bluefire/v1/artifact HTTP/1.1\r\n"));
        assert_authenticated_artifact_request(&artifact_request, port);
        artifact_socket
            .write_all(&loopback_acknowledgement(
                &artifact_request,
                status_code,
                reason,
                stored,
                digest_override,
                None,
            ))
            .unwrap();
        artifact_request
    })
}

fn serve_disposable_peer_receiver(listener: TcpListener) -> thread::JoinHandle<Vec<u8>> {
    let port = listener.local_addr().unwrap().port();
    let receiver_process_id = disposable_peer_process_id();
    thread::spawn(move || {
        let (mut challenge_socket, peer) = listener.accept().unwrap();
        assert!(peer.ip().is_loopback());
        let challenge_request = read_http_request(&mut challenge_socket);
        assert!(challenge_request.starts_with(b"GET /bluefire/v1/challenge HTTP/1.1\r\n"));
        challenge_socket
            .write_all(&disposable_peer_challenge(
                &challenge_request,
                port,
                receiver_process_id,
            ))
            .unwrap();
        drop(challenge_socket);

        let (mut artifact_socket, peer) = listener.accept().unwrap();
        assert!(peer.ip().is_loopback());
        let artifact_request = read_http_request(&mut artifact_socket);
        assert!(artifact_request.starts_with(b"POST /bluefire/v1/artifact HTTP/1.1\r\n"));
        assert_authenticated_artifact_request(&artifact_request, port);
        artifact_socket
            .write_all(&disposable_peer_acknowledgement(
                &artifact_request,
                receiver_process_id,
            ))
            .unwrap();
        artifact_request
    })
}

#[test]
fn loopback_action_uses_only_the_declared_ephemeral_receiver() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = serve_authenticated_receiver(listener, 200, "OK", false, None);

    let root = TempDir::new().unwrap();
    let destination = NetworkDestination {
        host: "127.0.0.1".to_string(),
        port,
    };
    let profile = profile(&root, vec![destination.clone()]);
    let created = create_fixture(&root, &profile, "network.txt");
    let mut request = manifest(
        &profile,
        "sandbox.network.loopback.v1",
        json!({"artifact": "network.txt", "destination": destination}),
    );
    request.evidence_refs = vec![created.evidence[0].evidence_id.clone()];
    seal_manifest(&mut request);
    let result = execute_authenticated_network(request, profile);
    assert_eq!(result.status, TaskStatus::Success);
    assert_eq!(result.output["http_status"], 200);
    assert_eq!(result.output["receiver_acknowledged"], true);
    assert_eq!(result.output["receiver_stored"], false);
    assert_eq!(
        result.evidence[0].references[0],
        created.evidence[0].evidence_id
    );
    let received = receiver.join().unwrap();
    assert!(received.ends_with(
        b"{\"record_id\":\"synthetic-001\",\"synthetic\":true,\"template\":\"telemetry-seed\",\"value\":\"telemetry-value-001\"}\n"
    ));
}

#[test]
fn loopback_action_without_exact_task_environment_never_connects() {
    for partial_key in [None, Some(&"a".repeat(64))] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (_root, request, profile) = network_case(port);

        let result = execute_network_without_authentication(
            request,
            profile,
            partial_key.map(String::as_str),
        );

        assert_eq!(result.status, TaskStatus::ControlBlocked);
        assert_eq!(
            result.error.unwrap().code,
            "receiver_authentication_unavailable"
        );
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn loopback_action_refuses_tampered_challenge_before_artifact_transmission() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let request = read_http_request(&mut socket);
        socket
            .write_all(&loopback_challenge(
                &request,
                port,
                Some("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
            ))
            .unwrap();
        request
    });
    let (_root, request, profile) = network_case(port);

    let result = execute_authenticated_network(request, profile);

    assert_eq!(result.status, TaskStatus::Failed);
    assert_eq!(result.error.unwrap().code, "receiver_authentication_failed");
    let received = receiver.join().unwrap();
    assert!(received.starts_with(b"GET /bluefire/v1/challenge HTTP/1.1\r\n"));
    assert!(!received.windows(8).any(|window| window == b"artifact"));
}

#[test]
fn loopback_action_refuses_cross_task_challenge() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let request = read_http_request(&mut socket);
        socket
            .write_all(&loopback_challenge(&request, port, None))
            .unwrap();
        request
    });
    let (_root, request, profile) = network_case(port);
    let other_task = format!("execute-{}", "2".repeat(64));

    let result =
        execute_network_with_authentication(request, profile, &other_task, &RECEIVER_TASK_KEY);

    assert_eq!(result.status, TaskStatus::Failed);
    assert_eq!(result.error.unwrap().code, "receiver_authentication_failed");
    assert_eq!(
        request_header(&receiver.join().unwrap(), "x-bluefire-task-id"),
        other_task
    );
}

#[test]
fn peer_handoff_refuses_disposable_challenge_drift_before_artifact_transmission() {
    for (field, value) in [
        ("receiver_process_id", json!(std::process::id())),
        ("receiver_mode", json!("bounded_receiver")),
        ("accepted_artifact_limit", json!(2)),
        ("storage_mode", json!("receiver_owned")),
        ("exit_after_accept", json!(false)),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let receiver = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let request = read_http_request(&mut socket);
            socket
                .write_all(&disposable_peer_challenge_with_override(
                    &request,
                    port,
                    disposable_peer_process_id(),
                    Some((field, value)),
                ))
                .unwrap();
            drop(socket);
            thread::sleep(StdDuration::from_millis(100));
            listener.set_nonblocking(true).unwrap();
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            request
        });
        let (_root, request, profile) = peer_case(port);

        let result = execute_authenticated_network(request, profile);

        assert_eq!(result.status, TaskStatus::Failed);
        assert_eq!(result.error.unwrap().code, "receiver_authentication_failed");
        let received = receiver.join().unwrap();
        assert!(received.starts_with(b"GET /bluefire/v1/challenge HTTP/1.1\r\n"));
    }
}

#[test]
fn peer_handoff_refuses_disposable_acknowledgement_drift() {
    for (field, value) in [
        ("receiver_process_id", json!(std::process::id())),
        ("receiver_mode", json!("bounded_receiver")),
        ("terminal_disposition", json!("remain_available")),
        ("stored", json!(true)),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let receiver = thread::spawn(move || {
            let receiver_process_id = disposable_peer_process_id();
            let (mut challenge_socket, _) = listener.accept().unwrap();
            let challenge_request = read_http_request(&mut challenge_socket);
            challenge_socket
                .write_all(&disposable_peer_challenge(
                    &challenge_request,
                    port,
                    receiver_process_id,
                ))
                .unwrap();
            drop(challenge_socket);
            let (mut artifact_socket, _) = listener.accept().unwrap();
            let artifact_request = read_http_request(&mut artifact_socket);
            artifact_socket
                .write_all(&disposable_peer_acknowledgement_with_override(
                    &artifact_request,
                    receiver_process_id,
                    Some((field, value)),
                ))
                .unwrap();
        });
        let (_root, request, profile) = peer_case(port);

        let result = execute_authenticated_network(request, profile);

        assert_eq!(result.status, TaskStatus::Failed);
        assert_eq!(result.output["receiver_acknowledged"], false);
        assert!(result
            .error
            .unwrap()
            .message
            .contains("acknowledgement failed"));
        receiver.join().unwrap();
    }
}

#[test]
fn loopback_action_refuses_authenticated_challenge_for_another_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let wrong_port = if port == u16::MAX { port - 1 } else { port + 1 };
    let receiver = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let request = read_http_request(&mut socket);
        let sha256 = request_header(&request, "x-bluefire-sha256");
        let content_length = request_header(&request, "x-bluefire-content-length")
            .parse::<usize>()
            .unwrap();
        socket
            .write_all(&loopback_challenge_bound(
                wrong_port,
                "127.0.0.1",
                RECEIVER_TASK_ID,
                &"1".repeat(64),
                &"2".repeat(64),
                (&sha256, content_length),
                None,
            ))
            .unwrap();
    });
    let (_root, request, profile) = network_case(port);

    let result = execute_authenticated_network(request, profile);

    assert_eq!(result.status, TaskStatus::Failed);
    assert_eq!(result.error.unwrap().code, "receiver_authentication_failed");
    receiver.join().unwrap();
}

#[test]
fn loopback_action_refuses_tampered_acknowledgement_authentication() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = thread::spawn(move || {
        let (mut challenge_socket, _) = listener.accept().unwrap();
        let challenge_request = read_http_request(&mut challenge_socket);
        challenge_socket
            .write_all(&loopback_challenge(&challenge_request, port, None))
            .unwrap();
        drop(challenge_socket);
        let (mut artifact_socket, _) = listener.accept().unwrap();
        let artifact_request = read_http_request(&mut artifact_socket);
        artifact_socket
            .write_all(&loopback_acknowledgement(
                &artifact_request,
                200,
                "OK",
                false,
                None,
                Some("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
            ))
            .unwrap();
    });
    let (_root, request, profile) = network_case(port);

    let result = execute_authenticated_network(request, profile);

    assert_eq!(result.status, TaskStatus::Failed);
    assert_eq!(result.output["receiver_acknowledged"], false);
    assert!(result
        .error
        .unwrap()
        .message
        .contains("authentication failed"));
    receiver.join().unwrap();
}

#[test]
fn loopback_action_refuses_response_header_smuggling_and_does_not_leak_secrets() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let request = read_http_request(&mut socket);
        let response = loopback_challenge(&request, port, None);
        let separator = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        let mut smuggled = response[..separator].to_vec();
        smuggled.extend_from_slice(b"\r\nContent-Length: 0");
        smuggled.extend_from_slice(&response[separator..]);
        socket.write_all(&smuggled).unwrap();
    });
    let (_root, request, profile) = network_case(port);

    let result = execute_authenticated_network(request, profile);

    assert_eq!(result.status, TaskStatus::Failed);
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains(&hex::encode(RECEIVER_TASK_KEY)));
    assert_eq!(result.error.unwrap().code, "receiver_authentication_failed");
    receiver.join().unwrap();
}

#[test]
fn loopback_action_rejects_arbitrary_2xx_without_digest_bound_json() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = serve_authenticated_receiver(listener, 204, "No Content", false, None);

    let root = TempDir::new().unwrap();
    let destination = NetworkDestination {
        host: "127.0.0.1".to_string(),
        port,
    };
    let profile = profile(&root, vec![destination.clone()]);
    assert_eq!(
        create_fixture(&root, &profile, "network-unbound.txt").status,
        TaskStatus::Success
    );
    let result = execute_authenticated_network(
        manifest(
            &profile,
            "sandbox.network.loopback.v1",
            json!({"artifact": "network-unbound.txt", "destination": destination}),
        ),
        profile,
    );

    assert_eq!(result.status, TaskStatus::Failed);
    assert_eq!(result.output["http_status"], 204);
    assert_eq!(result.output["receiver_acknowledged"], false);
    assert_eq!(result.error.unwrap().code, "loopback_response_failed");
    receiver.join().unwrap();
}

#[test]
fn loopback_action_rejects_acknowledgement_for_other_content() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = serve_authenticated_receiver(
        listener,
        200,
        "OK",
        false,
        Some("0000000000000000000000000000000000000000000000000000000000000000"),
    );

    let root = TempDir::new().unwrap();
    let destination = NetworkDestination {
        host: "127.0.0.1".to_string(),
        port,
    };
    let profile = profile(&root, vec![destination.clone()]);
    assert_eq!(
        create_fixture(&root, &profile, "network-wrong-ack.txt").status,
        TaskStatus::Success
    );
    let result = execute_authenticated_network(
        manifest(
            &profile,
            "sandbox.network.loopback.v1",
            json!({"artifact": "network-wrong-ack.txt", "destination": destination}),
        ),
        profile,
    );

    assert_eq!(result.status, TaskStatus::Failed);
    assert_eq!(result.output["receiver_acknowledged"], false);
    assert!(result
        .error
        .unwrap()
        .message
        .contains("digest did not match"));
    receiver.join().unwrap();
}

#[test]
fn loopback_trickle_response_cannot_extend_the_monotonic_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = thread::spawn(move || {
        let (mut challenge_socket, _) = listener.accept().unwrap();
        let challenge_request = read_http_request(&mut challenge_socket);
        assert!(challenge_request.starts_with(b"GET /bluefire/v1/challenge HTTP/1.1\r\n"));
        challenge_socket
            .write_all(&loopback_challenge(&challenge_request, port, None))
            .unwrap();
        drop(challenge_socket);
        let (mut socket, _) = listener.accept().unwrap();
        let request = read_http_request(&mut socket);
        assert!(request.starts_with(b"POST /bluefire/v1/artifact HTTP/1.1\r\n"));
        for byte in b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n" {
            if socket.write_all(&[*byte]).is_err() {
                break;
            }
            thread::sleep(StdDuration::from_millis(20));
        }
    });

    let root = TempDir::new().unwrap();
    let destination = NetworkDestination {
        host: "127.0.0.1".to_string(),
        port,
    };
    let profile = profile(&root, vec![destination.clone()]);
    assert_eq!(
        create_fixture(&root, &profile, "network-slow.txt").status,
        TaskStatus::Success
    );
    let mut request = manifest(
        &profile,
        "sandbox.network.loopback.v1",
        json!({"artifact": "network-slow.txt", "destination": destination}),
    );
    request.limits.timeout_ms = 80;
    seal_manifest(&mut request);
    let started = Instant::now();
    let result = execute_authenticated_network(request, profile);
    assert_eq!(result.status, TaskStatus::TimedOut);
    assert!(started.elapsed() < StdDuration::from_millis(500));
    receiver.join().unwrap();
}

#[test]
fn disposable_vertical_slice_runs_real_steps_and_cleans_in_reverse_order() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = serve_disposable_peer_receiver(listener);

    let root = TempDir::new().unwrap();
    let destination = NetworkDestination {
        host: "127.0.0.1".to_string(),
        port,
    };
    let profile = profile(&root, vec![destination.clone()]);
    let mut receipts = Vec::new();

    let created = create_fixture(&root, &profile, "fixtures/input.jsonl");
    assert_eq!(created.status, TaskStatus::Success);
    receipts.extend(created.receipt_ids.clone());

    let transformed = runner().execute(
        manifest(
            &profile,
            "sandbox.fixture.transform.v1",
            json!({
                "input": "fixtures/input.jsonl",
                "output": "fixtures/transformed.jsonl",
                "redact_values": true
            }),
        ),
        profile.clone(),
    );
    assert_eq!(transformed.status, TaskStatus::Success);
    receipts.extend(transformed.receipt_ids.clone());

    let listed = runner().execute(
        manifest(
            &profile,
            "sandbox.discovery.list.v1",
            json!({"path": "fixtures/transformed.jsonl"}),
        ),
        profile.clone(),
    );
    assert_eq!(listed.status, TaskStatus::Success);
    assert_eq!(listed.output["entries"].as_array().unwrap().len(), 1);

    let metadata = runner().execute(
        manifest(
            &profile,
            "sandbox.discovery.metadata.v1",
            json!({"path": "fixtures/transformed.jsonl"}),
        ),
        profile.clone(),
    );
    assert_eq!(metadata.status, TaskStatus::Success);
    assert_eq!(metadata.output["entries"].as_array().unwrap().len(), 1);

    let staged = runner().execute(
        manifest(
            &profile,
            "sandbox.collection.stage.v1",
            json!({
                "inputs": ["fixtures/transformed.jsonl"],
                "destination_directory": "staged",
                "bundle_format": "jsonl"
            }),
        ),
        profile.clone(),
    );
    assert_eq!(staged.status, TaskStatus::Success);
    receipts.extend(staged.receipt_ids.clone());
    assert_eq!(staged.output["artifact"], "staged/bundle.jsonl");

    let delivered = execute_authenticated_network(
        manifest(
            &profile,
            "sandbox.peer.handoff.v1",
            json!({"port": destination.port}),
        ),
        profile.clone(),
    );
    assert_eq!(delivered.status, TaskStatus::Success);
    assert_eq!(delivered.output["http_status"], 200);
    assert_eq!(delivered.output["receiver_acknowledged"], true);
    assert_eq!(delivered.output["receiver_stored"], false);
    assert_eq!(
        delivered.output["lab_authorization"]["scope"],
        "approved_task"
    );
    assert_eq!(
        delivered.output["lab_authorization"]["credential_kind"],
        "managed_one_task_hmac_capability"
    );
    assert_eq!(
        delivered.output["lab_authorization"]["challenge_verified"],
        true
    );
    assert_eq!(
        delivered.output["lab_authorization"]["raw_credential_exposed"],
        false
    );
    assert_eq!(
        delivered.output["lab_peers"]["scope"],
        "authorized_disposable_loopback_lab"
    );
    assert_eq!(
        delivered.output["lab_peers"]["source_kind"],
        "rust_runner_process"
    );
    assert_eq!(
        delivered.output["lab_peers"]["destination_kind"],
        "managed_loopback_receiver_process"
    );
    assert_eq!(
        delivered.output["lab_peers"]["source_process_id"],
        std::process::id()
    );
    assert_eq!(
        delivered.output["lab_peers"]["destination_process_id"],
        disposable_peer_process_id()
    );
    assert_eq!(delivered.output["lab_peers"]["distinct_processes"], true);
    assert_eq!(
        delivered.output["lab_peers"]["receiver_mode"],
        "disposable_peer"
    );
    assert_eq!(delivered.output["lab_peers"]["accepted_artifact_limit"], 1);
    assert_eq!(delivered.output["lab_peers"]["storage_mode"], "memory_only");
    assert_eq!(delivered.output["lab_peers"]["exit_after_accept"], true);
    assert_eq!(delivered.output["lab_peers"]["transfer_acknowledged"], true);
    for field in [
        &delivered.output["lab_authorization"]["credential_handle"],
        &delivered.output["lab_peers"]["source_handle"],
        &delivered.output["lab_peers"]["destination_handle"],
    ] {
        let value = field.as_str().unwrap();
        assert_eq!(value.len(), 64);
        assert!(value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }
    assert_ne!(
        delivered.output["lab_peers"]["source_handle"],
        delivered.output["lab_peers"]["destination_handle"]
    );
    assert!(!serde_json::to_string(&delivered)
        .unwrap()
        .contains(&hex::encode(RECEIVER_TASK_KEY)));
    assert!(receiver
        .join()
        .unwrap()
        .starts_with(b"POST /bluefire/v1/artifact HTTP/1.1\r\n"));

    let exported = runner().execute(
        manifest(
            &profile,
            "sandbox.export.local.v1",
            json!({
                "source": "staged/bundle.jsonl",
                "retention_label": "ephemeral"
            }),
        ),
        profile.clone(),
    );
    assert_eq!(exported.status, TaskStatus::Success);
    receipts.extend(exported.receipt_ids.clone());

    // Each receipt owns only objects created by its action. Reverse ordering
    // removes children before the action that originally created a parent.
    receipts.reverse();
    let cleaned = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": receipts}),
        ),
        profile,
    );
    assert_eq!(cleaned.status, TaskStatus::Success);
    assert_eq!(cleaned.output["verification_performed"], true);
    assert!(cleaned.output["verified_removed_paths"].as_u64().unwrap() >= 1);
    assert!(cleaned.output["verified_receipts"].as_u64().unwrap() >= 1);
    assert_no_workspace_artifacts(root.path());
}

#[test]
fn restricted_persistence_marker_is_profile_and_capability_gated_then_cleans() {
    const ACTION_ID: &str = "sandbox.restricted.persistence-marker.v1";
    let root = TempDir::new().unwrap();

    let mut tier_denied = profile(&root, Vec::new());
    tier_denied.max_safety_tier = SafetyTier::Controlled;
    seal_profile(&mut tier_denied);
    let result = runner().execute(
        manifest(
            &tier_denied,
            ACTION_ID,
            json!({"label": "persistence_detection_canary"}),
        ),
        tier_denied,
    );
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "safety_tier_blocked");
    assert!(!root
        .path()
        .join("restricted/persistence-marker.json")
        .exists());

    let mut allowlist_denied = profile(&root, Vec::new());
    allowlist_denied
        .allowed_actions
        .retain(|action| action != ACTION_ID);
    seal_profile(&mut allowlist_denied);
    let result = runner().execute(
        manifest(
            &allowlist_denied,
            ACTION_ID,
            json!({"label": "control_validation"}),
        ),
        allowlist_denied,
    );
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "action_not_allowed");

    let mut capability_denied = profile(&root, Vec::new());
    capability_denied
        .capabilities
        .retain(|capability| *capability != Capability::SandboxRestricted);
    seal_profile(&mut capability_denied);
    let result = runner().execute(
        manifest(
            &capability_denied,
            ACTION_ID,
            json!({"label": "control_validation"}),
        ),
        capability_denied,
    );
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert_eq!(result.error.unwrap().code, "capability_blocked");

    let profile = profile(&root, Vec::new());
    for params in [
        json!({"label": "arbitrary"}),
        json!({"label": "control_validation", "path": "caller/chosen.json"}),
    ] {
        let refused = runner().execute(manifest(&profile, ACTION_ID, params), profile.clone());
        assert_eq!(refused.status, TaskStatus::Refused);
        assert_eq!(refused.error.unwrap().code, "invalid_action_params");
    }
    let created = runner().execute(
        manifest(
            &profile,
            ACTION_ID,
            json!({"label": "persistence_detection_canary"}),
        ),
        profile.clone(),
    );
    assert_eq!(created.status, TaskStatus::Success, "{created:#?}");
    assert_eq!(
        created.output["artifact"],
        "restricted/persistence-marker.json"
    );
    assert!(created.output["sha256"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71));
    assert_eq!(created.receipt_ids.len(), 1);
    let marker: Value = serde_json::from_slice(
        &fs::read(root.path().join("restricted/persistence-marker.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(marker["kind"], "non_executable_marker");
    assert_eq!(marker["executable"], false);
    assert_eq!(marker["label"], "persistence_detection_canary");

    let cleaned = runner().execute(
        manifest(
            &profile,
            "sandbox.cleanup.v1",
            json!({"receipt_ids": created.receipt_ids}),
        ),
        profile,
    );
    assert_eq!(cleaned.status, TaskStatus::Success, "{cleaned:#?}");
    assert_no_workspace_artifacts(root.path());
}

#[test]
fn inventory_and_execute_cli_emit_the_versioned_json_contract() {
    let inventory_output = Command::new(runner_binary())
        .args(["inventory", "--json"])
        .output()
        .unwrap();
    assert!(inventory_output.status.success());
    let inventory_json: Value = serde_json::from_slice(&inventory_output.stdout).unwrap();
    assert_eq!(
        inventory_json["schema_version"],
        "bluefire.runner-inventory.v1"
    );
    assert_eq!(
        inventory_json["action_sdk_version"],
        "bluefire.runner-action-sdk.v1"
    );
    assert_eq!(
        inventory_json["receipt_protocol"],
        "bluefire.runner-receipt-wal.v2"
    );
    assert_eq!(inventory_json["actions"].as_array().unwrap().len(), 19);

    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let request = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "cli.txt", "content_template": "empty", "record_count": 1}),
    );
    let documents = TempDir::new().unwrap();
    let manifest_path = documents.path().join("manifest.json");
    let profile_path = documents.path().join("profile.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();
    fs::write(&profile_path, serde_json::to_vec_pretty(&profile).unwrap()).unwrap();
    let output = Command::new(runner_binary())
        .arg("execute")
        .arg("--manifest")
        .arg(&manifest_path)
        .arg("--profile")
        .arg(&profile_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: TaskResult = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result.schema_version, RESULT_SCHEMA_VERSION);
    assert_eq!(result.status, TaskStatus::Success);
}
