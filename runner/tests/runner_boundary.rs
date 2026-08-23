use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use bluefire_runner::contract::{
    MANIFEST_SCHEMA_VERSION, PROFILE_SCHEMA_VERSION, RESULT_SCHEMA_VERSION,
};
use bluefire_runner::{
    inventory, seal_manifest, seal_profile, utc_now, Approval, Capability, EvidenceKind,
    ExecutionLimits, ExecutionManifest, NetworkDestination, Platform, RunMode, Runner,
    RunnerProfile, SafetyTier, TargetScope, TaskResult, TaskStatus,
};
use chrono::Duration;
use serde_json::{json, Value};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn runner_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bluefire-runner"))
}

fn runner() -> Runner {
    Runner::with_executable(runner_binary())
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
        capabilities: vec![
            Capability::FilesystemRead,
            Capability::FilesystemWrite,
            Capability::ProcessSpawn,
            Capability::NetworkLoopback,
            Capability::ExportLocal,
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
        json!({"path": path, "content_template": "telemetry-seed"}),
    );
    runner().execute(request, profile.clone())
}

#[test]
fn valid_fixture_has_structured_provenance_and_receipt() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let result = create_fixture(&root, &profile, "artifacts/seed.txt");
    assert_eq!(result.schema_version, RESULT_SCHEMA_VERSION);
    assert_eq!(result.status, TaskStatus::Success);
    assert!(root.path().join("artifacts/seed.txt").is_file());
    assert_eq!(result.receipt_ids.len(), 1);
    assert!(result.request_hash.starts_with("sha256:"));
    assert_eq!(result.policy_digest, profile.policy_digest);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.evidence[0].kind, EvidenceKind::Executed);
    assert!(result.evidence[0].evidence_id.starts_with("sha256:"));
    assert_eq!(result.evidence[0].references.len(), 1);
}

#[test]
fn simulate_unknown_action_and_unknown_parameter_never_execute() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());

    let mut simulate = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "simulate.txt", "content_template": "empty"}),
    );
    simulate.mode = RunMode::Simulate;
    seal_manifest(&mut simulate);
    let result = runner().execute(simulate, profile.clone());
    assert_eq!(result.status, TaskStatus::ControlBlocked);
    assert!(!root.path().join("simulate.txt").exists());

    let mut unknown = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "unknown.txt", "content_template": "empty"}),
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
        json!({"path": "blocked.txt", "content_template": "empty"}),
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
        json!({"path": "approved/a.txt", "content_template": "empty"}),
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
        json!({"path": "../escape.txt", "content_template": "empty"}),
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
        json!({"path": "approved/timeout.txt", "content_template": "empty"}),
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
        json!({"path": "approved.txt", "content_template": "empty"}),
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
fn fixed_transform_has_bounded_output_and_no_caller_executable() {
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
            "transform": "uppercase-ascii"
        }),
    );
    request.limits.max_stdout_bytes = 4;
    seal_manifest(&mut request);
    let result = runner().execute(request, profile);
    assert_eq!(result.status, TaskStatus::Success);
    assert!(result.stdout.truncated);
    assert_eq!(result.stdout.text.len(), 4);
    let bytes = fs::read(root.path().join("output.txt")).unwrap();
    assert_eq!(bytes, b"BLUEFIRE-FIXTURE-V1\nKIND=TELEMETRY-SEED\n");
}

#[test]
fn collection_partial_result_retains_a_cleanup_receipt() {
    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    assert_eq!(
        create_fixture(&root, &profile, "input.txt").status,
        TaskStatus::Success
    );
    let request = manifest(
        &profile,
        "sandbox.collection.stage.v1",
        json!({
            "inputs": ["input.txt", "missing.txt"],
            "destination_directory": "stage"
        }),
    );
    let result = runner().execute(request, profile);
    assert_eq!(result.status, TaskStatus::Partial);
    assert_eq!(result.receipt_ids.len(), 1);
    assert!(root.path().join("stage/000-input.txt").is_file());
    assert_eq!(result.evidence[0].kind, EvidenceKind::Executed);
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
    assert_eq!(result.status, TaskStatus::Success);
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

#[test]
fn loopback_action_uses_only_the_declared_ephemeral_receiver() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = thread::spawn(move || {
        let (mut socket, peer) = listener.accept().unwrap();
        assert!(peer.ip().is_loopback());
        let mut request = Vec::new();
        socket.read_to_end(&mut request).unwrap();
        assert!(request.starts_with(b"POST /bluefire/v1/artifact HTTP/1.1\r\n"));
        socket
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        request
    });

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
    let result = runner().execute(request, profile);
    assert_eq!(result.status, TaskStatus::Success);
    assert_eq!(result.output["http_status"], 204);
    assert_eq!(
        result.evidence[0].references[0],
        created.evidence[0].evidence_id
    );
    let received = receiver.join().unwrap();
    assert!(received.ends_with(b"bluefire-fixture-v1\nkind=telemetry-seed\n"));
}

#[test]
fn disposable_vertical_slice_runs_real_steps_and_cleans_in_reverse_order() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receiver = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).unwrap();
        socket
            .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        request
    });

    let root = TempDir::new().unwrap();
    let destination = NetworkDestination {
        host: "127.0.0.1".to_string(),
        port,
    };
    let profile = profile(&root, vec![destination.clone()]);
    let mut receipts = Vec::new();

    let created = create_fixture(&root, &profile, "fixtures/input.txt");
    assert_eq!(created.status, TaskStatus::Success);
    receipts.extend(created.receipt_ids.clone());

    let transformed = runner().execute(
        manifest(
            &profile,
            "sandbox.fixture.transform.v1",
            json!({
                "input": "fixtures/input.txt",
                "output": "fixtures/transformed.txt",
                "transform": "uppercase-ascii"
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
            json!({"path": "fixtures", "max_entries": 10}),
        ),
        profile.clone(),
    );
    assert_eq!(listed.status, TaskStatus::Success);
    assert_eq!(listed.output["entries"].as_array().unwrap().len(), 2);

    let metadata = runner().execute(
        manifest(
            &profile,
            "sandbox.discovery.metadata.v1",
            json!({"path": "fixtures/transformed.txt"}),
        ),
        profile.clone(),
    );
    assert_eq!(metadata.status, TaskStatus::Success);
    assert!(metadata.output["sha256"].as_str().is_some());

    let staged = runner().execute(
        manifest(
            &profile,
            "sandbox.collection.stage.v1",
            json!({
                "inputs": ["fixtures/transformed.txt"],
                "destination_directory": "staged"
            }),
        ),
        profile.clone(),
    );
    assert_eq!(staged.status, TaskStatus::Success);
    receipts.extend(staged.receipt_ids.clone());
    let bundle = staged.output["staged"][0]["artifact"]
        .as_str()
        .unwrap()
        .to_string();

    let delivered = runner().execute(
        manifest(
            &profile,
            "sandbox.network.loopback.v1",
            json!({"artifact": bundle, "destination": destination}),
        ),
        profile.clone(),
    );
    assert_eq!(delivered.status, TaskStatus::Success);
    assert_eq!(delivered.output["http_status"], 201);
    assert!(receiver
        .join()
        .unwrap()
        .starts_with(b"POST /bluefire/v1/artifact HTTP/1.1\r\n"));

    let exported = runner().execute(
        manifest(
            &profile,
            "sandbox.export.local.v1",
            json!({
                "source": "staged/000-transformed.txt",
                "destination": "exports/bundle.bin"
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
    assert!(fs::read_dir(root.path()).unwrap().next().is_none());
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
    assert_eq!(inventory_json["actions"].as_array().unwrap().len(), 8);

    let root = TempDir::new().unwrap();
    let profile = profile(&root, Vec::new());
    let request = manifest(
        &profile,
        "sandbox.fixture.create.v1",
        json!({"path": "cli.txt", "content_template": "empty"}),
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
