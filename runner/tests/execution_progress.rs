//! Failure evidence preserves completed input work without claiming publication.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use bluefire_runner::contract::{MANIFEST_SCHEMA_VERSION, PROFILE_SCHEMA_VERSION};
use bluefire_runner::{
    inventory, seal_manifest, seal_profile, utc_now, Capability, EvidenceKind, ExecutionLimits,
    ExecutionManifest, Platform, RunMode, Runner, RunnerProfile, SafetyTier, TargetScope,
    TaskResult, TaskStatus,
};
use chrono::Duration;
use serde_json::{json, Value};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        for _ in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "bluefire-execution-progress-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("isolated test workspace: {error}"),
            }
        }
        panic!("could not allocate an isolated test workspace");
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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

fn profile(root: &Workspace) -> RunnerProfile {
    let mut profile = RunnerProfile {
        schema_version: PROFILE_SCHEMA_VERSION.into(),
        profile_id: "profile:execution-progress".into(),
        runner_id: "runner:execution-progress".into(),
        platform: Platform::current(),
        sandbox_root: root.0.clone(),
        allowed_actions: inventory()
            .into_iter()
            .map(|item| item.action_id.to_string())
            .collect(),
        reviewed_execution: None,
        file_access_binding: None,
        control_blocked_actions: Vec::new(),
        action_bindings: Vec::new(),
        native_tool_installations: Vec::new(),
        provider_bindings: Vec::new(),
        provider_artifacts: Vec::new(),
        capabilities: vec![
            Capability::FilesystemRead,
            Capability::FilesystemWrite,
            Capability::ExportLocal,
            Capability::Cleanup,
        ],
        max_safety_tier: SafetyTier::Controlled,
        approval_required_at_or_above: None,
        target_scope: TargetScope {
            filesystem: vec![".".into()],
            network: Vec::new(),
        },
        limits: limits(),
        policy_digest: String::new(),
    };
    seal_profile(&mut profile);
    profile
}

fn manifest(profile: &RunnerProfile, action: &str, params: Value) -> ExecutionManifest {
    let descriptor = inventory()
        .into_iter()
        .find(|item| item.action_id == action)
        .expect("registered action");
    let requested_at = utc_now() - Duration::seconds(1);
    let mut manifest = ExecutionManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.into(),
        request_id: format!("request:{}", action.replace('.', "-")),
        run_id: "run:execution-progress".into(),
        step_id: format!("step:{}", action.replace('.', "-")),
        behavior_id: descriptor.behavior_ids[0].into(),
        action_id: action.into(),
        execution_binding: None,
        provider_binding: None,
        reviewed_operation: None,
        grant_attempt: None,
        grant_cleanup: None,
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
        cleanup_action_id: "sandbox.cleanup.v1".into(),
        policy_digest: profile.policy_digest.clone(),
        approval: None,
        evidence_refs: Vec::new(),
        request_hash: String::new(),
    };
    seal_manifest(&mut manifest);
    manifest
}

fn execute(profile: &RunnerProfile, action: &str, params: Value) -> TaskResult {
    Runner::new()
        .unwrap()
        .execute(manifest(profile, action, params), profile.clone())
}

fn fixture(profile: &RunnerProfile) -> Vec<String> {
    let result = execute(
        profile,
        "sandbox.fixture.create.v1",
        json!({"path":"fixtures/source.jsonl","content_template":"telemetry-seed","record_count":1}),
    );
    assert_eq!(result.status, TaskStatus::Success, "{result:#?}");
    result.receipt_ids
}

fn assert_refused(result: &TaskResult, code: &str, started: bool) {
    assert_eq!(result.status, TaskStatus::ControlBlocked, "{result:#?}");
    assert_eq!(result.error.as_ref().unwrap().code, code);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(
        result.evidence[0].kind,
        if started {
            EvidenceKind::Executed
        } else {
            EvidenceKind::ControlBlocked
        }
    );
    assert_eq!(result.evidence[0].details["side_effects_started"], started);
    assert_eq!(result.evidence[0].details["status"], "control_blocked");
    assert!(result.output.is_null());
    assert!(result.receipt_ids.is_empty());
}

fn cleanup(profile: &RunnerProfile, receipts: Vec<String>) {
    let result = execute(
        profile,
        "sandbox.cleanup.v1",
        json!({"receipt_ids":receipts}),
    );
    assert_eq!(result.status, TaskStatus::Success, "{result:#?}");
}

#[test]
fn transform_and_export_destination_refusals_preserve_input_execution() {
    for export in [false, true] {
        let root = Workspace::new();
        let profile = profile(&root);
        let receipts = fixture(&profile);
        let source = fs::read(root.0.join("fixtures/source.jsonl")).unwrap();
        let (action, destination, params) = if export {
            (
                "sandbox.export.local.v1",
                "exports/review/bundle.bin",
                json!({"source":"fixtures/source.jsonl","retention_label":"review"}),
            )
        } else {
            (
                "sandbox.fixture.transform.v1",
                "fixtures/transformed.jsonl",
                json!({"input":"fixtures/source.jsonl","output":"fixtures/transformed.jsonl","redact_values":false}),
            )
        };
        let target = root.0.join(destination);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"existing test-owned output").unwrap();
        let result = execute(&profile, action, params);
        assert_refused(&result, "path_rejected", true);
        assert_eq!(fs::read(&target).unwrap(), b"existing test-owned output");
        assert_eq!(
            fs::read(root.0.join("fixtures/source.jsonl")).unwrap(),
            source
        );
        fs::remove_file(&target).unwrap();
        cleanup(&profile, receipts);
    }
}

#[test]
fn observability_output_limit_preserves_read_without_publication() {
    let root = Workspace::new();
    let profile = profile(&root);
    let mut receipts = fixture(&profile);
    let staged = execute(
        &profile,
        "sandbox.collection.stage.v1",
        json!({"inputs":["fixtures/source.jsonl"],"destination_directory":"staged","bundle_format":"jsonl"}),
    );
    assert_eq!(staged.status, TaskStatus::Success, "{staged:#?}");
    receipts.extend(staged.receipt_ids);
    let source = fs::read(root.0.join("staged/bundle.jsonl")).unwrap();
    let mut request = manifest(
        &profile,
        "sandbox.observability.variant.v1",
        json!({"representation":"canonical"}),
    );
    request.limits.max_artifact_bytes = source.len() as u64;
    seal_manifest(&mut request);
    let result = Runner::new().unwrap().execute(request, profile.clone());
    assert_refused(&result, "artifact_limit_blocked", true);
    assert_eq!(
        fs::read(root.0.join("staged/bundle.jsonl")).unwrap(),
        source
    );
    assert!(!root.0.join("observability/variant.bin").exists());
    cleanup(&profile, receipts);
}

#[test]
fn transform_path_authorization_refusal_remains_before_execution() {
    let root = Workspace::new();
    let profile = profile(&root);
    let receipts = fixture(&profile);
    let source = fs::read(root.0.join("fixtures/source.jsonl")).unwrap();
    let result = execute(
        &profile,
        "sandbox.fixture.transform.v1",
        json!({"input":"../outside.jsonl","output":"fixtures/transformed.jsonl","redact_values":false}),
    );
    assert_refused(&result, "path_rejected", false);
    assert_eq!(
        fs::read(root.0.join("fixtures/source.jsonl")).unwrap(),
        source
    );
    assert!(!root.0.join("fixtures/transformed.jsonl").exists());
    cleanup(&profile, receipts);
}
