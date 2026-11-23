//! Exercise report retention after a synthetic observation, without a worker.

use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        for _ in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "bluefire-file-access-retention-{}-{}",
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

fn documents(workspace: &Workspace, owner: bool) -> (RunnerProfile, ExecutionManifest) {
    let action = if owner {
        OWNER.action_id
    } else {
        PROBE.action_id
    };
    let limits = json!({"timeout_ms":5000,"max_stdout_bytes":8192,"max_stderr_bytes":8192,"max_artifact_bytes":1048576,"max_files":32});
    let scope = json!({"filesystem":["fixtures"],"network":[]});
    let profile: RunnerProfile = serde_json::from_value(json!({
        "schema_version":crate::contract::PROFILE_SCHEMA_VERSION,
        "profile_id":"profile:retention-test","runner_id":"runner:retention-test",
        "platform":Platform::current(),"sandbox_root":workspace.0,
        "allowed_actions":[action],"capabilities":["filesystem_read","filesystem_write"],
        "max_safety_tier":"controlled","target_scope":scope,"limits":limits,
        "policy_digest":"a".repeat(64)
    }))
    .unwrap();
    let now = crate::contract::utc_now();
    let manifest = serde_json::from_value(json!({
        "schema_version":crate::contract::MANIFEST_SCHEMA_VERSION,
        "request_id":"request:retention-test","run_id":"run:retention-test","step_id":"step:read",
        "behavior_id":action,"action_id":action,"mode":"execute",
        "runner_id":profile.runner_id,"runner_profile_id":profile.profile_id,
        "platform":Platform::current(),"requested_at":now,"expires_at":now+chrono::Duration::minutes(1),
        "params":{},"target_scope":scope,"required_capabilities":["filesystem_read","filesystem_write"],
        "safety_tier":"controlled","limits":limits,"cleanup_action_id":"sandbox.cleanup.v1",
        "policy_digest":profile.policy_digest,"request_hash":"b".repeat(64)
    })).unwrap();
    (profile, manifest)
}

#[test]
fn post_observation_report_limits_retain_execution_progress() {
    for owner in [false, true] {
        for file_limit in [false, true] {
            let workspace = Workspace::new();
            let root = SafeRoot::open(&workspace.0).unwrap();
            let (profile, mut manifest) = documents(&workspace, owner);
            if file_limit {
                manifest.limits.max_files = 0;
            } else {
                manifest.limits.max_artifact_bytes = 1;
            }
            let context = ActionContext {
                manifest: &manifest,
                profile: &profile,
                root: &root,
                execution_started: Cell::new(false),
            };
            let failure = retain_observation(
                &context,
                "fixtures/access-probe.json",
                json!({"synthetic":true}),
            )
            .unwrap_err();
            assert_eq!(failure.status, TaskStatus::Refused);
            assert_eq!(failure.code, "artifact_limit");
            assert!(context.execution_started.get());
            assert_eq!(fs::read_dir(&workspace.0).unwrap().count(), 0);
        }
    }
}

#[test]
fn post_observation_path_conflict_retains_execution_and_existing_report() {
    for owner in [false, true] {
        let workspace = Workspace::new();
        let root = SafeRoot::open(&workspace.0).unwrap();
        let (profile, manifest) = documents(&workspace, owner);
        let context = ActionContext {
            manifest: &manifest,
            profile: &profile,
            root: &root,
            execution_started: Cell::new(false),
        };
        let path = if owner {
            "fixtures/access-owner.json"
        } else {
            "fixtures/access-probe.json"
        };
        fs::create_dir(workspace.0.join("fixtures")).unwrap();
        fs::write(workspace.0.join(path), b"existing test report").unwrap();
        let failure = retain_observation(&context, path, json!({"synthetic":true})).unwrap_err();
        assert_eq!(failure.status, TaskStatus::ControlBlocked);
        assert_eq!(failure.code, "path_rejected");
        assert!(context.execution_started.get());
        assert_eq!(
            fs::read(workspace.0.join(path)).unwrap(),
            b"existing test report"
        );
        assert!(!workspace.0.join(".bluefire").exists());
        assert_eq!(
            fs::read_dir(workspace.0.join("fixtures")).unwrap().count(),
            1
        );
    }
}

#[test]
fn missing_enrollment_refusal_remains_before_execution() {
    for owner in [false, true] {
        let workspace = Workspace::new();
        let root = SafeRoot::open(&workspace.0).unwrap();
        let (profile, manifest) = documents(&workspace, owner);
        let context = ActionContext {
            manifest: &manifest,
            profile: &profile,
            root: &root,
            execution_started: Cell::new(false),
        };
        let failure = Box::new(Prepared { owner }).execute(&context).unwrap_err();
        assert_eq!(failure.status, TaskStatus::Refused);
        assert_eq!(failure.code, "file_access_binding_required");
        assert!(!context.execution_started.get());
        assert_eq!(fs::read_dir(&workspace.0).unwrap().count(), 0);
    }
}
