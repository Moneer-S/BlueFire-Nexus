use super::*;
use crate::canonical::canonical_hash;
use crate::contract::{seal_manifest, seal_profile, ExecutionManifest, RunnerProfile};
use serde_json::{json, Value};

pub(crate) fn fixture() -> Value {
    let service: Value = serde_json::from_str(include_str!(
        "../../tests_platform/fixtures/owned_service_admission_v1.json"
    ))
    .unwrap();
    let corpus: Value =
        serde_json::from_str(include_str!("../tests/fixtures/s3_access_binding_v1.json")).unwrap();
    let request = corpus["cases"][0]["request"].clone();
    let mut profile = service["profile"].clone();
    profile["allowed_actions"] = json!([S3_ACTION_ID]);
    profile["capabilities"] = json!(["cloud_aws_s3_access"]);
    profile
        .as_object_mut()
        .unwrap()
        .remove("native_tool_installations");
    let mut profile: RunnerProfile = serde_json::from_value(profile).unwrap();
    seal_profile(&mut profile);
    let profile = serde_json::to_value(profile).unwrap();
    let mut manifest = service["manifest"].clone();
    manifest["action_id"] = json!(S3_ACTION_ID);
    manifest["required_capabilities"] = json!(["cloud_aws_s3_access"]);
    manifest["policy_digest"] = profile["policy_digest"].clone();
    manifest["requested_at"] = corpus["now"].clone();
    manifest["expires_at"] = request["deadline"].clone();
    manifest["approval"]["approved_at"] = corpus["now"].clone();
    manifest["approval"]["expires_at"] = request["deadline"].clone();
    manifest["params"] = json!({
        "worker_request": request,
        "workflow_approval": {
            "schema_version":"bluefire.s3-workflow-approval.v1",
            "workflow_job_id":"job-workflow", "operation_job_id":"job-inspect",
            "environment_id":"owned-s3", "scope_digest":request["scope_digest"],
            "request_digest":canonical_hash(&request), "phase":"inspect",
            "reviewed_by":"operator", "review_digest":format!("sha256:{}", "f".repeat(64)),
            "expected_workflow_revision":0, "prior_run_ids":[], "policy_change_digest":null
        }
    });
    let mut manifest: ExecutionManifest = serde_json::from_value(manifest).unwrap();
    seal_manifest(&mut manifest);
    let manifest = serde_json::to_value(manifest).unwrap();
    let admission = json!({
        "schema_version":"bluefire.s3-access-admission.v1",
        "issuer":service["admission"]["issuer"],
        "manifest_digest":canonical_hash(&manifest), "profile_digest":canonical_hash(&profile),
        "request_digest":canonical_hash(&request),
        "approval_digest":canonical_hash(&manifest["params"]["workflow_approval"]),
        "host":{
            "environment_id":"owned-s3", "scope_digest":request["scope_digest"],
            "runtime_digest":request["runtime_digest"], "worker_generation":request["worker_generation"],
            "ledger_root":"/opt/bluefire/state/s3", "runtime_root":"/opt/bluefire/runtime/s3",
            "owner_uid":1000
        },
        "native_runner_digest":format!("sha256:{}", "e".repeat(64)),
        "credential_digest":format!("sha256:{}", "d".repeat(64)),
        "issued_at":corpus["now"], "expires_at":request["deadline"]
    });
    json!({"admission":admission,"manifest":manifest,"profile":profile,"now":corpus["now"]})
}

pub(crate) fn checked(value: &Value) -> Result<VerifiedS3Admission, String> {
    let mut issuer = value["admission"]["issuer"].clone();
    issuer.as_object_mut().unwrap().remove("server_instance_id");
    wire::validate(
        &value["admission"],
        &issuer,
        &value["manifest"],
        &value["profile"],
        DateTime::parse_from_rfc3339(value["now"].as_str().unwrap()).unwrap(),
    )
}

pub(crate) fn reseal(value: &mut Value) {
    let mut profile: RunnerProfile = serde_json::from_value(value["profile"].clone()).unwrap();
    seal_profile(&mut profile);
    value["profile"] = serde_json::to_value(profile).unwrap();
    value["manifest"]["policy_digest"] = value["profile"]["policy_digest"].clone();
    let request = &value["manifest"]["params"]["worker_request"];
    value["manifest"]["params"]["workflow_approval"]["request_digest"] =
        json!(canonical_hash(request));
    let mut manifest: ExecutionManifest =
        serde_json::from_value(value["manifest"].clone()).unwrap();
    seal_manifest(&mut manifest);
    value["manifest"] = serde_json::to_value(manifest).unwrap();
    value["admission"]["manifest_digest"] = json!(canonical_hash(&value["manifest"]));
    value["admission"]["profile_digest"] = json!(canonical_hash(&value["profile"]));
    value["admission"]["request_digest"] = json!(canonical_hash(
        &value["manifest"]["params"]["worker_request"]
    ));
    value["admission"]["approval_digest"] = json!(canonical_hash(
        &value["manifest"]["params"]["workflow_approval"]
    ));
}

#[test]
fn valid_configured_admission_binds_the_exact_request_and_review() {
    let value = fixture();
    let admission = checked(&value).unwrap();
    assert_eq!(admission.binding().operation(), "inspect_policy");
    assert_eq!(admission.workflow_id(), "job-workflow");
    assert_eq!(admission.phase(), "inspect");
    assert_eq!(admission.revision(), 0);
}

#[test]
fn human_reviewer_name_matches_saved_product_contract() {
    let mut value = fixture();
    value["manifest"]["params"]["workflow_approval"]["reviewed_by"] = json!("Jane Doe");
    reseal(&mut value);
    assert!(checked(&value).is_ok());
}

#[test]
fn rehashing_does_not_supply_missing_capability_or_expand_admission() {
    for (pointer, replacement) in [
        ("/profile/capabilities", json!(["network_loopback"])),
        ("/profile/allowed_actions", json!([])),
        ("/profile/control_blocked_actions", json!([S3_ACTION_ID])),
        ("/manifest/action_id", json!("network.loopback.v1")),
        (
            "/manifest/required_capabilities",
            json!(["network_loopback"]),
        ),
        ("/manifest/mode", json!("simulate")),
        ("/manifest/params/workflow_approval/phase", json!("apply")),
        (
            "/manifest/params/workflow_approval/review_digest",
            Value::Null,
        ),
        (
            "/manifest/params/workflow_approval/expected_workflow_revision",
            json!(true),
        ),
        (
            "/manifest/params/workflow_approval/prior_run_ids",
            json!(["run-a", "run-a"]),
        ),
        ("/admission/host/owner_uid", json!(0)),
        ("/admission/host/runtime_root", json!("/opt/../tmp/runtime")),
        (
            "/admission/host/scope_digest",
            json!(format!("sha256:{}", "a".repeat(64))),
        ),
        ("/admission/expires_at", json!("2026-10-09T00:00:31Z")),
    ] {
        let mut value = fixture();
        *value.pointer_mut(pointer).unwrap() = replacement;
        reseal(&mut value);
        assert!(checked(&value).is_err(), "accepted {pointer}");
    }
}

#[test]
fn expired_and_future_admission_are_refused() {
    for now in ["2026-10-08T23:59:59Z", "2026-10-09T00:00:30Z"] {
        let mut value = fixture();
        value["now"] = json!(now);
        assert!(checked(&value).is_err());
    }
}

#[test]
fn ordinary_registry_cannot_dispatch_the_reserved_cloud_action() {
    let value = fixture();
    let manifest = serde_json::from_value(value["manifest"].clone()).unwrap();
    let profile = serde_json::from_value(value["profile"].clone()).unwrap();
    let result = crate::Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, crate::TaskStatus::Refused);
    assert_eq!(result.error.unwrap().code, "s3_admission_required");
    assert!(result.receipt_ids.is_empty() && result.cleanup.is_none());
}

#[test]
fn resealed_endpoint_file_authority_cannot_enter_the_cloud_channel() {
    let mut value = fixture();
    assert!(checked(&value).is_ok());
    let generation = "a".repeat(32);
    let acl =
        canonical_hash(&json!({"system.posix_acl_access":null,"system.posix_acl_default":null}));
    let binding = json!({
        "schema_version":"bluefire.file-access-execution.v1",
        "enrollment_id":format!("file-enrollment-{}", "b".repeat(32)),
        "enrollment_digest":format!("sha256:{}", "c".repeat(64)),
        "resource_id":format!("file-resource-{}", "d".repeat(32)),
        "resource_generation":format!("file-generation-{generation}"),
        "expires_at_ms":crate::contract::utc_now().timestamp_millis()+90_000,
        "control_revision":1,"mode":"0640",
        "resource":{"root":format!("/run/bluefire-file-access/data/{generation}"),
            "root_device":3,"root_inode":101,"parent_device":3,"parent_inode":102,
            "device":3,"inode":103,"owner_uid":1000,"group_gid":1002,
            "sha256":format!("sha256:{}", "e".repeat(64)),"size":100,"record_count":6,
            "acl_digest":acl,"parent_acl_digest":acl},
        "worker":{"socket_path":format!("/run/bluefire-file-access/control/{generation}/probe.sock"),
            "uid":1002,"gid":1002,"pid":23,"start_ticks":42,"launch_nonce":"f".repeat(64),
            "namespaces":{"mnt":"mnt:[123]","net":"net:[123]","pid":"pid:[123]","ipc":"ipc:[123]"}}
    });
    let endpoint: crate::file_access::FileAccessBinding =
        serde_json::from_value(binding.clone()).unwrap();
    endpoint.current().unwrap();
    value["profile"]["file_access_binding"] = binding;
    reseal(&mut value);
    assert!(checked(&value).is_err());
}

#[test]
fn explicit_null_endpoint_binding_is_not_absent_cloud_authority() {
    let mut value = fixture();
    value["profile"]["file_access_binding"] = Value::Null;
    assert!(serde_json::from_value::<RunnerProfile>(value["profile"].clone()).is_err());
    assert!(checked(&value).is_err());
}
