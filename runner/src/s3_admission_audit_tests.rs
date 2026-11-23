//! Pure admission-v3 data checks; no inherited channel, credentials or dispatch.

use super::*;

pub(crate) fn audited(mut value: Value) -> Value {
    let request = &value["manifest"]["params"]["worker_request"];
    let scope = &request["scope"];
    let limits = json!({"api_calls":9,"sessions":1,"files":4,"sdk_body_bytes":393216,
        "compressed_bytes":262144,"expanded_bytes":1048576,"events":500,"seconds":30});
    let commitment = json!({
        "schema_version":"bluefire.s3-audit-workflow.v1",
        "workflow_job_id":format!("job-{}", "1".repeat(32)),"environment_id":"owned-s3",
        "resource_key":canonical_hash(&json!({"account_id":scope["account_id"],"region":scope["region"],"bucket":scope["bucket"]})),
        "scope_digest":request["scope_digest"],
        "source":{
            "schema_version":"bluefire.s3-audit-source.v1","audit_source_id":"synthetic-trail",
            "experiment_scope_digest":request["scope_digest"],
            "trail_arn":format!("arn:aws:cloudtrail:{}:{}:trail/synthetic",scope["region"].as_str().unwrap(),scope["account_id"].as_str().unwrap()),
            "source_account_id":scope["account_id"],"event_region":scope["region"],
            "audit_bucket":"synthetic-audit-delivery","audit_bucket_owner_account_id":scope["account_id"],
            "audit_bucket_region":"us-west-2",
            "exact_delivery_root_prefix":format!("AWSLogs/{}/CloudTrail/{}/",scope["account_id"].as_str().unwrap(),scope["region"].as_str().unwrap()),
            "collector_role_arn":format!("arn:aws:iam::{}:role/audit-collector",scope["account_id"].as_str().unwrap()),
            "managed_profile_digest":format!("sha256:{}","6".repeat(64)),
            "protected_runtime_digest":request["runtime_digest"],"worker_generation":request["worker_generation"],
            "expires_at":scope["expires_at"],"audit_limits":limits,
        },
        "budget":{"per_batch":limits,"workflow":{"api_calls":18,"sessions":2,"files":8,
            "sdk_body_bytes":786432,"compressed_bytes":524288,"expanded_bytes":2097152,
            "events":1000,"seconds":60,"batches":2,"wire_plus_expansion_bytes":2883584}},
    });
    let workflow = &mut value["manifest"]["params"]["workflow_approval"];
    workflow["schema_version"] = json!("bluefire.s3-workflow-approval.v3");
    workflow["workflow_job_id"] = commitment["workflow_job_id"].clone();
    workflow["audit_workflow_digest"] = json!(canonical_hash(&commitment));
    value["admission"]["schema_version"] = json!("bluefire.s3-access-admission.v3");
    if value["admission"]["host"]
        .get("fixture_lifecycle")
        .is_none()
    {
        value["admission"]["host"]["fixture_lifecycle"] = Value::Null;
    }
    value["admission"]["host"]["audit_workflow"] = commitment;
    reseal(&mut value);
    value
}

pub(crate) fn fixture() -> Value {
    audited(super::fixture())
}

fn rebind(value: &mut Value) {
    value["manifest"]["params"]["workflow_approval"]["audit_workflow_digest"] = json!(
        canonical_hash(&value["admission"]["host"]["audit_workflow"])
    );
    reseal(value);
}

fn collector() -> Value {
    let mut value = fixture();
    let request = crate::s3_access_binding::audit::tests::request("baseline");
    value["manifest"]["params"]["worker_request"] = request.clone();
    value["admission"]["host"]["audit_workflow"]["source"] = request["audit"]["source"].clone();
    let workflow = &mut value["manifest"]["params"]["workflow_approval"];
    workflow["phase"] = json!("audit_baseline");
    workflow["operation_job_id"] = request["audit"]["operation_job_id"].clone();
    workflow["prior_run_ids"] = json!(request["audit"]["original_pair"]["reads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|read| read["run_id"].clone())
        .collect::<Vec<_>>());
    value["now"] = request["audit"]["issued_at"].clone();
    value["admission"]["issued_at"] = value["now"].clone();
    value["admission"]["expires_at"] = request["deadline"].clone();
    value["manifest"]["requested_at"] = value["now"].clone();
    value["manifest"]["expires_at"] = request["deadline"].clone();
    value["manifest"]["approval"]["approved_at"] = value["now"].clone();
    value["manifest"]["approval"]["expires_at"] = request["deadline"].clone();
    rebind(&mut value);
    value
}

#[test]
fn collector_v3_checks_original_workflow_source_and_runs_but_dispatch_stays_refused() {
    let value = collector();
    let admission = checked(&value).unwrap();
    assert!(admission.binding().audit().is_some());
    assert_eq!(
        admission.profile_digest(),
        canonical_hash(&value["profile"])
    );
    assert!(admission.binding().assert_dispatch_supported().is_err());
    for pointer in [
        "/manifest/params/workflow_approval/operation_job_id",
        "/admission/host/audit_workflow/source/managed_profile_digest",
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = if pointer.ends_with("operation_job_id") {
            json!(format!("job-{}", "f".repeat(32)))
        } else {
            json!(format!("sha256:{}", "f".repeat(64)))
        };
        rebind(&mut changed);
        assert!(checked(&changed).is_err());
    }
    let mut missing = value;
    missing["manifest"]["params"]["workflow_approval"]["prior_run_ids"] = json!([]);
    reseal(&mut missing);
    assert!(checked(&missing).is_err());
}

#[test]
fn collector_admission_cannot_precede_original_collection_interval_or_renew_it() {
    for (now, expires) in [
        ("2026-10-09T00:00:59Z", "2026-10-09T00:01:20Z"),
        ("2026-10-09T00:01:00Z", "2026-10-09T00:01:31Z"),
    ] {
        let mut value = collector();
        value["now"] = json!(now);
        value["admission"]["issued_at"] = json!(now);
        value["admission"]["expires_at"] = json!(expires);
        value["manifest"]["requested_at"] = json!(now);
        value["manifest"]["approval"]["approved_at"] = json!(now);
        value["manifest"]["expires_at"] = json!(expires);
        value["manifest"]["approval"]["expires_at"] = json!(expires);
        reseal(&mut value);
        assert!(checked(&value).is_err());
    }
}

#[test]
fn audited_business_admission_preserves_v1_request_and_separate_native_profile() {
    let original = super::fixture();
    let value = audited(original.clone());
    let admission = checked(&value).unwrap();
    assert_eq!(
        value["manifest"]["params"]["worker_request"],
        original["manifest"]["params"]["worker_request"]
    );
    assert_eq!(
        admission.profile_digest(),
        canonical_hash(&value["profile"])
    );
    assert_ne!(
        admission.profile_digest(),
        admission.audit_workflow().unwrap().managed_profile_digest()
    );
    assert_eq!(
        admission.audit_workflow().unwrap().scope_digest(),
        admission.binding().scope_digest()
    );
}

#[test]
fn audited_fixture_admission_keeps_original_v2_authority_and_nullable_host_contract() {
    let original =
        crate::s3_fixture_binding::tests::fixture_admission("prepare_fixture", "primary", None);
    let value = audited(original.clone());
    let admission = checked(&value).unwrap();
    assert_eq!(
        value["manifest"]["params"]["worker_request"],
        original["manifest"]["params"]["worker_request"]
    );
    assert!(admission.fixture_authority_digest().is_some() && admission.audit_workflow().is_some());
    let mut missing = value;
    missing["admission"]["host"]["fixture_lifecycle"] = Value::Null;
    reseal(&mut missing);
    assert!(checked(&missing).is_err());
}

#[test]
fn audited_closed_shapes_digest_and_runtime_source_substitutions_refuse() {
    for pointer in [
        "/admission/host/audit_workflow/source/protected_runtime_digest",
        "/admission/host/audit_workflow/source/worker_generation",
        "/admission/host/audit_workflow/scope_digest",
        "/admission/host/audit_workflow/resource_key",
    ] {
        let mut value = fixture();
        *value.pointer_mut(pointer).unwrap() = json!(format!("sha256:{}", "0".repeat(64)));
        rebind(&mut value);
        assert!(checked(&value).is_err(), "{pointer}");
    }
    let mut value = fixture();
    value["manifest"]["params"]["workflow_approval"]["audit_workflow_digest"] =
        json!(format!("sha256:{}", "0".repeat(64)));
    reseal(&mut value);
    assert!(checked(&value).is_err());
    let mut value = fixture();
    value["admission"]["host"]
        .as_object_mut()
        .unwrap()
        .remove("fixture_lifecycle");
    assert!(checked(&value).is_err());
}

#[test]
fn legacy_and_audited_host_approval_variants_cannot_be_mixed_or_downgraded() {
    for pointer in [
        "/admission/schema_version",
        "/manifest/params/workflow_approval/schema_version",
    ] {
        let mut value = fixture();
        *value.pointer_mut(pointer).unwrap() = json!(value
            .pointer(pointer)
            .unwrap()
            .as_str()
            .unwrap()
            .replace(".v3", ".v1"));
        reseal(&mut value);
        assert!(checked(&value).is_err());
    }
    let original = super::fixture();
    let admission = checked(&original).unwrap();
    assert!(admission.audit_workflow().is_none());
    assert_eq!(
        admission.binding().canonical_json(),
        crate::canonical::canonical_json(&original["manifest"]["params"]["worker_request"])
    );
}

#[test]
fn source_expiry_caps_business_but_preserves_original_policy_recovery() {
    let mut business = fixture();
    business["admission"]["host"]["audit_workflow"]["source"]["expires_at"] =
        json!("2026-10-09T00:00:01Z");
    rebind(&mut business);
    assert!(checked(&business).is_err()); // The envelope must also be capped.
    business["admission"]["expires_at"] = json!("2026-10-09T00:00:01Z");
    assert!(checked(&business).is_ok());
    business["now"] = json!("2026-10-09T00:00:02Z");
    assert!(checked(&business).is_err());
    for (operation, phase) in [
        ("reconcile_policy", "reconcile"),
        ("rollback_policy", "rollback"),
    ] {
        let mut recovery = fixture();
        let corpus: Value =
            serde_json::from_str(include_str!("../tests/fixtures/s3_access_binding_v1.json"))
                .unwrap();
        let mut request = corpus["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["request"]["operation"] == "rollback_policy")
            .unwrap()["request"]
            .clone();
        if operation == "reconcile_policy" {
            request["operation"] = json!(operation);
            request["max_sends"] = json!(2);
            request["exclusive_writer_digest"] = Value::Null;
        }
        recovery["manifest"]["params"]["workflow_approval"]["policy_change_digest"] =
            json!(canonical_hash(&request["policy_change"]));
        recovery["manifest"]["params"]["worker_request"] = request;
        recovery["manifest"]["params"]["workflow_approval"]["phase"] = json!(phase);
        recovery["admission"]["host"]["audit_workflow"]["source"]["expires_at"] =
            json!("2026-10-09T00:00:01Z");
        recovery["now"] = json!("2026-10-09T00:00:02Z");
        rebind(&mut recovery);
        assert!(checked(&recovery).is_ok(), "{operation}");
        assert_eq!(
            checked(&recovery)
                .unwrap()
                .audit_workflow()
                .unwrap()
                .document()
                .unwrap(),
            recovery["admission"]["host"]["audit_workflow"]
        );
    }
}

#[test]
fn source_expiry_preserves_exact_fixture_recovery_and_cleanup_without_renewal() {
    for operation in ["reconcile_fixture", "cleanup_fixture"] {
        let mut value = audited(crate::s3_fixture_binding::tests::fixture_admission(
            operation, "primary", None,
        ));
        value["admission"]["host"]["audit_workflow"]["source"]["expires_at"] =
            json!("2026-10-09T00:00:01Z");
        value["now"] = json!("2026-10-09T00:00:02Z");
        rebind(&mut value);
        assert!(checked(&value).is_ok(), "{operation}");
        assert_eq!(
            checked(&value)
                .unwrap()
                .audit_workflow()
                .unwrap()
                .source_expires_at()
                .to_rfc3339(),
            "2026-10-09T00:00:01+00:00"
        );
    }
}

#[test]
fn collector_requests_are_still_explicitly_unavailable() {
    for schema in [
        "bluefire.s3-worker-request.v1",
        "bluefire.s3-worker-request.v3",
    ] {
        let mut value = fixture();
        value["manifest"]["params"]["worker_request"]["schema_version"] = json!(schema);
        value["manifest"]["params"]["worker_request"]["operation"] = json!("collect_audit");
        reseal(&mut value);
        assert!(checked(&value).is_err());
    }
}
