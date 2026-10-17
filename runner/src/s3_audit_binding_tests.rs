use super::*;
use serde_json::json;

fn scope() -> Scope {
    let corpus: Value =
        serde_json::from_str(include_str!("../tests/fixtures/s3_access_binding_v1.json")).unwrap();
    serde_json::from_value(corpus["cases"][0]["request"]["scope"].clone()).unwrap()
}

fn fixture(scope: &Scope) -> Value {
    let scope_digest = canonical_hash(&encoded(scope).unwrap());
    json!({
        "schema_version":WORKFLOW_SCHEMA,"workflow_job_id":format!("job-{}", "1".repeat(32)),
        "environment_id":"synthetic-audited-environment",
        "resource_key":canonical_hash(&json!({"account_id":scope.account_id,"region":scope.region,"bucket":scope.bucket})),
        "scope_digest":scope_digest,
        "source":{
            "schema_version":"bluefire.s3-audit-source.v1","audit_source_id":"synthetic-trail-delivery",
            "experiment_scope_digest":scope_digest,
            "trail_arn":format!("arn:aws:cloudtrail:{}:{}:trail/synthetic", scope.region, scope.account_id),
            "source_account_id":scope.account_id,"event_region":scope.region,
            "audit_bucket":"bluefire-audit-fixture","audit_bucket_owner_account_id":scope.account_id,
            "audit_bucket_region":"us-west-2",
            "exact_delivery_root_prefix":format!("AWSLogs/{}/CloudTrail/{}/", scope.account_id, scope.region),
            "collector_role_arn":format!("arn:aws:iam::{}:role/bluefire-audit-reader", scope.account_id),
            "managed_profile_digest":format!("sha256:{}", "6".repeat(64)),
            "protected_runtime_digest":format!("sha256:{}", "d".repeat(64)),
            "worker_generation":format!("sha256:{}", "c".repeat(64)),"expires_at":scope.expires_at,
            "audit_limits":{"api_calls":9,"sessions":1,"files":4,"sdk_body_bytes":393216,
                "compressed_bytes":262144,"expanded_bytes":1048576,"events":500,"seconds":30},
        },
        "budget":{
            "per_batch":{"api_calls":9,"sessions":1,"files":4,"sdk_body_bytes":393216,
                "compressed_bytes":262144,"expanded_bytes":1048576,"events":500,"seconds":30},
            "workflow":{"api_calls":18,"sessions":2,"files":8,"sdk_body_bytes":786432,
                "compressed_bytes":524288,"expanded_bytes":2097152,"events":1000,"seconds":60,
                "batches":2,"wire_plus_expansion_bytes":2883584},
        },
    })
}

fn checked(scope: &Scope, value: &Value) -> Checked<AuditWorkflow> {
    AuditWorkflow::from_json(
        canonical_json(value).as_bytes(),
        scope,
        &format!("sha256:{}", "d".repeat(64)),
        &format!("sha256:{}", "c".repeat(64)),
    )
}

#[test]
fn complete_workflow_matches_canonical_python_shape_and_separate_host_profile_identity() {
    let scope = scope();
    let value = fixture(&scope);
    let checked = checked(&scope, &value).unwrap();
    assert_eq!(checked.document().unwrap(), value);
    assert_eq!(checked.digest(), canonical_hash(&value));
    assert_eq!(checked.source_digest(), canonical_hash(&value["source"]));
    assert_eq!(
        checked.workflow_id(),
        value["workflow_job_id"].as_str().unwrap()
    );
    assert_eq!(checked.environment_id(), "synthetic-audited-environment");
    assert_eq!(
        checked.scope_digest(),
        canonical_hash(&encoded(&scope).unwrap())
    );
    assert_eq!(
        checked.resource_key(),
        value["resource_key"].as_str().unwrap()
    );
    assert_eq!(
        checked.runtime_digest(),
        format!("sha256:{}", "d".repeat(64))
    );
    assert_eq!(
        checked.worker_generation(),
        format!("sha256:{}", "c".repeat(64))
    );
    assert_eq!(
        checked.managed_profile_digest(),
        format!("sha256:{}", "6".repeat(64))
    );
    assert_ne!(
        checked.managed_profile_digest(),
        canonical_hash(&json!({"profile_id":"native-profile"}))
    );
    assert_eq!(checked.budget().workflow.api_calls, 18);
    assert_eq!(checked.budget().workflow.sessions + 4, 6);
    assert_eq!(
        checked.budget().workflow.wire_plus_expansion_bytes,
        2_883_584
    );
}

#[test]
fn all_integer_layers_refuse_boolean_float_and_negative_aliases() {
    let scope = scope();
    for path in [
        "/source/audit_limits/sessions",
        "/budget/per_batch/sessions",
        "/budget/workflow/batches",
    ] {
        for replacement in [json!(true), json!(1.0), json!(-1)] {
            let mut value = fixture(&scope);
            *value.pointer_mut(path).unwrap() = replacement;
            assert!(checked(&scope, &value).is_err(), "{path}");
        }
    }
}

#[test]
fn every_closed_layer_refuses_unknown_missing_and_duplicate_fields() {
    let scope = scope();
    for path in [
        "",
        "/source",
        "/source/audit_limits",
        "/budget",
        "/budget/per_batch",
        "/budget/workflow",
    ] {
        let mut value = fixture(&scope);
        value
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), json!(0));
        assert!(checked(&scope, &value).is_err(), "{path}");
        let mut value = fixture(&scope);
        let object = value.pointer_mut(path).unwrap().as_object_mut().unwrap();
        let name = object.keys().next().unwrap().clone();
        object.remove(&name);
        assert!(checked(&scope, &value).is_err(), "{path}");
    }
    let original = canonical_json(&fixture(&scope));
    let duplicate = format!("{{\"schema_version\":\"duplicate\",{}", &original[1..]);
    assert!(AuditWorkflow::from_json(
        duplicate.as_bytes(),
        &scope,
        &format!("sha256:{}", "d".repeat(64)),
        &format!("sha256:{}", "c".repeat(64))
    )
    .is_err());
    let duplicate_nested =
        original.replacen("\"api_calls\":9", "\"api_calls\":9,\"api_calls\":9", 1);
    assert!(AuditWorkflow::from_json(
        duplicate_nested.as_bytes(),
        &scope,
        &format!("sha256:{}", "d".repeat(64)),
        &format!("sha256:{}", "c".repeat(64))
    )
    .is_err());
}

#[test]
fn schema_identity_and_original_resource_substitutions_refuse() {
    let scope = scope();
    for (path, replacement) in [
        ("/schema_version", json!("bluefire.s3-audit-source.v1")),
        ("/workflow_job_id", json!("job-invalid")),
        ("/workflow_job_id", json!(format!("job-{}", "A".repeat(32)))),
        ("/environment_id", json!("../environment")),
        ("/scope_digest", json!(format!("sha256:{}", "0".repeat(64)))),
        (
            "/source/experiment_scope_digest",
            json!(format!("sha256:{}", "0".repeat(64))),
        ),
        (
            "/resource_key",
            json!(canonical_hash(
                &json!({"account_id":scope.account_id,"region":"us-west-2","bucket":"bluefire-audit-fixture"})
            )),
        ),
    ] {
        let mut value = fixture(&scope);
        *value.pointer_mut(path).unwrap() = replacement;
        assert!(checked(&scope, &value).is_err(), "{path}");
    }
    let value = fixture(&scope);
    let mut changed_scope = scope.clone();
    changed_scope.bucket = "different-experiment-bucket".into();
    assert!(checked(&changed_scope, &value).is_err());
}

#[test]
fn source_schema_account_region_role_trail_prefix_and_digest_are_closed() {
    let scope = scope();
    for (field, replacement) in [
        ("schema_version", "bluefire.s3-audit-source.v2"),
        ("audit_source_id", "../source"),
        ("source_account_id", "999999999999"),
        ("event_region", "us-west-2"),
        ("audit_bucket_owner_account_id", "999999999999"),
        ("audit_bucket_region", "us-gov-west-1"),
        ("audit_bucket", "bucket--x-s3"),
        (
            "trail_arn",
            "arn:aws:cloudtrail:us-east-1:999999999999:trail/synthetic",
        ),
        (
            "collector_role_arn",
            "arn:aws:iam::123456789012:role/bluefire-probe",
        ),
        (
            "exact_delivery_root_prefix",
            "AWSLogs/123456789012/CloudTrail/us-west-2/",
        ),
        (
            "exact_delivery_root_prefix",
            "../AWSLogs/123456789012/CloudTrail/us-east-1/",
        ),
        (
            "exact_delivery_root_prefix",
            "x//AWSLogs/123456789012/CloudTrail/us-east-1/",
        ),
        (
            "exact_delivery_root_prefix",
            "x%2f/AWSLogs/123456789012/CloudTrail/us-east-1/",
        ),
        ("managed_profile_digest", "unsealed"),
    ] {
        let mut value = fixture(&scope);
        value["source"][field] = json!(replacement);
        assert!(checked(&scope, &value).is_err(), "{field}");
    }
}

#[test]
fn expected_runtime_and_generation_are_independent_exact_bindings() {
    let scope = scope();
    let value = fixture(&scope);
    let runtime = format!("sha256:{}", "d".repeat(64));
    let generation = format!("sha256:{}", "c".repeat(64));
    let changed = format!("sha256:{}", "f".repeat(64));
    for (runtime, generation) in [
        (changed.as_str(), generation.as_str()),
        (runtime.as_str(), changed.as_str()),
        ("invalid", generation.as_str()),
    ] {
        assert!(AuditWorkflow::from_json(
            canonical_json(&value).as_bytes(),
            &scope,
            runtime,
            generation
        )
        .is_err());
    }
}

#[test]
fn six_sessions_and_six_weighted_attempts_are_required_without_limit_increase() {
    let original = scope();
    assert!(checked(&original, &fixture(&original)).is_ok());
    let mut changed = original.clone();
    changed.limits.sessions = 5;
    assert!(checked(&changed, &fixture(&changed)).is_err());
    assert_eq!(changed.limits.sessions, 5);
    let mut changed = original.clone();
    changed.limits.business_attempts = 5;
    assert!(checked(&changed, &fixture(&changed)).is_err());
    assert_eq!(changed.limits.business_attempts, 5);
}

#[test]
fn expiry_is_original_canonical_data_not_a_current_clock_check() {
    let scope = scope();
    for expires in ["2026-10-09T00:00:05Z", "2026-10-09T00:00:05.123456Z"] {
        let mut value = fixture(&scope);
        value["source"]["expires_at"] = json!(expires);
        assert_eq!(
            checked(&scope, &value).unwrap().source_expires_at(),
            &utc_time(expires).unwrap()
        );
    }
    for expires in [
        "2026-10-09T00:00:00Z",
        "2026-10-09T01:00:01Z",
        "2026-10-09T00:00:05.000000Z",
        "2026-10-09T00:00:05+00:00",
        "2026-10-09T00:00:05.123Z",
    ] {
        let mut value = fixture(&scope);
        value["source"]["expires_at"] = json!(expires);
        assert!(checked(&scope, &value).is_err(), "{expires}");
    }
}

#[test]
fn budget_minima_are_rederived_from_scope_not_caller_totals() {
    let mut scope = scope();
    scope.limits.audit_events = 90;
    scope.limits.audit_seconds = 40;
    scope.limits.request_seconds = 25;
    scope.expires_at = "2026-10-09T00:30:00Z".into();
    let mut value = fixture(&scope);
    assert!(checked(&scope, &value).is_err());
    value["budget"]["per_batch"]["events"] = json!(45);
    value["budget"]["workflow"]["events"] = json!(90);
    value["budget"]["per_batch"]["seconds"] = json!(20);
    value["budget"]["workflow"]["seconds"] = json!(40);
    let checked = checked(&scope, &value).unwrap();
    assert_eq!(checked.budget().per_batch.events, 45);
    assert_eq!(checked.budget().per_batch.seconds, 20);
    assert_eq!(
        checked.document().unwrap()["source"]["audit_limits"]["events"],
        500
    );
}

#[test]
fn compressed_bytes_share_wire_and_do_not_add_a_second_allowance() {
    let scope = scope();
    let mut value = fixture(&scope);
    value["source"]["audit_limits"]["sdk_body_bytes"] = json!(200000);
    assert!(checked(&scope, &value).is_err());
    for field in ["sdk_body_bytes", "compressed_bytes"] {
        value["budget"]["per_batch"][field] = json!(200000);
        value["budget"]["workflow"][field] = json!(400000);
    }
    value["budget"]["workflow"]["wire_plus_expansion_bytes"] = json!(2 * (200000 + 1048576));
    let checked = checked(&scope, &value).unwrap();
    assert_eq!(checked.budget().per_batch.compressed_bytes, 200000);
    assert_eq!(
        checked.budget().workflow.wire_plus_expansion_bytes,
        2 * (200000 + 1048576)
    );
}

#[test]
fn one_file_budget_uses_the_exact_compressed_response_clamp() {
    let scope = scope();
    let mut value = fixture(&scope);
    value["source"]["audit_limits"]["files"] = json!(1);
    value["budget"]["per_batch"]["files"] = json!(1);
    value["budget"]["per_batch"]["compressed_bytes"] = json!(65_536);
    value["budget"]["workflow"]["files"] = json!(2);
    value["budget"]["workflow"]["compressed_bytes"] = json!(131_072);

    let checked = checked(&scope, &value).unwrap();
    assert_eq!(checked.budget().per_batch.files, 1);
    assert_eq!(checked.budget().per_batch.compressed_bytes, 65_536);
    assert_eq!(checked.budget().workflow.files, 2);
    assert_eq!(checked.budget().workflow.compressed_bytes, 131_072);
}

#[test]
fn one_file_budget_rejects_a_self_consistent_compressed_value_above_the_clamp() {
    let scope = scope();
    let mut value = fixture(&scope);
    value["source"]["audit_limits"]["files"] = json!(1);
    value["budget"]["per_batch"]["files"] = json!(1);
    value["budget"]["per_batch"]["compressed_bytes"] = json!(65_537);
    value["budget"]["workflow"]["files"] = json!(2);
    value["budget"]["workflow"]["compressed_bytes"] = json!(131_074);

    assert!(checked(&scope, &value).is_err());
}

#[test]
fn underfunded_scope_or_changed_source_caps_never_raise_limits() {
    for field in ["api_calls", "audit_bytes", "audit_events"] {
        let original = scope();
        let mut raw = encoded(&original).unwrap();
        raw["limits"][field] = json!(if field == "api_calls" { 17 } else { 1 });
        let changed: Scope = serde_json::from_value(raw).unwrap();
        assert!(checked(&changed, &fixture(&changed)).is_err(), "{field}");
    }
    let scope = scope();
    for (field, value) in [
        ("api_calls", 8),
        ("sessions", 2),
        ("files", 5),
        ("sdk_body_bytes", 393217),
        ("compressed_bytes", 262145),
        ("expanded_bytes", 1048577),
        ("events", 501),
        ("seconds", 31),
    ] {
        let mut row = fixture(&scope);
        row["source"]["audit_limits"][field] = json!(value);
        assert!(checked(&scope, &row).is_err(), "{field}");
    }
}

#[test]
fn maximum_prefix_and_raw_input_bounds_are_checked_without_truncation() {
    let scope = scope();
    let mut value = fixture(&scope);
    let suffix = format!("AWSLogs/{}/CloudTrail/{}/", scope.account_id, scope.region);
    value["source"]["exact_delivery_root_prefix"] =
        json!(format!("{}/{}", "p".repeat(255 - suffix.len()), suffix));
    assert!(checked(&scope, &value).is_ok());
    let valid = value.clone();
    let prefix = value["source"]["exact_delivery_root_prefix"]
        .as_str()
        .unwrap();
    value["source"]["exact_delivery_root_prefix"] = json!(format!("p{prefix}"));
    assert!(checked(&scope, &value).is_err());
    let mut bytes = canonical_json(&valid).into_bytes();
    bytes.resize(MAX_WORKFLOW_BYTES, b' ');
    assert!(AuditWorkflow::from_json(
        &bytes,
        &scope,
        &format!("sha256:{}", "d".repeat(64)),
        &format!("sha256:{}", "c".repeat(64))
    )
    .is_ok());
    bytes.push(b' ');
    assert!(AuditWorkflow::from_json(
        &bytes,
        &scope,
        &format!("sha256:{}", "d".repeat(64)),
        &format!("sha256:{}", "c".repeat(64))
    )
    .is_err());
}

#[test]
fn valid_source_changes_are_distinct_commitments_not_new_authority() {
    let scope = scope();
    let original = fixture(&scope);
    let first = checked(&scope, &original).unwrap();
    let mut changed = original.clone();
    changed["source"]["managed_profile_digest"] = json!(format!("sha256:{}", "7".repeat(64)));
    changed["source"]["audit_bucket"] = json!("bluefire-other-audit-fixture");
    let second = checked(&scope, &changed).unwrap();
    assert_ne!(first.digest(), second.digest());
    assert_ne!(first.source_digest(), second.source_digest());
    assert_eq!(first.resource_key(), second.resource_key());
    let mut detached = first.document().unwrap();
    detached["source"]["audit_limits"]["events"] = json!(1);
    assert_eq!(first.document().unwrap(), original);
}

#[test]
fn shared_workflow_vector_matches_literal_documents_and_digests() {
    let vector: Value =
        serde_json::from_str(include_str!("../tests/fixtures/s3_audit_workflow_v1.json")).unwrap();
    assert_eq!(
        vector["schema_version"],
        "bluefire.s3-audit-workflow-vector.v1"
    );
    assert_eq!(vector["origin"], "handcrafted_synthetic_consistency_only");
    let scope: Scope = serde_json::from_value(vector["scope"].clone()).unwrap();
    let source = &vector["source"];
    let workflow = &vector["workflow"];
    let expected = &vector["expected"];
    assert!(digest(expected["source_digest"].as_str().unwrap()));
    assert!(digest(expected["workflow_digest"].as_str().unwrap()));
    let checked = AuditWorkflow::from_json(
        canonical_json(workflow).as_bytes(),
        &scope,
        source["protected_runtime_digest"].as_str().unwrap(),
        source["worker_generation"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        canonical_json(&encoded(&scope).unwrap()),
        canonical_json(&vector["scope"])
    );
    assert_eq!(
        canonical_json(&checked.document().unwrap()),
        canonical_json(workflow)
    );
    assert_eq!(canonical_json(&workflow["source"]), canonical_json(source));
    assert_eq!(
        checked.source_digest(),
        expected["source_digest"].as_str().unwrap()
    );
    assert_eq!(
        checked.digest(),
        expected["workflow_digest"].as_str().unwrap()
    );
}
