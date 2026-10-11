//! Pure v2 parser/admission checks. No SDK, network, or worker dispatch.

use super::*;
use crate::s3_access_binding::S3WorkerBinding;
use crate::s3_access_send::S3SendPreview;
use crate::s3_admission::tests::{checked, fixture, reseal};

pub(crate) fn fixture_admission(
    operation: &str,
    purpose: &str,
    expected_etag: Option<&str>,
) -> Value {
    let mut value = fixture();
    let request = &mut value["manifest"]["params"]["worker_request"];
    request["schema_version"] = json!(REQUEST_SCHEMA);
    request["operation"] = json!(operation);
    request["max_sends"] = json!(match operation {
        "prepare_fixture" => 6,
        "reconcile_fixture" => 5,
        _ => 7,
    });
    request["fixture"] = json!({"schema_version":"bluefire.s3-fixture-operation.v2",
        "intent_id":"c".repeat(64),"purpose":purpose,"expected_etag":expected_etag});
    let scope_id = request["scope"]["scope_id"].as_str().unwrap().to_owned();
    for object in request["scope"]["objects"].as_array_mut().unwrap() {
        let raw = payload(&scope_id, object["purpose"].as_str().unwrap());
        object["sha256"] = json!(format!("sha256:{}", sha256_hex(&raw)));
        object["size_bytes"] = json!(raw.len());
    }
    request["scope_digest"] = json!(canonical_hash(&request["scope"]));
    let scope_digest = request["scope_digest"].clone();
    let descriptor = json!({"schema_version":"bluefire.s3-fixture-enrollment.v2",
        "scope_digest":scope_digest,"generation_digest":value["admission"]["issuer"]["enrollment_generation"],
        "exclusive_writer_digest":format!("sha256:{}", "d".repeat(64)),"bucket_shape":BUCKET_SHAPE});
    let authority = canonical_hash(&descriptor);
    value["manifest"]["params"]["worker_request"]["fixture_authority_digest"] = json!(authority);
    let workflow = &mut value["manifest"]["params"]["workflow_approval"];
    workflow["schema_version"] = json!("bluefire.s3-workflow-approval.v2");
    workflow["scope_digest"] = scope_digest.clone();
    workflow["phase"] = json!(match operation {
        "prepare_fixture" => "prepare",
        "reconcile_fixture" => "reconcile_fixtures",
        _ => "cleanup",
    });
    workflow["fixture_authority_digest"] = json!(authority);
    workflow["fixture_intent_id"] = json!("c".repeat(64));
    value["admission"]["schema_version"] = json!("bluefire.s3-access-admission.v2");
    value["admission"]["host"]["scope_digest"] = scope_digest;
    value["admission"]["host"]["fixture_lifecycle"] = descriptor;
    reseal(&mut value);
    value
}

fn request(value: &Value) -> &Value {
    &value["manifest"]["params"]["worker_request"]
}
fn binding(value: &Value) -> S3WorkerBinding {
    S3WorkerBinding::from_json(canonical_json(request(value)).as_bytes()).unwrap()
}

#[test]
fn fixture_request_plans_exact_controller_only_sends_and_write_sequence() {
    for (name, tag, count, write) in [
        ("prepare_fixture", None, 6, Some("PutObject")),
        ("reconcile_fixture", None, 5, None),
        (
            "cleanup_fixture",
            Some("\"owned\""),
            7,
            Some("DeleteObject"),
        ),
        ("cleanup_fixture", None, 5, None),
    ] {
        let value = fixture_admission(name, "primary", tag);
        let binding = binding(&value);
        assert!(checked(&value).is_ok());
        assert_eq!(binding.operation_plan().len(), count);
        assert!(binding
            .operation_plan()
            .iter()
            .all(|call| call.role == "controller"));
        for sequence in 1..=count {
            let mut frame = json!({"kind":"send","request_digest":binding.digest(),"sequence":sequence,
                "send":binding.planned_send(sequence).unwrap()});
            frame["send_digest"] = json!(canonical_hash(&frame));
            let encoded = format!("{}\n", canonical_json(&frame));
            let preview =
                S3SendPreview::from_frame(&binding, encoded.as_bytes(), sequence as u64).unwrap();
            assert_eq!(preview.is_write(), sequence == 5 && write.is_some());
            if sequence > 1 {
                assert_eq!(
                    frame["send"]["resource"]["fixture_authority_digest"],
                    request(&value)["fixture_authority_digest"]
                );
            }
        }
        assert!(binding.planned_send(count + 1).is_err());
    }
}

#[test]
fn v1_and_v2_request_and_enrollment_authority_cannot_be_interchanged() {
    let original = fixture_admission("prepare_fixture", "primary", None);
    for pointer in [
        "/manifest/params/worker_request/schema_version",
        "/admission/schema_version",
        "/manifest/params/workflow_approval/schema_version",
    ] {
        let mut value = original.clone();
        *value.pointer_mut(pointer).unwrap() = json!(value
            .pointer(pointer)
            .unwrap()
            .as_str()
            .unwrap()
            .replace(".v2", ".v1"));
        reseal(&mut value);
        assert!(checked(&value).is_err(), "{pointer}");
    }
    let mut legacy = fixture();
    legacy["manifest"]["params"]["worker_request"]["schema_version"] = json!(REQUEST_SCHEMA);
    reseal(&mut legacy);
    assert!(checked(&legacy).is_err());
}

#[test]
fn resealed_wrong_fixture_generation_scope_intent_or_bucket_shape_is_refused() {
    for (pointer, replacement) in [
        (
            "/admission/host/fixture_lifecycle/generation_digest",
            json!(format!("sha256:{}", "9".repeat(64))),
        ),
        (
            "/admission/host/fixture_lifecycle/bucket_shape",
            json!("versioned"),
        ),
        (
            "/manifest/params/workflow_approval/fixture_intent_id",
            json!("e".repeat(64)),
        ),
        (
            "/manifest/params/worker_request/fixture_authority_digest",
            json!(format!("sha256:{}", "a".repeat(64))),
        ),
        (
            "/manifest/params/worker_request/fixture/expected_etag",
            json!("\"existing\""),
        ),
        (
            "/manifest/params/worker_request/fixture/purpose",
            json!("arbitrary"),
        ),
    ] {
        let mut value = fixture_admission("prepare_fixture", "primary", None);
        *value.pointer_mut(pointer).unwrap() = replacement;
        reseal(&mut value);
        assert!(checked(&value).is_err(), "{pointer}");
    }
}

#[test]
fn exact_payload_and_duplicate_free_explicit_fixture_fields_are_required() {
    let value = fixture_admission("prepare_fixture", "primary", None);
    let request = request(&value);
    let raw = canonical_json(request);
    for key in [
        "fixture",
        "intent_id",
        "expected_etag",
        "fixture_authority_digest",
    ] {
        let repeated = raw.replacen(
            &format!("\"{key}\":"),
            &format!("\"{key}\":null,\"{key}\":"),
            1,
        );
        assert!(
            S3WorkerBinding::from_json(repeated.as_bytes()).is_err(),
            "{key}"
        );
    }
    for key in ["fixture", "fixture_authority_digest"] {
        let mut changed = request.clone();
        changed.as_object_mut().unwrap().remove(key);
        assert!(S3WorkerBinding::from_json(canonical_json(&changed).as_bytes()).is_err());
    }
    let mut missing = request.clone();
    missing["fixture"]
        .as_object_mut()
        .unwrap()
        .remove("expected_etag");
    assert!(S3WorkerBinding::from_json(canonical_json(&missing).as_bytes()).is_err());
    let mut altered = request.clone();
    altered["scope"]["objects"][0]["size_bytes"] = json!(3);
    altered["scope_digest"] = json!(canonical_hash(&altered["scope"]));
    assert!(S3WorkerBinding::from_json(canonical_json(&altered).as_bytes()).is_err());
}

#[test]
fn business_request_under_new_enrollment_retains_fixture_authority() {
    let mut value = fixture_admission("prepare_fixture", "primary", None);
    let request = &mut value["manifest"]["params"]["worker_request"];
    request["schema_version"] = json!("bluefire.s3-worker-request.v1");
    request["operation"] = json!("inspect_policy");
    request["max_sends"] = json!(2);
    for key in ["fixture", "fixture_authority_digest"] {
        request.as_object_mut().unwrap().remove(key);
    }
    let workflow = &mut value["manifest"]["params"]["workflow_approval"];
    workflow["schema_version"] = json!("bluefire.s3-workflow-approval.v1");
    workflow["phase"] = json!("inspect");
    for key in ["fixture_authority_digest", "fixture_intent_id"] {
        workflow.as_object_mut().unwrap().remove(key);
    }
    reseal(&mut value);
    let admitted = checked(&value).unwrap();
    assert!(admitted.fixture_authority_digest().is_some());
    assert!(admitted.binding().fixture().is_none());
}

#[test]
fn cleanup_etag_is_closed_opaque_identity_not_an_md5_claim() {
    for accepted in ["\"owned-1\"", "\"opaque+identity._\""] {
        assert!(etag(accepted));
    }
    for refused in [
        "unquoted",
        "\"*\"",
        "\"x\"\r\nIf-Match:*",
        "\"\"",
        "\"unicode-\u{e9}\"",
    ] {
        assert!(!etag(refused));
    }
}

#[test]
fn python_fixture_corpus_matches_native_payload_send_and_result_contracts() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../tests_platform/fixtures/s3_fixture_v2.json"
    ))
    .unwrap();
    assert_eq!(corpus["schema_version"], "bluefire.s3-fixture-golden.v2");
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for (case, expected_sends) in cases.iter().zip([6, 5, 7, 5]) {
        let request = &case["request"];
        let binding = S3WorkerBinding::from_json(canonical_json(request).as_bytes()).unwrap();
        assert_eq!(binding.digest(), case["request_digest"].as_str().unwrap());
        assert_eq!(
            binding
                .checked_fixture_enrollment(&corpus["enrollment"])
                .unwrap(),
            canonical_hash(&corpus["enrollment"])
        );
        for purpose in ["primary", "health"] {
            assert_eq!(
                payload(request["scope"]["scope_id"].as_str().unwrap(), purpose),
                corpus["payloads"][purpose].as_str().unwrap().as_bytes()
            );
        }
        let sends = case["sends"].as_array().unwrap();
        assert_eq!(sends.len(), expected_sends);
        assert_eq!(binding.operation_plan().len(), expected_sends);
        for (index, frame) in sends.iter().enumerate() {
            assert_eq!(binding.planned_send(index + 1).unwrap(), frame["send"]);
            let encoded = format!("{}\n", canonical_json(frame));
            let preview =
                S3SendPreview::from_frame(&binding, encoded.as_bytes(), (index + 1) as u64)
                    .unwrap();
            assert_eq!(
                preview.is_write(),
                index == 4
                    && matches!(
                        case["name"].as_str(),
                        Some("prepare_fixture" | "cleanup_fixture")
                    )
            );
        }
        #[cfg(target_os = "linux")]
        {
            use crate::s3_worker_result::WorkerResult;
            let frame = |result: &Value| {
                format!(
                    "{}\n",
                    canonical_json(&json!({"kind":"result","result":result}))
                )
            };
            let checked = WorkerResult::from_frame(
                &binding,
                frame(&case["result"]).as_bytes(),
                expected_sends as u64,
            )
            .unwrap();
            assert_eq!(checked.document(), &case["result"]);
            if case["name"] == "cleanup_fixture" {
                let mut invalid = case["result"].clone();
                invalid["calls"][4]["http_status"] = json!(200);
                assert!(WorkerResult::from_frame(
                    &binding,
                    frame(&invalid).as_bytes(),
                    expected_sends as u64,
                )
                .is_err());
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn fixture_result_preserves_only_exact_observed_shape_and_finite_service_errors() {
    use crate::s3_worker_result::WorkerResult;
    for (operation, tag, state) in [
        ("prepare_fixture", None, "owned"),
        ("reconcile_fixture", None, "absent"),
        ("cleanup_fixture", Some("\"owned\""), "absent"),
        ("cleanup_fixture", None, "absent"),
    ] {
        let value = fixture_admission(operation, "primary", tag);
        let binding = binding(&value);
        let mut calls: Vec<_> = binding.operation_plan().iter().map(|call| json!({
            "operation":call.operation,"role":call.role,"request_id":"synthetic-id","http_status":200,
        })).collect();
        calls[2]["http_status"] = json!(404);
        calls[2]["error_code"] = json!("ObjectLockConfigurationNotFoundError");
        if operation == "cleanup_fixture" && tag.is_some() {
            calls[4]["http_status"] = json!(204);
        }
        let absent = if operation == "cleanup_fixture" && tag.is_some() {
            5
        } else {
            3
        };
        calls[absent]["http_status"] = json!(404);
        calls[absent]["error_code"] = json!("NoSuchKey");
        let result = json!({"schema_version":RESULT_SCHEMA,"request_digest":binding.digest(),
            "outcome":"observed","problem":null,"send_permits_consumed":calls.len(),
            "calls":calls,"runtime_isolation_proven":false,
            "data":{"purpose":"primary","intent_id":"c".repeat(64),"state":state,
                "etag":if state == "owned" { json!("\"owned\"") } else { Value::Null },
                "expected_object":request(&value)["scope"]["objects"][0],"bucket_shape":BUCKET_SHAPE,"policy_mutated":false}});
        let frame = |result: &Value| {
            format!(
                "{}\n",
                canonical_json(&json!({"kind":"result","result":result}))
            )
        };
        assert!(
            WorkerResult::from_frame(&binding, frame(&result).as_bytes(), calls.len() as u64)
                .is_ok()
        );
        for (pointer, altered) in [
            ("/data/policy_mutated", json!(true)),
            ("/data/intent_id", json!("f".repeat(64))),
            ("/calls/2/error_code", json!("OtherServiceError")),
            ("/schema_version", json!("bluefire.s3-worker-result.v1")),
        ] {
            let mut invalid = result.clone();
            *invalid.pointer_mut(pointer).unwrap() = altered;
            assert!(WorkerResult::from_frame(
                &binding,
                frame(&invalid).as_bytes(),
                calls.len() as u64
            )
            .is_err());
        }
        if operation == "cleanup_fixture" && tag.is_none() {
            let mut overlong = result.clone();
            let extra = overlong["calls"][4].clone();
            overlong["calls"].as_array_mut().unwrap().push(extra);
            overlong["send_permits_consumed"] = json!(6);
            assert!(WorkerResult::from_frame(&binding, frame(&overlong).as_bytes(), 6).is_err());
            let mut failed = result;
            failed["outcome"] = json!("failed");
            failed["problem"] = json!("scoped_operation_failed");
            failed["data"] = Value::Null;
            failed["send_permits_consumed"] = json!(6);
            assert!(WorkerResult::from_frame(&binding, frame(&failed).as_bytes(), 6).is_err());
        }
    }
}
