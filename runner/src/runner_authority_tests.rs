use super::*;

fn grant_documents() -> (RunnerProfile, ExecutionManifest) {
    let binding = alias_binding(
        "acme.profile.v1",
        "acme.profile-action.v1",
        "endpoint.discovery.system.v1",
    );
    let (mut profile, mut manifest) = alias_documents(Path::new("."), binding, json!({}));
    enroll_reviewed(&mut profile, &mut manifest);
    let compiled_digest = format!("sha256:{}", "c".repeat(64));
    let plan_digest = format!("sha256:{}", "d".repeat(64));
    let authorization = canonical_hash(&json!({
        "schema_version": "bluefire.grant-attempt-plan-binding.v1",
        "compiled_digest": compiled_digest,
        "plan_digest": plan_digest,
    }));
    assert_eq!(
        authorization,
        "sha256:b87d288d8ef3e774e6a2ebc5d78cd28df06c85fde7574be46340aed7d7d181d0"
    );
    profile
        .reviewed_execution
        .as_mut()
        .unwrap()
        .authorization_digest = authorization.clone();
    manifest
        .reviewed_operation
        .as_mut()
        .unwrap()
        .authorization_digest = authorization;
    profile.approval_required_at_or_above = Some(crate::contract::SafetyTier::Safe);
    manifest.grant_attempt = Some(crate::contract::GrantAttempt {
        schema_version: "bluefire.runner-grant-attempt.v1".into(),
        issuer: "capability-grant-controller.v1".into(),
        grant_id: format!("grant-{}", "a".repeat(32)),
        grant_digest: format!("sha256:{}", "a".repeat(64)),
        attempt_id: format!("attempt-{}", "b".repeat(32)),
        lease_digest: format!("sha256:{}", "b".repeat(64)),
        compiled_digest,
        plan_digest,
        native_envelope_digest: canonical_hash(
            &serde_json::to_value(profile.reviewed_execution.as_ref().unwrap()).unwrap(),
        ),
        run_id: manifest.run_id.clone(),
        issued_at: manifest.requested_at,
        expires_at: manifest.expires_at,
        request_hash: String::new(),
    });
    reseal_documents(&mut profile, &mut manifest);
    (profile, manifest)
}

#[test]
fn grant_attempt_is_not_human_approval_and_binds_exact_native_envelope() {
    let (profile, manifest) = grant_documents();
    assert!(manifest.approval.is_none());
    assert!(validate_policy(&manifest, &profile).is_ok());
    let wire = serde_json::to_value(&manifest).unwrap();
    assert!(wire["approval"].is_null());
    assert!(wire["grant_attempt"].get("approved_by").is_none());
    assert_eq!(
        manifest.grant_attempt.as_ref().unwrap().request_hash,
        manifest.request_hash
    );
    for field in [
        "schema", "issuer", "grant", "attempt", "run", "compiled", "plan", "envelope", "lease",
        "deadline", "issued", "hash", "approval",
    ] {
        let mut changed = manifest.clone();
        let grant = changed.grant_attempt.as_mut().unwrap();
        match field {
            "schema" => grant.schema_version = "bluefire.runner-grant-attempt.v2".into(),
            "issuer" => grant.issuer = "operator".into(),
            "grant" => grant.grant_id = "grant-invalid".into(),
            "attempt" => grant.attempt_id = format!("attempt-{}", "A".repeat(32)),
            "run" => grant.run_id = "another-run".into(),
            "compiled" => grant.compiled_digest = format!("sha256:{}", "e".repeat(64)),
            "plan" => grant.plan_digest = format!("sha256:{}", "e".repeat(64)),
            "envelope" => grant.native_envelope_digest = format!("sha256:{}", "e".repeat(64)),
            "lease" => grant.lease_digest = "not-a-digest".into(),
            "deadline" => grant.expires_at = changed.expires_at - ChronoDuration::seconds(1),
            "issued" => grant.issued_at = changed.requested_at + ChronoDuration::seconds(1),
            "approval" => {
                changed.approval = Some(crate::contract::Approval {
                    approved_by: "operator".into(),
                    approved_at: changed.requested_at,
                    expires_at: changed.expires_at,
                    request_hash: String::new(),
                })
            }
            _ => (),
        }
        crate::contract::seal_manifest(&mut changed);
        if field == "hash" {
            changed.grant_attempt.as_mut().unwrap().request_hash =
                format!("sha256:{}", "e".repeat(64));
        }
        assert_eq!(
            validate_policy(&changed, &profile).err().unwrap().code,
            "grant_attempt_invalid",
            "{field}"
        );
    }
    let mut missing = manifest;
    missing.grant_attempt = None;
    crate::contract::seal_manifest(&mut missing);
    assert_eq!(
        validate_policy(&missing, &profile).err().unwrap().code,
        "approval_required"
    );
}

#[test]
fn grant_attempt_requires_finite_authority_and_rejects_null_or_unknown_wire_fields() {
    let (mut profile, mut manifest) = grant_documents();
    let wire = serde_json::to_value(&manifest).unwrap();
    for field in ["null", "extra", "missing"] {
        let mut changed = wire.clone();
        match field {
            "null" => changed["grant_attempt"] = Value::Null,
            "extra" => changed["grant_attempt"]["approved_by"] = json!("operator"),
            _ => {
                changed["grant_attempt"]
                    .as_object_mut()
                    .unwrap()
                    .remove("lease_digest");
            }
        }
        assert!(
            serde_json::from_value::<ExecutionManifest>(changed).is_err(),
            "{field}"
        );
    }
    profile.reviewed_execution = None;
    manifest.reviewed_operation = None;
    reseal_documents(&mut profile, &mut manifest);
    assert_eq!(
        validate_policy(&manifest, &profile).err().unwrap().code,
        "grant_attempt_invalid"
    );
    manifest.grant_attempt = None;
    crate::contract::seal_manifest(&mut manifest);
    assert!(serde_json::to_value(&manifest)
        .unwrap()
        .get("grant_attempt")
        .is_none());
    assert_eq!(expected_manifest_hash(&manifest), manifest.request_hash);
}

#[test]
fn grant_attempt_cannot_expand_its_finite_envelope_or_bypass_profile_limits() {
    let (profile, manifest) = grant_documents();
    let mut changed_profile = profile.clone();
    let reviewed = changed_profile.reviewed_execution.as_mut().unwrap();
    let mut extra = reviewed.operations[0].clone();
    extra.step_id = "second-step".into();
    reviewed.operations.push(extra);
    reviewed.operations.sort();
    let mut changed = manifest.clone();
    reseal_documents(&mut changed_profile, &mut changed);
    assert_eq!(
        validate_policy(&changed, &changed_profile)
            .err()
            .unwrap()
            .code,
        "grant_attempt_invalid"
    );

    let mut changed = manifest.clone();
    changed.target_scope.filesystem = vec!["outside-fixtures".into()];
    crate::contract::seal_manifest(&mut changed);
    assert_eq!(
        validate_policy(&changed, &profile).err().unwrap().code,
        "target_scope_blocked"
    );
    let mut changed = manifest;
    changed.limits.timeout_ms = profile.limits.timeout_ms + 1;
    crate::contract::seal_manifest(&mut changed);
    assert_eq!(
        validate_policy(&changed, &profile).err().unwrap().code,
        "resource_limit_blocked"
    );
}

#[test]
fn malformed_grant_is_rejected_even_without_an_approval_threshold() {
    let (mut profile, mut manifest) = grant_documents();
    profile.approval_required_at_or_above = None;
    manifest.grant_attempt.as_mut().unwrap().issuer = "operator".into();
    reseal_documents(&mut profile, &mut manifest);
    assert_eq!(
        validate_policy(&manifest, &profile).err().unwrap().code,
        "grant_attempt_invalid"
    );
}

fn cleanup_documents(root: &Path) -> (RunnerProfile, ExecutionManifest) {
    let (mut profile, mut manifest) = grant_documents();
    let action = find_action("sandbox.cleanup.v1").unwrap().descriptor();
    profile.sandbox_root = root.to_path_buf();
    profile.allowed_actions = vec![action.action_id.into()];
    profile.action_bindings.clear();
    profile.capabilities = action.capabilities.to_vec();
    profile.max_safety_tier = action.safety_tier;
    profile.reviewed_execution.as_mut().unwrap().operations = vec![ReviewedOperationIdentity {
        step_id: "clean".into(),
        behavior_id: action.action_id.into(),
        action_id: action.action_id.into(),
        execution_binding_digest: None,
    }];
    manifest.action_id = action.action_id.into();
    manifest.behavior_id = action.action_id.into();
    manifest.step_id = "clean".into();
    manifest.execution_binding = None;
    manifest.required_capabilities = action.capabilities.to_vec();
    manifest.safety_tier = action.safety_tier;
    manifest.target_scope.filesystem.clear();
    manifest.params = json!({"receipt_ids": ["1".repeat(64)]});
    manifest.reviewed_operation = Some(ReviewedOperation {
        step_id: "clean".into(),
        behavior_id: action.action_id.into(),
        action_id: action.action_id.into(),
        execution_binding_digest: None,
        authorization_digest: profile
            .reviewed_execution
            .as_ref()
            .unwrap()
            .authorization_digest
            .clone(),
    });
    let previous = manifest.grant_attempt.take().unwrap();
    manifest.expires_at = manifest.requested_at + ChronoDuration::seconds(10);
    manifest.limits.timeout_ms = 1000;
    reseal_documents(&mut profile, &mut manifest);
    manifest.grant_cleanup = Some(crate::contract::GrantCleanup {
        schema_version: "bluefire.runner-grant-cleanup.v1".into(),
        issuer: "capability-grant-controller.v1".into(),
        grant_id: previous.grant_id,
        grant_digest: previous.grant_digest,
        attempt_id: previous.attempt_id,
        lease_digest: previous.lease_digest,
        compiled_digest: previous.compiled_digest,
        plan_digest: previous.plan_digest,
        native_envelope_digest: canonical_hash(
            &serde_json::to_value(profile.reviewed_execution.as_ref().unwrap()).unwrap(),
        ),
        obligation_digest: format!("sha256:{}", "e".repeat(64)),
        run_id: manifest.run_id.clone(),
        runner_policy_digest: profile.policy_digest.clone(),
        workspace_id: SafeRoot::open(root).unwrap().workspace_id(),
        receipts: vec![crate::contract::GrantCleanupReceipt {
            receipt_id: "1".repeat(64),
            source_request_hash: format!("sha256:{}", "2".repeat(64)),
            source_task_id: "task-source".into(),
        }],
        issued_at: manifest.requested_at,
        expires_at: manifest.expires_at,
        timeout_ms: 1000,
        request_hash: String::new(),
    });
    crate::contract::seal_manifest(&mut manifest);
    (profile, manifest)
}

#[test]
fn cleanup_authority_cannot_expand_original_policy_receipts_or_deadline() {
    let (profile, manifest) = cleanup_documents(Path::new("."));
    assert!(validate_policy(&manifest, &profile).is_ok());
    assert!(manifest.approval.is_none() && manifest.grant_attempt.is_none());
    for field in [
        "issuer",
        "grant",
        "profile",
        "receipts",
        "envelope",
        "timeout",
        "deadline",
        "scope",
        "hash",
        "duplicate",
        "task",
        "compiled",
    ] {
        let mut changed = manifest.clone();
        let cleanup = changed.grant_cleanup.as_mut().unwrap();
        match field {
            "issuer" => cleanup.issuer = "operator".into(),
            "grant" => cleanup.grant_id = "grant-invalid".into(),
            "profile" => cleanup.runner_policy_digest = format!("sha256:{}", "3".repeat(64)),
            "receipts" => changed.params = json!({"receipt_ids": ["3".repeat(64)]}),
            "envelope" => cleanup.native_envelope_digest = format!("sha256:{}", "3".repeat(64)),
            "timeout" => changed.limits.timeout_ms = cleanup.timeout_ms + 1,
            "deadline" => cleanup.expires_at = cleanup.issued_at + ChronoDuration::seconds(121),
            "scope" => changed.target_scope.filesystem = vec!["fixtures".into()],
            "duplicate" => cleanup.receipts.push(cleanup.receipts[0].clone()),
            "task" => cleanup.receipts[0].source_task_id = "../other".into(),
            "compiled" => cleanup.compiled_digest = format!("sha256:{}", "3".repeat(64)),
            _ => (),
        }
        crate::contract::seal_manifest(&mut changed);
        if field == "hash" {
            changed.grant_cleanup.as_mut().unwrap().request_hash =
                format!("sha256:{}", "3".repeat(64));
        }
        assert_eq!(
            validate_policy(&changed, &profile).err().unwrap().code,
            "grant_cleanup_invalid",
            "{field}"
        );
    }
    let mut changed_profile = profile.clone();
    let mut changed = manifest.clone();
    changed_profile.limits.max_files += 1;
    reseal_documents(&mut changed_profile, &mut changed);
    assert_eq!(
        validate_policy(&changed, &changed_profile)
            .err()
            .unwrap()
            .code,
        "grant_cleanup_invalid"
    );
    let (business_profile, mut business) = grant_documents();
    business.grant_attempt = None;
    business.grant_cleanup = manifest.grant_cleanup;
    crate::contract::seal_manifest(&mut business);
    assert_eq!(
        validate_policy(&business, &business_profile)
            .err()
            .unwrap()
            .code,
        "grant_cleanup_invalid"
    );
}

#[test]
fn cleanup_wire_rejects_unknown_or_competing_authority() {
    let (profile, manifest) = cleanup_documents(Path::new("."));
    let wire = serde_json::to_value(&manifest).unwrap();
    for field in ["null", "extra", "receipt-extra", "missing"] {
        let mut changed = wire.clone();
        match field {
            "null" => changed["grant_cleanup"] = Value::Null,
            "extra" => changed["grant_cleanup"]["approved_by"] = json!("operator"),
            "receipt-extra" => changed["grant_cleanup"]["receipts"][0]["path"] = json!("outside"),
            _ => {
                changed["grant_cleanup"]
                    .as_object_mut()
                    .unwrap()
                    .remove("obligation_digest");
            }
        }
        assert!(
            serde_json::from_value::<ExecutionManifest>(changed).is_err(),
            "{field}"
        );
    }
    let mut changed = manifest.clone();
    changed.approval = Some(crate::contract::Approval {
        approved_by: "operator".into(),
        approved_at: changed.requested_at,
        expires_at: changed.expires_at,
        request_hash: String::new(),
    });
    crate::contract::seal_manifest(&mut changed);
    assert_eq!(
        validate_policy(&changed, &profile).err().unwrap().code,
        "grant_cleanup_invalid"
    );
    let mut changed = manifest;
    changed.grant_attempt = grant_documents().1.grant_attempt;
    crate::contract::seal_manifest(&mut changed);
    assert_eq!(
        validate_policy(&changed, &profile).err().unwrap().code,
        "grant_attempt_invalid"
    );
}

#[test]
fn cleanup_obligation_checks_native_receipt_workspace_and_source_request() {
    let root_path = std::env::temp_dir().join(format!(
        "bluefire-grant-cleanup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root_path).unwrap();
    let root = SafeRoot::open(&root_path).unwrap();
    let (profile, mut manifest) = cleanup_documents(&root_path);
    let mut source = manifest.clone();
    source.grant_cleanup = None;
    source.target_scope.filesystem = vec!["fixtures".into()];
    crate::contract::seal_manifest(&mut source);
    let target = root.prepare_new_file("fixtures/owned.txt").unwrap();
    let bytes = b"owned synthetic data";
    let mut paths = vec![crate::safety::owned_file(target.relative.clone(), bytes)];
    paths.extend(crate::safety::owned_directories(
        &target.created_directories,
    ));
    let intent = root.begin_receipt(&source, &profile, paths).unwrap();
    root.write_new(&target, bytes, &intent).unwrap();
    root.commit_receipt(&intent, &profile).unwrap();
    let cleanup = manifest.grant_cleanup.as_mut().unwrap();
    cleanup.receipts[0].receipt_id = intent.id().into();
    cleanup.receipts[0].source_request_hash = source.request_hash.clone();
    manifest.params = json!({"receipt_ids": [intent.id()]});
    crate::contract::seal_manifest(&mut manifest);
    assert!(validate_grant_cleanup_receipts(&manifest, &profile, &root).is_ok());
    let mut changed = manifest.clone();
    changed.grant_cleanup.as_mut().unwrap().receipts[0].source_request_hash =
        format!("sha256:{}", "f".repeat(64));
    assert_eq!(
        validate_grant_cleanup_receipts(&changed, &profile, &root)
            .unwrap_err()
            .code,
        "grant_cleanup_receipt_invalid"
    );
    changed = manifest.clone();
    changed.grant_cleanup.as_mut().unwrap().workspace_id = "f".repeat(64);
    assert!(validate_grant_cleanup_receipts(&changed, &profile, &root).is_err());
    assert!(target.absolute.exists());
    let result = Runner::new().unwrap().execute(manifest, profile);
    assert_eq!(result.status, TaskStatus::Success, "{result:#?}");
    assert!(!target.absolute.exists());
    std::fs::remove_dir_all(root_path).unwrap();
}

#[test]
fn reviewed_authority_cannot_be_omitted_or_attached_to_legacy_profile() {
    let binding = alias_binding(
        "acme.profile.v1",
        "acme.profile-action.v1",
        "endpoint.discovery.system.v1",
    );
    let (mut profile, mut manifest) = alias_documents(Path::new("."), binding, json!({}));
    let mut legacy = profile.clone();
    enroll_reviewed(&mut profile, &mut manifest);
    let mut missing = manifest.clone();
    missing.reviewed_operation = None;
    crate::contract::seal_manifest(&mut missing);
    assert_eq!(
        validate_policy(&missing, &profile).err().unwrap().code,
        "reviewed_operation_blocked"
    );
    reseal_documents(&mut legacy, &mut manifest);
    assert_eq!(
        validate_policy(&manifest, &legacy).err().unwrap().code,
        "reviewed_operation_blocked"
    );
}
