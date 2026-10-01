use super::*;

fn record(role: Role, digest: &str, size: u64) -> NativeToolInstallation {
    let binding = role.binding();
    NativeToolInstallation {
        schema_version: crate::native_tool_installations::SCHEMA.into(),
        adapter_id: binding.adapter_id.into(),
        adapter_version: binding.adapter_version.into(),
        adapter_contract_digest: binding.adapter_contract_digest.into(),
        tool_id: binding.tool_id.into(),
        tool_version: match role {
            Role::Manager => MANAGER_VERSION.into(),
            Role::Payload => env!("CARGO_PKG_VERSION").into(),
        },
        platform: "linux".into(),
        architecture: match role {
            Role::Manager => "x86_64".into(),
            Role::Payload => std::env::consts::ARCH.into(),
        },
        content_sha256: digest.into(),
        size_bytes: size,
        installation_location: match role {
            Role::Manager => "/usr/bin/systemctl".into(),
            Role::Payload => "/opt/bluefire/bluefire-runner".into(),
        },
    }
}

fn manager() -> NativeToolInstallation {
    record(Role::Manager, MANAGER_SHA256, MANAGER_SIZE)
}

fn documents(records: &[NativeToolInstallation]) -> (Value, Value) {
    let reference = |item: &NativeToolInstallation| {
        json!({
            "installation_id": item.tool_id, "path": item.installation_location,
            "digest": item.digest(), "content_sha256": item.content_sha256
        })
    };
    (
        json!({"installations": {"manager": reference(&records[0]), "payload": reference(&records[1])}}),
        json!({"native_tool_installations": records}),
    )
}

#[test]
fn compiled_contracts_have_real_canonical_digests_and_no_dispatch() {
    for role in [Role::Manager, Role::Payload] {
        let document = role.contract();
        assert_eq!(canonical_hash(&document), role.binding().adapter_contract_digest);
        assert_eq!(document["dispatch"], "unregistered");
        assert!(document.get("adapter_contract_digest").is_none());
        assert_eq!(document.as_object().unwrap().len(), 10);
        assert!(crate::actions::find_action(role.binding().adapter_id).is_none());
    }
    assert!(crate::actions::find_action(crate::service_admission::SERVICE_ACTION_ID).is_none());
    assert!(crate::reviewed_chmod_builds::verify(&manager()).is_err());
    assert_eq!(crate::native_tool_setup::inspect_installation(&manager())["code"], "binding_mismatch");
    assert_eq!(Role::Payload.contract()["identity"]["version"], env!("CARGO_PKG_VERSION"));
    assert_ne!(MANAGER_BINDING.adapter_contract_digest, PAYLOAD_BINDING.adapter_contract_digest);
}

#[test]
fn manager_accepts_only_the_reviewed_package_tuple() {
    let baseline = manager();
    assert_eq!(
        Role::Manager.validate(&baseline, ("unused", 0)).is_ok(),
        std::env::consts::ARCH == "x86_64"
    );
    let mut variants = Vec::new();
    let mut changed = baseline.clone();
    changed.tool_version = "255.4-1ubuntu8.11".into();
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.content_sha256 = format!("sha256:{}", "0".repeat(64));
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.size_bytes += 1;
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.architecture = "aarch64".into();
    variants.push(changed);
    let mut changed = baseline;
    changed.platform = "windows".into();
    variants.push(changed);
    for changed in variants {
        assert!(Role::Manager.validate(&changed, ("unused", 0)).is_err());
    }
}

#[test]
fn payload_requires_current_runner_version_bytes_and_size() {
    let digest = format!("sha256:{}", "3".repeat(64));
    let baseline = record(Role::Payload, &digest, 4096);
    assert!(Role::Payload.validate(&baseline, (&digest, 4096)).is_ok());
    assert!(Role::Payload.validate(&baseline, (MANAGER_SHA256, 4096)).is_err());
    assert!(Role::Payload.validate(&baseline, (&digest, 4097)).is_err());
    let mut changed = baseline.clone();
    changed.tool_version = format!("{}-unreviewed", env!("CARGO_PKG_VERSION"));
    assert!(Role::Payload.validate(&changed, (&digest, 4096)).is_err());
    changed = baseline;
    changed.content_sha256 = MANAGER_SHA256.into();
    assert!(Role::Payload.validate(&changed, (&digest, 4096)).is_err());
}

#[test]
fn role_identity_cannot_be_relabelled_or_use_fixture_contracts() {
    let digest = format!("sha256:{}", "4".repeat(64));
    for (role, baseline) in [(Role::Manager, manager()), (Role::Payload, record(Role::Payload, &digest, 64))] {
        let mut variants = Vec::new();
        let mut changed = baseline.clone();
        changed.adapter_id = "sandbox.permission.chmod.v1".into();
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.tool_id = "gnu.coreutils.chmod.v1".into();
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.adapter_version = "2.0.0".into();
        variants.push(changed);
        let mut changed = baseline.clone();
        changed.adapter_contract_digest = format!("sha256:{}", "a".repeat(64));
        variants.push(changed);
        let mut changed = baseline;
        changed.adapter_contract_digest = match role {
            Role::Manager => PAYLOAD_BINDING.adapter_contract_digest.into(),
            Role::Payload => MANAGER_BINDING.adapter_contract_digest.into(),
        };
        variants.push(changed);
        for changed in variants {
            assert!(role.validate(&changed, (&digest, 64)).is_err());
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn scope_selects_exact_unique_role_records_without_aliases() {
    let digest = format!("sha256:{}", "5".repeat(64));
    let records = [manager(), record(Role::Payload, &digest, 64)];
    let (scope, profile) = documents(&records);
    assert_eq!(select(&scope, &profile, (&digest, 64)).unwrap(), records);
    for field in ["digest", "path", "installation_id", "content_sha256"] {
        let mut changed = scope.clone();
        changed["installations"]["manager"][field] = json!("unbound");
        assert!(select(&changed, &profile, (&digest, 64)).is_err(), "{field}");
    }
    let mut swapped = scope.clone();
    swapped["installations"]["manager"] = scope["installations"]["payload"].clone();
    swapped["installations"]["payload"] = scope["installations"]["manager"].clone();
    assert!(select(&swapped, &profile, (&digest, 64)).is_err());
    let mut duplicate = profile.clone();
    duplicate["native_tool_installations"].as_array_mut().unwrap().push(json!(records[0]));
    assert!(select(&scope, &duplicate, (&digest, 64)).is_err());
    let mut alias = records[0].clone();
    alias.installation_location = "/opt/duplicate/systemctl".into();
    duplicate["native_tool_installations"][2] = json!(alias);
    assert!(select(&scope, &duplicate, (&digest, 64)).is_err());
    let mut missing = profile.clone();
    missing["native_tool_installations"].as_array_mut().unwrap().pop();
    assert!(select(&scope, &missing, (&digest, 64)).is_err());
    let mut unknown = scope;
    unknown["installations"]["extra"] = json!({});
    assert!(select(&unknown, &profile, (&digest, 64)).is_err());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn rehashing_changed_metadata_does_not_grant_build_authority() {
    let digest = format!("sha256:{}", "6".repeat(64));
    for role in [0, 1] {
        let mut records = [manager(), record(Role::Payload, &digest, 64)];
        records[role].content_sha256 = format!("sha256:{}", "7".repeat(64));
        let (scope, profile) = documents(&records);
        assert!(select(&scope, &profile, (&digest, 64)).is_err());
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[test]
fn unsupported_host_architecture_cannot_select_the_manager() {
    let digest = format!("sha256:{}", "8".repeat(64));
    let (scope, profile) = documents(&[manager(), record(Role::Payload, &digest, 64)]);
    assert!(select(&scope, &profile, (&digest, 64)).is_err());
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn exact_role_metadata_cannot_admit_an_unsafe_or_symlinked_installation() {
    use std::time::Duration;
    let deadline = Instant::now() + Duration::from_secs(5);
    let running = std::fs::read("/proc/self/exe").unwrap();
    let digest = format!("sha256:{}", crate::canonical::sha256_hex(&running));
    let current = CurrentExecutable::observe(&digest, deadline).unwrap();
    let root = std::env::temp_dir().join(format!(
        "bluefire-service-installation-test-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("manager");
    std::fs::write(&path, b"untrusted").unwrap();
    let result = std::panic::catch_unwind(|| {
        for location in [path.to_str().unwrap(), "/proc/self/exe"] {
            let mut manager = manager();
            manager.installation_location = location.into();
            let (scope, profile) = documents(&[manager, record(Role::Payload, &digest, running.len() as u64)]);
            assert!(inspect(&scope, &profile, &current, deadline).is_err());
        }
    });
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(root).unwrap();
    result.unwrap();
}
