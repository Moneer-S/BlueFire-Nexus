use super::*;
use chrono::Timelike;
use std::io::Cursor;
use std::time::{Duration, SystemTime};

fn run(
    input: &mut impl Read,
    output: &mut impl Write,
    execute: impl FnMut(&wire::Packet, framing::Begin) -> Result<Value>,
) -> Result<i32> {
    run_checked(input, output, |_| Ok(()), execute)
}

fn digest(seed: char) -> String {
    format!("sha256:{}", seed.to_string().repeat(64))
}

fn fixture() -> Value {
    let now = chrono::DateTime::<chrono::Utc>::from(SystemTime::now());
    let now = now.with_nanosecond(now.nanosecond() / 1000 * 1000).unwrap();
    let created = (now - chrono::Duration::minutes(2)).to_rfc3339();
    let requested = (now - chrono::Duration::seconds(1)).to_rfc3339();
    let deadline = (now + chrono::Duration::seconds(50)).to_rfc3339();
    let expires = (now + chrono::Duration::minutes(15)).to_rfc3339();
    let id = "a".repeat(32);
    let domain = "S-1-5-21-101-202-303";
    let principal = |rid, seed: char| json!({"sid":format!("{domain}-{rid}"),"kind":"domain_user","credential_handle":format!("credential-{}",seed.to_string().repeat(32)),"group_sids":[],"sid_history":[],"identity_receipt_digest":digest(seed)});
    let host = |name: &str, seed, ip, product| json!({"host_id":digest(seed),"fqdn":format!("{name}.example.test"),"ipv4":ip,"os_product":product,"os_build":"10.0.20348.1","architecture":"x86_64","identity_receipt_digest":digest(seed)});
    let file = |purpose, name, seed: char| json!({"purpose":purpose,"name":name,"file_id":seed.to_string().repeat(32),"volume_serial":"ffffffffffffffff","sha256":digest(seed),"size_bytes":16,"records":1,"ntfs_digest":digest(seed)});
    let scope = json!({"schema_version":"bluefire.ad-smb-scope.v1","scope_id":id,"domain":{"dns":"example.test","sid":domain},"hosts":{"dc":host("dc",'1',"10.0.0.1","windows_server_2022"),"member":host("member",'2',"10.0.0.2","windows_server_2022"),"client":host("client",'3',"10.0.0.3","windows_client")},"principals":{"controller":principal(1001,'4'),"probe":principal(1002,'5'),"legitimate":principal(1003,'6')},"share":{"name":format!("bf_{id}"),"local_root":format!("C:\\BlueFire\\AD\\{id}"),"unc":format!("\\\\member.example.test\\bf_{id}"),"identity_digest":digest('7'),"root_file_id":"7".repeat(32),"volume_serial":"ffffffffffffffff","root_ntfs_digest":digest('8'),"baseline_descriptor_digest":digest('9'),"dfs":false,"administrative":false},"files":[file("primary","records.jsonl",'a'),file("health","health.jsonl",'b')],"authentication":{"package":"Kerberos","spn":"cifs/member.example.test","signing_required":true,"encryption_required":true,"ntlm_fallback":false,"mutual_authentication_required":true,"hardened_unc_receipt_digest":digest('c')},"network":{"flows":[{"source":"client","destination":"dc","transport":"tcp","port_from":88,"port_through":88},{"source":"client","destination":"dc","transport":"udp","port_from":53,"port_through":53},{"source":"client","destination":"member","transport":"tcp","port_from":445,"port_through":445}],"policy_receipt_digest":digest('c'),"kernel_traffic_metered":false},"limits":{"generated_bytes":65536,"returned_payload_bytes":1048576,"business_attempts":6,"sessions":6,"session_seconds":900,"business_seconds":1800,"audit_seconds":600,"cleanup_seconds":900,"operation_seconds":60,"audit_events":1000,"audit_bytes":4194304,"share_changes":1,"rollbacks":1},"created_at":created,"expires_at":expires,"ownership_receipt_digest":digest('d'),"readiness_receipt_digest":digest('e'),"exclusive_writer_receipt_digest":digest('f'),"native_parser_digest":digest('0')});
    let request = json!({"schema_version":"bluefire.ad-smb-step.v1","request_id":"","workflow_job_id":format!("job-{}", "1".repeat(32)),"operation_job_id":format!("job-{}", "2".repeat(32)),"index":0,"phase":"inspect","step":"inspect_member","scope":scope,"scope_digest":"","target":null,"requested_at":requested,"deadline":deadline,"environment_digest":digest('1'),"host":{"runner_profile_id":"profile-member","host_id":digest('2'),"native_generation":digest('3'),"profile_digest":"","channel_digest":digest('4')},"principal_binding_digest":digest('5'),"review_digest":digest('6'),"reviewed_by":"Synthetic reviewer","change":null});
    let profile = json!({"schema_version":"bluefire.runner-profile.v1","profile_id":"profile-member","runner_id":"bluefire-rust-runner.v1","platform":"windows","sandbox_root":"C:\\BlueFire\\scratch","allowed_actions":["owned.ad.smb_access.v1"],"control_blocked_actions":[],"capabilities":["ad_smb_access"],"max_safety_tier":"controlled","approval_required_at_or_above":"safe","target_scope":{"filesystem":[],"network":[]},"limits":{"timeout_ms":60000,"max_stdout_bytes":MAX_RESULT,"max_stderr_bytes":65536,"max_artifact_bytes":1048576,"max_files":2},"policy_digest":""});
    let mut packet = json!({"schema_version":"bluefire.ad-smb-worker-request.v1","challenge":"1".repeat(64),"task_id":"","request_hash":"","manifest":{"params":{"ad_smb_request":request}},"profile":profile,"channel_digest":digest('4'),"host_role":"member","host_id":digest('2'),"client_identity_digest":digest('3'),"credential_binding_digest":null,"expected_upn_sha256":null,"prior_local_authentication_ids":[],"remaining_ms":40000});
    reseal(&mut packet);
    packet
}

fn reseal(packet: &mut Value) {
    use sha2::{Digest, Sha256};
    packet["profile"]["policy_digest"] = json!("");
    packet["profile"]["policy_digest"] = json!(json::hash(&packet["profile"]).unwrap());
    let mut request = packet["manifest"]["params"]["ad_smb_request"].clone();
    request["host"]["profile_digest"] = packet["profile"]["policy_digest"].clone();
    request["scope_digest"] = json!(json::hash(&request["scope"]).unwrap());
    request["request_id"] = json!(hex::encode(Sha256::digest(
        format!(
            "{}:{}",
            request["operation_job_id"].as_str().unwrap(),
            request["index"]
        )
        .as_bytes()
    ))[..32]
        .to_string());
    let profile = &packet["profile"];
    packet["manifest"] = json!({"schema_version":"bluefire.runner-manifest.v1","request_id":format!("ad-{}",request["request_id"].as_str().unwrap()),"run_id":request["operation_job_id"],"step_id":request["step"],"behavior_id":"identity.ad.smb_access.v1","action_id":"owned.ad.smb_access.v1","mode":"execute","runner_id":profile["runner_id"],"runner_profile_id":profile["profile_id"],"platform":"windows","requested_at":request["requested_at"],"expires_at":request["deadline"],"params":{"ad_smb_request":request},"target_scope":{"filesystem":[],"network":[]},"required_capabilities":["ad_smb_access"],"safety_tier":"controlled","limits":profile["limits"],"cleanup_action_id":null,"policy_digest":profile["policy_digest"],"approval":{"approved_by":request["reviewed_by"],"approved_at":request["requested_at"],"expires_at":request["deadline"],"request_hash":""},"evidence_refs":[],"request_hash":""});
    for key in ["requested_at", "expires_at"] {
        packet["manifest"][key] = json!(json::time(&packet["manifest"][key])
            .unwrap()
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true));
    }
    packet["manifest"]["approval"]["approved_at"] = packet["manifest"]["requested_at"].clone();
    packet["manifest"]["approval"]["expires_at"] = packet["manifest"]["expires_at"].clone();
    let hash = json::hash(&packet["manifest"]).unwrap();
    packet["manifest"]["request_hash"] = json!(hash);
    packet["manifest"]["approval"]["request_hash"] = packet["manifest"]["request_hash"].clone();
    let binding =
        json::hash(&json!({"manifest":packet["manifest"],"profile":packet["profile"]})).unwrap();
    packet["request_hash"] = json!(binding);
    packet["task_id"] = json!(format!("execute-{}", &binding[7..]));
}

fn validate(value: Value) -> Result<wire::Packet> {
    wire::Packet::validate(
        value,
        chrono::DateTime::<chrono::Utc>::from(SystemTime::now()).fixed_offset(),
        Instant::now(),
    )
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut value = (bytes.len() as u32).to_le_bytes().to_vec();
    value.extend_from_slice(bytes);
    value
}
fn member_begin(packet: &Value) -> Vec<u8> {
    let mut value = b"BFADBEG1".to_vec();
    value.extend(hex::decode(packet["challenge"].as_str().unwrap()).unwrap());
    value.extend(hex::decode(&json::hash(packet).unwrap()[7..]).unwrap());
    value.push(0);
    frame(&value)
}
fn input(packet: &Value) -> Vec<u8> {
    let mut value = frame(&serde_json::to_vec(packet).unwrap());
    value.extend(member_begin(packet));
    value
}

fn client_fixture(index: u64) -> Value {
    use sha2::{Digest, Sha256};
    let mut packet = fixture();
    let reader = if index == 0 { "probe" } else { "legitimate" };
    let purpose = if index == 2 { "health" } else { "primary" };
    packet["profile"]["profile_id"] = json!("profile-client");
    packet["host_role"] = json!("client");
    packet["host_id"] = json!(digest('3'));
    packet["credential_binding_digest"] = json!(digest('5'));
    packet["expected_upn_sha256"] = json!(format!(
        "sha256:{:x}",
        Sha256::digest(b"reader@example.test")
    ));
    let request = &mut packet["manifest"]["params"]["ad_smb_request"];
    request["phase"] = json!("baseline");
    request["index"] = json!(index);
    request["step"] = json!(format!("read_{reader}_{purpose}"));
    request["host"]["runner_profile_id"] = json!("profile-client");
    request["host"]["host_id"] = json!(digest('3'));
    let scope = &request["scope"];
    request["target"] = json!({"schema_version":"bluefire.ad-smb-read-target.v1","scope_digest":request["scope_digest"],"scope_id":scope["scope_id"],"reader":reader,"expected_remote_sid":scope["principals"][reader]["sid"],"member_host_id":scope["hosts"]["member"]["host_id"],"client_host_id":scope["hosts"]["client"]["host_id"],"member_fqdn":scope["hosts"]["member"]["fqdn"],"share_unc":scope["share"]["unc"],"file":scope["files"][usize::from(index == 2)],"hardened_unc_receipt_digest":scope["authentication"]["hardened_unc_receipt_digest"],"admission_verified":false,"authenticated_remote_reader":false,"effective_access_claim":false});
    reseal(&mut packet);
    packet
}

fn client_begin(packet: &Value, upn: &[u8], password: &[u16]) -> Vec<u8> {
    let prefix = member_begin(packet);
    let mut value = prefix[4..prefix.len() - 1].to_vec();
    value.push(1);
    value.extend_from_slice(&(upn.len() as u16).to_le_bytes());
    value.extend_from_slice(upn);
    value.extend_from_slice(&(password.len() as u16).to_le_bytes());
    for unit in password {
        value.extend_from_slice(&unit.to_le_bytes());
    }
    frame(&value)
}

#[test]
fn exact_three_read_targets_and_private_begin_are_accepted_without_native_calls() {
    for index in 0..3 {
        let value = client_fixture(index);
        let packet = validate(value.clone()).unwrap();
        let secret = client_begin(&value, b"reader@example.test", &[0x51, 0xd83d, 0xde00]);
        let begin = framing::begin(&mut Cursor::new(secret), &packet).unwrap();
        assert!(matches!(begin, framing::Begin::Client { .. }));
    }
}

#[test]
fn private_begin_rejects_wrong_upn_bad_utf16_zero_units_and_member_credentials() {
    let value = client_fixture(0);
    let packet = validate(value.clone()).unwrap();
    for (upn, password) in [
        (b"other@example.test".as_slice(), vec![81]),
        (b"reader@example.test".as_slice(), vec![0]),
        (b"reader@example.test".as_slice(), vec![0xd800]),
        (b"reader@example.test".as_slice(), vec![]),
    ] {
        assert!(framing::begin(
            &mut Cursor::new(client_begin(&value, upn, &password)),
            &packet
        )
        .is_err());
    }
    let member = fixture();
    assert!(framing::begin(
        &mut Cursor::new(client_begin(&member, b"reader@example.test", &[81])),
        &validate(member).unwrap()
    )
    .is_err());
}

#[test]
fn read_identity_role_prior_context_and_exact_target_cannot_drift() {
    for (path, value) in [
        ("/host_role", json!("member")),
        ("/credential_binding_digest", json!(digest('f'))),
        ("/client_identity_digest", json!(digest('f'))),
        (
            "/prior_local_authentication_ids",
            json!(["0000000000000000"]),
        ),
        (
            "/prior_local_authentication_ids",
            json!(["0000000000000001", "0000000000000001"]),
        ),
        (
            "/manifest/params/ad_smb_request/target/file/volume_serial",
            json!("00000000ffffffff"),
        ),
        (
            "/manifest/params/ad_smb_request/target/admission_verified",
            json!(true),
        ),
    ] {
        let mut packet = client_fixture(0);
        *packet.pointer_mut(path).unwrap() = value;
        reseal(&mut packet);
        assert!(validate(packet).is_err(), "{path}");
    }
}

#[test]
fn original_deadline_and_explicit_time_precision_are_enforced() {
    let packet = fixture();
    let deadline = json::time(&packet["manifest"]["params"]["ad_smb_request"]["deadline"]).unwrap();
    assert!(wire::Packet::validate(packet, deadline, Instant::now()).is_err());
    for value in [
        "2026-10-09T00:00:60Z",
        "2026-10-09T00:00:00.000000001Z",
        "2026-10-09T00:00:00",
    ] {
        assert!(json::time(&json!(value)).is_err());
    }
}

#[test]
fn descriptor_base64_must_be_canonical_and_digest_bound() {
    use sha2::{Digest, Sha256};
    let valid = json!({"binary_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAA=","sha256":format!("sha256:{:x}",Sha256::digest([0u8;20]))});
    assert_eq!(acl::bytes(&valid).unwrap(), [0u8; 20]);
    for value in [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAB=",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
        "AAAA====",
        "AA=A",
    ] {
        let mut changed = valid.clone();
        changed["binary_b64"] = json!(value);
        assert!(acl::bytes(&changed).is_err());
    }
}

fn reviewed_fixture(phase: &str) -> Value {
    use sha2::{Digest, Sha256};
    let mut packet = if phase == "retest" {
        client_fixture(0)
    } else {
        fixture()
    };
    let request = &mut packet["manifest"]["params"]["ad_smb_request"];
    request["phase"] = json!(phase);
    request["step"] = json!(match phase {
        "harden" => "harden_share",
        "rollback" => "rollback_share",
        _ => "read_probe_primary",
    });
    let scope = &mut request["scope"];
    scope["share"]["baseline_descriptor_digest"] =
        json!(format!("sha256:{:x}", Sha256::digest([0u8; 20])));
    let scope_digest = json::hash(scope).unwrap();
    let aces: Vec<Value> = ["probe", "legitimate", "controller"].into_iter().enumerate().map(|(index,role)| json!({"ace_type":"access_allowed","flags":0,"trustee_sid":scope["principals"][role]["sid"],"smb_right":if role == "controller" { "Full" } else { "Read" },"raw_ace_digest":digest(char::from(b'1' + index as u8))})).collect();
    // Public structural fixture only. These zero bytes are deliberately not a native descriptor.
    let before = json!({"binary_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAA=","sha256":scope["share"]["baseline_descriptor_digest"],"revision":1,"control":0x8004,"owner_sid":scope["principals"]["controller"]["sid"],"group_sid":scope["principals"]["controller"]["sid"],"sacl":null,"dacl":{"revision":2,"aces":aces}});
    let mut after = before.clone();
    after["binary_b64"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    after["sha256"] = json!(format!("sha256:{:x}", Sha256::digest([0u8; 21])));
    after["dacl"]["aces"] = json!(&aces[1..]);
    request["change"] = json!({"schema_version":"bluefire.ad-smb-acl-change.v1","scope_digest":scope_digest,"before":{"schema_version":"bluefire.ad-smb-snapshot.v1","scope_digest":scope_digest,"native_parser_digest":scope["native_parser_digest"],"source_receipt_digest":digest('7'),"observed_at":scope["created_at"],"resource":{"member_host_id":scope["hosts"]["member"]["host_id"],"share":scope["share"],"files":scope["files"]},"descriptor":before},"after_descriptor":after,"removed_ace":aces[0],"before_digest":json::hash(&before).unwrap(),"after_digest":json::hash(&after).unwrap(),"native_projection_verified":false,"effective_access_claim":false});
    if phase == "retest" {
        request["target"]["scope_digest"] = json!(scope_digest);
    }
    reseal(&mut packet);
    packet
}

#[test]
fn fixed_write_retest_and_audit_public_operations_validate_without_os_calls() {
    for phase in ["harden", "rollback", "retest"] {
        assert!(validate(reviewed_fixture(phase)).is_ok(), "{phase}");
    }
    let mut audit = fixture();
    audit["manifest"]["params"]["ad_smb_request"]["phase"] = json!("audit");
    audit["manifest"]["params"]["ad_smb_request"]["step"] = json!("collect_audit");
    reseal(&mut audit);
    assert!(validate(audit).is_ok());
}

#[test]
fn reviewed_change_cannot_swap_remaining_ace_or_claim_native_authenticity() {
    for path in [
        "/manifest/params/ad_smb_request/change/native_projection_verified",
        "/manifest/params/ad_smb_request/change/effective_access_claim",
    ] {
        let mut packet = reviewed_fixture("harden");
        *packet.pointer_mut(path).unwrap() = json!(true);
        reseal(&mut packet);
        assert!(validate(packet).is_err());
    }
    let mut packet = reviewed_fixture("harden");
    packet["manifest"]["params"]["ad_smb_request"]["change"]["after_descriptor"]["dacl"]["aces"]
        .as_array_mut()
        .unwrap()
        .reverse();
    reseal(&mut packet);
    assert!(validate(packet).is_err());
}

#[test]
fn actual_python_sealed_public_fixture_has_exact_native_identity_and_delay_clamp() {
    let raw = include_bytes!("../../tests/fixtures/ad_smb_worker_request.json");
    let value = json::parse(raw).unwrap();
    assert_eq!(
        json::hash(&value).unwrap(),
        "sha256:3395fb37c27839c82d5a02142c1885164c9eb9ef82ea461c45d9d64f905b8631"
    );
    let ingress = Instant::now();
    let now = chrono::DateTime::parse_from_rfc3339("2026-10-09T00:00:02Z").unwrap();
    let packet = wire::Packet::validate(value, now, ingress).unwrap();
    let canonical_len = serde_json::to_vec(&packet.value).unwrap().len();
    assert_eq!(packet.output_limit, 4_194_304 - 4096 - canonical_len - 1024);
    assert_eq!(
        packet.monotonic_deadline.duration_since(ingress),
        Duration::from_secs(28)
    );
    assert_eq!(packet.request()["step"], "read_probe_primary");
    assert_eq!(
        packet.value["credential_binding_digest"],
        packet.request()["principal_binding_digest"]
    );
}

#[test]
fn exact_member_packet_and_original_identity_are_accepted() {
    let packet = fixture();
    assert!(validate(packet.clone()).is_ok());
    let mut wrong = packet;
    wrong["task_id"] = json!("execute-other");
    assert!(validate(wrong).is_err());
}

#[test]
fn duplicate_nested_keys_floats_and_trailing_json_are_refused() {
    for raw in [
        r#"{"x":{"a":1,"a":2}}"#,
        r#"{"x":1.0}"#,
        r#"{"x":1} {}"#,
        r#"{"x":NaN}"#,
    ] {
        assert!(json::parse(raw.as_bytes()).is_err());
    }
}

#[test]
fn resealed_scope_and_authority_mutations_are_refused() {
    let paths = [
        ("/profile/file_access_binding", Value::Null),
        ("/profile/limits/max_files", json!(3)),
        ("/profile/limits/timeout_ms", json!(true)),
        ("/profile/allowed_actions/0", json!("system.info.v1")),
        (
            "/manifest/params/ad_smb_request/scope/hosts/member/fqdn",
            json!("wrong.invalid.test"),
        ),
        (
            "/manifest/params/ad_smb_request/scope/authentication/encryption_required",
            json!(false),
        ),
        (
            "/manifest/params/ad_smb_request/scope/files/0/volume_serial",
            json!("0000000000000001"),
        ),
        (
            "/manifest/params/ad_smb_request/scope/principals/probe/sid_history",
            json!(["S-1-5-18"]),
        ),
        (
            "/manifest/params/ad_smb_request/scope/network/flows/0/port_through",
            json!(99),
        ),
        (
            "/manifest/params/ad_smb_request/step",
            json!("arbitrary_operation"),
        ),
    ];
    for (path, replacement) in paths {
        let mut value = fixture();
        if path.ends_with("file_access_binding") {
            value["profile"]["file_access_binding"] = replacement;
        } else {
            *value.pointer_mut(path).unwrap() = replacement;
        }
        reseal(&mut value);
        assert!(validate(value).is_err(), "{path}");
    }
}

#[test]
fn old_synthetic_four_limit_profile_is_not_native_admission() {
    let mut packet = fixture();
    packet["profile"]["limits"] =
        json!({"timeout_ms":60000,"output_bytes":1000000,"files":2,"bytes":65536});
    reseal(&mut packet);
    assert!(validate(packet).is_err());
}

#[test]
fn valid_begin_dispatches_once_and_output_is_framed() {
    let packet = fixture();
    let mut count = 0;
    let mut output = Vec::new();
    assert_eq!(
        run(&mut Cursor::new(input(&packet)), &mut output, |_, begin| {
            assert!(matches!(begin, framing::Begin::Member));
            count += 1;
            Ok(json!({"synthetic":true}))
        }),
        Ok(0)
    );
    assert_eq!(count, 1);
    let mut output = Cursor::new(output);
    let ready = json::parse(&framing::read(&mut output, MAX_READY).unwrap()).unwrap();
    let terminal = json::parse(&framing::read(&mut output, MAX_RESULT).unwrap()).unwrap();
    assert_eq!(ready["schema_version"], "bluefire.ad-smb-worker-ready.v1");
    assert_eq!(terminal["result"], json!({"synthetic":true}));
    assert_eq!(ready["packet_digest"], terminal["packet_digest"]);
}

#[test]
fn malformed_begin_and_trailing_data_never_dispatch() {
    for change in 0..4 {
        let packet = fixture();
        let mut data = input(&packet);
        match change {
            0 => {
                data.pop();
            }
            1 => data.push(0),
            2 => *data.last_mut().unwrap() = 1,
            _ => {
                let last = data.len();
                data[last - 20] ^= 1;
            }
        }
        let mut output = Vec::new();
        assert_eq!(
            run(&mut Cursor::new(data), &mut output, |_, _| panic!(
                "must not dispatch"
            )),
            Ok(4)
        );
        let mut output = Cursor::new(output);
        framing::read(&mut output, MAX_READY).unwrap();
        let result = json::parse(&framing::read(&mut output, MAX_RESULT).unwrap()).unwrap();
        assert_eq!(result["result"], error(Code::BeginInvalid, false));
    }
}

#[test]
fn output_overflow_retains_uncertainty_without_raw_payload() {
    let mut packet = fixture();
    packet["profile"]["limits"]["max_stdout_bytes"] = json!(1024);
    reseal(&mut packet);
    let mut output = Vec::new();
    assert_eq!(
        run(&mut Cursor::new(input(&packet)), &mut output, |_, _| Ok(
            json!({"raw":"x".repeat(4096)})
        )),
        Ok(4)
    );
    let mut output = Cursor::new(output);
    framing::read(&mut output, MAX_READY).unwrap();
    let result = json::parse(&framing::read(&mut output, MAX_RESULT).unwrap()).unwrap();
    assert_eq!(result["result"], error(Code::ResultBoundExceeded, true));
}

#[test]
fn native_failure_is_sanitized_and_marked_as_possible_effects() {
    let packet = fixture();
    let mut output = Vec::new();
    assert_eq!(
        run(&mut Cursor::new(input(&packet)), &mut output, |_, _| Err(
            Code::NativeFailed
        )),
        Ok(4)
    );
    let mut output = Cursor::new(output);
    framing::read(&mut output, MAX_READY).unwrap();
    let result = json::parse(&framing::read(&mut output, MAX_RESULT).unwrap()).unwrap();
    assert_eq!(result["result"], error(Code::NativeFailed, true));
}

#[test]
fn original_ingress_budget_is_not_renewed_by_ready() {
    let packet = fixture();
    let now = chrono::DateTime::<chrono::Utc>::from(SystemTime::now()).fixed_offset();
    let validated =
        wire::Packet::validate(packet, now, Instant::now() - Duration::from_secs(41)).unwrap();
    assert_eq!(validated.current(), Err(Code::Deadline));
}

#[test]
fn prepare_time_remaining_is_clamped_to_fresh_absolute_deadline_after_pipe_delay() {
    let mut packet = fixture();
    packet["remaining_ms"] = json!(60000);
    let now = chrono::DateTime::<chrono::Utc>::from(SystemTime::now()).fixed_offset();
    let ingress = Instant::now();
    let validated = wire::Packet::validate(packet, now, ingress).unwrap();
    assert!(validated.monotonic_deadline.duration_since(ingress) < Duration::from_secs(51));
    assert!(validated.current().is_ok());
}

#[test]
fn impossible_public_lengths_fail_before_any_ready() {
    for data in [
        (MAX_PUBLIC as u32 + 1).to_le_bytes().to_vec(),
        0u32.to_le_bytes().to_vec(),
        vec![1, 0],
    ] {
        let mut output = Vec::new();
        assert!(run(&mut Cursor::new(data), &mut output, |_, _| panic!(
            "must not dispatch"
        ))
        .is_err());
        assert!(output.is_empty());
    }
}

#[test]
fn local_host_check_precedes_ready_and_repeats_before_dispatch() {
    for refusal in [1, 2] {
        let packet = fixture();
        let mut checks = 0;
        let mut output = Vec::new();
        let result = run_checked(
            &mut Cursor::new(input(&packet)),
            &mut output,
            |_| {
                checks += 1;
                if checks == refusal {
                    Err(Code::PreconditionFailed)
                } else {
                    Ok(())
                }
            },
            |_, _| panic!("host refusal must not dispatch"),
        );
        assert_eq!(checks, refusal);
        if refusal == 1 {
            assert_eq!(result, Err(Code::PreconditionFailed));
            assert!(output.is_empty());
        } else {
            assert_eq!(result, Ok(4));
            let mut output = Cursor::new(output);
            framing::read(&mut output, MAX_READY).unwrap();
            let result = json::parse(&framing::read(&mut output, MAX_RESULT).unwrap()).unwrap();
            assert_eq!(result["result"], error(Code::PreconditionFailed, false));
        }
    }
}

#[test]
fn successful_local_host_checks_do_not_replace_original_deadline() {
    let mut packet = fixture();
    packet["remaining_ms"] = json!(1);
    let mut output = Vec::new();
    assert_eq!(
        run_checked(
            &mut Cursor::new(input(&packet)),
            &mut output,
            |_| {
                std::thread::sleep(Duration::from_millis(10));
                Ok(())
            },
            |_, _| panic!("expired host check must not dispatch")
        ),
        Err(Code::Deadline)
    );
    assert!(output.is_empty());

    let packet = fixture();
    let mut checks = 0;
    let mut dispatches = 0;
    assert_eq!(
        run_checked(
            &mut Cursor::new(input(&packet)),
            &mut Vec::new(),
            |_| {
                checks += 1;
                Ok(())
            },
            |_, _| {
                dispatches += 1;
                Ok(json!({"synthetic":true}))
            }
        ),
        Ok(0)
    );
    assert_eq!((checks, dispatches), (2, 1));
}

#[test]
fn audit_byte_allowance_preserves_worst_case_json_and_channel_headroom() {
    let packet = validate(fixture()).unwrap();
    let events = 1000;
    let limit = wire::audit_limit(packet.output_limit, events, 4_194_304).unwrap();
    assert!(limit < 4_194_304);
    assert!(6 * limit + 3 * events + 2048 <= packet.output_limit);
    assert_eq!(wire::audit_limit(packet.output_limit, events, 32), Ok(32));
    assert!(wire::audit_limit(2048 + 3 * events, events, 4_194_304).is_err());
    assert!(wire::audit_limit(2048, usize::MAX, 4_194_304).is_err());
    let escaped = serde_json::to_vec(&"\u{0001}".repeat(limit)).unwrap();
    assert_eq!(escaped.len(), 6 * limit + 2);
    assert!(escaped.len() + 2046 + 3 * events <= packet.output_limit);
}
