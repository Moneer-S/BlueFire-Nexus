use super::*;
use std::cell::{Cell, RefCell};
use std::io::Cursor;
use std::time::Duration;

const GENERATION: &str = "0123456789abcdef0123456789abcdef";
const JOB: &str = "job-abcdef0123456789abcdef0123456789";
struct FakeClock {
    start: Instant,
    elapsed: Cell<Duration>,
    wall: RefCell<DateTime<FixedOffset>>,
    cancelled: Cell<bool>,
}
impl FakeClock {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            elapsed: Cell::new(Duration::ZERO),
            wall: RefCell::new(DateTime::parse_from_rfc3339("2026-10-12T12:00:01Z").unwrap()),
            cancelled: Cell::new(false),
        }
    }
}
impl Clock for FakeClock {
    fn monotonic(&self) -> Instant {
        self.start + self.elapsed.get()
    }
    fn wall(&self) -> DateTime<FixedOffset> {
        *self.wall.borrow()
    }
    fn cancelled(&self) -> bool {
        self.cancelled.get()
    }
}
fn sha(letter: char) -> String {
    format!("sha256:{}", letter.to_string().repeat(64))
}
fn id(index: u8) -> Value {
    json!({"volume_serial":"fedcba9876543210","file_id":format!("{index:032x}")})
}
fn seal(value: &mut Value) {
    value["profile"]["policy_digest"] = json!("");
    value["profile"]["policy_digest"] = json!(wire::hash(&value["profile"]));
    value["manifest"]["policy_digest"] = value["profile"]["policy_digest"].clone();
    value["manifest"]["params"]["windows_file_read_request"]["host"]["profile_digest"] =
        value["profile"]["policy_digest"].clone();
    value["manifest"]["request_hash"] = json!("");
    value["manifest"]["approval"]["request_hash"] = json!("");
    value["manifest"]["request_hash"] = json!(wire::hash(&value["manifest"]));
    value["manifest"]["approval"]["request_hash"] = value["manifest"]["request_hash"].clone();
    let transport = wire::hash(&json!({"manifest":value["manifest"],"profile":value["profile"]}));
    value["task_id"] = json!(format!("execute-{}", &transport[7..]));
    value["request_hash"] = json!(transport);
}
fn packet() -> Value {
    let request_id = crate::canonical::sha256_hex(format!("{JOB}:read_generated_pair").as_bytes())
        [..32]
        .to_owned();
    let limits = json!({"timeout_ms":5000,"max_stdout_bytes":8192,"max_stderr_bytes":1024,"max_artifact_bytes":1,"max_files":1});
    let profile = json!({"schema_version":"bluefire.runner-profile.v1","profile_id":"synthetic.windows-pair",
        "runner_id":"bluefire-rust-runner.v1","platform":"windows","sandbox_root":format!("C:\\BlueFire\\EndpointAccess\\{GENERATION}"),
        "allowed_actions":["private.windows.file_read_pair.v2"],"control_blocked_actions":[],"capabilities":["windows_file_read_pair"],
        "max_safety_tier":"controlled","approval_required_at_or_above":"safe","target_scope":{"filesystem":[],"network":[]},"limits":limits,"policy_digest":""});
    let request = json!({"schema_version":"bluefire.windows-file-worker-operation.v2","request_id":request_id,"operation_job_id":JOB,
        "generation":GENERATION,"control_revision":7,"credential_binding_digest":sha('a'),
        "host":{"runner_profile_id":"synthetic.windows-pair","profile_digest":"","native_generation":sha('b'),"host_id":sha('c'),"channel_digest":sha('d')},
        "resource":{"owner_sid":"S-1-5-21-101-202-303-1001","reader_sid":"S-1-5-21-101-202-303-1002","ancestors":[id(1),id(2),id(3),id(4)],
        "file_identity":id(5),"size_bytes":13,"sha256":sha('e'),"state":"readable"}});
    let manifest = json!({"schema_version":"bluefire.runner-manifest.v1","request_id":format!("win-read-{request_id}"),"run_id":JOB,"step_id":"read_generated_pair",
        "behavior_id":"identity.windows.file_read_pair.v2","action_id":"private.windows.file_read_pair.v2","mode":"execute","runner_id":"bluefire-rust-runner.v1",
        "runner_profile_id":"synthetic.windows-pair","platform":"windows","requested_at":"2026-10-12T12:00:00Z","expires_at":"2026-10-12T12:00:05Z",
        "params":{"windows_file_read_request":request},"target_scope":{"filesystem":[],"network":[]},"required_capabilities":["windows_file_read_pair"],
        "safety_tier":"controlled","limits":limits,"cleanup_action_id":null,"policy_digest":"",
        "approval":{"approved_by":"synthetic-reviewer","approved_at":"2026-10-12T12:00:00Z","expires_at":"2026-10-12T12:00:05Z","request_hash":""},"evidence_refs":[],"request_hash":""});
    let mut value = json!({"schema_version":"bluefire.windows-file-worker-request.v2","challenge":"f".repeat(64),"task_id":"","request_hash":"","manifest":manifest,"profile":profile,"remaining_ms":4000});
    seal(&mut value);
    value
}
fn frame(raw: &[u8]) -> Vec<u8> {
    let mut value = (raw.len() as u32).to_le_bytes().to_vec();
    value.extend_from_slice(raw);
    value
}
fn begin(packet: &Value) -> Vec<u8> {
    let mut value = b"BFWFBEG2".to_vec();
    value.extend_from_slice(&[255; 32]);
    value.extend_from_slice(&hex::decode(&wire::hash(packet)[7..]).unwrap());
    value.extend_from_slice(&hex::decode(GENERATION).unwrap());
    value.extend_from_slice(&7u32.to_le_bytes());
    value.extend_from_slice(&[170; 32]);
    value.extend_from_slice(&2u16.to_le_bytes());
    value.extend_from_slice(&[65, 0, 66, 0]);
    value
}
fn input(value: &Value, begin: &[u8]) -> Cursor<Vec<u8>> {
    let mut bytes = frame(&serde_json::to_vec(value).unwrap());
    bytes.extend_from_slice(&frame(begin));
    Cursor::new(bytes)
}
fn frames(bytes: Vec<u8>) -> Vec<Value> {
    let mut input = Cursor::new(bytes);
    let mut rows = Vec::new();
    while input.position() < input.get_ref().len() as u64 {
        rows.push(
            serde_json::from_slice(
                &framing::read(&mut input, MAX_TERMINAL, Code::RequestInvalid).unwrap(),
            )
            .unwrap(),
        );
    }
    rows
}
fn observed(packet: &wire::Packet, outcome: ReadOutcome) -> DispatchResult {
    DispatchResult {
        value: json!({"schema_version":"bluefire.windows-fixed-read-pair.v2","request_id":packet.request()["request_id"],"outcome":outcome,
        "reader":{"outcome":"allowed"},"owner":{"outcome":if outcome == ReadOutcome::Unknown { "unknown" } else { "allowed" }}}),
        outcome,
    }
}

#[test]
fn pair_capability_is_precise_without_changing_v1_or_inventory() {
    let value = pair_protocol_capability();
    assert_eq!(
        value,
        json!({"schema_version":"bluefire.windows-file-worker-capability.v2","runner_id":"bluefire-rust-runner.v1","runner_version":env!("CARGO_PKG_VERSION"),
        "platform":crate::Platform::current(),"architecture":std::env::consts::ARCH,"supported":cfg!(all(target_os="windows",target_arch="x86_64")),
        "worker_command":"windows-file-baseline-worker","worker_schema":"bluefire.windows-file-worker-request.v2","read_schema":"bluefire.windows-fixed-read-pair.v2", "scope":"protocol_support_only",
        "action_id":"private.windows.file_read_pair.v2","capability":"windows_file_read_pair","max_data_opens":2,"max_bytes_per_read":1048576,"max_total_read_bytes":2097152,"max_execution_ms":5000})
    );
    assert!(serde_json::to_vec(&value).unwrap().len() < 1024);
    assert_eq!(protocol_capability()["worker_schema"], REQUEST_SCHEMA);
    assert!(!crate::inventory()
        .iter()
        .any(|action| action.action_id == "private.windows.file_read_pair.v2"));
}

#[test]
fn v2_packet_and_begin_are_not_accepted_by_v1_or_silently_downgraded() {
    let value = packet();
    let clock = FakeClock::new();
    assert!(wire::Packet::validate(value.clone(), &clock, clock.start).is_err());
    let bound = wire::Packet::validate_for(Protocol::PairV2, value.clone(), &clock, clock.start)
        .unwrap_or_else(|_| panic!("fixture"));
    let mut old_begin = begin(&value);
    old_begin[..8].copy_from_slice(b"BFWFBEG1");
    assert!(framing::BeginReader::default()
        .consume(&mut Cursor::new(frame(&old_begin)), &bound)
        .is_err());
    for field in [
        "action",
        "capability",
        "schema",
        "step",
        "behavior",
        "state",
    ] {
        let mut changed = value.clone();
        match field {
            "action" => {
                changed["profile"]["allowed_actions"] = json!([PRIVATE_ACTION]);
                changed["manifest"]["action_id"] = json!(PRIVATE_ACTION);
            }
            "capability" => {
                changed["profile"]["capabilities"] = json!([PRIVATE_CAPABILITY]);
                changed["manifest"]["required_capabilities"] = json!([PRIVATE_CAPABILITY]);
            }
            "schema" => {
                changed["manifest"]["params"]["windows_file_read_request"]["schema_version"] =
                    json!("bluefire.windows-file-worker-operation.v1")
            }
            "step" => changed["manifest"]["step_id"] = json!("read_generated"),
            "behavior" => {
                changed["manifest"]["behavior_id"] = json!("identity.windows.file_read.v1")
            }
            "state" => {
                changed["manifest"]["params"]["windows_file_read_request"]["resource"]["state"] =
                    json!("metadata_only")
            }
            _ => unreachable!(),
        }
        seal(&mut changed);
        assert!(
            wire::Packet::validate_for(Protocol::PairV2, changed, &clock, clock.start).is_err(),
            "{field}"
        );
    }
}

#[test]
fn returned_partial_pair_keeps_reader_truth_and_actual_exit_four() {
    for late in [false, true] {
        let value = packet();
        let clock = FakeClock::new();
        let mut output = Vec::new();
        let result = run_checked_for(
            Protocol::PairV2,
            &mut input(&value, &begin(&value)),
            &mut output,
            &clock,
            |packet, _, _| {
                if late {
                    clock.elapsed.set(Duration::from_secs(5));
                }
                let mut proof = observed(packet, ReadOutcome::Unknown);
                proof.value["issue"] = json!("cleanup_unknown");
                proof.value["failed_stage"] = json!("cleanup");
                Ok(proof)
            },
        );
        assert_eq!(result, Ok(4));
        let rows = frames(output);
        assert_eq!(
            rows[0]["schema_version"],
            "bluefire.windows-file-worker-ready.v2"
        );
        assert_eq!(rows[1]["operation"], "read_generated_pair");
        assert_eq!(rows[1]["result"]["reader"]["outcome"], "allowed");
        assert_eq!(rows[1]["result"]["outcome"], "unknown");
        assert_eq!(rows[1]["result"]["issue"], "cleanup_unknown");
        assert_eq!(rows[1]["result"]["failed_stage"], "cleanup");
        assert_eq!(rows[1]["observed_at"].is_null(), late);
    }
}

#[test]
fn complete_pair_uses_one_interval_and_only_one_begin() {
    let value = packet();
    let clock = FakeClock::new();
    let bound = wire::Packet::validate_for(Protocol::PairV2, value.clone(), &clock, clock.start)
        .unwrap_or_else(|_| panic!("fixture"));
    let mut reader = framing::BeginReader::default();
    let _ = framing::take_erasures();
    let units = reader
        .consume(&mut Cursor::new(frame(&begin(&value))), &bound)
        .unwrap_or_else(|_| panic!("fixture"));
    drop(units);
    assert!(matches!(
        reader.consume(&mut Cursor::new(frame(&begin(&value))), &bound),
        Err(Code::BeginConsumed)
    ));
    assert!(framing::take_erasures()
        .iter()
        .all(|(_, _, zeroed)| *zeroed));
    for outcome in [ReadOutcome::Allowed, ReadOutcome::DataAccessDenied] {
        let mut output = Vec::new();
        assert_eq!(
            run_checked_for(
                Protocol::PairV2,
                &mut input(&value, &begin(&value)),
                &mut output,
                &clock,
                |packet, _, _| Ok(observed(packet, outcome))
            ),
            Ok(0)
        );
        assert!(!frames(output)[1]["observed_at"].is_null());
    }
}

#[test]
fn paired_aggregate_stdout_bound_counts_both_prefixes_and_never_partially_appends() {
    for maximum in [1024, 1400, 8192] {
        let mut value = packet();
        value["profile"]["limits"]["max_stdout_bytes"] = json!(maximum);
        value["manifest"]["limits"]["max_stdout_bytes"] = json!(maximum);
        seal(&mut value);
        let mut output = Vec::new();
        let result = run_checked_for(
            Protocol::PairV2,
            &mut input(&value, &begin(&value)),
            &mut output,
            &FakeClock::new(),
            |packet, _, _| {
                let mut proof = observed(packet, ReadOutcome::Allowed);
                proof.value["padding"] = json!("x".repeat(16000));
                Ok(proof)
            },
        );
        assert!(result == Ok(4) || result == Err(Code::ResultBoundExceeded));
        assert!(output.len() <= maximum);
        let rows = frames(output);
        assert!(!rows.is_empty() && rows.len() <= 2);
        if rows.len() == 2 {
            assert_eq!(rows[1]["result"]["code"], "result_bound_exceeded");
        }
    }
}

#[test]
fn pair_wall_rollback_and_cancel_before_begin_never_dispatch() {
    for cancel in [false, true] {
        let value = packet();
        let clock = FakeClock::new();
        if cancel {
            clock.cancelled.set(true);
        } else {
            *clock.wall.borrow_mut() =
                DateTime::parse_from_rfc3339("2026-10-12T11:59:59Z").unwrap();
        }
        let calls = Cell::new(0);
        let result = run_checked_for(
            Protocol::PairV2,
            &mut input(&value, &begin(&value)),
            &mut Vec::new(),
            &clock,
            |packet, _, _| {
                calls.set(calls.get() + 1);
                Ok(observed(packet, ReadOutcome::Allowed))
            },
        );
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
    }
}

#[test]
fn pair_fixture_matches_independent_stdlib_canonical_and_begin_goldens() {
    // Independently derived from literal fixture data with Python stdlib, not
    // either native/Python wire implementation or their canonical helpers.
    let value = packet();
    assert_eq!(
        value["manifest"]["params"]["windows_file_read_request"]["request_id"],
        "e11879634b2ce0543febffcd6aff102e"
    );
    assert_eq!(
        value["profile"]["policy_digest"],
        "sha256:ade6357ac6f629cef9adee176e85655ce43d12787606e6ac4295c35b2dd66b48"
    );
    assert_eq!(
        value["manifest"]["request_hash"],
        "sha256:b175fa5328f1dd3db384e91120bc3c12a08aac277aabe523a358c3cc9ff13185"
    );
    assert_eq!(
        value["request_hash"],
        "sha256:d127eb80abfc673b4d236b33d439f06782c6f33cd9625fa5cffbb18a677eee14"
    );
    assert_eq!(
        value["task_id"],
        "execute-d127eb80abfc673b4d236b33d439f06782c6f33cd9625fa5cffbb18a677eee14"
    );
    assert_eq!(
        wire::hash(&value),
        "sha256:a46b6399401f059407cc138c1281626acbb15f1f451731575a58fc70101f9db1"
    );
    let canonical = crate::canonical::canonical_json(&value);
    assert_eq!(canonical.len(), 3622);
    assert_eq!(hex::encode(&frame(canonical.as_bytes())[..4]), "260e0000");
    assert_eq!(hex::encode(&begin(&value)[..124]), "4246574642454732ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa46b6399401f059407cc138c1281626acbb15f1f451731575a58fc70101f9db10123456789abcdef0123456789abcdef07000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
}

fn correction_packet() -> Value {
    let protocol = Protocol::CorrectionPairV3;
    let mut value = packet();
    let request_id =
        crate::canonical::sha256_hex(format!("{JOB}:{}", protocol.operation()).as_bytes())[..32]
            .to_owned();
    value["schema_version"] = json!(protocol.request());
    value["profile"]["profile_id"] = json!("synthetic.windows-correction");
    value["profile"]["allowed_actions"] = json!([protocol.action()]);
    value["profile"]["capabilities"] = json!([protocol.capability()]);
    value["manifest"]["request_id"] = json!(format!("win-read-{request_id}"));
    value["manifest"]["step_id"] = json!(protocol.operation());
    value["manifest"]["behavior_id"] = json!(protocol.behavior());
    value["manifest"]["action_id"] = json!(protocol.action());
    value["manifest"]["required_capabilities"] = json!([protocol.capability()]);
    value["manifest"]["runner_profile_id"] = json!("synthetic.windows-correction");
    let request = &mut value["manifest"]["params"]["windows_file_read_request"];
    request["schema_version"] = json!(protocol.operation_schema());
    request["request_id"] = json!(request_id);
    request["control_revision"] = json!(2);
    request["correction_binding_digest"] = json!(sha('1'));
    request["host"]["runner_profile_id"] = json!("synthetic.windows-correction");
    request["resource"]["state"] = json!("metadata_only");
    seal(&mut value);
    value
}
fn correction_begin(value: &Value) -> Vec<u8> {
    let mut raw = begin(value);
    raw[..8].copy_from_slice(b"BFWFBEG3");
    raw[88..92].copy_from_slice(&2u32.to_le_bytes());
    raw.splice(124..124, [0x11; 32]);
    raw
}
fn correction_observed(packet: &wire::Packet, outcome: ReadOutcome) -> DispatchResult {
    let mut result = observed(packet, outcome);
    result.value["schema_version"] = json!(Protocol::CorrectionPairV3.read());
    result.value["reader"]["outcome"] = json!(outcome);
    result
}

#[test]
fn correction_capability_is_distinct_bounded_and_not_an_ordinary_action() {
    let value = correction_protocol_capability();
    assert_eq!(value["worker_command"], "windows-file-correction-worker");
    assert_eq!(
        value["schema_version"],
        "bluefire.windows-file-worker-capability.v3"
    );
    assert_eq!(value["scope"], "protocol_support_only");
    assert_eq!(
        value["action_id"],
        "private.windows.file_read_pair_correction.v3"
    );
    assert_eq!(value["capability"], "windows_file_read_pair_correction");
    assert_eq!(value["max_data_opens"], 2);
    assert_eq!(value["max_total_read_bytes"], 2_097_152);
    assert_eq!(value["max_execution_ms"], 5000);
    assert!(serde_json::to_vec(&value).unwrap().len() < MAX_READY);
    assert!(!crate::inventory()
        .iter()
        .any(|action| action.action_id == Protocol::CorrectionPairV3.action()));
}

#[test]
fn correction_request_is_closed_and_never_downgrades_v1_or_v2() {
    let value = correction_packet();
    let clock = FakeClock::new();
    for protocol in [Protocol::ReaderV1, Protocol::PairV2] {
        assert!(wire::Packet::validate_for(protocol, value.clone(), &clock, clock.start).is_err());
    }
    let bound = wire::Packet::validate_for(
        Protocol::CorrectionPairV3,
        value.clone(),
        &clock,
        clock.start,
    )
    .unwrap_or_else(|_| panic!("fixture"));
    assert_eq!(bound.binding()["correction_binding_digest"], sha('1'));
    for change in [
        "missing",
        "malformed",
        "upper",
        "revision",
        "state",
        "extra",
        "operation",
        "action",
        "capability",
        "behavior",
    ] {
        let mut changed = value.clone();
        let request = &mut changed["manifest"]["params"]["windows_file_read_request"];
        match change {
            "missing" => {
                request
                    .as_object_mut()
                    .unwrap()
                    .remove("correction_binding_digest");
            }
            "malformed" => request["correction_binding_digest"] = json!("1".repeat(64)),
            "upper" => request["correction_binding_digest"] = json!(sha('A')),
            "revision" => request["control_revision"] = json!(1),
            "state" => request["resource"]["state"] = json!("readable"),
            "extra" => request["correction_authorized"] = json!(true),
            "operation" => request["schema_version"] = json!(Protocol::PairV2.operation_schema()),
            "action" => changed["manifest"]["action_id"] = json!(Protocol::PairV2.action()),
            "capability" => {
                changed["manifest"]["required_capabilities"] =
                    json!([Protocol::PairV2.capability()])
            }
            "behavior" => changed["manifest"]["behavior_id"] = json!(Protocol::PairV2.behavior()),
            _ => unreachable!(),
        }
        seal(&mut changed);
        assert!(
            wire::Packet::validate_for(Protocol::CorrectionPairV3, changed, &clock, clock.start)
                .is_err(),
            "{change}"
        );
    }
    assert!(
        wire::Packet::validate_for(Protocol::CorrectionPairV3, packet(), &clock, clock.start)
            .is_err()
    );
}

#[test]
fn correction_begin_digest_magic_length_and_consumption_bind_before_dispatch() {
    let value = correction_packet();
    let clock = FakeClock::new();
    let bound = wire::Packet::validate_for(
        Protocol::CorrectionPairV3,
        value.clone(),
        &clock,
        clock.start,
    )
    .unwrap_or_else(|_| panic!("fixture"));
    for change in [
        "digest",
        "v2_magic",
        "v1_magic",
        "missing_digest",
        "short",
        "extra",
    ] {
        let mut raw = correction_begin(&value);
        match change {
            "digest" => raw[124] ^= 1,
            "v2_magic" => raw[..8].copy_from_slice(b"BFWFBEG2"),
            "v1_magic" => raw[..8].copy_from_slice(b"BFWFBEG1"),
            "missing_digest" => {
                raw.drain(124..156);
            }
            "short" => {
                raw.truncate(155);
            }
            "extra" => raw.push(0),
            _ => unreachable!(),
        }
        let mut reader = framing::BeginReader::default();
        let _ = framing::take_erasures();
        assert!(
            matches!(
                reader.consume(&mut Cursor::new(frame(&raw)), &bound),
                Err(Code::BeginInvalid)
            ),
            "{change}"
        );
        assert!(matches!(
            reader.consume(&mut Cursor::new(frame(&correction_begin(&value))), &bound),
            Err(Code::BeginConsumed)
        ));
        assert!(framing::take_erasures()
            .iter()
            .all(|(_, _, zeroed)| *zeroed));
        let calls = Cell::new(0);
        let result = run_checked_for(
            Protocol::CorrectionPairV3,
            &mut input(&value, &raw),
            &mut Vec::new(),
            &clock,
            |packet, _, _| {
                calls.set(calls.get() + 1);
                Ok(correction_observed(packet, ReadOutcome::Allowed))
            },
        );
        assert_eq!(result, Ok(4));
        assert_eq!(calls.get(), 0);
    }
    let mut reader = framing::BeginReader::default();
    let units = reader
        .consume(&mut Cursor::new(frame(&correction_begin(&value))), &bound)
        .unwrap_or_else(|_| panic!("fixture"));
    assert_eq!(units.0, [65, 66]);
    drop(units);
}

#[test]
fn correction_ready_result_and_late_partial_bind_the_same_opaque_claim() {
    let value = correction_packet();
    for late in [false, true] {
        let clock = FakeClock::new();
        let mut output = Vec::new();
        assert_eq!(
            run_checked_for(
                Protocol::CorrectionPairV3,
                &mut input(&value, &correction_begin(&value)),
                &mut output,
                &clock,
                |packet, _, _| {
                    if late {
                        clock.elapsed.set(Duration::from_secs(5));
                    }
                    Ok(correction_observed(packet, ReadOutcome::DataAccessDenied))
                }
            ),
            Ok(if late { 4 } else { 0 })
        );
        let rows = frames(output);
        assert_eq!(
            rows[0]["schema_version"],
            "bluefire.windows-file-worker-ready.v3"
        );
        assert_eq!(rows[0]["correction_binding_digest"], sha('1'));
        assert_eq!(rows[0]["readiness_scope"], "protocol_only");
        assert_eq!(
            rows[1]["schema_version"],
            "bluefire.windows-file-worker-result.v3"
        );
        assert_eq!(rows[1]["correction_binding_digest"], sha('1'));
        assert_eq!(rows[1]["operation"], "read_generated_pair_correction");
        assert_eq!(rows[1]["result"]["reader"]["outcome"], "data_access_denied");
        assert_eq!(rows[1]["observed_at"].is_null(), late);
        if late {
            assert_eq!(rows[1]["result"]["outcome"], "unknown");
        }
    }
}

#[test]
fn correction_fixture_matches_python_stdlib_canonical_and_begin_goldens() {
    let value = correction_packet();
    assert_eq!(
        value["manifest"]["params"]["windows_file_read_request"]["request_id"],
        "4f5df61ef6fafc566b35369cf50ef092"
    );
    assert_eq!(
        value["profile"]["policy_digest"],
        "sha256:72aecfbdf7e8df622b04b07beb601014b3c9da2fec669427ecebd96a6ad40326"
    );
    assert_eq!(
        value["manifest"]["request_hash"],
        "sha256:d8f39eafe5f3d9e176e87b9872a29bfd95cc21b40010776aa9d866db3506d674"
    );
    assert_eq!(
        value["request_hash"],
        "sha256:69fc121218f93b9d8bddb6e72ca69ee6c357bbd1609de8d5a48273b7715972ae"
    );
    assert_eq!(
        wire::hash(&value),
        "sha256:856f3cba47b3b3e4d6d6df62323055b3496ce448dc53469971ff9db92338bfbc"
    );
    assert_eq!(crate::canonical::canonical_json(&value).len(), 3813);
    assert_eq!(hex::encode(&correction_begin(&value)[..156]), "4246574642454733ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff856f3cba47b3b3e4d6d6df62323055b3496ce448dc53469971ff9db92338bfbc0123456789abcdef0123456789abcdef02000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111111111111111111111111111111111111111111111111111111111111111");
}

#[test]
fn correction_stdout_bound_and_pre_begin_cancellation_never_expand_authority() {
    for maximum in [1024, 1400, 8192] {
        let mut value = correction_packet();
        value["profile"]["limits"]["max_stdout_bytes"] = json!(maximum);
        value["manifest"]["limits"]["max_stdout_bytes"] = json!(maximum);
        seal(&mut value);
        let mut output = Vec::new();
        let result = run_checked_for(
            Protocol::CorrectionPairV3,
            &mut input(&value, &correction_begin(&value)),
            &mut output,
            &FakeClock::new(),
            |packet, _, _| {
                let mut proof = correction_observed(packet, ReadOutcome::DataAccessDenied);
                proof.value["padding"] = json!("x".repeat(16000));
                Ok(proof)
            },
        );
        assert!(result == Ok(4) || result == Err(Code::ResultBoundExceeded));
        assert!(output.len() <= maximum);
        let rows = frames(output);
        if rows.len() == 2 {
            assert_eq!(rows[1]["result"]["code"], "result_bound_exceeded");
        }
    }
    for cancel in [false, true] {
        let value = correction_packet();
        let clock = FakeClock::new();
        if cancel {
            clock.cancelled.set(true);
        } else {
            *clock.wall.borrow_mut() =
                DateTime::parse_from_rfc3339("2026-10-12T11:59:59Z").unwrap();
        }
        let calls = Cell::new(0);
        let result = run_checked_for(
            Protocol::CorrectionPairV3,
            &mut input(&value, &correction_begin(&value)),
            &mut Vec::new(),
            &clock,
            |packet, _, _| {
                calls.set(calls.get() + 1);
                Ok(correction_observed(packet, ReadOutcome::Allowed))
            },
        );
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
    }
}
