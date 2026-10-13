use super::*;
use std::cell::{Cell, RefCell};
use std::io::Cursor;
use std::time::Duration;

// Synthetic authority/account values only. No OS, host identity or credential
// provider is queried by these tests; dispatch always uses an in-memory callback.
const GENERATION: &str = "0123456789abcdef0123456789abcdef";
const JOB: &str = "job-abcdef0123456789abcdef0123456789";
const OWNER: &str = "S-1-5-21-101-202-303-1001";
const READER: &str = "S-1-5-21-101-202-303-1002";

#[test]
fn capability_declares_only_the_exact_compiled_private_protocol() {
    assert_eq!(
        protocol_capability(),
        json!({
            "schema_version": "bluefire.windows-file-worker-capability.v1",
            "runner_id": "bluefire-rust-runner.v1",
            "runner_version": env!("CARGO_PKG_VERSION"),
            "platform": crate::Platform::current(),
            "architecture": std::env::consts::ARCH,
            "supported": cfg!(all(target_os = "windows", target_arch = "x86_64")),
            "worker_command": "windows-file-worker",
            "worker_schema": "bluefire.windows-file-worker-request.v1",
            "read_schema": "bluefire.windows-fixed-read.v1",
            "scope": "protocol_support_only",
        })
    );
    assert!(serde_json::to_vec(&protocol_capability()).unwrap().len() < 1024);
    assert!(!crate::inventory()
        .iter()
        .any(|action| action.action_id == PRIVATE_ACTION));
}

struct FakeClock {
    origin: Instant,
    elapsed: Cell<Duration>,
    wall: RefCell<DateTime<FixedOffset>>,
    cancelled: Cell<bool>,
}
impl FakeClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            elapsed: Cell::new(Duration::ZERO),
            wall: RefCell::new(
                DateTime::parse_from_rfc3339("2026-10-12T12:00:01Z")
                    .unwrap_or_else(|_| panic!("synthetic clock")),
            ),
            cancelled: Cell::new(false),
        }
    }
}
impl Clock for FakeClock {
    fn monotonic(&self) -> Instant {
        self.origin + self.elapsed.get()
    }
    fn wall(&self) -> DateTime<FixedOffset> {
        *self.wall.borrow()
    }
    fn cancelled(&self) -> bool {
        self.cancelled.get()
    }
}
fn sha(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}
fn object_id(index: u8) -> Value {
    json!({"volume_serial":"fedcba9876543210","file_id":format!("{index:032x}")})
}
fn manifest_seal(packet: &mut Value) {
    packet["manifest"]["request_hash"] = json!("");
    packet["manifest"]["approval"]["request_hash"] = json!("");
    let seal = wire::hash(&packet["manifest"]);
    packet["manifest"]["request_hash"] = json!(seal);
    packet["manifest"]["approval"]["request_hash"] = packet["manifest"]["request_hash"].clone();
    let transport = wire::hash(&json!({"manifest":packet["manifest"],"profile":packet["profile"]}));
    packet["request_hash"] = json!(transport);
    packet["task_id"] = json!(format!("execute-{}", &transport[7..]));
}
fn profile_seal(packet: &mut Value) {
    packet["profile"]["policy_digest"] = json!("");
    packet["profile"]["policy_digest"] = json!(wire::hash(&packet["profile"]));
    packet["manifest"]["policy_digest"] = packet["profile"]["policy_digest"].clone();
    packet["manifest"]["params"]["windows_file_read_request"]["host"]["profile_digest"] =
        packet["profile"]["policy_digest"].clone();
    manifest_seal(packet);
}
fn packet() -> Value {
    let request_id =
        crate::canonical::sha256_hex(format!("{JOB}:read_generated").as_bytes())[..32].to_owned();
    let limits = json!({"timeout_ms":5000,"max_stdout_bytes":8192,"max_stderr_bytes":1024,"max_artifact_bytes":1,"max_files":1});
    let profile = json!({"schema_version":"bluefire.runner-profile.v1","profile_id":"synthetic.windows-reader",
        "runner_id":"bluefire-rust-runner.v1","platform":"windows","sandbox_root":format!("C:\\BlueFire\\EndpointAccess\\{GENERATION}"),
        "allowed_actions":[PRIVATE_ACTION],"control_blocked_actions":[],"capabilities":[PRIVATE_CAPABILITY],
        "max_safety_tier":"controlled","approval_required_at_or_above":"safe","target_scope":{"filesystem":[],"network":[]},"limits":limits,"policy_digest":""});
    let request = json!({"schema_version":"bluefire.windows-file-worker-operation.v1","request_id":request_id,"operation_job_id":JOB,
        "generation":GENERATION,"control_revision":7,"credential_binding_digest":sha('a'),
        "host":{"runner_profile_id":"synthetic.windows-reader","profile_digest":"","native_generation":sha('b'),"host_id":sha('c'),"channel_digest":sha('d')},
        "resource":{"owner_sid":OWNER,"reader_sid":READER,"ancestors":[object_id(1),object_id(2),object_id(3),object_id(4)],
            "file_identity":object_id(5),"size_bytes":13,"sha256":sha('e'),"state":"readable"}});
    let manifest = json!({"schema_version":"bluefire.runner-manifest.v1","request_id":format!("win-read-{request_id}"),"run_id":JOB,"step_id":"read_generated",
        "behavior_id":"identity.windows.file_read.v1","action_id":PRIVATE_ACTION,"mode":"execute","runner_id":"bluefire-rust-runner.v1",
        "runner_profile_id":"synthetic.windows-reader","platform":"windows","requested_at":"2026-10-12T12:00:00Z","expires_at":"2026-10-12T12:00:05Z",
        "params":{"windows_file_read_request":request},"target_scope":{"filesystem":[],"network":[]},"required_capabilities":[PRIVATE_CAPABILITY],
        "safety_tier":"controlled","limits":limits,"cleanup_action_id":null,"policy_digest":"",
        "approval":{"approved_by":"synthetic-reviewer","approved_at":"2026-10-12T12:00:00Z","expires_at":"2026-10-12T12:00:05Z","request_hash":""},
        "evidence_refs":[],"request_hash":""});
    let mut value = json!({"schema_version":REQUEST_SCHEMA,"challenge":"f".repeat(64),"task_id":"","request_hash":"","manifest":manifest,"profile":profile,"remaining_ms":4000});
    profile_seal(&mut value);
    value
}
fn request(value: &Value) -> &Value {
    &value["manifest"]["params"]["windows_file_read_request"]
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut framed = (bytes.len() as u32).to_le_bytes().to_vec();
    framed.extend_from_slice(bytes);
    framed
}
fn begin(value: &Value, password: &[u16]) -> Vec<u8> {
    let mut bytes = b"BFWFBEG1".to_vec();
    bytes.extend_from_slice(
        &hex::decode(value["challenge"].as_str().unwrap_or_default()).unwrap_or_default(),
    );
    bytes.extend_from_slice(&hex::decode(&wire::hash(value)[7..]).unwrap_or_default());
    bytes.extend_from_slice(
        &hex::decode(request(value)["generation"].as_str().unwrap_or_default()).unwrap_or_default(),
    );
    bytes.extend_from_slice(
        &(request(value)["control_revision"]
            .as_u64()
            .unwrap_or_default() as u32)
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &hex::decode(
            &request(value)["credential_binding_digest"]
                .as_str()
                .unwrap_or_default()[7..],
        )
        .unwrap_or_default(),
    );
    bytes.extend_from_slice(&(password.len() as u16).to_le_bytes());
    for unit in password {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}
fn input(value: &Value, private: &[u8]) -> Cursor<Vec<u8>> {
    let mut bytes = frame(&serde_json::to_vec(value).unwrap_or_default());
    bytes.extend_from_slice(&frame(private));
    Cursor::new(bytes)
}
fn output_frames(bytes: Vec<u8>) -> Vec<Value> {
    let mut input = Cursor::new(bytes);
    let mut values = Vec::new();
    while input.position() < input.get_ref().len() as u64 {
        let bytes = framing::read(&mut input, MAX_TERMINAL, Code::RequestInvalid)
            .unwrap_or_else(|_| panic!("synthetic output frame"));
        values.push(
            serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("synthetic output JSON")),
        );
    }
    values
}
fn observed(packet: &wire::Packet, outcome: ReadOutcome) -> DispatchResult {
    DispatchResult {
        value: json!({"schema_version":"bluefire.windows-fixed-read.v1","request_id":packet.request()["request_id"],"outcome":outcome}),
        outcome,
    }
}
fn success(packet: &wire::Packet) -> DispatchResult {
    observed(packet, ReadOutcome::Allowed)
}
fn run(value: &Value, private: &[u8], clock: &FakeClock) -> (Result<i32>, Vec<Value>, usize) {
    let mut output = Vec::new();
    let calls = Cell::new(0);
    let result = run_checked(
        &mut input(value, private),
        &mut output,
        clock,
        |packet, units, _| {
            calls.set(calls.get() + 1);
            assert!(!units.0.is_empty());
            Ok(success(packet))
        },
    );
    (result, output_frames(output), calls.get())
}

#[test]
fn ready_begin_terminal_bind_the_exact_original_task() {
    let value = packet();
    let (result, output, calls) = run(&value, &begin(&value, &[65, 66]), &FakeClock::new());
    assert_eq!(result, Ok(0));
    assert_eq!(calls, 1);
    assert_eq!(output.len(), 2);
    assert_eq!(output[0]["schema_version"], READY_SCHEMA);
    assert_eq!(output[0]["readiness_scope"], "protocol_only");
    assert_eq!(output[1]["schema_version"], RESULT_SCHEMA);
    assert_eq!(output[1]["operation"], "read_generated");
    for name in ["challenge", "task_id", "request_hash"] {
        assert_eq!(output[0][name], value[name]);
        assert_eq!(output[1][name], value[name]);
    }
    for name in [
        "generation",
        "control_revision",
        "credential_binding_digest",
    ] {
        assert_eq!(output[0][name], request(&value)[name]);
        assert_eq!(output[1][name], request(&value)[name]);
    }
    assert_eq!(output[0]["packet_digest"], wire::hash(&value));
    assert_eq!(output[1]["packet_digest"], wire::hash(&value));
    assert!(
        output[0].get("pid").is_none()
            && output[0].get("job_owned").is_none()
            && output[0].get("authenticated").is_none()
    );
    assert_ne!(value["request_hash"], value["manifest"]["request_hash"]);
    assert_eq!(output[1]["observed_at"], "2026-10-12T12:00:01.000000Z");
}
#[test]
fn wrong_original_transport_manifest_profile_and_host_bindings_refuse() {
    for fault in 0..9 {
        let mut value = packet();
        match fault {
            0 => value["request_hash"] = json!(sha('0')),
            1 => value["task_id"] = json!("execute-".to_owned() + &"0".repeat(64)),
            2 => value["manifest"]["request_hash"] = json!(sha('0')),
            3 => value["profile"]["policy_digest"] = json!(sha('0')),
            4 => {
                value["manifest"]["approval"]["request_hash"] = json!(sha('0'));
            }
            5 => {
                value["manifest"]["params"]["windows_file_read_request"]["host"]
                    ["runner_profile_id"] = json!("wrong-profile");
                manifest_seal(&mut value);
            }
            6 => {
                value["manifest"]["params"]["windows_file_read_request"]["host"]
                    ["profile_digest"] = json!(sha('0'));
                manifest_seal(&mut value);
            }
            7 => {
                value["manifest"]["params"]["windows_file_read_request"]["host"]
                    ["native_generation"] = json!("unknown");
                manifest_seal(&mut value);
            }
            _ => {
                value["manifest"]["run_id"] = json!("job-".to_owned() + &"0".repeat(32));
                manifest_seal(&mut value);
            }
        }
        let (result, output, calls) = run(&value, &begin(&value, &[65]), &FakeClock::new());
        assert_eq!(result, Err(Code::RequestInvalid));
        assert_eq!(calls, 0);
        assert!(output.is_empty());
    }
}
#[test]
fn unsupported_schema_action_profile_scope_and_arbitrary_parameters_refuse() {
    for fault in 0..13 {
        let mut value = packet();
        match fault {
            0 => value["schema_version"] = json!("bluefire.ad-smb-worker-request.v1"),
            1 => value["manifest"]["action_id"] = json!("owned.ad.smb_access.v1"),
            2 => value["profile"]["allowed_actions"] = json!([PRIVATE_ACTION, "arbitrary.command"]),
            3 => value["profile"]["capabilities"] = json!(["process"]),
            4 => value["profile"]["target_scope"]["filesystem"] = json!(["C:\\other"]),
            5 => value["profile"]["target_scope"]["network"] = json!(["example.invalid"]),
            6 => value["profile"]["sandbox_root"] = json!("C:\\BlueFire\\EndpointAccess"),
            7 => {
                value["manifest"]["params"]["windows_file_read_request"]["resource"]["path"] =
                    json!("C:\\other")
            }
            8 => {
                value["manifest"]["params"]["windows_file_read_request"]["account"] =
                    json!("arbitrary")
            }
            9 => {
                value["manifest"]["params"]["windows_file_read_request"]["domain"] =
                    json!("example.invalid")
            }
            10 => {
                value["manifest"]["params"]["windows_file_read_request"]["command"] =
                    json!("arbitrary")
            }
            11 => {
                value["manifest"]["params"]["windows_file_read_request"]["resource"]["reader_sid"] =
                    json!("S-1-5-21-0101-202-303-1002")
            }
            _ => {
                value["manifest"]["params"]["windows_file_read_request"]["resource"]["reader_sid"] =
                    json!(OWNER)
            }
        }
        profile_seal(&mut value);
        let (result, output, calls) = run(&value, &begin(&value, &[65]), &FakeClock::new());
        assert_eq!(result, Err(Code::RequestInvalid));
        assert_eq!(calls, 0);
        assert!(output.is_empty());
    }
}
#[test]
fn full_width_identities_roundtrip_as_fixed_hex_only() {
    let value = packet();
    let decoded = wire::parse(&serde_json::to_vec(&value).unwrap_or_default())
        .unwrap_or_else(|_| panic!("synthetic packet"));
    assert_eq!(value, decoded);
    let checked = wire::Packet::validate(decoded, &FakeClock::new(), Instant::now())
        .unwrap_or_else(|_| panic!("synthetic packet validation"));
    assert!(checked.resource().is_ok());
    for key in ["volume_serial", "file_id"] {
        let mut invalid = packet();
        invalid["manifest"]["params"]["windows_file_read_request"]["resource"]["file_identity"]
            [key] = json!(123u64);
        manifest_seal(&mut invalid);
        assert_eq!(
            run(&invalid, &begin(&invalid, &[65]), &FakeClock::new()).0,
            Err(Code::RequestInvalid)
        );
    }
    let mut high = value.clone();
    high["manifest"]["params"]["windows_file_read_request"]["resource"]["file_identity"]
        ["file_id"] = json!("80000000000000000000000000000001");
    manifest_seal(&mut high);
    assert_eq!(run(&high, &begin(&high, &[65]), &FakeClock::new()).0, Ok(0));
    let mut wrong_volume = value.clone();
    wrong_volume["manifest"]["params"]["windows_file_read_request"]["resource"]["file_identity"]
        ["volume_serial"] = json!("7edcba9876543210");
    manifest_seal(&mut wrong_volume);
    assert_eq!(
        run(
            &wrong_volume,
            &begin(&wrong_volume, &[65]),
            &FakeClock::new()
        )
        .0,
        Err(Code::RequestInvalid)
    );
}
#[test]
fn duplicate_keys_unknown_fields_float_numbers_and_trailing_public_json_refuse() {
    let value = packet();
    let original = serde_json::to_string(&value).unwrap_or_default();
    let variants = [
        original.replace(
            "\"control_revision\":7",
            "\"control_revision\":7,\"control_revision\":7",
        ),
        original.replace("\"control_revision\":7", "\"control_revision\":7.0"),
        format!("{original} {{}}"),
    ];
    for variant in variants {
        assert!(wire::parse(variant.as_bytes()).is_err());
    }
    let mut unknown = value.clone();
    unknown["unknown"] = json!(true);
    assert_eq!(
        run(&unknown, &begin(&unknown, &[65]), &FakeClock::new()).0,
        Err(Code::RequestInvalid)
    );
    assert!(wire::parse(&vec![b' '; MAX_PUBLIC + 1]).is_err());
}
#[test]
fn begin_exact_magic_challenge_digest_generation_revision_and_credential_binding() {
    let value = packet();
    let valid = begin(&value, &[65]);
    for at in [0, 8, 40, 72, 88, 92] {
        let mut wrong = valid.clone();
        wrong[at] ^= 1;
        let (result, output, calls) = run(&value, &wrong, &FakeClock::new());
        assert_eq!(result, Ok(4));
        assert_eq!(calls, 0);
        assert_eq!(output.len(), 2);
        assert_eq!(output[1]["result"]["code"], "begin_invalid");
        assert_eq!(output[1]["result"]["possible_effects"], false);
    }
    let mut wrong = valid;
    wrong[..8].copy_from_slice(b"BFADBEG1");
    assert_eq!(run(&value, &wrong, &FakeClock::new()).2, 0);
}
#[test]
fn begin_consumed_before_io_even_after_invalid_input() {
    let value = packet();
    let clock = FakeClock::new();
    let checked = wire::Packet::validate(value.clone(), &clock, clock.origin)
        .unwrap_or_else(|_| panic!("synthetic packet"));
    for failed_first in [false, true] {
        let mut reader = framing::BeginReader::default();
        let first = if failed_first {
            vec![0; 8]
        } else {
            begin(&value, &[65])
        };
        assert_eq!(
            reader
                .consume(&mut Cursor::new(frame(&first)), &checked)
                .is_err(),
            failed_first
        );
        assert!(matches!(
            reader.consume(&mut Cursor::new(frame(&begin(&value, &[65]))), &checked),
            Err(Code::BeginConsumed)
        ));
    }
}
#[test]
fn malformed_private_units_and_extra_frames_refuse_before_dispatch_and_erase() {
    let _ = framing::take_erasures();
    let value = packet();
    for units in [vec![], vec![0], vec![0xd800], vec![65; 257]] {
        let (result, output, calls) = run(&value, &begin(&value, &units), &FakeClock::new());
        assert_eq!(result, Ok(4));
        assert_eq!(calls, 0);
        assert_eq!(output[1]["result"]["code"], "begin_invalid");
    }
    let erased = framing::take_erasures();
    assert!(erased.iter().all(|(_, _, zero)| *zero));
    assert!(erased
        .iter()
        .any(|(kind, length, _)| *kind == "bytes" && *length >= 126));
    assert!(erased.iter().any(|(kind, _, _)| *kind == "units"));
    let mut bytes = input(&value, &begin(&value, &[65])).into_inner();
    bytes.extend_from_slice(&frame(&begin(&value, &[65])));
    let mut output = Vec::new();
    let calls = Cell::new(0);
    assert_eq!(
        run_checked(
            &mut Cursor::new(bytes),
            &mut output,
            &FakeClock::new(),
            |packet, _, _| {
                calls.set(calls.get() + 1);
                Ok(success(packet))
            }
        ),
        Ok(4)
    );
    assert_eq!(calls.get(), 0);
    assert_eq!(output_frames(output)[1]["result"]["code"], "begin_invalid");
}
#[test]
fn success_dispatch_drop_erases_password_units_and_raw_begin() {
    let _ = framing::take_erasures();
    let value = packet();
    assert_eq!(
        run(&value, &begin(&value, &[65, 66, 67]), &FakeClock::new()).0,
        Ok(0)
    );
    let erased = framing::take_erasures();
    assert!(erased.iter().all(|(_, _, zero)| *zero));
    assert!(erased.contains(&("units", 3, true)));
    assert!(erased.contains(&("bytes", 132, true)));
}
struct DelayOutput<'a> {
    bytes: Vec<u8>,
    clock: &'a FakeClock,
    change_wall: bool,
}
impl Write for DelayOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self
            .bytes
            .windows(READY_SCHEMA.len())
            .any(|w| w == READY_SCHEMA.as_bytes())
        {
            self.clock.elapsed.set(Duration::from_secs(6));
            if self.change_wall {
                *self.clock.wall.borrow_mut() -= chrono::Duration::hours(1);
            }
        }
        Ok(())
    }
}
struct RollbackOutput<'a> {
    bytes: Vec<u8>,
    clock: &'a FakeClock,
}
impl Write for RollbackOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        *self.clock.wall.borrow_mut() = DateTime::parse_from_rfc3339("2026-10-12T11:59:59Z")
            .unwrap_or_else(|_| panic!("synthetic rollback"));
        Ok(())
    }
}
#[test]
fn rollback_before_begin_refuses_dispatch_inside_monotonic_limit() {
    let value = packet();
    let clock = FakeClock::new();
    let calls = Cell::new(0);
    let mut output = RollbackOutput {
        bytes: Vec::new(),
        clock: &clock,
    };
    assert_eq!(
        run_checked(
            &mut input(&value, &begin(&value, &[65])),
            &mut output,
            &clock,
            |packet, _, _| {
                calls.set(1);
                Ok(success(packet))
            }
        ),
        Ok(4)
    );
    assert_eq!(calls.get(), 0);
    assert_eq!(clock.elapsed.get(), Duration::ZERO);
    let frames = output_frames(output.bytes);
    assert_eq!(frames[1]["result"]["code"], "deadline");
    assert_eq!(frames[1]["result"]["possible_effects"], false);
    assert!(frames[1]["observed_at"].is_null());
}
#[test]
fn ready_wait_and_wall_rollback_never_renew_original_monotonic_deadline() {
    let value = packet();
    let clock = FakeClock::new();
    let calls = Cell::new(0);
    let mut output = DelayOutput {
        bytes: Vec::new(),
        clock: &clock,
        change_wall: true,
    };
    assert_eq!(
        run_checked(
            &mut input(&value, &begin(&value, &[65])),
            &mut output,
            &clock,
            |packet, _, _| {
                calls.set(1);
                Ok(success(packet))
            }
        ),
        Ok(4)
    );
    assert_eq!(calls.get(), 0);
    let frames = output_frames(output.bytes);
    assert_eq!(frames[1]["result"]["code"], "deadline");
    assert_eq!(frames[1]["result"]["possible_effects"], false);
    assert!(frames[1]["observed_at"].is_null());
}
#[test]
fn original_lifetime_approval_limits_and_cancellation_are_closed() {
    for fault in 0..6 {
        let mut value = packet();
        match fault {
            0 => value["manifest"]["expires_at"] = json!("2026-10-12T12:00:00Z"),
            1 => value["manifest"]["expires_at"] = json!("2026-10-12T12:00:06Z"),
            2 => value["manifest"]["approval"]["expires_at"] = json!("2026-10-12T12:00:06Z"),
            3 => value["manifest"]["approval"]["approved_at"] = json!("2026-10-12T12:00:01Z"),
            4 => value["remaining_ms"] = json!(5001),
            _ => value["profile"]["limits"]["max_stdout_bytes"] = json!(8193),
        }
        manifest_seal(&mut value);
        assert_eq!(
            run(&value, &begin(&value, &[65]), &FakeClock::new()).0,
            Err(Code::RequestInvalid)
        );
    }
    let value = packet();
    let clock = FakeClock::new();
    *clock.wall.borrow_mut() += chrono::Duration::seconds(5);
    assert_eq!(
        run(&value, &begin(&value, &[65]), &clock).0,
        Err(Code::RequestInvalid)
    );
    clock.cancelled.set(true);
    assert_eq!(
        run(&value, &begin(&value, &[65]), &clock).0,
        Err(Code::Cancelled)
    );
}
#[test]
fn native_failure_late_result_and_bounded_terminal_preserve_possible_effects() {
    for fault in 0..3 {
        let value = packet();
        let clock = FakeClock::new();
        let mut output = Vec::new();
        let result = run_checked(
            &mut input(&value, &begin(&value, &[65])),
            &mut output,
            &clock,
            |packet, _, _| match fault {
                0 => Err(Code::NativeFailed),
                1 => {
                    clock.elapsed.set(Duration::from_secs(6));
                    Ok(success(packet))
                }
                _ => {
                    let mut result = success(packet);
                    result.value["too_large"] = json!("x".repeat(MAX_TERMINAL));
                    Ok(result)
                }
            },
        );
        assert_eq!(result, Ok(4));
        let frames = output_frames(output);
        assert_eq!(frames[1]["result"]["schema_version"], ERROR_SCHEMA);
        assert_eq!(frames[1]["result"]["possible_effects"], true);
        assert_eq!(
            frames[1]["result"]["code"],
            match fault {
                0 => "native_failed",
                1 => "deadline",
                _ => "result_bound_exceeded",
            }
        );
        assert!(serde_json::to_vec(&frames[1]).unwrap_or_default().len() <= MAX_TERMINAL);
    }
}
#[test]
fn typed_allowed_denied_unknown_results_have_distinct_proofs_and_exit_semantics() {
    for outcome in [
        ReadOutcome::Allowed,
        ReadOutcome::DataAccessDenied,
        ReadOutcome::Unknown,
    ] {
        let value = packet();
        let mut output = Vec::new();
        let code = run_checked(
            &mut input(&value, &begin(&value, &[65])),
            &mut output,
            &FakeClock::new(),
            |packet, _, _| Ok(observed(packet, outcome)),
        );
        assert_eq!(
            code,
            Ok(if outcome == ReadOutcome::Unknown {
                4
            } else {
                0
            })
        );
        let frames = output_frames(output);
        assert_eq!(
            frames[1]["result"]["schema_version"],
            "bluefire.windows-fixed-read.v1"
        );
        assert_eq!(
            frames[1]["result"]["outcome"],
            serde_json::to_value(outcome).unwrap_or_default()
        );
        assert!(frames[1]["observed_at"].is_string());
    }
    let value = packet();
    let mut output = Vec::new();
    assert_eq!(
        run_checked(
            &mut input(&value, &begin(&value, &[65])),
            &mut output,
            &FakeClock::new(),
            |packet, _, _| {
                let mut result = success(packet);
                result.value["outcome"] = json!("unknown");
                Ok(result)
            }
        ),
        Ok(4)
    );
    assert_eq!(output_frames(output)[1]["result"]["code"], "native_failed");
}
#[test]
fn completion_timestamp_never_fabricates_an_original_window_after_rollback() {
    let value = packet();
    let clock = FakeClock::new();
    let mut output = Vec::new();
    assert_eq!(
        run_checked(
            &mut input(&value, &begin(&value, &[65])),
            &mut output,
            &clock,
            |packet, _, _| {
                *clock.wall.borrow_mut() -= chrono::Duration::hours(1);
                Ok(success(packet))
            }
        ),
        Ok(4)
    );
    let frames = output_frames(output);
    assert_eq!(frames[1]["result"]["code"], "deadline");
    assert!(frames[1]["observed_at"].is_null());
}
#[test]
fn public_and_private_frame_bounds_and_partial_reads_refuse() {
    for size in [0, MAX_PUBLIC + 1] {
        let mut output = Vec::new();
        assert_eq!(
            run_checked(
                &mut Cursor::new((size as u32).to_le_bytes()),
                &mut output,
                &FakeClock::new(),
                |_, _, _| panic!("must not dispatch")
            ),
            Err(Code::RequestInvalid)
        );
        assert!(output.is_empty());
    }
    let value = packet();
    let clock = FakeClock::new();
    let checked = wire::Packet::validate(value, &clock, clock.origin)
        .unwrap_or_else(|_| panic!("synthetic packet"));
    for bytes in [
        vec![0, 0, 0, 0],
        (MAX_BEGIN as u32 + 1).to_le_bytes().to_vec(),
        vec![5, 0, 0, 0, 1, 2],
    ] {
        let mut reader = framing::BeginReader::default();
        assert!(reader.consume(&mut Cursor::new(bytes), &checked).is_err());
    }
}
#[test]
fn aggregate_stdout_bound_includes_ready_terminal_and_both_prefixes() {
    for limit in [1024u64, 1536, 2048, 8192] {
        for big in [false, true] {
            let mut value = packet();
            value["profile"]["limits"]["max_stdout_bytes"] = json!(limit);
            value["manifest"]["limits"]["max_stdout_bytes"] = json!(limit);
            profile_seal(&mut value);
            let mut output = Vec::new();
            let result = run_checked(
                &mut input(&value, &begin(&value, &[65])),
                &mut output,
                &FakeClock::new(),
                |packet, _, _| {
                    let mut proof = success(packet);
                    if big {
                        proof.value["big"] = json!("x".repeat(MAX_TERMINAL));
                    }
                    Ok(proof)
                },
            );
            assert!(output.len() <= limit as usize);
            let frames = output_frames(output);
            assert!(!frames.is_empty());
            if frames.len() == 1 {
                assert_eq!(result, Err(Code::ResultBoundExceeded));
            } else {
                assert_eq!(frames.len(), 2);
                assert_eq!(result, Ok(if big { 4 } else { 0 }));
                if big {
                    assert_eq!(frames[1]["result"]["code"], "result_bound_exceeded");
                }
            }
        }
    }
}
#[test]
fn insufficient_stdout_remainder_never_emits_an_extra_frame_prefix() {
    let mut value = packet();
    value["profile"]["limits"]["max_stdout_bytes"] = json!(1024);
    value["manifest"]["limits"]["max_stdout_bytes"] = json!(1024);
    profile_seal(&mut value);
    let mut output = Vec::new();
    let result = run_checked(
        &mut input(&value, &begin(&value, &[65])),
        &mut output,
        &FakeClock::new(),
        |packet, _, _| {
            let mut proof = success(packet);
            proof.value["big"] = json!("x".repeat(MAX_TERMINAL));
            Ok(proof)
        },
    );
    assert_eq!(result, Err(Code::ResultBoundExceeded));
    assert!(output.len() <= 1024);
    let first_length = u32::from_le_bytes(
        output[..4]
            .try_into()
            .unwrap_or_else(|_| panic!("synthetic prefix")),
    ) as usize;
    assert_eq!(output.len(), first_length + 4);
    assert_eq!(output_frames(output).len(), 1);
}

#[test]
fn synthetic_packet_matches_independent_canonical_and_begin_goldens() {
    let value = packet();
    assert_eq!(
        request(&value)["request_id"],
        "e2f7d90bd8dea87e68adf95b7af07cdb"
    );
    assert_eq!(
        value["profile"]["policy_digest"],
        "sha256:40e4c924a48d362a28a53c0d806a3028126d07653c025bfa5e0de971be76248d"
    );
    assert_eq!(
        value["manifest"]["request_hash"],
        "sha256:9953af0ea0f009aa6e4ff36ce320cc4956e59551b77abf9aaa3bcc4b44add22e"
    );
    assert_eq!(
        value["request_hash"],
        "sha256:a3a22e5e8a62d08477284b88cf4939208fee9c95afba076d66f18f4a56fd678c"
    );
    assert_eq!(
        wire::hash(&value),
        "sha256:80475057ae804011ecd7445eeb6cb03a3def98fea876b16bb06d7465240e7565"
    );
    assert_eq!(crate::canonical::canonical_json(&value).len(), 3598);
    assert_eq!(
        hex::encode(&begin(&value, &[65])[..124]),
        concat!(
            "4246574642454731ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "80475057ae804011ecd7445eeb6cb03a3def98fea876b16bb06d7465240e7565",
            "0123456789abcdef0123456789abcdef07000000",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
    );
    let expected_ready = concat!(
        r#"{"challenge":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","control_revision":7,"credential_binding_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
        r#""generation":"0123456789abcdef0123456789abcdef","packet_digest":"sha256:80475057ae804011ecd7445eeb6cb03a3def98fea876b16bb06d7465240e7565","readiness_scope":"protocol_only","#,
        r#""request_hash":"sha256:a3a22e5e8a62d08477284b88cf4939208fee9c95afba076d66f18f4a56fd678c","schema_version":"bluefire.windows-file-worker-ready.v1","#,
        r#""task_id":"execute-a3a22e5e8a62d08477284b88cf4939208fee9c95afba076d66f18f4a56fd678c"}"#
    );
    let expected_terminal = concat!(
        r#"{"challenge":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","control_revision":7,"credential_binding_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
        r#""generation":"0123456789abcdef0123456789abcdef","observed_at":"2026-10-12T12:00:01.000000Z","operation":"read_generated","packet_digest":"sha256:80475057ae804011ecd7445eeb6cb03a3def98fea876b16bb06d7465240e7565","#,
        r#""request_hash":"sha256:a3a22e5e8a62d08477284b88cf4939208fee9c95afba076d66f18f4a56fd678c","result":{"bytes_read":13,"cleanup":{"controller_restored":true,"handles_released":true,"impersonation_reverted":true,"owned_process_exit_required":false},"#,
        r#""data_open_attempted":true,"effective_reader_verified":true,"failed_stage":null,"independent_observation":false,"issue":null,"observed_sha256":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","#,
        r#""outcome":"allowed","request_id":"e2f7d90bd8dea87e68adf95b7af07cdb","resource_rechecked":true,"schema_version":"bluefire.windows-fixed-read.v1"},"schema_version":"bluefire.windows-file-worker-result.v1","#,
        r#""task_id":"execute-a3a22e5e8a62d08477284b88cf4939208fee9c95afba076d66f18f4a56fd678c"}"#
    );
    let mut output = Vec::new();
    assert_eq!(
        run_checked(
            &mut input(&value, &begin(&value, &[65])),
            &mut output,
            &FakeClock::new(),
            |packet, _, _| {
                // Synthetic fixture of the actual production Serialize type,
                // not an observed native read or a replacement proof structure.
                let proof = crate::windows_file_access_read::ReadProof {
                    schema_version: "bluefire.windows-fixed-read.v1",
                    request_id: packet.request()["request_id"]
                        .as_str()
                        .unwrap_or_default()
                        .into(),
                    outcome: ReadOutcome::Allowed,
                    issue: None,
                    failed_stage: None,
                    data_open_attempted: true,
                    bytes_read: 13,
                    observed_sha256: Some(
                        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                            .into(),
                    ),
                    effective_reader_verified: true,
                    resource_rechecked: true,
                    independent_observation: false,
                    cleanup: crate::windows_file_access_read::CleanupFacts {
                        handles_released: true,
                        impersonation_reverted: true,
                        controller_restored: true,
                        owned_process_exit_required: false,
                    },
                };
                let outcome = proof.outcome;
                let value = serde_json::to_value(proof).map_err(|_| Code::NativeFailed)?;
                Ok(DispatchResult { value, outcome })
            },
        ),
        Ok(0)
    );
    let mut expected_output = frame(expected_ready.as_bytes());
    expected_output.extend_from_slice(&frame(expected_terminal.as_bytes()));
    assert_eq!(output, expected_output);
}
