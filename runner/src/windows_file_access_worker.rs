//! Fixed Windows generated-file reader protocol and private no-argument CLI.
//! No ordinary action, listener, launcher or enrollment authority is installed.
//!
//! Production callers MUST authenticate and durably reserve the original task,
//! pin the native image, retain the child's PID+creation-time generation, assign
//! the suspended child to their owned kill-on-close Windows Job before resume,
//! and revalidate original admission/generation/Job ownership before releasing
//! Begin. A Ready frame establishes protocol readiness only, not those premises.
//! Packet/manifest/profile/host hashes establish byte consistency only; none
//! authenticates their source, enrolls a host or supplies execution authority.
//! The same supervisor must enforce the original hard deadline and verify Job
//! drainage after failure, including the native reader's reversion-failure abort.
//!
//! The private manifest/profile identities below are a closed worker grammar,
//! not capabilities registered with the ordinary runner. Existing AD and Python
//! primary-only contracts are not accepted or changed.

#[path = "windows_file_access_worker/windows_file_access_worker_framing.rs"]
mod framing;
#[cfg(test)]
#[path = "windows_file_access_worker/windows_file_access_worker_pair_tests.rs"]
mod pair_tests;
#[cfg(test)]
#[path = "windows_file_access_worker/windows_file_access_worker_tests.rs"]
mod tests;
#[path = "windows_file_access_worker/windows_file_access_worker_wire.rs"]
mod wire;

use crate::windows_file_access_read::ReadOutcome;
use chrono::{DateTime, FixedOffset, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::time::Instant;

const MAX_PUBLIC: usize = 65_536;
const MAX_BEGIN: usize = 2048;
const MAX_TERMINAL: usize = 8192;
const MAX_READY: usize = 1024;
const PRIVATE_ACTION: &str = "private.windows.file_read.v1";
const PRIVATE_CAPABILITY: &str = "windows_file_read";
const REQUEST_SCHEMA: &str = "bluefire.windows-file-worker-request.v1";
const READY_SCHEMA: &str = "bluefire.windows-file-worker-ready.v1";
const RESULT_SCHEMA: &str = "bluefire.windows-file-worker-result.v1";
const ERROR_SCHEMA: &str = "bluefire.windows-file-worker-error.v1";
const READ_SCHEMA: &str = "bluefire.windows-fixed-read.v1";
type Result<T> = std::result::Result<T, Code>;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Protocol {
    ReaderV1,
    PairV2,
    CorrectionPairV3,
}
impl Protocol {
    fn request(self) -> &'static str {
        match self {
            Self::ReaderV1 => REQUEST_SCHEMA,
            Self::PairV2 => "bluefire.windows-file-worker-request.v2",
            Self::CorrectionPairV3 => "bluefire.windows-file-worker-request.v3",
        }
    }
    fn ready(self) -> &'static str {
        match self {
            Self::ReaderV1 => READY_SCHEMA,
            Self::PairV2 => "bluefire.windows-file-worker-ready.v2",
            Self::CorrectionPairV3 => "bluefire.windows-file-worker-ready.v3",
        }
    }
    fn result(self) -> &'static str {
        match self {
            Self::ReaderV1 => RESULT_SCHEMA,
            Self::PairV2 => "bluefire.windows-file-worker-result.v2",
            Self::CorrectionPairV3 => "bluefire.windows-file-worker-result.v3",
        }
    }
    fn error(self) -> &'static str {
        match self {
            Self::ReaderV1 => ERROR_SCHEMA,
            Self::PairV2 => "bluefire.windows-file-worker-error.v2",
            Self::CorrectionPairV3 => "bluefire.windows-file-worker-error.v3",
        }
    }
    fn read(self) -> &'static str {
        match self {
            Self::ReaderV1 => READ_SCHEMA,
            Self::PairV2 => "bluefire.windows-fixed-read-pair.v2",
            Self::CorrectionPairV3 => "bluefire.windows-fixed-read-pair-correction.v3",
        }
    }
    fn action(self) -> &'static str {
        match self {
            Self::ReaderV1 => PRIVATE_ACTION,
            Self::PairV2 => "private.windows.file_read_pair.v2",
            Self::CorrectionPairV3 => "private.windows.file_read_pair_correction.v3",
        }
    }
    fn capability(self) -> &'static str {
        match self {
            Self::ReaderV1 => PRIVATE_CAPABILITY,
            Self::PairV2 => "windows_file_read_pair",
            Self::CorrectionPairV3 => "windows_file_read_pair_correction",
        }
    }
    fn operation(self) -> &'static str {
        match self {
            Self::ReaderV1 => "read_generated",
            Self::PairV2 => "read_generated_pair",
            Self::CorrectionPairV3 => "read_generated_pair_correction",
        }
    }
    fn operation_schema(self) -> &'static str {
        match self {
            Self::ReaderV1 => "bluefire.windows-file-worker-operation.v1",
            Self::PairV2 => "bluefire.windows-file-worker-operation.v2",
            Self::CorrectionPairV3 => "bluefire.windows-file-worker-operation.v3",
        }
    }
    fn behavior(self) -> &'static str {
        match self {
            Self::ReaderV1 => "identity.windows.file_read.v1",
            Self::PairV2 => "identity.windows.file_read_pair.v2",
            Self::CorrectionPairV3 => "identity.windows.file_read_pair_correction.v3",
        }
    }
    fn begin_magic(self) -> &'static [u8; 8] {
        match self {
            Self::ReaderV1 => b"BFWFBEG1",
            Self::PairV2 => b"BFWFBEG2",
            Self::CorrectionPairV3 => b"BFWFBEG3",
        }
    }
}

/// Describes compiled protocol support only. The querying supervisor must pin
/// this actual image; this record cannot establish enrollment or live readiness.
pub fn protocol_capability() -> Value {
    json!({
        "schema_version": "bluefire.windows-file-worker-capability.v1",
        "runner_id": "bluefire-rust-runner.v1",
        "runner_version": env!("CARGO_PKG_VERSION"),
        "platform": crate::Platform::current(),
        "architecture": std::env::consts::ARCH,
        "supported": cfg!(all(target_os = "windows", target_arch = "x86_64")),
        "worker_command": "windows-file-worker",
        "worker_schema": REQUEST_SCHEMA,
        "read_schema": READ_SCHEMA,
        "scope": "protocol_support_only",
    })
}

pub fn pair_protocol_capability() -> Value {
    json!({
        "schema_version": "bluefire.windows-file-worker-capability.v2",
        "runner_id": "bluefire-rust-runner.v1",
        "runner_version": env!("CARGO_PKG_VERSION"),
        "platform": crate::Platform::current(),
        "architecture": std::env::consts::ARCH,
        "supported": cfg!(all(target_os = "windows", target_arch = "x86_64")),
        "worker_command": "windows-file-baseline-worker",
        "worker_schema": Protocol::PairV2.request(),
        "read_schema": Protocol::PairV2.read(),
        "scope": "protocol_support_only",
        "action_id": Protocol::PairV2.action(),
        "capability": Protocol::PairV2.capability(),
        "max_data_opens": 2,
        "max_bytes_per_read": 1_048_576,
        "max_total_read_bytes": 2_097_152,
        "max_execution_ms": 5000,
    })
}

/// V3 binds an opaque upstream correction claim, not correction authority or
/// causation. It observes the fixed metadata-only postimage with the same bounds.
pub fn correction_protocol_capability() -> Value {
    json!({
        "schema_version": "bluefire.windows-file-worker-capability.v3",
        "runner_id": "bluefire-rust-runner.v1",
        "runner_version": env!("CARGO_PKG_VERSION"),
        "platform": crate::Platform::current(),
        "architecture": std::env::consts::ARCH,
        "supported": cfg!(all(target_os = "windows", target_arch = "x86_64")),
        "worker_command": "windows-file-correction-worker",
        "worker_schema": Protocol::CorrectionPairV3.request(),
        "read_schema": Protocol::CorrectionPairV3.read(),
        "scope": "protocol_support_only",
        "action_id": Protocol::CorrectionPairV3.action(),
        "capability": Protocol::CorrectionPairV3.capability(),
        "max_data_opens": 2,
        "max_bytes_per_read": 1_048_576,
        "max_total_read_bytes": 2_097_152,
        "max_execution_ms": 5000,
    })
}

/// Credentials arrive only through the existing bounded two-stage stdin
/// protocol. The parent owns cancellation, blocked I/O and whole-Job drainage.
pub fn run_fixed() -> std::result::Result<i32, String> {
    run_fixed_for(Protocol::ReaderV1)
}

pub fn run_fixed_pair() -> std::result::Result<i32, String> {
    run_fixed_for(Protocol::PairV2)
}

pub fn run_fixed_correction() -> std::result::Result<i32, String> {
    run_fixed_for(Protocol::CorrectionPairV3)
}

fn run_fixed_for(protocol: Protocol) -> std::result::Result<i32, String> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        let mut input = std::io::stdin().lock();
        let mut output = std::io::stdout().lock();
        run_private_for(protocol, &mut input, &mut output, &|| false).map_err(str::to_owned)
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = protocol;
        Err("the fixed Windows file worker requires Windows x86_64".into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Code {
    RequestInvalid,
    BeginInvalid,
    BeginConsumed,
    Deadline,
    Cancelled,
    NativeFailed,
    OutputFailed,
    ResultBoundExceeded,
}
trait Clock {
    fn monotonic(&self) -> Instant;
    fn wall(&self) -> DateTime<FixedOffset>;
    fn cancelled(&self) -> bool;
}
struct SystemClock<'a> {
    cancelled: &'a dyn Fn() -> bool,
}
impl Clock for SystemClock<'_> {
    fn monotonic(&self) -> Instant {
        Instant::now()
    }
    fn wall(&self) -> DateTime<FixedOffset> {
        DateTime::<Utc>::from(std::time::SystemTime::now()).fixed_offset()
    }
    fn cancelled(&self) -> bool {
        (self.cancelled)()
    }
}
struct DispatchResult {
    value: Value,
    outcome: ReadOutcome,
}

/// Private streams must belong to the authenticated supervisor's disposable
/// worker. Never call this in the controller: failed native reversion aborts.
/// Only the fixed private CLI uses this entry; ordinary action inventory does not.
pub fn run_private(
    input: &mut impl Read,
    output: &mut impl Write,
    cancelled: &dyn Fn() -> bool,
) -> std::result::Result<i32, &'static str> {
    run_private_for(Protocol::ReaderV1, input, output, cancelled)
}

fn run_private_for(
    protocol: Protocol,
    input: &mut impl Read,
    output: &mut impl Write,
    cancelled: &dyn Fn() -> bool,
) -> std::result::Result<i32, &'static str> {
    let clock = SystemClock { cancelled };
    run_checked_for(
        protocol,
        input,
        output,
        &clock,
        |packet, credential, clock| {
            let resource = packet.resource()?;
            let prepared = crate::windows_file_access_read::PreparedRead::new(
                wire::text(&packet.request()["request_id"])?,
                resource,
                packet.monotonic_deadline,
            )
            .map_err(|_| Code::Deadline)?;
            let secret = crate::windows_file_access_read::SecretCredential::from_private_delivery(
                wire::text(&packet.request()["generation"])?,
                &credential.0,
            )
            .map_err(|_| Code::BeginInvalid)?;
            drop(credential);
            packet.current(clock)?;
            let (value, outcome) = match protocol {
                Protocol::PairV2 => {
                    let proof = prepared.read_pair(secret, &|| packet.current(clock).is_err());
                    let outcome = proof.outcome;
                    (serde_json::to_value(proof), outcome)
                }
                Protocol::CorrectionPairV3 => {
                    let proof =
                        prepared.read_pair_correction(secret, &|| packet.current(clock).is_err());
                    let outcome = proof.outcome;
                    (serde_json::to_value(proof), outcome)
                }
                Protocol::ReaderV1 => {
                    let proof = prepared.read(secret, &|| packet.current(clock).is_err());
                    let outcome = proof.outcome;
                    (serde_json::to_value(proof), outcome)
                }
            };
            let value = value.map_err(|_| Code::NativeFailed)?;
            Ok(DispatchResult { value, outcome })
        },
    )
    .map_err(|_| "Windows fixed worker exchange refused")
}

#[cfg(test)]
fn run_checked(
    input: &mut impl Read,
    output: &mut impl Write,
    clock: &impl Clock,
    dispatch: impl FnMut(&wire::Packet, framing::SecretUnits, &dyn Clock) -> Result<DispatchResult>,
) -> Result<i32> {
    run_checked_for(Protocol::ReaderV1, input, output, clock, dispatch)
}

fn run_checked_for(
    protocol: Protocol,
    input: &mut impl Read,
    output: &mut impl Write,
    clock: &impl Clock,
    mut dispatch: impl FnMut(&wire::Packet, framing::SecretUnits, &dyn Clock) -> Result<DispatchResult>,
) -> Result<i32> {
    let ingress = clock.monotonic();
    if clock.cancelled() {
        return Err(Code::Cancelled);
    }
    let public = framing::read(input, MAX_PUBLIC, Code::RequestInvalid)?;
    let packet = wire::Packet::validate_for(protocol, wire::parse(&public)?, clock, ingress)?;
    packet.current(clock)?;
    let binding = packet.binding();
    let mut ready = binding.clone();
    ready["schema_version"] = json!(protocol.ready());
    ready["readiness_scope"] = json!("protocol_only");
    let mut remaining_stdout = packet.output_limit;
    framing::write(output, &ready, MAX_READY, &mut remaining_stdout)?;
    // This deadline was fixed at ingress. Output/Begin waits never start a new
    // interval, and a wall-clock rollback cannot extend the monotonic bound.
    let mut begin = framing::BeginReader::default();
    let mut possible_effects = false;
    let attempted = (|| {
        packet.current(clock)?;
        let credential = begin.consume(input, &packet)?;
        packet.current(clock)?;
        possible_effects = true;
        let mut result = dispatch(&packet, credential, clock)?;
        if protocol == Protocol::ReaderV1 {
            packet.current(clock)?;
        }
        let expected_outcome =
            serde_json::to_value(result.outcome).map_err(|_| Code::NativeFailed)?;
        if result.value["schema_version"] != protocol.read()
            || result.value["request_id"] != packet.request()["request_id"]
            || result.value["outcome"] != expected_outcome
        {
            return Err(Code::NativeFailed);
        }
        let observed_at = if protocol != Protocol::ReaderV1 {
            match packet.completion(clock) {
                Ok(timestamp) => Some(timestamp),
                Err(code) => {
                    // Retain truthful earlier phases, but never timestamp a late
                    // partial pair as completed inside its original interval.
                    if result.outcome != ReadOutcome::Unknown {
                        result.outcome = ReadOutcome::Unknown;
                        result.value["outcome"] = json!("unknown");
                        result.value["issue"] = json!(if code == Code::Cancelled {
                            "cancelled"
                        } else {
                            "deadline"
                        });
                        result.value["failed_stage"] = json!("complete");
                    }
                    None
                }
            }
        } else {
            Some(packet.completion(clock)?)
        };
        Ok((result, observed_at))
    })();
    // Exit0 means a completed allowed OR denied observation. It never means
    // access was allowed. An unknown native proof is retained but exits4.
    let failed = attempted
        .as_ref()
        .map_or(true, |(result, _)| result.outcome == ReadOutcome::Unknown);
    let (result, observed_at) = match attempted {
        Ok((result, timestamp)) => (result.value, timestamp),
        Err(code) => (
            error_for(protocol, code, possible_effects),
            packet.completion(clock).ok(),
        ),
    };
    let mut terminal = binding;
    terminal["schema_version"] = json!(protocol.result());
    terminal["operation"] = json!(protocol.operation());
    terminal["observed_at"] = json!(observed_at);
    terminal["result"] = result;
    let limit = remaining_stdout.saturating_sub(4).min(MAX_TERMINAL);
    if serde_json::to_vec(&terminal)
        .map_err(|_| Code::NativeFailed)?
        .len()
        > limit
    {
        terminal["result"] = error_for(protocol, Code::ResultBoundExceeded, possible_effects);
        framing::write(output, &terminal, MAX_TERMINAL, &mut remaining_stdout)?;
        return Ok(4);
    }
    framing::write(output, &terminal, MAX_TERMINAL, &mut remaining_stdout)?;
    Ok(if failed { 4 } else { 0 })
}
fn error_for(protocol: Protocol, code: Code, possible_effects: bool) -> Value {
    json!({"schema_version":protocol.error(),"code":code,"possible_effects":possible_effects})
}
