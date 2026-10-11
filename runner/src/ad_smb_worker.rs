//! Fixed private AD ingress, separate from the ordinary action registry.
//!
//! Hashes below establish consistency, never host trust or one-use authority.
//! The authenticated parent must reserve the exact original task and own this
//! process in a Windows Job before releasing Begin. Synchronous native calls
//! still require the parent's original-deadline termination and cleanup proof.

#[path = "ad_smb_worker/ad_smb_worker_acl.rs"]
mod acl;
#[path = "ad_smb_worker/ad_smb_worker_dispatch.rs"]
mod dispatch;
#[path = "ad_smb_worker/ad_smb_worker_framing.rs"]
mod framing;
#[path = "ad_smb_worker/ad_smb_worker_host.rs"]
mod host;
#[path = "ad_smb_worker/ad_smb_worker_json.rs"]
mod json;
#[path = "ad_smb_worker/ad_smb_worker_scope.rs"]
mod scope;
#[cfg(test)]
#[path = "ad_smb_worker/ad_smb_worker_tests.rs"]
mod tests;
#[path = "ad_smb_worker/ad_smb_worker_wire.rs"]
mod wire;

use serde::Serialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::time::Instant;

const MAX_PUBLIC: usize = 1_048_576;
const MAX_READY: usize = 4096;
const MAX_BEGIN: usize = 2048;
const MAX_RESULT: usize = 4 * 1024 * 1024 + 65_536;
type Result<T> = std::result::Result<T, Code>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Code {
    RequestInvalid,
    BeginInvalid,
    Deadline,
    NativeUnavailable,
    PreconditionFailed,
    NativeFailed,
    ResultBoundExceeded,
}

/// This fixed branch has no command arguments and never emits raw native errors.
pub fn run_fixed() -> std::result::Result<i32, String> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    run_checked(&mut input, &mut output, host::verify, dispatch::execute)
        .map_err(|_| "AD worker input or output refused".into())
}

fn run_checked(
    input: &mut impl Read,
    output: &mut impl Write,
    mut check_host: impl FnMut(&wire::Packet) -> Result<()>,
    mut execute: impl FnMut(&wire::Packet, framing::Begin) -> Result<Value>,
) -> Result<i32> {
    let ingress = Instant::now();
    let public = framing::read(input, MAX_PUBLIC).map_err(|_| Code::RequestInvalid)?;
    let value = json::parse(&public)?;
    let now = chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now()).fixed_offset();
    let packet = wire::Packet::validate(value, now, ingress)?;
    check_host(&packet)?;
    packet.current()?;
    framing::write(
        output,
        &json!({"schema_version":"bluefire.ad-smb-worker-ready.v1","challenge":packet.value["challenge"],"packet_digest":packet.digest,"task_id":packet.value["task_id"],"request_hash":packet.value["request_hash"],"pid":std::process::id()}),
        MAX_READY,
    )?;
    let mut possible_effects = false;
    let result = (|| {
        let begin = framing::begin(input, &packet)?;
        check_host(&packet)?;
        packet.current()?;
        possible_effects = true;
        execute(&packet, begin)
    })();
    let failed = result.is_err();
    let payload = match result {
        Ok(value) => value,
        Err(code) => error(code, possible_effects),
    };
    let mut terminal = json!({"schema_version":"bluefire.ad-smb-worker-result.v1","challenge":packet.value["challenge"],"packet_digest":packet.digest,"task_id":packet.value["task_id"],"request_hash":packet.value["request_hash"],"operation":packet.request()["step"],"result":payload});
    let encoded = serde_json::to_vec(&terminal).map_err(|_| Code::NativeFailed)?;
    if encoded.len() > packet.output_limit {
        terminal["result"] = error(Code::ResultBoundExceeded, possible_effects);
        framing::write(output, &terminal, packet.output_limit)?;
        return Ok(4);
    }
    framing::write(output, &terminal, packet.output_limit)?;
    Ok(if failed { 4 } else { 0 })
}

fn error(code: Code, possible_effects: bool) -> Value {
    json!({"schema_version":"bluefire.ad-smb-worker-error.v1","code":code,"possible_effects":possible_effects})
}
