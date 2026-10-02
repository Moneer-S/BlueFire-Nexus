//! Linux inherited-channel provenance and live read-only launch checks.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;

use super::wire::require;
use super::{wire, VerifiedServiceAdmission, REFUSAL};
use crate::canonical::{canonical_hash, canonical_json, sha256_hex};
use crate::native_tool_inspection::CurrentExecutable;

const MAX_CHANNEL: u64 = 64 * 1024;
const PROTOCOL: &str = "bluefire.owned-user-service-launch.v1";
// Reviewed packaged source, independent of the launch document. A source test
// checks this pin; keeping only its digest leaves Cargo/sdist builds standalone.
const WATCHDOG_SOURCE_SHA256: &str =
    "b196eb772b1f69226b9b828d918938e63ee40822dc3393a313a5f3590200e9f9"; // pragma: allowlist secret -- public watchdog source checksum, regression-tested

extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn getuid() -> u32;
    fn geteuid() -> u32;
    fn getppid() -> i32;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Parent {
    pid: u32,
    start_ticks: u64,
    executable_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema_version: String,
    stage: String,
    issuer: Value,
    enrollment_digest: String,
    key: String,
    envelope_digest: String,
    parent: Parent,
    runner_digest: String,
    watchdog_digest: String,
    interpreter_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    admission: Value,
    authentication: String,
}

fn bounded(path: impl AsRef<Path>, max: u64) -> Result<Vec<u8>, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x800)
        .open(path)
        .map_err(|_| REFUSAL)?;
    require(file.metadata().map_err(|_| REFUSAL)?.is_file())?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSAL)?;
    require(bytes.len() as u64 <= max)?;
    Ok(bytes)
}

fn sealed(value: Option<OsString>, parent: u32) -> Result<File, String> {
    let raw = value.and_then(|v| v.into_string().ok()).ok_or(REFUSAL)?;
    let fd: i32 = raw.parse().map_err(|_| REFUSAL)?;
    require(fd > 2 && fd.to_string() == raw)?;
    let seals = unsafe { fcntl(fd, 1034) };
    require(seals >= 0 && seals & 0xF == 0xF)?;
    // The validated inherited descriptor is now owned and closed by this call.
    let file = unsafe { File::from_raw_fd(fd) };
    let details = file.metadata().map_err(|_| REFUSAL)?;
    require(
        details.is_file()
            && details.uid() == unsafe { getuid() }
            && details.nlink() == 0
            && details.mode() & 0o7777 == 0o600
            && (1..=MAX_CHANNEL).contains(&details.len()),
    )?;
    let original = std::fs::metadata(format!("/proc/{parent}/fd/{fd}")).map_err(|_| REFUSAL)?;
    require(original.dev() == details.dev() && original.ino() == details.ino())?;
    Ok(file)
}

fn contents(file: &File) -> Result<Vec<u8>, String> {
    let length = file.metadata().map_err(|_| REFUSAL)?.len() as usize;
    let mut bytes = vec![0; length];
    file.read_exact_at(&mut bytes, 0).map_err(|_| REFUSAL)?;
    // Canonical bytes reject duplicate fields before parsing nested Value data.
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| REFUSAL)?;
    require(canonical_json(&value).as_bytes() == bytes)?;
    Ok(bytes)
}

fn packaged_watchdog_digest(bytes: &[u8]) -> String {
    let canonical: Vec<u8> = bytes
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| {
            if *byte == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
                None
            } else {
                Some(*byte)
            }
        })
        .collect();
    sha256_hex(&canonical)
}

fn check_parent(
    context: &Context,
    parent: u32,
) -> Result<crate::native_tool_inspection::InspectedNativeTool, String> {
    require(context.parent.pid == parent && parent > 1)?;
    let stat = bounded(format!("/proc/{parent}/stat"), 4096)?;
    let end = stat.iter().rposition(|b| *b == b')').ok_or(REFUSAL)?;
    let fields = std::str::from_utf8(stat.get(end + 2..).ok_or(REFUSAL)?).map_err(|_| REFUSAL)?;
    let ticks: u64 = fields
        .split_whitespace()
        .nth(19)
        .ok_or(REFUSAL)?
        .parse()
        .map_err(|_| REFUSAL)?;
    require(ticks == context.parent.start_ticks)?;
    let executable_path = std::fs::read_link(format!("/proc/{parent}/exe")).map_err(|_| REFUSAL)?;
    let name = executable_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(REFUSAL)?;
    require(name.strip_prefix("python3").is_some_and(|suffix| {
        suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    }))?;
    let interpreter = crate::native_tool_inspection::inspect_candidate(
        executable_path.to_str().ok_or(REFUSAL)?,
        std::env::consts::ARCH,
        context.interpreter_digest.clone(),
        Duration::from_secs(5),
    )
    .map_err(|_| REFUSAL)?;
    let executable = interpreter.observed_identity().0;
    require(
        executable == context.parent.executable_digest && executable == context.interpreter_digest,
    )?;
    let args = bounded(format!("/proc/{parent}/cmdline"), 8192)?;
    let args: Vec<_> = args.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
    require(args.len() == 7 && args[1..5] == [b"-I".as_slice(), b"-B", b"-X", b"utf8"])?;
    let script = std::str::from_utf8(args[5]).map_err(|_| REFUSAL)?;
    let fd = script.strip_prefix("/proc/self/fd/").ok_or(REFUSAL)?;
    require(!fd.is_empty() && fd.bytes().all(|b| b.is_ascii_digit()))?;
    let script_bytes = bounded(format!("/proc/{parent}/fd/{fd}"), 2 * 1024 * 1024)?;
    require(
        format!("sha256:{}", sha256_hex(&script_bytes)) == context.watchdog_digest
            && packaged_watchdog_digest(&script_bytes) == WATCHDOG_SOURCE_SHA256,
    )?;
    interpreter.recheck().map_err(|_| REFUSAL)?;
    Ok(interpreter)
}

fn authenticate(context: &Context, raw: &[u8]) -> Result<Value, String> {
    require(
        context.schema_version == PROTOCOL
            && context.stage == "watchdog"
            && context.enrollment_digest == canonical_hash(&context.issuer)
            && context.envelope_digest == format!("sha256:{}", sha256_hex(raw)),
    )?;
    let envelope: Envelope = serde_json::from_slice(raw).map_err(|_| REFUSAL)?;
    let key = hex::decode(&context.key).map_err(|_| REFUSAL)?;
    require(key.len() == 32)?;
    let signature = hex::decode(&envelope.authentication).map_err(|_| REFUSAL)?;
    let mut verifier = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| REFUSAL)?;
    verifier.update(canonical_json(&envelope.admission).as_bytes());
    verifier.verify_slice(&signature).map_err(|_| REFUSAL)?;
    Ok(envelope.admission)
}

pub(super) fn verify(
    context_fd: Option<OsString>,
    envelope_fd: Option<OsString>,
    manifest_path: &Path,
    profile_path: &Path,
) -> Result<VerifiedServiceAdmission, String> {
    require(context_fd.is_some() && envelope_fd.is_some() && context_fd != envelope_fd)?;
    let parent = unsafe { getppid() } as u32;
    let uid = unsafe { getuid() };
    require(uid > 0 && uid == unsafe { geteuid() })?;
    let context_file = sealed(context_fd, parent)?;
    let envelope_file = sealed(envelope_fd, parent)?;
    let context: Context =
        serde_json::from_slice(&contents(&context_file)?).map_err(|_| REFUSAL)?;
    let interpreter = check_parent(&context, parent)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .ok_or(REFUSAL)?;
    let current_runner =
        CurrentExecutable::observe(&context.runner_digest, deadline).map_err(|_| REFUSAL)?;
    let admission = authenticate(&context, &contents(&envelope_file)?)?;
    let manifest =
        serde_json::from_slice(&bounded(manifest_path, 1024 * 1024)?).map_err(|_| REFUSAL)?;
    let profile =
        serde_json::from_slice(&bounded(profile_path, 1024 * 1024)?).map_err(|_| REFUSAL)?;
    let mut checked = wire::validate(
        &admission,
        &context.issuer,
        &manifest,
        &profile,
        crate::contract::utc_now().fixed_offset(),
    )?;
    if let Some(runtime) = &checked.observation_runtime {
        require(runtime.matches(&checked.scope["observation_runtime"]))?;
        runtime.require_supported(deadline)?;
    }
    require(
        checked.owner_uid() == uid
            && admission["issuer"]["runner_id"] == manifest["runner_id"]
            && checked.scope["installations"]["payload"]["content_sha256"] == context.runner_digest,
    )?;
    let boot = bounded("/proc/sys/kernel/random/boot_id", 64)?;
    require(std::str::from_utf8(&boot).map_err(|_| REFUSAL)?.trim() == checked.boot_id())?;
    checked.installations =
        crate::service_installations::inspect(&checked.scope, &profile, &current_runner, deadline)?
            .into_iter()
            .collect();
    check_parent(&context, parent)?;
    interpreter.recheck().map_err(|_| REFUSAL)?;
    require(unsafe { getppid() } as u32 == parent)?;
    for installation in &checked.installations {
        installation.recheck().map_err(|_| REFUSAL)?;
    }
    current_runner.recheck().map_err(|_| REFUSAL)?;
    Ok(checked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn self_authored_envelope_cannot_supply_context_or_key() {
        let envelope =
            json!({"admission": {}, "authentication":"0".repeat(64), "key":"0".repeat(64)});
        assert!(serde_json::from_value::<Context>(envelope.clone()).is_err());
        assert!(serde_json::from_value::<Envelope>(envelope).is_err());
        assert!(verify(
            None,
            Some("4".into()),
            Path::new("unused"),
            Path::new("unused")
        )
        .is_err());
        assert!(verify(
            Some("4".into()),
            None,
            Path::new("unused"),
            Path::new("unused")
        )
        .is_err());
    }

    #[test]
    fn invalid_unsealed_and_aliased_descriptors_are_refused() {
        assert!(sealed(Some("123456789".into()), 1).is_err());
        assert!(sealed(Some("02".into()), 1).is_err());
        assert!(sealed(Some("0".into()), 1).is_err());
        assert!(verify(
            Some("4".into()),
            Some("4".into()),
            Path::new("unused"),
            Path::new("unused")
        )
        .is_err());
    }
}
