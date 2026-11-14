//! Fixed inherited-channel launcher for the installed Linux Strix worker.
//!
//! This command accepts no target, program, path, or network argument. The
//! controller transfers exact pinned descriptors over one inherited seqpacket
//! socket. This process owns the worker pidfd, cgroup and disposable identity
//! until it verifies terminal cleanup.

#![cfg(target_os = "linux")]

use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::canonical::canonical_json;
use crate::strix_worker_runtime_exec::{
    launch_fixed_runtime, FixedRuntimeDescriptors, FixedRuntimeIdentity, FixedRuntimeLaunch,
    FixedRuntimeProcess,
};
use crate::strix_worker_runtime_support as support;

const REFUSAL: &str = "the fixed installed Strix runtime IPC was refused";
const CHANNEL_FD: RawFd = 3;
const IPC_SCHEMA: &str = "bluefire.strix-worker-runtime-ipc.v1";
const WAIT_SLICE: Duration = Duration::from_secs(1);

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn peer(channel: RawFd) -> Result<libc::ucred, String> {
    let mut socket_type: libc::c_int = 0;
    let mut size = size_of::<libc::c_int>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockopt(
                channel,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut socket_type as *mut libc::c_int).cast(),
                &mut size,
            )
        } == 0,
    )?;
    require(size as usize == size_of::<libc::c_int>() && socket_type == libc::SOCK_SEQPACKET)?;
    let mut domain: libc::c_int = 0;
    size = size_of::<libc::c_int>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockopt(
                channel,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                (&mut domain as *mut libc::c_int).cast(),
                &mut size,
            )
        } == 0,
    )?;
    require(size as usize == size_of::<libc::c_int>() && domain == libc::AF_UNIX)?;
    let enabled: libc::c_int = 1;
    require(
        unsafe {
            libc::setsockopt(
                channel,
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as _,
            )
        } == 0,
    )?;
    let mut credentials: libc::ucred = unsafe { zeroed() };
    size = size_of::<libc::ucred>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockopt(
                channel,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut size,
            )
        } == 0,
    )?;
    require(
        size as usize == size_of::<libc::ucred>()
            && credentials.pid == unsafe { libc::getppid() }
            && credentials.pid > 1,
    )?;
    Ok(credentials)
}

fn canonical_packet(packet: &[u8], kind: &str, fields: usize) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(packet).map_err(|_| REFUSAL)?;
    require(canonical_json(&value).as_bytes() == packet)?;
    let row = value.as_object().ok_or(REFUSAL)?;
    require(
        row.len() == fields
            && row.get("schema_version") == Some(&json!(IPC_SCHEMA))
            && row.get("kind") == Some(&json!(kind)),
    )?;
    Ok(value)
}

fn send(channel: RawFd, value: &Value, rights: &[RawFd]) -> Result<(), String> {
    support::send_packet(channel, canonical_json(value).as_bytes(), rights)
}

fn launch_packet(
    channel: RawFd,
    credentials: (i32, u32, u32),
) -> Result<FixedRuntimeLaunch, String> {
    let (packet, rights) = support::receive_packet(channel, 11, credentials)?;
    let value = canonical_packet(&packet, "launch", 3)?;
    let identity: FixedRuntimeIdentity =
        serde_json::from_value(value["identity"].clone()).map_err(|_| REFUSAL)?;
    let [closure_mount, closure_manifest, interpreter, bootstrap, lockdown, strix_entrypoint,
        objective, config, mcp, launch_material, cancellation]: [OwnedFd; 11] =
        rights.try_into().map_err(|_| REFUSAL)?;
    Ok(FixedRuntimeLaunch {
        descriptors: FixedRuntimeDescriptors {
            closure_mount,
            closure_manifest,
            interpreter,
            bootstrap,
            lockdown,
            strix_entrypoint,
            objective,
            config,
            mcp,
            launch_material,
            cancellation,
        },
        identity,
    })
}

fn observed_packet(process: &FixedRuntimeProcess) -> Result<Value, String> {
    let mut observed = process.observation.as_object().cloned().ok_or(REFUSAL)?;
    require(
        observed
            .insert("observation_ref".into(), json!(process.observation_ref))
            .is_none(),
    )?;
    Ok(json!({"schema_version":IPC_SCHEMA,"kind":"observed","observed":observed}))
}

fn terminal(
    process: &FixedRuntimeProcess,
    reason: &str,
    status: Option<i32>,
) -> Result<Value, String> {
    require(process.pid == 0 && matches!(reason, "completed" | "cancelled"))?;
    let exit_code = status
        .filter(|value| libc::WIFEXITED(*value))
        .map(|value| libc::WEXITSTATUS(value));
    let signal = status
        .filter(|value| libc::WIFSIGNALED(*value))
        .map(|value| libc::WTERMSIG(value));
    let worker = process.observation["worker"].as_object().ok_or(REFUSAL)?;
    let mut receipt = json!({
        "schema_version":"bluefire.strix-worker-runtime-terminal.v1",
        "attempt_id":&process.prelaunch_bindings.attempt_id,
        "resource_claim_ref":&process.prelaunch_bindings.resource_claim_ref,
        "plan_ref":&process.plan_ref,
        "worker_pid":worker.get("pid").ok_or(REFUSAL)?,
        "worker_uid":worker.get("uid").ok_or(REFUSAL)?,
        "worker_gid":worker.get("gid").ok_or(REFUSAL)?,
        "worker_start_ticks":worker.get("start_ticks").ok_or(REFUSAL)?,
        "cgroup_ref":process.observation["cgroup_ref"],
        "observation_ref":&process.observation_ref,
        "workspace_ref":process.observation["workspace_ref"],
        "qualified_receipt_ref":process.qualified_receipt_ref.as_deref(),
        "reason":reason,
        "exit_code":exit_code,
        "signal":signal,
        "worker_reaped":true,
        "cgroup_empty_and_removed":true,
        "endpoint_absent":true,
        "staging_root_absent":true,
        "identity_released":true,
        "workspace_fd_transferred":true,
        "verified_absent":true
    });
    let receipt_ref = format!(
        "sha256:{:x}",
        Sha256::digest(canonical_json(&receipt).as_bytes())
    );
    receipt
        .as_object_mut()
        .ok_or(REFUSAL)?
        .insert("receipt_ref".into(), json!(receipt_ref));
    Ok(json!({"schema_version":IPC_SCHEMA,"kind":"terminal","terminal":receipt}))
}

fn wait_slice(process: &mut FixedRuntimeProcess) -> Result<Option<i32>, String> {
    if let Some(status) = process.poll_finished()? {
        return Ok(Some(status));
    }
    let mut poll = libc::pollfd {
        fd: process.pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let until = Instant::now() + WAIT_SLICE;
    let timeout = until
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(i32::MAX as u128) as i32;
    let result = unsafe { libc::poll(&mut poll, 1, timeout) };
    require(result >= 0)?;
    process.poll_finished()
}

fn run(channel: RawFd, credentials: (i32, u32, u32)) -> Result<(), String> {
    let launch = launch_packet(channel, credentials)?;
    let mut process = launch_fixed_runtime(launch)?;
    let observed = observed_packet(&process)?;
    send(
        channel,
        &observed,
        &[
            process.endpoint_directory.as_raw_fd(),
            process.control_listener.as_raw_fd(),
            process.model_listener.as_raw_fd(),
            process.caido_listener.as_raw_fd(),
            process.pidfd.as_raw_fd(),
            process.workspace_directory.as_raw_fd(),
        ],
    )?;
    support::wait_readable(
        channel,
        process.pidfd.as_raw_fd(),
        process.cancellation.as_raw_fd(),
        Instant::now() + Duration::from_secs(120),
    )?;
    let (packet, rights) = support::receive_packet(channel, 0, credentials)?;
    require(rights.is_empty())?;
    if canonical_packet(&packet, "cancel", 2).is_ok() {
        process.cancel_and_reap()?;
        send(channel, &terminal(&process, "cancelled", None)?, &[])?;
        return Ok(());
    }
    let basis = canonical_packet(&packet, "basis", 3)?;
    let receipt = process.complete_startup(&basis["basis"])?.clone();
    send(
        channel,
        &json!({
        "schema_version":IPC_SCHEMA,"kind":"qualified",
        "qualified":receipt
        }),
        &[],
    )?;
    loop {
        let (packet, rights) = support::receive_packet(channel, 0, credentials)?;
        require(rights.is_empty())?;
        let command = canonical_packet(&packet, "wait", 2)
            .or_else(|_| canonical_packet(&packet, "cancel", 2))?;
        match command["kind"].as_str().ok_or(REFUSAL)? {
            "wait" => {
                if let Some(status) = wait_slice(&mut process)? {
                    send(
                        channel,
                        &terminal(&process, "completed", Some(status))?,
                        &[],
                    )?;
                    return Ok(());
                }
                send(
                    channel,
                    &json!({"schema_version":IPC_SCHEMA,"kind":"running"}),
                    &[],
                )?;
            }
            "cancel" => {
                process.cancel_and_reap()?;
                send(channel, &terminal(&process, "cancelled", None)?, &[])?;
                return Ok(());
            }
            _ => return Err(REFUSAL.into()),
        }
    }
}

pub fn run_fixed_runtime_cli(args: &[String]) -> Result<i32, String> {
    require(args.is_empty() && unsafe { libc::geteuid() } == 0)?;
    let channel = unsafe { OwnedFd::from_raw_fd(CHANNEL_FD) };
    let credentials = peer(channel.as_raw_fd())?;
    // The controller-supplied channel is the sole inherited authority.
    require(unsafe { libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 0_u32) } == 0)?;
    run(
        channel.as_raw_fd(),
        (credentials.pid, credentials.uid, credentials.gid),
    )?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_contract_is_fixed_and_bounded() {
        assert_eq!(CHANNEL_FD, 3);
        assert_eq!(IPC_SCHEMA, "bluefire.strix-worker-runtime-ipc.v1");
        assert_eq!(WAIT_SLICE, Duration::from_secs(1));
        assert!(canonical_packet(
            br#"{"kind":"wait","schema_version":"bluefire.strix-worker-runtime-ipc.v1"}"#,
            "wait",
            2
        )
        .is_ok());
        assert!(canonical_packet(br#"{"kind":"wait","schema_version":"bluefire.strix-worker-runtime-ipc.v1","argv":["sh"]}"#, "wait", 2).is_err());
    }
}
