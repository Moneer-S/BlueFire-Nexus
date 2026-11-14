//! Descriptor-only fixed-exec launcher for the pinned Linux Strix runtime.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::canonical::canonical_json;
use crate::strix_worker_boundary_cgroup::{self, CgroupLeaf};
use crate::strix_worker_boundary_identity::{self, IdentityLease};
use crate::strix_worker_runtime_support as support;

const REFUSAL: &str = "the fixed installed Strix runtime launch was refused";
pub(crate) const OBSERVATION_FD: RawFd = 30;
pub(crate) const OBSERVATION_BASIS_FD: RawFd = 31;
pub(crate) const STARTUP_TIMEOUT_MS: i32 = 30_000;
pub(crate) const REAP_TIMEOUT_MS: i32 = 5_000;
pub(crate) const MODEL_RELAY_PORT: u16 = 48_081;
pub(crate) const CAIDO_RELAY_PORT: u16 = 48_080;
pub(crate) const CONTROL_SOCKET_PATH: &str = "/run/bluefire/controller.sock";
pub(crate) const FIXED_ARGV: [&str; 7] = [
    "/runtime/bin/python",
    "-I",
    "-S",
    "-B",
    "-X",
    "utf8",
    "/bootstrap/worker.py",
];
pub(crate) const FIXED_ENVIRONMENT: [&str; 4] = [
    "BLUEFIRE_STRIX_WORKER_LAUNCH_FILE=/run/bluefire/launch.json",
    "LANG=C",
    "LC_ALL=C",
    "PATH=/runtime/bin",
];
const INPUT_SEALS: i32 =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
const MAX_PINNED_FILE: u64 = 256 * 1024 * 1024;
const BARRIER_GO: &[u8] = b"G";
const LISTENERS_READY: &[u8] = b"R";
const BASIS_READY: &[u8] = b"B";
const ARMED_SCHEMA: &str = "bluefire.strix-fixed-exec-armed.v1";
const OBSERVATION_BASIS_SCHEMA: &str = "bluefire.strix-fixed-exec-observation-basis.v1";
const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PinnedFileIdentity {
    pub(crate) digest: String,
    pub(crate) byte_length: u64,
    pub(crate) mode: u32,
    pub(crate) seals: Option<i32>,
}

pub(crate) struct FixedRuntimeDescriptors {
    pub(crate) closure_mount: OwnedFd,
    pub(crate) closure_manifest: OwnedFd,
    pub(crate) interpreter: OwnedFd,
    pub(crate) bootstrap: OwnedFd,
    pub(crate) lockdown: OwnedFd,
    pub(crate) strix_entrypoint: OwnedFd,
    pub(crate) objective: OwnedFd,
    pub(crate) config: OwnedFd,
    pub(crate) mcp: OwnedFd,
    pub(crate) launch_material: OwnedFd,
    pub(crate) cancellation: OwnedFd,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixedPrelaunchBindings {
    pub(crate) attempt_id: String,
    pub(crate) resource_claim_ref: String,
    pub(crate) boundary_helper_digest: String,
    pub(crate) input_bindings_ref: String,
    pub(crate) sealed_inputs_ref: String,
    pub(crate) startup_overlay_ref: String,
    pub(crate) installed_projection_ref: String,
    pub(crate) private_device_policy_digest: String,
    pub(crate) source_root_identity_digest: String,
    pub(crate) controller_boot_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixedRuntimeIdentity {
    pub(crate) plan_ref: String,
    pub(crate) closure_inventory_digest: String,
    pub(crate) closure_manifest_ref: String,
    pub(crate) closure_manifest: PinnedFileIdentity,
    pub(crate) seccomp_profile_digest: String,
    pub(crate) guest_projection_digest: String,
    pub(crate) interpreter: PinnedFileIdentity,
    pub(crate) bootstrap: PinnedFileIdentity,
    pub(crate) lockdown: PinnedFileIdentity,
    pub(crate) strix_entrypoint: PinnedFileIdentity,
    pub(crate) objective: PinnedFileIdentity,
    pub(crate) config: PinnedFileIdentity,
    pub(crate) mcp: PinnedFileIdentity,
    pub(crate) launch_material: PinnedFileIdentity,
    pub(crate) prelaunch_bindings: FixedPrelaunchBindings,
}

pub(crate) struct FixedRuntimeLaunch {
    pub(crate) descriptors: FixedRuntimeDescriptors,
    pub(crate) identity: FixedRuntimeIdentity,
}

struct CopiedRuntimeFiles {
    interpreter: OwnedFd,
    bootstrap: OwnedFd,
    lockdown: OwnedFd,
    strix_entrypoint: OwnedFd,
}

fn open_copied_runtime_files(
    root: &Path,
    launch: &FixedRuntimeLaunch,
) -> Result<CopiedRuntimeFiles, String> {
    let directory = File::open(root).map_err(|_| REFUSAL)?;
    let open = |path: &str, identity: &PinnedFileIdentity| -> Result<OwnedFd, String> {
        let descriptor = support::open_beneath(directory.as_raw_fd(), path, false)?;
        validate_file(descriptor.as_raw_fd(), identity)?;
        Ok(descriptor)
    };
    Ok(CopiedRuntimeFiles {
        interpreter: open("runtime/bin/python", &launch.identity.interpreter)?,
        bootstrap: open("bootstrap/worker.py", &launch.identity.bootstrap)?,
        lockdown: open("bootstrap/worker_lockdown.py", &launch.identity.lockdown)?,
        strix_entrypoint: open("runtime/bin/strix", &launch.identity.strix_entrypoint)?,
    })
}

pub(crate) struct FixedRuntimeProcess {
    pub(crate) pid: i32,
    pub(crate) pidfd: OwnedFd,
    pub(crate) observation_channel: OwnedFd,
    pub(crate) endpoint_directory: OwnedFd,
    pub(crate) control_listener: OwnedFd,
    pub(crate) model_listener: OwnedFd,
    pub(crate) caido_listener: OwnedFd,
    pub(crate) workspace_directory: OwnedFd,
    pub(crate) cgroup: CgroupLeaf,
    pub(crate) identity: IdentityLease,
    pub(crate) staging_root: PathBuf,
    pub(crate) plan_ref: String,
    pub(crate) cancellation: OwnedFd,
    pub(crate) prelaunch_bindings: FixedPrelaunchBindings,
    pub(crate) seccomp_profile_digest: String,
    pub(crate) observation: Value,
    pub(crate) observation_ref: String,
    pub(crate) qualified_receipt_ref: Option<String>,
    pub(crate) qualified_receipt: Option<Value>,
    basis_sent: bool,
}

fn wait_exact(pid: i32, pidfd: RawFd, deadline: Instant) -> Result<(), String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    require(!remaining.is_zero())?;
    let timeout =
        i32::try_from(remaining.as_millis().min(i32::MAX as u128)).map_err(|_| REFUSAL)?;
    let mut poll = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    require(unsafe { libc::poll(&mut poll, 1, timeout) } == 1)?;
    require(poll.revents & libc::POLLIN != 0)?;
    let mut status = 0;
    loop {
        let observed = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if observed == pid {
            return Ok(());
        }
        if observed < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(REFUSAL.into());
    }
}

fn stop_exact(pid: i32, pidfd: RawFd, cgroup: &Path, deadline: Instant) -> Result<(), String> {
    let killed = fs::write(cgroup.join("cgroup.kill"), b"1").is_ok();
    if !killed {
        require(
            unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd, libc::SIGKILL, 0, 0) } == 0,
        )?;
    }
    wait_exact(pid, pidfd, deadline)?;
    wait_cgroup_empty(cgroup, deadline)
}

fn wait_cgroup_empty(cgroup: &Path, deadline: Instant) -> Result<(), String> {
    loop {
        if strix_worker_boundary_cgroup::members(cgroup)?.is_empty()
            && strix_worker_boundary_cgroup::threads(cgroup)?.is_empty()
        {
            return Ok(());
        }
        require(Instant::now() < deadline)?;
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn value_ref(value: &Value) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(canonical_json(value).as_bytes())
    )
}

fn process_identity(pid: i32, uid: u32, gid: u32) -> Result<Value, String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| REFUSAL)?;
    let tail = stat.rsplit_once(") ").ok_or(REFUSAL)?.1;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    require(fields.len() > 19)?;
    let start_ticks: u64 = fields[19].parse().map_err(|_| REFUSAL)?;
    require(start_ticks > 0)?;
    let status = fs::read_to_string(format!("/proc/{pid}/status")).map_err(|_| REFUSAL)?;
    let nspid_row = status
        .lines()
        .find_map(|row| row.strip_prefix("NSpid:\t"))
        .ok_or(REFUSAL)?;
    let nspid = nspid_row
        .split_whitespace()
        .map(str::parse::<i32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| REFUSAL)?;
    require(
        !nspid.is_empty()
            && nspid.len() <= 8
            && nspid[0] == pid
            && nspid.iter().all(|item| *item > 0),
    )?;
    let uid_row = status
        .lines()
        .find_map(|row| row.strip_prefix("Uid:\t"))
        .ok_or(REFUSAL)?;
    let gid_row = status
        .lines()
        .find_map(|row| row.strip_prefix("Gid:\t"))
        .ok_or(REFUSAL)?;
    require(
        uid_row
            .split_whitespace()
            .all(|part| part.parse::<u32>().ok() == Some(uid)),
    )?;
    require(
        gid_row
            .split_whitespace()
            .all(|part| part.parse::<u32>().ok() == Some(gid)),
    )?;
    Ok(json!({"pid":pid,"uid":uid,"gid":gid,"start_ticks":start_ticks,"nspid":nspid}))
}

fn private_root_identity(pid: i32) -> Result<Value, String> {
    let path = CString::new(format!("/proc/{pid}/root")).map_err(|_| REFUSAL)?;
    let mut details: libc::statx = unsafe { zeroed() };
    require(
        unsafe {
            libc::statx(
                libc::AT_FDCWD,
                path.as_ptr(),
                0,
                libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
                &mut details,
            )
        } == 0,
    )?;
    require(
        details.stx_mask & libc::STATX_MNT_ID != 0 && details.stx_mnt_id > 0 && details.stx_ino > 0,
    )?;
    Ok(
        json!({"mount_id":details.stx_mnt_id,"device":libc::makedev(details.stx_dev_major, details.stx_dev_minor),"inode":details.stx_ino}),
    )
}

fn retained_file_fact(fd: RawFd, digest: &str) -> Result<Value, String> {
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd, &mut details) } == 0)?;
    require(details.st_mode & libc::S_IFMT == libc::S_IFREG && details.st_size >= 0)?;
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    require(seals == INPUT_SEALS)?;
    Ok(json!({
        "device":details.st_dev,"inode":details.st_ino,
        "mode":details.st_mode & 0o777,"uid":details.st_uid,"gid":details.st_gid,
        "nlink":details.st_nlink,"size":details.st_size,"digest":digest,"seals":seals
    }))
}

fn namespace_fact(pid: i32, kind: &str) -> Result<Value, String> {
    require(matches!(kind, "ipc" | "mnt" | "net" | "pid" | "uts"))?;
    let details = fs::metadata(format!("/proc/{pid}/ns/{kind}")).map_err(|_| REFUSAL)?;
    require(details.ino() > 0)?;
    Ok(json!({"device":details.dev(),"inode":details.ino()}))
}

fn root_directory_fact(pid: i32, kind: &str) -> Result<Value, String> {
    require(matches!(
        kind,
        "config" | "home" | "root" | "tmp" | "workspace"
    ))?;
    let path = match kind {
        "root" => format!("/proc/{pid}/root"),
        "home" => format!("/proc/{pid}/root/home/worker"),
        _ => format!("/proc/{pid}/root/{kind}"),
    };
    let details = fs::metadata(path).map_err(|_| REFUSAL)?;
    require(details.is_dir() && details.ino() > 0)?;
    Ok(
        json!({"device":details.dev(),"inode":details.ino(),"mode":details.mode() & 0o777,"uid":details.uid(),"gid":details.gid()}),
    )
}

fn digest_fd(fd: RawFd, maximum: u64) -> Result<(String, u64), String> {
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd, &mut details) } == 0)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFREG
            && details.st_size >= 0
            && details.st_size as u64 <= maximum,
    )?;
    let mut digest = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while offset < details.st_size as u64 {
        let count = usize::try_from((details.st_size as u64 - offset).min(buffer.len() as u64))
            .map_err(|_| REFUSAL)?;
        let read =
            unsafe { libc::pread(fd, buffer.as_mut_ptr().cast(), count, offset as libc::off_t) };
        require(read > 0)?;
        digest.update(&buffer[..read as usize]);
        offset += read as u64;
    }
    let mut after: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd, &mut after) } == 0)?;
    require(
        details.st_dev == after.st_dev
            && details.st_ino == after.st_ino
            && details.st_size == after.st_size
            && details.st_mtime == after.st_mtime
            && details.st_mtime_nsec == after.st_mtime_nsec,
    )?;
    Ok((format!("sha256:{:x}", digest.finalize()), offset))
}

fn validate_file(fd: RawFd, identity: &PinnedFileIdentity) -> Result<(), String> {
    require(valid_digest(&identity.digest) && identity.byte_length <= MAX_PINNED_FILE)?;
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd, &mut details) } == 0)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFREG
            && details.st_nlink <= 1
            && details.st_mode & 0o777 == identity.mode
            && details.st_size >= 0
            && details.st_size as u64 == identity.byte_length,
    )?;
    if let Some(seals) = identity.seals {
        require(seals == INPUT_SEALS && unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } == seals)?;
    }
    let (observed, length) = digest_fd(fd, MAX_PINNED_FILE)?;
    require(observed == identity.digest && length == identity.byte_length)
}

fn validate_launch(launch: &FixedRuntimeLaunch) -> Result<(), String> {
    for value in [
        &launch.identity.plan_ref,
        &launch.identity.closure_inventory_digest,
        &launch.identity.closure_manifest_ref,
        &launch.identity.seccomp_profile_digest,
        &launch.identity.guest_projection_digest,
    ] {
        require(valid_digest(value))?;
    }
    let mut root: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(launch.descriptors.closure_mount.as_raw_fd(), &mut root) } == 0)?;
    require(root.st_mode & libc::S_IFMT == libc::S_IFDIR)?;
    for (file, identity) in [
        (
            &launch.descriptors.closure_manifest,
            &launch.identity.closure_manifest,
        ),
        (
            &launch.descriptors.interpreter,
            &launch.identity.interpreter,
        ),
        (&launch.descriptors.bootstrap, &launch.identity.bootstrap),
        (&launch.descriptors.lockdown, &launch.identity.lockdown),
        (
            &launch.descriptors.strix_entrypoint,
            &launch.identity.strix_entrypoint,
        ),
        (&launch.descriptors.objective, &launch.identity.objective),
        (&launch.descriptors.config, &launch.identity.config),
        (&launch.descriptors.mcp, &launch.identity.mcp),
        (
            &launch.descriptors.launch_material,
            &launch.identity.launch_material,
        ),
    ] {
        validate_file(file.as_raw_fd(), identity)?;
    }
    require(launch.identity.interpreter.mode == 0o555)?;
    require(
        launch.identity.closure_manifest.mode == 0o400
            && launch.identity.closure_manifest.seals == Some(INPUT_SEALS)
            && launch.identity.closure_manifest.digest == launch.identity.closure_manifest_ref,
    )?;
    require(launch.identity.bootstrap.mode == 0o444 && launch.identity.lockdown.mode == 0o444)?;
    require(launch.identity.strix_entrypoint.mode == 0o444)?;
    for identity in [
        &launch.identity.objective,
        &launch.identity.config,
        &launch.identity.mcp,
        &launch.identity.launch_material,
    ] {
        require(identity.mode == 0o444 && identity.seals == Some(INPUT_SEALS))?;
    }
    let bindings = &launch.identity.prelaunch_bindings;
    require(!bindings.attempt_id.is_empty() && bindings.attempt_id.len() <= 128)?;
    for value in [
        &bindings.resource_claim_ref,
        &bindings.boundary_helper_digest,
        &bindings.input_bindings_ref,
        &bindings.sealed_inputs_ref,
        &bindings.startup_overlay_ref,
        &bindings.installed_projection_ref,
        &bindings.private_device_policy_digest,
        &bindings.source_root_identity_digest,
    ] {
        require(valid_digest(value))?;
    }
    require(
        bindings.controller_boot_id.len() == 36
            && bindings
                .controller_boot_id
                .bytes()
                .all(|byte| byte == b'-' || byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
    )?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| REFUSAL)?;
    require(boot_id.trim() == bindings.controller_boot_id)?;
    let helper = File::open("/proc/self/exe").map_err(|_| REFUSAL)?;
    require(digest_fd(helper.as_raw_fd(), MAX_PINNED_FILE)?.0 == bindings.boundary_helper_digest)?;
    let mut root_stat: libc::statx = unsafe { zeroed() };
    require(
        unsafe {
            libc::statx(
                launch.descriptors.closure_mount.as_raw_fd(),
                b"\0".as_ptr().cast(),
                libc::AT_EMPTY_PATH,
                libc::STATX_MNT_ID | libc::STATX_BASIC_STATS,
                &mut root_stat,
            )
        } == 0,
    )?;
    require(root_stat.stx_mask & libc::STATX_MNT_ID != 0 && root_stat.stx_mnt_id > 0)?;
    let source_root = json!({
        "schema_version":"bluefire.strix-runtime-source-root-identity.v1",
        "role":"strix-linux-runtime-closure-root",
        "st_dev":root.st_dev,
        "st_ino":root.st_ino,
        "mount_id":root_stat.stx_mnt_id,
        "boot_id":bindings.controller_boot_id,
    });
    require(value_ref(&source_root) == bindings.source_root_identity_digest)?;
    let cancellation_fd = launch.descriptors.cancellation.as_raw_fd();
    require(unsafe { libc::fcntl(cancellation_fd, libc::F_GETFD) } >= 0)?;
    let mut cancellation = libc::pollfd {
        fd: cancellation_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    require(unsafe { libc::poll(&mut cancellation, 1, 0) } == 0)?;
    Ok(())
}

fn single_threaded_helper() -> Result<(), String> {
    let tasks = fs::read_dir("/proc/self/task").map_err(|_| REFUSAL)?;
    require(tasks.filter_map(Result::ok).count() == 1)
}

fn seqpacket_pair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut pair = [-1_i32; 2];
    require(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        } == 0,
    )?;
    let enabled: libc::c_int = 1;
    for fd in pair {
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } != 0
        {
            unsafe {
                libc::close(pair[0]);
                libc::close(pair[1]);
            }
            return Err(REFUSAL.into());
        }
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) })
}

fn clone_worker(pidfd: &mut i32) -> Result<i32, String> {
    let mut args = CloneArgs {
        flags: (libc::CLONE_PIDFD
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWUTS) as u64,
        pidfd: (pidfd as *mut i32) as u64,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            (&mut args as *mut CloneArgs).cast::<libc::c_void>(),
            size_of::<CloneArgs>(),
        ) as i32
    };
    require(result >= 0)?;
    if result > 0 {
        require(*pidfd >= 0)?;
    }
    Ok(result)
}

fn send_byte(fd: RawFd, value: &[u8]) -> Result<(), String> {
    require(
        unsafe { libc::send(fd, value.as_ptr().cast(), value.len(), libc::MSG_NOSIGNAL) }
            == value.len() as isize,
    )
}

fn receive_exact_byte(fd: RawFd, expected: &[u8]) -> Result<(), String> {
    let mut byte = [0_u8; 1];
    let read = unsafe { libc::recv(fd, byte.as_mut_ptr().cast(), byte.len(), 0) };
    require(read == 1 && byte == expected)
}

fn make_mount_private() -> Result<(), String> {
    require(
        unsafe {
            libc::mount(
                ptr::null(),
                b"/\0".as_ptr().cast(),
                ptr::null(),
                (libc::MS_REC | libc::MS_PRIVATE) as _,
                ptr::null(),
            )
        } == 0,
    )
}

fn mount_tmpfs(path: &Path, options: &str, nodev: bool) -> Result<(), String> {
    let target = CString::new(path.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    let filesystem = CString::new("tmpfs").map_err(|_| REFUSAL)?;
    let data = CString::new(options).map_err(|_| REFUSAL)?;
    let mut flags = libc::MS_NOSUID | libc::MS_NOEXEC;
    if nodev {
        flags |= libc::MS_NODEV;
    }
    require(
        unsafe {
            libc::mount(
                filesystem.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                flags as _,
                data.as_ptr().cast(),
            )
        } == 0,
    )
}

fn chmod_chown(path: &Path, mode: u32, uid: u32, gid: u32) -> Result<(), String> {
    let value = CString::new(path.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    require(unsafe { libc::chown(value.as_ptr(), uid, gid) } == 0)?;
    require(unsafe { libc::chmod(value.as_ptr(), mode) } == 0)
}

fn bind_fd(fd: RawFd, target: &Path, executable: bool) -> Result<(), String> {
    let source = CString::new(format!("/proc/self/fd/{fd}")).map_err(|_| REFUSAL)?;
    let target_c = CString::new(target.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    require(
        unsafe {
            libc::mount(
                source.as_ptr(),
                target_c.as_ptr(),
                ptr::null(),
                libc::MS_BIND as _,
                ptr::null(),
            )
        } == 0,
    )?;
    let mut flags =
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID;
    if !executable {
        flags |= libc::MS_NOEXEC;
    }
    require(
        unsafe {
            libc::mount(
                ptr::null(),
                target_c.as_ptr(),
                ptr::null(),
                flags as _,
                ptr::null(),
            )
        } == 0,
    )
}

fn publish_guest_launch_file(
    source: RawFd,
    target: &Path,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(source, &mut details) } == 0)?;
    require(details.st_size > 4 && details.st_size <= 64 * 1024)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(target)
        .map_err(|_| REFUSAL)?;
    let mut bytes = vec![0_u8; details.st_size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let read = unsafe {
            libc::pread(
                source,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
                offset as _,
            )
        };
        require(read > 0)?;
        offset += read as usize;
    }
    file.write_all(&bytes).map_err(|_| REFUSAL)?;
    file.sync_all().map_err(|_| REFUSAL)?;
    require(unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0)?;
    require(unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } == 0)?;
    let mut published: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(file.as_raw_fd(), &mut published) } == 0)?;
    require(
        published.st_nlink == 1
            && published.st_uid == uid
            && published.st_gid == gid
            && published.st_mode & 0o777 == 0o600,
    )?;
    Ok(())
}

fn write_private_etc(root: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let etc = root.join("etc");
    mount_tmpfs(&etc, "mode=0755,size=64k", true)?;
    let rows = [
        (
            "passwd",
            format!("worker:x:{uid}:{gid}:BlueFire worker:/home/worker:/sbin/nologin\n"),
        ),
        ("group", format!("worker:x:{gid}:\n")),
        (
            "nsswitch.conf",
            "hosts: files\npasswd: files\ngroup: files\n".into(),
        ),
        ("hosts", "127.0.0.1 localhost\n::1 localhost\n".into()),
    ];
    for (name, bytes) in rows {
        let path = etc.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| REFUSAL)?;
        file.write_all(bytes.as_bytes()).map_err(|_| REFUSAL)?;
        file.sync_all().map_err(|_| REFUSAL)?;
        require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
    }
    Ok(())
}

fn make_device(path: &Path, major: u64, minor: u64) -> Result<(), String> {
    let value = CString::new(path.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    let device = libc::makedev(major as _, minor as _);
    require(unsafe { libc::mknod(value.as_ptr(), libc::S_IFCHR | 0o666, device) } == 0)
}

fn write_private_dev(root: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let dev = root.join("dev");
    mount_tmpfs(&dev, "mode=0755,size=64k", false)?;
    for (name, major, minor) in [
        ("null", 1, 3),
        ("zero", 1, 5),
        ("random", 1, 8),
        ("urandom", 1, 9),
    ] {
        make_device(&dev.join(name), major, minor)?;
    }
    fs::create_dir(dev.join("shm")).map_err(|_| REFUSAL)?;
    chmod_chown(&dev.join("shm"), 0o700, uid, gid)
}

fn prepare_private_mounts(
    root: &Path,
    uid: u32,
    gid: u32,
    launch: &FixedRuntimeLaunch,
    copied: &CopiedRuntimeFiles,
) -> Result<(), String> {
    for relative in ["config", "home/worker", "run/bluefire", "tmp", "workspace"] {
        let path = root.join(relative);
        mount_tmpfs(&path, "mode=0700,size=8m", true)?;
        chmod_chown(&path, 0o700, uid, gid)?;
    }
    mount_tmpfs(&root.join("inputs"), "mode=0755,size=4m", true)?;
    chmod_chown(&root.join("inputs"), 0o755, 0, 0)?;
    write_private_etc(root, uid, gid)?;
    write_private_dev(root, uid, gid)?;
    for (relative, file) in [
        ("inputs/objective.json", &launch.descriptors.objective),
        ("inputs/config.json", &launch.descriptors.config),
        ("inputs/mcp.json", &launch.descriptors.mcp),
    ] {
        let path = root.join(relative);
        File::create(&path).map_err(|_| REFUSAL)?;
        bind_fd(file.as_raw_fd(), &path, false)?;
    }
    publish_guest_launch_file(
        launch.descriptors.launch_material.as_raw_fd(),
        &root.join("run/bluefire/launch.json"),
        uid,
        gid,
    )?;
    chmod_chown(&root.join("inputs"), 0o555, 0, 0)?;
    for (relative, file, executable) in [
        ("runtime/bin/python", &copied.interpreter, true),
        ("bootstrap/worker.py", &copied.bootstrap, false),
        ("bootstrap/worker_lockdown.py", &copied.lockdown, false),
        ("runtime/bin/strix", &copied.strix_entrypoint, false),
    ] {
        bind_fd(file.as_raw_fd(), &root.join(relative), executable)?;
    }
    Ok(())
}

fn pivot_to(root: &Path) -> Result<(), String> {
    let root_c = CString::new(root.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    require(unsafe { libc::chdir(root_c.as_ptr()) } == 0)?;
    require(
        unsafe {
            libc::syscall(
                libc::SYS_pivot_root,
                b".\0".as_ptr().cast::<libc::c_char>(),
                b".\0".as_ptr().cast::<libc::c_char>(),
            )
        } == 0,
    )?;
    require(unsafe { libc::umount2(b".\0".as_ptr().cast(), libc::MNT_DETACH) } == 0)?;
    require(unsafe { libc::chdir(b"/\0".as_ptr().cast()) } == 0)
}

fn bring_loopback_up() -> Result<(), String> {
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    require(socket >= 0)?;
    let mut request: libc::ifreq = unsafe { zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(b"lo\0") {
        *slot = *byte as libc::c_char;
    }
    require(unsafe { libc::ioctl(socket, libc::SIOCGIFFLAGS, &mut request) } == 0)?;
    unsafe { request.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16 };
    let changed = unsafe { libc::ioctl(socket, libc::SIOCSIFFLAGS, &request) } == 0;
    unsafe { libc::close(socket) };
    require(changed)
}

fn set_private_hostname() -> Result<(), String> {
    let hostname = b"bluefire-worker";
    require(unsafe { libc::sethostname(hostname.as_ptr().cast(), hostname.len()) } == 0)
}

fn tcp_listener(port: u16) -> Result<OwnedFd, String> {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    require(raw >= 0)?;
    let listener = unsafe { OwnedFd::from_raw_fd(raw) };
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    require(
        unsafe {
            libc::bind(
                listener.as_raw_fd(),
                (&address as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        } == 0,
    )?;
    require(unsafe { libc::listen(listener.as_raw_fd(), 8) } == 0)?;
    Ok(listener)
}

fn unix_listener() -> Result<OwnedFd, String> {
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    require(raw >= 0)?;
    let listener = unsafe { OwnedFd::from_raw_fd(raw) };
    let enabled: libc::c_int = 1;
    require(
        unsafe {
            libc::setsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } == 0,
    )?;
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as _;
    for (slot, byte) in address
        .sun_path
        .iter_mut()
        .zip(CONTROL_SOCKET_PATH.as_bytes())
    {
        *slot = *byte as libc::c_char;
    }
    require(
        unsafe {
            libc::bind(
                listener.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        } == 0,
    )?;
    let path = CString::new(CONTROL_SOCKET_PATH).map_err(|_| REFUSAL)?;
    require(unsafe { libc::chmod(path.as_ptr(), 0o600) } == 0)?;
    require(unsafe { libc::listen(listener.as_raw_fd(), 8) } == 0)?;
    Ok(listener)
}

fn verify_endpoint_directory(fd: RawFd, uid: u32, gid: u32) -> Result<(), String> {
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd, &mut details) } == 0)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFDIR
            && details.st_mode & 0o777 == 0o700
            && details.st_uid == uid
            && details.st_gid == gid,
    )
}

fn remove_endpoint(fd: RawFd) -> Result<(), String> {
    let name = b"controller.sock\0";
    require(unsafe { libc::unlinkat(fd, name.as_ptr().cast(), 0) } == 0)?;
    let mut details: libc::stat = unsafe { zeroed() };
    let observed = unsafe {
        libc::fstatat(
            fd,
            name.as_ptr().cast(),
            &mut details,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    require(observed == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT))
}

fn duplicate_observation(channel: RawFd) -> Result<(), String> {
    if channel != OBSERVATION_FD {
        require(unsafe { libc::dup3(channel, OBSERVATION_FD, 0) } == OBSERVATION_FD)?;
    }
    require(unsafe { libc::fcntl(OBSERVATION_FD, libc::F_SETFD, 0) } == 0)
}

fn duplicate_basis(source: RawFd) -> Result<(), String> {
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(source, &mut details) } == 0)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFREG
            && details.st_mode & 0o777 == 0o400
            && unsafe { libc::fcntl(source, libc::F_GET_SEALS) } == INPUT_SEALS,
    )?;
    if source != OBSERVATION_BASIS_FD {
        require(unsafe { libc::dup3(source, OBSERVATION_BASIS_FD, 0) } == OBSERVATION_BASIS_FD)?;
    }
    require(unsafe { libc::fcntl(OBSERVATION_BASIS_FD, libc::F_SETFD, 0) } == 0)
}

fn open_endpoint_directory() -> Result<OwnedFd, String> {
    let raw = unsafe {
        libc::open(
            b"/run/bluefire\0".as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(raw >= 0)?;
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn open_workspace_directory(uid: u32, gid: u32) -> Result<OwnedFd, String> {
    let raw = unsafe {
        libc::open(
            b"/workspace\0".as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(raw >= 0)?;
    let directory = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(raw, &mut details) } == 0)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFDIR
            && details.st_mode & 0o777 == 0o700
            && details.st_uid == uid
            && details.st_gid == gid,
    )?;
    Ok(directory)
}

fn mark_all_cloexec() -> Result<(), String> {
    require(
        unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) } == 0,
    )
}

fn exec_python(interpreter: RawFd) -> Result<(), String> {
    let argv: Vec<CString> = FIXED_ARGV
        .iter()
        .map(|value| CString::new(*value).map_err(|_| REFUSAL.to_string()))
        .collect::<Result<_, _>>()?;
    let environment: Vec<CString> = FIXED_ENVIRONMENT
        .iter()
        .map(|value| CString::new(*value).map_err(|_| REFUSAL.to_string()))
        .collect::<Result<_, _>>()?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|value| value.as_ptr()).collect();
    argv_ptrs.push(ptr::null());
    let mut environment_ptrs: Vec<*const libc::c_char> =
        environment.iter().map(|value| value.as_ptr()).collect();
    environment_ptrs.push(ptr::null());
    require(
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                interpreter,
                b"\0".as_ptr().cast::<libc::c_char>(),
                argv_ptrs.as_ptr(),
                environment_ptrs.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        } == 0,
    )
}

fn child_main(
    launch: FixedRuntimeLaunch,
    channel: OwnedFd,
    root: PathBuf,
    uid: u32,
    gid: u32,
    owner_pid: i32,
) -> ! {
    let result = (|| -> Result<(), String> {
        // A helper lost before this check cannot leave a runnable worker.
        require(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } == 0)?;
        require(unsafe { libc::getppid() } == owner_pid)?;
        receive_exact_byte(channel.as_raw_fd(), BARRIER_GO)?;
        // `/proc` is intentionally absent after pivot. Mark the complete
        // inherited inventory now; only the fixed observation fd is cleared
        // below and the interpreter fd is consumed by execveat.
        mark_all_cloexec()?;
        make_mount_private()?;
        support::materialize_closure(
            launch.descriptors.closure_mount.as_raw_fd(),
            launch.descriptors.closure_manifest.as_raw_fd(),
            &root,
            &launch.identity.closure_manifest_ref,
            &launch.identity.closure_inventory_digest,
        )?;
        let copied = open_copied_runtime_files(&root, &launch)?;
        prepare_private_mounts(&root, uid, gid, &launch, &copied)?;
        support::seal_closure_root(&root)?;
        pivot_to(&root)?;
        set_private_hostname()?;
        bring_loopback_up()?;
        strix_worker_boundary_identity::drop_privileges(uid, gid)?;
        require(unsafe { libc::chdir(b"/workspace\0".as_ptr().cast()) } == 0)?;
        let control = unix_listener()?;
        let model = tcp_listener(MODEL_RELAY_PORT)?;
        let caido = tcp_listener(CAIDO_RELAY_PORT)?;
        let endpoint = open_endpoint_directory()?;
        let workspace = open_workspace_directory(uid, gid)?;
        support::send_packet(
            channel.as_raw_fd(),
            LISTENERS_READY,
            &[
                endpoint.as_raw_fd(),
                control.as_raw_fd(),
                model.as_raw_fd(),
                caido.as_raw_fd(),
                workspace.as_raw_fd(),
            ],
        )?;
        let (payload, mut basis) =
            support::receive_packet(channel.as_raw_fd(), 1, (unsafe { libc::getppid() }, 0, 0))?;
        require(payload == BASIS_READY && basis.len() == 1)?;
        duplicate_basis(basis.remove(0).as_raw_fd())?;
        duplicate_observation(channel.as_raw_fd())?;
        exec_python(copied.interpreter.as_raw_fd())
    })();
    if result.is_err() {
        let _ = send_byte(channel.as_raw_fd(), b"E");
    }
    unsafe { libc::_exit(127) }
}

fn receive_listeners(
    channel: RawFd,
    pidfd: RawFd,
    cancellation: RawFd,
    deadline: Instant,
    pid: i32,
    uid: u32,
    gid: u32,
) -> Result<[OwnedFd; 5], String> {
    support::wait_readable(channel, pidfd, cancellation, deadline)?;
    let (payload, rights) = support::receive_packet(channel, 5, (pid, uid, gid))?;
    require(payload == LISTENERS_READY && rights.len() == 5)?;
    let [endpoint, control, model, caido, workspace]: [OwnedFd; 5] =
        rights.try_into().map_err(|_| REFUSAL)?;
    support::verify_listeners(
        endpoint.as_raw_fd(),
        control.as_raw_fd(),
        model.as_raw_fd(),
        caido.as_raw_fd(),
        uid,
        gid,
        CONTROL_SOCKET_PATH,
        MODEL_RELAY_PORT,
        CAIDO_RELAY_PORT,
    )?;
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(workspace.as_raw_fd(), &mut details) } == 0)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFDIR
            && details.st_mode & 0o777 == 0o700
            && details.st_uid == uid
            && details.st_gid == gid,
    )?;
    Ok([endpoint, control, model, caido, workspace])
}

fn runtime_observation(
    pid: i32,
    pidfd: RawFd,
    cgroup: &CgroupLeaf,
    uid: u32,
    gid: u32,
    endpoint: RawFd,
    control: RawFd,
    model: RawFd,
    caido: RawFd,
    workspace: RawFd,
    launch: &FixedRuntimeLaunch,
    attempt_id: &str,
    plan_ref: &str,
) -> Result<Value, String> {
    let worker = process_identity(pid, uid, gid)?;
    let mut pidfd_stat: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(pidfd, &mut pidfd_stat) } == 0)?;
    let pidfd_fact = json!({"device":pidfd_stat.st_dev,"inode":pidfd_stat.st_ino});
    require(strix_worker_boundary_cgroup::members(&cgroup.path)? == vec![pid])?;
    let cgroup_device = fs::metadata(&cgroup.path).map_err(|_| REFUSAL)?.dev();
    let cgroup_fact = json!({
        "path":cgroup.path.to_str().ok_or(REFUSAL)?,
        "device":cgroup_device,
        "inode":cgroup.inode,
        "members":[pid],
        "pids_max":strix_worker_boundary_cgroup::read_trimmed(&cgroup.path.join("pids.max"))?,
        "memory_max":strix_worker_boundary_cgroup::read_trimmed(&cgroup.path.join("memory.max"))?,
        "memory_swap_max":strix_worker_boundary_cgroup::read_trimmed(&cgroup.path.join("memory.swap.max"))?,
        "cpu_max":strix_worker_boundary_cgroup::read_trimmed(&cgroup.path.join("cpu.max"))?,
    });
    let listeners = support::verify_listeners(
        endpoint,
        control,
        model,
        caido,
        uid,
        gid,
        CONTROL_SOCKET_PATH,
        MODEL_RELAY_PORT,
        CAIDO_RELAY_PORT,
    )?;
    let listeners_value = serde_json::to_value(&listeners).map_err(|_| REFUSAL)?;
    let namespaces = json!({
        "mnt":namespace_fact(pid,"mnt")?,
        "net":namespace_fact(pid,"net")?,
        "ipc":namespace_fact(pid,"ipc")?,
        "pid":namespace_fact(pid,"pid")?,
        "uts":namespace_fact(pid,"uts")?,
    });
    let roots = json!({
        "config":root_directory_fact(pid,"config")?,
        "home":root_directory_fact(pid,"home")?,
        "root":root_directory_fact(pid,"root")?,
        "tmp":root_directory_fact(pid,"tmp")?,
        "workspace":root_directory_fact(pid,"workspace")?,
    });
    let inputs = json!({
        "config":retained_file_fact(launch.descriptors.config.as_raw_fd(), &launch.identity.config.digest)?,
        "mcp":retained_file_fact(launch.descriptors.mcp.as_raw_fd(), &launch.identity.mcp.digest)?,
        "objective":retained_file_fact(launch.descriptors.objective.as_raw_fd(), &launch.identity.objective.digest)?,
    });
    let mut workspace_stat: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(workspace, &mut workspace_stat) } == 0)?;
    let workspace_fact = json!({
        "device":workspace_stat.st_dev,"inode":workspace_stat.st_ino,
        "mode":workspace_stat.st_mode & 0o777,"uid":workspace_stat.st_uid,"gid":workspace_stat.st_gid,
    });
    require(roots.get("workspace") == Some(&workspace_fact))?;
    let root = private_root_identity(pid)?;
    Ok(json!({
        "schema_version":"bluefire.strix-worker-runtime-observation.v1",
        "attempt_id":attempt_id,
        "plan_ref":plan_ref,
        "worker":worker,
        "worker_custody_identity_digest":value_ref(&worker),
        "pidfd":pidfd_fact,
        "cgroup":cgroup_fact,
        "cgroup_ref":value_ref(&cgroup_fact),
        "listeners":listeners_value,
        "endpoint_directory_identity_ref":value_ref(&json!({"endpoint_directory_device":listeners.endpoint_directory_device,"endpoint_directory_inode":listeners.endpoint_directory_inode,"endpoint_directory_mode":listeners.endpoint_directory_mode,"endpoint_directory_uid":listeners.endpoint_directory_uid,"endpoint_directory_gid":listeners.endpoint_directory_gid})),
        "controller_socket_identity_ref":value_ref(&json!({"control":&listeners.control,"endpoint_path":&listeners.endpoint_path})),
        "model_listener_ref":value_ref(&serde_json::to_value(&listeners.model).map_err(|_| REFUSAL)?),
        "caido_listener_ref":value_ref(&serde_json::to_value(&listeners.caido).map_err(|_| REFUSAL)?),
        "namespaces":namespaces,
        "roots":roots,
        "inputs":inputs,
        "workspace":workspace_fact,
        "workspace_ref":value_ref(&workspace_fact),
        "private_root":root,
    }))
}

/// Launch the exact installed worker. The returned observation fd remains the
/// only pre-opened child authority and must yield the post-bootstrap native
/// receipt before any model or effect lease is released.
pub(crate) fn launch_fixed_runtime(
    launch: FixedRuntimeLaunch,
) -> Result<FixedRuntimeProcess, String> {
    require(unsafe { libc::geteuid() } == 0)?;
    single_threaded_helper()?;
    validate_launch(&launch)?;
    let mut identity = strix_worker_boundary_identity::acquire()?;
    let (parent_channel, child_channel) = seqpacket_pair()?;
    let owner_pid = unsafe { libc::getpid() };
    let mut pidfd_raw = -1;
    let pid = clone_worker(&mut pidfd_raw)?;
    if pid == 0 {
        drop(parent_channel);
        let root = PathBuf::from(format!("/tmp/bluefire-strix-runtime-root-{}", unsafe {
            libc::getpid()
        }));
        if fs::create_dir(&root).is_err() {
            unsafe { libc::_exit(127) }
        }
        child_main(
            launch,
            child_channel,
            root,
            identity.uid,
            identity.gid,
            owner_pid,
        );
    }
    drop(child_channel);
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
    let staging_root = PathBuf::from(format!("/tmp/bluefire-strix-runtime-root-{pid}"));
    let mut cgroup = match strix_worker_boundary_cgroup::prepare(pid) {
        Ok(value) => value,
        Err(error) => {
            let (_message, mut partial) = error.into_parts();
            let signalled = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    0,
                    0,
                )
            } == 0;
            let stopped = if signalled {
                wait_exact(
                    pid,
                    pidfd.as_raw_fd(),
                    Instant::now() + Duration::from_millis(REAP_TIMEOUT_MS as u64),
                )
            } else {
                Err(REFUSAL.into())
            };
            if let Some(leaf) = partial.as_mut() {
                let _ = leaf.remove();
            }
            let _ = identity.release();
            let _ = fs::remove_dir(&staging_root);
            stopped?;
            return Err(REFUSAL.into());
        }
    };
    let ready = (|| -> Result<[OwnedFd; 5], String> {
        send_byte(parent_channel.as_raw_fd(), BARRIER_GO)?;
        receive_listeners(
            parent_channel.as_raw_fd(),
            pidfd.as_raw_fd(),
            launch.descriptors.cancellation.as_raw_fd(),
            Instant::now() + Duration::from_millis(STARTUP_TIMEOUT_MS as u64),
            pid,
            identity.uid,
            identity.gid,
        )
    })();
    let [endpoint_directory, control_listener, model_listener, caido_listener, workspace_directory] =
        match ready {
            Ok(value) => value,
            Err(error) => {
                let _ = stop_exact(
                    pid,
                    pidfd.as_raw_fd(),
                    &cgroup.path,
                    Instant::now() + Duration::from_millis(REAP_TIMEOUT_MS as u64),
                );
                let _ = cgroup.remove();
                let _ = identity.release();
                let _ = fs::remove_dir(&staging_root);
                return Err(error);
            }
        };
    if let Err(error) =
        verify_endpoint_directory(endpoint_directory.as_raw_fd(), identity.uid, identity.gid)
    {
        let _ = stop_exact(
            pid,
            pidfd.as_raw_fd(),
            &cgroup.path,
            Instant::now() + Duration::from_millis(REAP_TIMEOUT_MS as u64),
        );
        let _ = remove_endpoint(endpoint_directory.as_raw_fd());
        let _ = cgroup.remove();
        let _ = identity.release();
        let _ = fs::remove_dir(&staging_root);
        return Err(error);
    }
    let plan_ref = launch.identity.plan_ref.clone();
    let prelaunch_bindings = launch.identity.prelaunch_bindings.clone();
    let seccomp_profile_digest = launch.identity.seccomp_profile_digest.clone();
    let observed = runtime_observation(
        pid,
        pidfd.as_raw_fd(),
        &cgroup,
        identity.uid,
        identity.gid,
        endpoint_directory.as_raw_fd(),
        control_listener.as_raw_fd(),
        model_listener.as_raw_fd(),
        caido_listener.as_raw_fd(),
        workspace_directory.as_raw_fd(),
        &launch,
        &prelaunch_bindings.attempt_id,
        &plan_ref,
    );
    let observation = match observed {
        Ok(value) => value,
        Err(error) => {
            let _ = stop_exact(
                pid,
                pidfd.as_raw_fd(),
                &cgroup.path,
                Instant::now() + Duration::from_millis(REAP_TIMEOUT_MS as u64),
            );
            let _ = remove_endpoint(endpoint_directory.as_raw_fd());
            let _ = cgroup.remove();
            let _ = identity.release();
            let _ = fs::remove_dir(&staging_root);
            return Err(error);
        }
    };
    let observation_ref = value_ref(&observation);
    Ok(FixedRuntimeProcess {
        pid,
        pidfd,
        observation_channel: parent_channel,
        endpoint_directory,
        control_listener,
        model_listener,
        caido_listener,
        workspace_directory,
        cgroup,
        identity,
        staging_root,
        plan_ref,
        cancellation: launch.descriptors.cancellation,
        prelaunch_bindings,
        seccomp_profile_digest,
        observation,
        observation_ref,
        qualified_receipt_ref: None,
        qualified_receipt: None,
        basis_sent: false,
    })
}

impl FixedRuntimeProcess {
    /// Publish one controller basis after the worker, listeners, and custody are known.
    /// This helper remains the only consumer and verifier of native startup packets.
    pub(crate) fn complete_startup(&mut self, basis: &Value) -> Result<&Value, String> {
        require(self.pid > 0 && !self.basis_sent && self.qualified_receipt_ref.is_none())?;
        let row = basis.as_object().ok_or(REFUSAL)?;
        require(row.len() == 4)?;
        require(row.get("schema_version") == Some(&json!(OBSERVATION_BASIS_SCHEMA)))?;
        let mut unsigned = row.clone();
        let basis_ref = unsigned.remove("basis_ref").ok_or(REFUSAL)?;
        require(
            basis_ref
                == json!(format!(
                    "sha256:{:x}",
                    Sha256::digest(canonical_json(&Value::Object(unsigned)).as_bytes())
                )),
        )?;
        let armed = row.get("armed_payload").ok_or(REFUSAL)?;
        let armed_row = armed.as_object().ok_or(REFUSAL)?;
        let receipt_base = row.get("qualified_receipt_base").ok_or(REFUSAL)?;
        let receipt_row = receipt_base.as_object().ok_or(REFUSAL)?;
        let observed = self.observation.as_object().ok_or(REFUSAL)?;
        let worker = observed
            .get("worker")
            .and_then(Value::as_object)
            .ok_or(REFUSAL)?;
        let root = observed
            .get("private_root")
            .and_then(Value::as_object)
            .ok_or(REFUSAL)?;
        let namespaces = observed
            .get("namespaces")
            .and_then(Value::as_object)
            .ok_or(REFUSAL)?;
        require(
            armed_row.get("schema_version") == Some(&json!(ARMED_SCHEMA))
                && armed_row.get("attempt_id") == Some(&json!(self.prelaunch_bindings.attempt_id))
                && armed_row.get("plan_ref") == Some(&json!(self.plan_ref))
                && armed_row.get("worker_custody_identity_digest")
                    == observed.get("worker_custody_identity_digest")
                && armed_row.get("seccomp_profile_digest")
                    == Some(&json!(self.seccomp_profile_digest))
                && receipt_row.get("attempt_id")
                    == Some(&json!(self.prelaunch_bindings.attempt_id))
                && receipt_row.get("plan_ref") == Some(&json!(self.plan_ref))
                && receipt_row.get("worker_host_pid") == worker.get("pid")
                && receipt_row.get("worker_uid") == worker.get("uid")
                && receipt_row.get("worker_gid") == worker.get("gid")
                && receipt_row.get("worker_start_ticks") == worker.get("start_ticks")
                && receipt_row.get("worker_nspid") == worker.get("nspid")
                && receipt_row.get("worker_custody_identity_digest")
                    == observed.get("worker_custody_identity_digest")
                && receipt_row.get("cgroup_ref") == observed.get("cgroup_ref")
                && receipt_row.get("native_observation_ref") == Some(&json!(self.observation_ref))
                && receipt_row.get("endpoint_directory_identity_ref")
                    == observed.get("endpoint_directory_identity_ref")
                && receipt_row.get("controller_socket_identity_ref")
                    == observed.get("controller_socket_identity_ref")
                && receipt_row.get("model_listener_ref") == observed.get("model_listener_ref")
                && receipt_row.get("caido_listener_ref") == observed.get("caido_listener_ref")
                && receipt_row.get("private_root_mount_id") == root.get("mount_id")
                && receipt_row.get("private_root_st_dev") == root.get("device")
                && receipt_row.get("private_root_st_ino") == root.get("inode")
                && receipt_row.get("mount_namespace_inode")
                    == namespaces.get("mnt").and_then(|value| value.get("inode"))
                && receipt_row.get("network_namespace_inode")
                    == namespaces.get("net").and_then(|value| value.get("inode"))
                && receipt_row.get("ipc_namespace_inode")
                    == namespaces.get("ipc").and_then(|value| value.get("inode"))
                && receipt_row.get("uts_namespace_inode")
                    == namespaces.get("uts").and_then(|value| value.get("inode"))
                && receipt_row.get("resource_claim_ref")
                    == Some(&json!(self.prelaunch_bindings.resource_claim_ref))
                && receipt_row.get("boundary_helper_digest")
                    == Some(&json!(self.prelaunch_bindings.boundary_helper_digest))
                && receipt_row.get("input_bindings_ref")
                    == Some(&json!(self.prelaunch_bindings.input_bindings_ref))
                && receipt_row.get("sealed_inputs_ref")
                    == Some(&json!(self.prelaunch_bindings.sealed_inputs_ref))
                && receipt_row.get("startup_overlay_ref")
                    == Some(&json!(self.prelaunch_bindings.startup_overlay_ref))
                && receipt_row.get("installed_projection_ref")
                    == Some(&json!(self.prelaunch_bindings.installed_projection_ref))
                && receipt_row.get("private_device_policy_digest")
                    == Some(&json!(self.prelaunch_bindings.private_device_policy_digest))
                && receipt_row.get("source_root_identity_digest")
                    == Some(&json!(self.prelaunch_bindings.source_root_identity_digest))
                && receipt_row.get("controller_boot_id")
                    == Some(&json!(self.prelaunch_bindings.controller_boot_id)),
        )?;
        let (basis_file, _) = support::sealed_basis(basis)?;
        support::send_packet(
            self.observation_channel.as_raw_fd(),
            BASIS_READY,
            &[basis_file.as_raw_fd()],
        )?;
        self.basis_sent = true;
        let receipt = support::await_two_phase(
            self.observation_channel.as_raw_fd(),
            self.pidfd.as_raw_fd(),
            self.cancellation.as_raw_fd(),
            (self.pid, self.identity.uid, self.identity.gid),
            Instant::now() + Duration::from_millis(STARTUP_TIMEOUT_MS as u64),
            armed,
            receipt_base,
        )?;
        self.qualified_receipt_ref = Some(
            receipt
                .get("receipt_ref")
                .and_then(Value::as_str)
                .ok_or(REFUSAL)?
                .to_owned(),
        );
        self.qualified_receipt = Some(receipt);
        self.qualified_receipt.as_ref().ok_or(REFUSAL.into())
    }

    fn cleanup_reaped(&mut self) -> Result<(), String> {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        require(unsafe { libc::poll(&mut poll, 1, 0) } == 1 && poll.revents & libc::POLLIN != 0)?;
        require(strix_worker_boundary_cgroup::members(&self.cgroup.path)?.is_empty())?;
        require(strix_worker_boundary_cgroup::threads(&self.cgroup.path)?.is_empty())?;
        remove_endpoint(self.endpoint_directory.as_raw_fd())?;
        require(self.cgroup.remove()?)?;
        require(self.identity.release()?)?;
        if self.staging_root.exists() {
            fs::remove_dir(&self.staging_root).map_err(|_| REFUSAL)?;
        }
        require(!self.staging_root.exists())?;
        self.pid = 0;
        Ok(())
    }

    pub(crate) fn cancel_and_reap(&mut self) -> Result<(), String> {
        require(self.pid > 0)?;
        stop_exact(
            self.pid,
            self.pidfd.as_raw_fd(),
            &self.cgroup.path,
            Instant::now() + Duration::from_millis(REAP_TIMEOUT_MS as u64),
        )?;
        self.cleanup_reaped()
    }

    /// Reap an exited worker without calling its normal completion cancellation.
    /// A still-running worker leaves all custody with this helper.
    pub(crate) fn poll_finished(&mut self) -> Result<Option<i32>, String> {
        require(self.pid > 0)?;
        let mut status = 0;
        let observed = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if observed == 0 {
            return Ok(None);
        }
        require(observed == self.pid)?;
        // The Python process has exited; any unexpected descendant remains
        // confined to the same exact leaf and is killed before cleanup.
        if !strix_worker_boundary_cgroup::members(&self.cgroup.path)?.is_empty() {
            fs::write(self.cgroup.path.join("cgroup.kill"), b"1").map_err(|_| REFUSAL)?;
        }
        wait_cgroup_empty(
            &self.cgroup.path,
            Instant::now() + Duration::from_millis(REAP_TIMEOUT_MS as u64),
        )?;
        self.cleanup_reaped()?;
        Ok(Some(status))
    }
}

impl Drop for FixedRuntimeProcess {
    fn drop(&mut self) {
        if self.pid <= 0 {
            return;
        }
        let _ = stop_exact(
            self.pid,
            self.pidfd.as_raw_fd(),
            &self.cgroup.path,
            Instant::now() + Duration::from_millis(REAP_TIMEOUT_MS as u64),
        );
        self.pid = 0;
        let _ = remove_endpoint(self.endpoint_directory.as_raw_fd());
        let _ = self.cgroup.remove();
        let _ = self.identity.release();
        let _ = fs::remove_dir(&self.staging_root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_environment_and_relays_are_fixed() {
        assert_eq!(FIXED_ARGV[0], "/runtime/bin/python");
        assert_eq!(
            FIXED_ARGV[1..],
            ["-I", "-S", "-B", "-X", "utf8", "/bootstrap/worker.py"]
        );
        assert_eq!(FIXED_ENVIRONMENT.len(), 4);
        assert!(FIXED_ENVIRONMENT.contains(&"LANG=C"));
        assert!(FIXED_ENVIRONMENT.contains(&"LC_ALL=C"));
        assert!(FIXED_ENVIRONMENT.contains(&"PATH=/runtime/bin"));
        assert_eq!((CAIDO_RELAY_PORT, MODEL_RELAY_PORT), (48_080, 48_081));
        assert_eq!(CONTROL_SOCKET_PATH, "/run/bluefire/controller.sock");
    }

    #[test]
    fn identity_contract_rejects_unbounded_values() {
        assert!(valid_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_digest("sha256:anything"));
        let identity = PinnedFileIdentity {
            digest: format!("sha256:{}", "a".repeat(64)),
            byte_length: MAX_PINNED_FILE + 1,
            mode: 0o444,
            seals: None,
        };
        assert!(identity.byte_length > MAX_PINNED_FILE);
    }
}
