//! Fixed Linux containment primitive for an installed Strix worker.
//!
//! This module intentionally accepts no executable, argv, target, path, or
//! network destination from an engine request.  Its first callable operation
//! is a harmless kernel self-test of the controller-owned boundary.  The
//! production controller binds the resulting kernel facts into its separate,
//! durable worker-containment receipt.

#![cfg(target_os = "linux")]

use std::fs;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::ptr;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::strix_worker_boundary_cgroup::{
    members as cgroup_members, prepare as prepare_cgroup, read_trimmed, threads as cgroup_threads,
    CPU_MAX, MEMORY_MAX, MEMORY_OOM_GROUP, MEMORY_SWAP_MAX, PIDS_MAX,
};
use crate::strix_worker_boundary_channel::{
    recv_packet, recv_packet_with_fd, send_packet, send_packet_with_fd, set_timeout, socket_pair,
    OwnedFd,
};
use crate::strix_worker_boundary_contract::{
    CloneArgs, SelfTestReceipt, SetupPacket, SetupPacketRead, ThreadPacket, WorkerResult,
};
use crate::strix_worker_boundary_exec::{
    self as fixed_exec, ChildBootstrap, ExecSources, InputBinding,
};
use crate::strix_worker_boundary_identity::{acquire as acquire_identity, drop_privileges};
use crate::strix_worker_boundary_root::{self as private_root, InputFact, LaunchSocketFact};
use crate::strix_worker_boundary_seccomp::{
    arch as seccomp_arch, install as install_seccomp, probe as seccomp_probe,
};

const REFUSAL: &str = "the fixed Linux Strix worker boundary was refused";
const PROVIDER_REQUEST: &[u8] = b"provider-probe";
const PROVIDER_RESPONSE: &[u8] = b"provider-ok";
const CONTROL_REQUEST: &[u8] = b"control-path-probe";
const CONTROL_RESPONSE: &[u8] = b"control-path-ok";
const SELF_TEST_SCHEMA: &str = "bluefire.strix-worker-kernel-self-test.v1";
const WORKER_PAYLOAD_ID: &[u8] = b"bluefire.strix-worker-fixed-exec-kernel-self-test.v1";

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn last_error() -> String {
    format!("{REFUSAL}: {}", std::io::Error::last_os_error())
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn clone_worker(pidfd: &mut i32) -> Result<i32, String> {
    let mut args = CloneArgs {
        flags: (libc::CLONE_PIDFD
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWUTS) as u64,
        pidfd: (pidfd as *mut i32) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut args as *mut CloneArgs,
            size_of::<CloneArgs>(),
        ) as i32
    };
    if result < 0 {
        Err(last_error())
    } else {
        Ok(result)
    }
}

fn namespace_inode(kind: &str) -> Result<u64, String> {
    let inode = fs::metadata(format!("/proc/self/ns/{kind}"))
        .map_err(|_| REFUSAL)?
        .ino();
    require(inode > 0)?;
    Ok(inode)
}

fn observed_tgid(tid: i32) -> Result<i32, String> {
    let status = fs::read_to_string(format!("/proc/{tid}/status")).map_err(|_| REFUSAL)?;
    let row = status
        .lines()
        .find(|row| row.starts_with("Tgid:\t"))
        .ok_or(REFUSAL)?;
    let value = row
        .strip_prefix("Tgid:\t")
        .ok_or(REFUSAL)?
        .parse()
        .map_err(|_| REFUSAL)?;
    require(value > 1)?;
    Ok(value)
}

fn observed_namespace_tid(tid: i32) -> Result<i32, String> {
    let status = fs::read_to_string(format!("/proc/{tid}/status")).map_err(|_| REFUSAL)?;
    let row = status
        .lines()
        .find(|row| row.starts_with("NSpid:\t"))
        .ok_or(REFUSAL)?;
    let value = row
        .strip_prefix("NSpid:\t")
        .ok_or(REFUSAL)?
        .split_whitespace()
        .last()
        .ok_or(REFUSAL)?
        .parse()
        .map_err(|_| REFUSAL)?;
    require(value > 0)?;
    Ok(value)
}

fn bring_loopback_up() -> Result<(), String> {
    let socket = OwnedFd::checked(unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
    })?;
    let mut request = [0_u8; 40];
    request[..3].copy_from_slice(b"lo\0");
    require(
        unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, request.as_mut_ptr()) } == 0,
    )?;
    let mut flags = i16::from_ne_bytes([request[libc::IFNAMSIZ], request[libc::IFNAMSIZ + 1]]);
    flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
    request[libc::IFNAMSIZ..libc::IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());
    require(unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, request.as_ptr()) } == 0)
}

fn loopback_listener() -> Result<(OwnedFd, u16), String> {
    let listener = OwnedFd::checked(unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
    })?;
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
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
    require(unsafe { libc::listen(listener.as_raw_fd(), 1) } == 0)?;
    let mut observed: libc::sockaddr_in = unsafe { zeroed() };
    let mut length = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockname(
                listener.as_raw_fd(),
                (&mut observed as *mut libc::sockaddr_in).cast(),
                &mut length,
            )
        } == 0,
    )?;
    let port = u16::from_be(observed.sin_port);
    require(port > 0)?;
    Ok((listener, port))
}

fn connect_ipv4(address: [u8; 4], port: u16) -> Result<OwnedFd, i32> {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    let socket = OwnedFd::checked(raw).map_err(|_| 0)?;
    let target = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address),
        },
        sin_zero: [0; 8],
    };
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&target as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    } == 0
    {
        Ok(socket)
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }
}

fn stream_write_all(fd: RawFd, bytes: &[u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        let sent = unsafe {
            libc::send(
                fd,
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
                libc::MSG_NOSIGNAL,
            )
        };
        require(sent > 0)?;
        offset += sent as usize;
    }
    Ok(())
}

fn stream_read_exact(fd: RawFd, length: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0_u8; length];
    let mut offset = 0;
    while offset < length {
        let received =
            unsafe { libc::recv(fd, bytes[offset..].as_mut_ptr().cast(), length - offset, 0) };
        require(received > 0)?;
        offset += received as usize;
    }
    Ok(bytes)
}

fn thread_probe(control: RawFd) -> Result<(bool, bool), String> {
    let (release_sender, release_receiver) = std::sync::mpsc::sync_channel::<()>(0);
    let (tid_sender, tid_receiver) = std::sync::mpsc::sync_channel::<i32>(0);
    let main_tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
    let handle = std::thread::Builder::new()
        .name("boundary-probe".into())
        .spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
            let _ = tid_sender.send(tid);
            let _ = release_receiver.recv();
            tid
        })
        .map_err(|_| REFUSAL)?;
    let tid = tid_receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| REFUSAL)?;
    require(tid > 0 && tid != main_tid)?;
    send_packet(
        control,
        &serde_json::to_vec(&ThreadPacket {
            schema_version: "bluefire.strix-worker-thread-ready.v1".into(),
            tid,
        })
        .map_err(|_| REFUSAL)?,
    )?;
    require(recv_packet(control)? == b"thread-observed")?;
    release_sender.send(()).map_err(|_| REFUSAL)?;
    let joined = handle.join().map_err(|_| REFUSAL)?;
    Ok((true, joined == tid))
}

fn child_worker(bootstrap: ChildBootstrap) -> ! {
    let control = fixed_exec::CONTROL_FD;
    let outcome = (|| -> Result<(), String> {
        let host_pid: i32 = String::from_utf8(recv_packet(control)?)
            .map_err(|_| REFUSAL)?
            .parse()
            .map_err(|_| REFUSAL)?;
        require(host_pid > 1)?;
        let namespaces = (
            namespace_inode("mnt")?,
            namespace_inode("pid")?,
            namespace_inode("net")?,
            namespace_inode("ipc")?,
            namespace_inode("uts")?,
        );
        bring_loopback_up()?;
        let (listener, relay_port) = loopback_listener()?;
        private_root::mount_and_pivot(
            &bootstrap.private_root,
            [
                fixed_exec::OBJECTIVE_FD,
                fixed_exec::CONFIG_FD,
                fixed_exec::MCP_FD,
            ],
            bootstrap.uid,
            bootstrap.gid,
        )?;
        for fd in [
            fixed_exec::OBJECTIVE_FD,
            fixed_exec::CONFIG_FD,
            fixed_exec::MCP_FD,
            fixed_exec::BOOTSTRAP_FD,
        ] {
            require(unsafe { libc::close(fd) } == 0)?;
        }
        drop_privileges(bootstrap.uid, bootstrap.gid)?;
        let (launch_listener, launch_socket) =
            private_root::create_launch_listener(bootstrap.uid, bootstrap.gid)?;
        let seccomp_policy_digest = install_seccomp()?;
        require(unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1)?;
        require(
            unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) }
                == libc::SECCOMP_MODE_FILTER as i32,
        )?;
        let setup = SetupPacket {
            schema_version: "bluefire.strix-worker-kernel-setup.v1",
            host_pid,
            namespace_pid: unsafe { libc::getpid() },
            pid_namespace_isolated: false,
            pid_namespace_matches_controller: true,
            disposable_uid: bootstrap.uid,
            disposable_gid: bootstrap.gid,
            mount_namespace_inode: namespaces.0,
            pid_namespace_inode: namespaces.1,
            network_namespace_inode: namespaces.2,
            ipc_namespace_inode: namespaces.3,
            uts_namespace_inode: namespaces.4,
            relay_port,
            input_facts: bootstrap
                .inputs
                .iter()
                .map(input_fact_from_binding)
                .collect(),
            launch_socket,
            bootstrap_digest: bootstrap.bootstrap_digest.clone(),
            worker_executable_digest: bootstrap.helper_executable_digest.clone(),
            fresh_address_space: bootstrap.fresh_address_space,
            environment_empty: bootstrap.environment_empty,
            exact_fd_inventory: bootstrap.exact_fd_inventory,
            working_directory_is_root: bootstrap.working_directory_is_root,
            no_new_privileges: true,
            seccomp_mode: libc::SECCOMP_MODE_FILTER as i32,
            seccomp_tsync: true,
            seccomp_installed_before_threads: true,
            seccomp_arch: seccomp_arch(),
            seccomp_policy_digest,
            process_policy: "same_tgid_thread_only",
        };
        send_packet_with_fd(
            control,
            &serde_json::to_vec(&setup).map_err(|_| REFUSAL)?,
            listener.as_raw_fd(),
        )?;
        drop(listener);
        send_packet_with_fd(control, b"launch-listener", launch_listener.as_raw_fd())?;
        drop(launch_listener);
        require(recv_packet(control)? == b"run")?;
        let relay_allowed = match connect_ipv4([127, 0, 0, 1], relay_port) {
            Ok(socket) => {
                stream_write_all(socket.as_raw_fd(), PROVIDER_REQUEST).is_ok()
                    && stream_read_exact(socket.as_raw_fd(), PROVIDER_RESPONSE.len())
                        .ok()
                        .as_deref()
                        == Some(PROVIDER_RESPONSE)
            }
            Err(_) => false,
        };
        let control_path_allowed = match private_root::connect_launch_socket() {
            Ok(socket) => {
                send_packet(socket.as_raw_fd(), CONTROL_REQUEST).is_ok()
                    && recv_packet(socket.as_raw_fd()).ok().as_deref() == Some(CONTROL_RESPONSE)
            }
            Err(_) => false,
        };
        let (thread_allowed, thread_distinct) = thread_probe(control)?;
        let process_probe = seccomp_probe();
        let root_probe = private_root::probe_root();
        let result = WorkerResult {
            schema_version: "bluefire.strix-worker-kernel-self-test-result.v1".into(),
            sealed_inputs_read: root_probe.sealed_inputs_read,
            sealed_inputs_immutable: root_probe.sealed_inputs_immutable,
            private_roots_writable: root_probe.private_roots_writable,
            host_root_absent: !Path::new("/etc/passwd").exists()
                && !Path::new("/run/docker.sock").exists()
                && !Path::new("/root/.aws/credentials").exists(),
            proc_absent: !Path::new("/proc").exists(),
            same_tgid_thread_allowed: thread_allowed,
            thread_tid_distinct: thread_distinct,
            clone3_enosys: process_probe.clone3_enosys,
            non_thread_clone_refused: process_probe.non_thread_clone_refused,
            fork_refused: process_probe.fork_refused,
            vfork_refused: process_probe.vfork_refused,
            exec_refused: process_probe.exec_refused,
            public_network_refused: connect_ipv4([1, 1, 1, 1], 443).is_err(),
            metadata_network_refused: connect_ipv4([169, 254, 169, 254], 80).is_err(),
            controller_relay_allowed: relay_allowed,
            controller_control_path_allowed: control_path_allowed,
        };
        send_packet(control, &serde_json::to_vec(&result).map_err(|_| REFUSAL)?)?;
        loop {
            unsafe { libc::pause() };
        }
    })();
    if outcome.is_err() {
        let _ = send_packet(control, b"refused");
    }
    unsafe { libc::_exit(125) }
}

fn input_fact_from_binding(binding: &InputBinding) -> InputFact {
    InputFact {
        kind: binding.kind.clone(),
        path: format!("/inputs/{}.json", binding.kind),
        sha256: binding.digest.clone(),
        byte_length: binding.byte_length,
        device: binding.device,
        inode: binding.inode,
        seals: libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE,
        mode: 0o444,
    }
}

/// Entered only through the digest-pinned self-exec transition.
pub fn run_fixed_self_test_child(args: &[String]) -> Result<i32, String> {
    require(args.is_empty())?;
    child_worker(fixed_exec::load_child()?)
}

fn serve_provider(listener: RawFd) -> Result<(), String> {
    set_timeout(listener, 5)?;
    let accepted = OwnedFd::checked(unsafe {
        libc::accept4(
            listener,
            ptr::null_mut(),
            ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    })?;
    set_timeout(accepted.as_raw_fd(), 5)?;
    require(stream_read_exact(accepted.as_raw_fd(), PROVIDER_REQUEST.len())? == PROVIDER_REQUEST)?;
    stream_write_all(accepted.as_raw_fd(), PROVIDER_RESPONSE)
}

fn serve_control_path(listener: RawFd, pid: i32, uid: u32, gid: u32) -> Result<(), String> {
    set_timeout(listener, 5)?;
    let accepted = OwnedFd::checked(unsafe {
        libc::accept4(
            listener,
            ptr::null_mut(),
            ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    })?;
    set_timeout(accepted.as_raw_fd(), 5)?;
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockopt(
                accepted.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } == 0,
    )?;
    require(
        length as usize == size_of::<libc::ucred>()
            && credentials.pid == pid
            && credentials.uid == uid
            && credentials.gid == gid,
    )?;
    require(recv_packet(accepted.as_raw_fd())? == CONTROL_REQUEST)?;
    send_packet(accepted.as_raw_fd(), CONTROL_RESPONSE)
}

fn validate_launch_listener(listener: RawFd, fact: &LaunchSocketFact) -> Result<(), String> {
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(listener, &mut details) } == 0)?;
    let mut socket_type = 0_i32;
    let mut socket_domain = 0_i32;
    let mut accepts = 0_i32;
    let mut passcred = 0_i32;
    for (name, value) in [
        (libc::SO_TYPE, &mut socket_type),
        (libc::SO_DOMAIN, &mut socket_domain),
        (libc::SO_ACCEPTCONN, &mut accepts),
        (libc::SO_PASSCRED, &mut passcred),
    ] {
        let mut length = size_of::<i32>() as libc::socklen_t;
        require(
            unsafe {
                libc::getsockopt(
                    listener,
                    libc::SOL_SOCKET,
                    name,
                    (value as *mut i32).cast(),
                    &mut length,
                )
            } == 0,
        )?;
        require(length as usize == size_of::<i32>())?;
    }
    let mut bound: libc::sockaddr_un = unsafe { zeroed() };
    let mut bound_length = size_of::<libc::sockaddr_un>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockname(
                listener,
                (&mut bound as *mut libc::sockaddr_un).cast(),
                &mut bound_length,
            )
        } == 0,
    )?;
    let bound_path = bound
        .sun_path
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    require(
        fact.parent_path == "/control"
            && fact.parent_mode == 0o700
            && fact.socket_path == private_root::LAUNCH_SOCKET_PATH
            && fact.socket_mode == 0o600
            && fact.socket_type == "unix-seqpacket-listener"
            && fact.passcred_enabled
            && socket_type == libc::SOCK_SEQPACKET
            && socket_domain == libc::AF_UNIX
            && accepts == 1
            && passcred == 1
            && details.st_ino == fact.descriptor_inode
            && details.st_uid == fact.socket_uid
            && details.st_gid == fact.socket_gid
            && details.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && bound.sun_family == libc::AF_UNIX as libc::sa_family_t
            && bound_path == private_root::LAUNCH_SOCKET_PATH.as_bytes(),
    )
}

fn signal_pidfd(pidfd: RawFd, signal: i32) -> Result<(), String> {
    require(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                signal,
                ptr::null::<libc::siginfo_t>(),
                0,
            )
        } == 0,
    )
}

fn wait_terminal(pid: i32, pidfd: RawFd, require_sigkill: bool) -> Result<(), String> {
    let mut observed = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    require(unsafe { libc::poll(&mut observed, 1, 5_000) } == 1)?;
    require(observed.revents & libc::POLLIN != 0)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return require(
                (libc::WIFSIGNALED(status) || libc::WIFEXITED(status))
                    && (!require_sigkill
                        || (libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL)),
            );
        }
        require(waited == 0 && Instant::now() < deadline)?;
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_numeric_emergency(pid: i32) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return require(libc::WIFSIGNALED(status) || libc::WIFEXITED(status));
        }
        require(waited == 0 && Instant::now() < deadline)?;
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn cleanup_after_error(pid: i32, pidfd: RawFd, cgroup: Option<&Path>) -> bool {
    let _ = signal_pidfd(pidfd, libc::SIGKILL);
    if let Some(path) = cgroup {
        let _ = fs::write(path.join("cgroup.kill"), b"1");
    }
    wait_terminal(pid, pidfd, false).is_ok()
}

fn cancel_exact_cgroup(pid: i32, pidfd: RawFd, cgroup: &Path) -> Result<(), String> {
    signal_pidfd(pidfd, 0)?;
    fs::write(cgroup.join("cgroup.kill"), b"1").map_err(|_| REFUSAL)?;
    wait_terminal(pid, pidfd, true)
}

/// Execute the fixed, harmless worker-boundary proof.
///
/// It is root-only and fails closed when namespaces, clone3 pidfds, a delegated
/// cgroup-v2 leaf, a disposable numeric identity, or seccomp is unavailable.
pub fn run_fixed_self_test(args: &[String]) -> Result<i32, String> {
    require(args.is_empty() && unsafe { libc::geteuid() } == 0)?;
    let controller_namespaces = (
        namespace_inode("mnt")?,
        namespace_inode("pid")?,
        namespace_inode("net")?,
        namespace_inode("ipc")?,
        namespace_inode("uts")?,
    );
    let boundary_helper_digest = fixed_exec::current_executable_digest()?;
    let worker_payload_identity_digest = digest(WORKER_PAYLOAD_ID);
    require(boundary_helper_digest != worker_payload_identity_digest)?;
    let mut identity = acquire_identity()?;
    let (uid, gid) = (identity.uid, identity.gid);
    let inputs = private_root::create_sealed_inputs()?;
    let input_fds = inputs.fds();
    let input_facts = inputs.facts();
    let input_bindings = ["objective", "config", "mcp"]
        .into_iter()
        .zip(input_fds)
        .map(|(kind, fd)| fixed_exec::input_binding_fd(kind, fd))
        .collect::<Result<Vec<InputBinding>, String>>()?;
    let mut root = private_root::create_staging_root()?;
    let bootstrap = fixed_exec::build_bootstrap(
        root.path(),
        uid,
        gid,
        &boundary_helper_digest,
        input_bindings,
    )?;
    let bootstrap_fd = bootstrap.file.as_raw_fd();
    let bootstrap_digest = bootstrap.digest.clone();
    let executable = fixed_exec::open_current_executable()?;
    let (parent_control, child_control) = socket_pair()?;
    set_timeout(parent_control.as_raw_fd(), 10)?;
    set_timeout(child_control.as_raw_fd(), 10)?;
    let mut pidfd_raw = -1;
    let pid = clone_worker(&mut pidfd_raw)?;
    if pid == 0 {
        drop(parent_control);
        if recv_packet(child_control.as_raw_fd()).ok().as_deref() != Some(b"activate") {
            unsafe { libc::_exit(125) }
        }
        let result = fixed_exec::exec_fixed(
            ExecSources {
                executable: executable.as_raw_fd(),
                control: child_control.as_raw_fd(),
                objective: input_fds[0],
                config: input_fds[1],
                mcp: input_fds[2],
                bootstrap: bootstrap_fd,
            },
            &boundary_helper_digest,
        );
        if result.is_err() {
            let _ = send_packet(child_control.as_raw_fd(), b"refused");
        }
        unsafe { libc::_exit(125) }
    }
    drop(child_control);
    let pidfd = match OwnedFd::checked(pidfd_raw) {
        Ok(value) => value,
        Err(error) => {
            // The child is still our unreaped direct child and is blocked on
            // the private control socket. This is the only safe numeric-PID
            // emergency cleanup path when the kernel broke CLONE_PIDFD.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            if wait_numeric_emergency(pid).is_err() {
                identity.retain_for_recovery();
            }
            return Err(error);
        }
    };
    if pid <= 1 {
        let _ = cleanup_after_error(pid, pidfd.as_raw_fd(), None);
        identity.retain_for_recovery();
        return Err(REFUSAL.into());
    }
    let mut cgroup = match prepare_cgroup(pid) {
        Ok(value) => value,
        Err(error) => {
            let (message, mut partial) = error.into_parts();
            let cleaned = cleanup_after_error(
                pid,
                pidfd.as_raw_fd(),
                partial.as_ref().map(|leaf| leaf.path.as_path()),
            );
            let partial_removed = match partial.as_mut() {
                Some(leaf) if cleaned => leaf.remove().unwrap_or(false),
                Some(_) => false,
                None => true,
            };
            if !cleaned || !partial_removed {
                identity.retain_for_recovery();
            }
            return Err(message);
        }
    };
    let mut child_reaped = false;
    let outcome = (|| -> Result<SelfTestReceipt<'static>, String> {
        require(cgroup_members(&cgroup.path)? == vec![pid])?;
        send_packet(parent_control.as_raw_fd(), b"activate")?;
        send_packet(parent_control.as_raw_fd(), pid.to_string().as_bytes())?;
        let (setup_bytes, listener) = recv_packet_with_fd(parent_control.as_raw_fd())?;
        let setup: SetupPacketRead = serde_json::from_slice(&setup_bytes).map_err(|_| REFUSAL)?;
        require(setup.schema_version == "bluefire.strix-worker-kernel-setup.v1")?;
        require(setup.host_pid == pid && setup.namespace_pid == pid)?;
        require(
            !setup.pid_namespace_isolated
                && setup.pid_namespace_matches_controller
                && setup.pid_namespace_inode == controller_namespaces.1
                && setup.mount_namespace_inode != controller_namespaces.0
                && setup.network_namespace_inode != controller_namespaces.2
                && setup.ipc_namespace_inode != controller_namespaces.3
                && setup.uts_namespace_inode != controller_namespaces.4,
        )?;
        require(setup.disposable_uid == uid && setup.disposable_gid == gid)?;
        require(
            setup.input_facts == input_facts
                && setup.bootstrap_digest == bootstrap_digest
                && setup.worker_executable_digest == boundary_helper_digest
                && setup.fresh_address_space
                && setup.environment_empty
                && setup.exact_fd_inventory
                && setup.working_directory_is_root,
        )?;
        require(
            setup.launch_socket.parent_uid == uid
                && setup.launch_socket.parent_gid == gid
                && setup.launch_socket.socket_uid == uid
                && setup.launch_socket.socket_gid == gid,
        )?;
        require(
            setup.no_new_privileges
                && setup.seccomp_mode == libc::SECCOMP_MODE_FILTER as i32
                && setup.seccomp_tsync
                && setup.seccomp_installed_before_threads
                && setup.seccomp_arch == seccomp_arch(),
        )?;
        require(valid_digest(&setup.seccomp_policy_digest))?;
        require(setup.process_policy == "same_tgid_thread_only")?;
        require(cgroup_members(&cgroup.path)? == vec![pid])?;
        let (launch_label, launch_listener) = recv_packet_with_fd(parent_control.as_raw_fd())?;
        require(launch_label == b"launch-listener")?;
        validate_launch_listener(launch_listener.as_raw_fd(), &setup.launch_socket)?;
        send_packet(parent_control.as_raw_fd(), b"run")?;
        serve_provider(listener.as_raw_fd())?;
        serve_control_path(launch_listener.as_raw_fd(), pid, uid, gid)?;
        let thread_packet: ThreadPacket =
            serde_json::from_slice(&recv_packet(parent_control.as_raw_fd())?)
                .map_err(|_| REFUSAL)?;
        require(thread_packet.schema_version == "bluefire.strix-worker-thread-ready.v1")?;
        let tgids_during_thread = cgroup_members(&cgroup.path)?;
        let tids_during_thread = cgroup_threads(&cgroup.path)?;
        let current_during_thread: u32 = read_trimmed(&cgroup.path.join("pids.current"))?
            .parse()
            .map_err(|_| REFUSAL)?;
        require(tgids_during_thread == vec![pid])?;
        require(tids_during_thread.len() == 2 && tids_during_thread.contains(&pid))?;
        let host_thread_tid = *tids_during_thread
            .iter()
            .find(|tid| **tid != pid)
            .ok_or(REFUSAL)?;
        require(
            current_during_thread == 2
                && observed_tgid(host_thread_tid)? == pid
                && observed_namespace_tid(host_thread_tid)? == thread_packet.tid,
        )?;
        send_packet(parent_control.as_raw_fd(), b"thread-observed")?;
        let result: WorkerResult =
            serde_json::from_slice(&recv_packet(parent_control.as_raw_fd())?)
                .map_err(|_| REFUSAL)?;
        require(result.schema_version == "bluefire.strix-worker-kernel-self-test-result.v1")?;
        require(
            result.sealed_inputs_read
                && result.sealed_inputs_immutable
                && result.private_roots_writable
                && result.host_root_absent
                && result.proc_absent
                && result.same_tgid_thread_allowed
                && result.thread_tid_distinct
                && result.clone3_enosys
                && result.non_thread_clone_refused
                && result.fork_refused
                && result.vfork_refused
                && result.exec_refused
                && result.public_network_refused
                && result.metadata_network_refused
                && result.controller_relay_allowed
                && result.controller_control_path_allowed,
        )?;
        let tgids = cgroup_members(&cgroup.path)?;
        let tids = cgroup_threads(&cgroup.path)?;
        let current: u32 = read_trimmed(&cgroup.path.join("pids.current"))?
            .parse()
            .map_err(|_| REFUSAL)?;
        require(tgids == vec![pid] && tids == vec![pid] && current == 1)?;
        cancel_exact_cgroup(pid, pidfd.as_raw_fd(), &cgroup.path)?;
        child_reaped = true;
        require(
            cgroup_members(&cgroup.path)?.is_empty() && cgroup_threads(&cgroup.path)?.is_empty(),
        )?;
        Ok(SelfTestReceipt {
            schema_version: SELF_TEST_SCHEMA,
            mechanism: "clone3-pidfd-cgroupv2-namespaces-seccomp",
            host_pid: pid,
            namespace_pid: setup.namespace_pid,
            pid_namespace_isolated: false,
            pid_namespace_matches_controller: true,
            pidfd_owned_from_spawn: true,
            disposable_uid: uid,
            disposable_gid: gid,
            identity_lease_inode: identity.inode,
            cgroup_inode: cgroup.inode,
            cgroup_pids_max: PIDS_MAX,
            cgroup_pids_current_during_thread: current_during_thread,
            cgroup_tids_during_thread: tids_during_thread,
            namespace_thread_tid: thread_packet.tid,
            cgroup_pids_current_before_cancel: current,
            cgroup_tgids_before_cancel: tgids,
            cgroup_tids_before_cancel: tids,
            process_policy: "same_tgid_thread_only",
            memory_max: MEMORY_MAX,
            memory_swap_max: MEMORY_SWAP_MAX,
            memory_oom_group: MEMORY_OOM_GROUP,
            cpu_max: CPU_MAX,
            mount_namespace_inode: setup.mount_namespace_inode,
            pid_namespace_inode: setup.pid_namespace_inode,
            network_namespace_inode: setup.network_namespace_inode,
            ipc_namespace_inode: setup.ipc_namespace_inode,
            uts_namespace_inode: setup.uts_namespace_inode,
            relay_scope:
                "new-netns-loopback-worker-bootstrap-created-controller-retained-listener-only",
            relay_port: setup.relay_port,
            input_facts: setup.input_facts,
            launch_socket: setup.launch_socket,
            controller_retained_launch_listener: true,
            bootstrap_digest: setup.bootstrap_digest,
            no_new_privileges: setup.no_new_privileges,
            seccomp_mode: setup.seccomp_mode,
            seccomp_tsync: true,
            seccomp_installed_before_threads: true,
            seccomp_arch: seccomp_arch(),
            seccomp_policy_digest: setup.seccomp_policy_digest,
            boundary_helper_executable_digest: boundary_helper_digest.clone(),
            worker_executable_digest: boundary_helper_digest.clone(),
            worker_payload_identity_digest: worker_payload_identity_digest.clone(),
            helper_worker_executable_same: true,
            same_tgid_thread_allowed: result.same_tgid_thread_allowed,
            thread_tid_distinct: result.thread_tid_distinct,
            clone3_enosys: result.clone3_enosys,
            non_thread_clone_refused: result.non_thread_clone_refused,
            fork_refused: result.fork_refused,
            vfork_refused: result.vfork_refused,
            exec_refused: result.exec_refused,
            public_network_refused: result.public_network_refused,
            metadata_network_refused: result.metadata_network_refused,
            host_root_absent: result.host_root_absent,
            proc_absent: result.proc_absent,
            private_writes_succeeded: result.private_roots_writable,
            controller_relay_allowed: result.controller_relay_allowed,
            cancellation_identity_verified_with_spawn_pidfd: true,
            cancelled_via_exact_cgroup_kill: true,
            cgroup_empty_after_cancel: true,
            cgroup_removed: false,
            private_root_removed: false,
            identity_lease_released: false,
            sealed_input_fds_closed: false,
            bootstrap_fd_closed: false,
            environment_cleared: true,
            fresh_address_space: setup.fresh_address_space,
            self_exec_working_directory_is_root: setup.working_directory_is_root,
            ambient_credential_absence_proven: true,
            controller_control_path_allowed: result.controller_control_path_allowed,
            activation_eligible_for_fixed_harmless_worker: true,
            installed_strix_qualified: false,
        })
    })();
    let mut receipt = match outcome {
        Ok(receipt) => receipt,
        Err(error) => {
            let cleaned =
                child_reaped || cleanup_after_error(pid, pidfd.as_raw_fd(), Some(&cgroup.path));
            let cgroup_removed = cleaned && cgroup.remove().unwrap_or(false);
            let root_removed = cgroup_removed && root.remove().unwrap_or(false);
            let identity_released = root_removed && identity.release().unwrap_or(false);
            if !identity_released {
                identity.retain_for_recovery();
            }
            return Err(error);
        }
    };
    drop(inputs);
    receipt.sealed_input_fds_closed = input_fds.iter().all(|fd| {
        (unsafe { libc::fcntl(*fd, libc::F_GETFD) }) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
    });
    drop(bootstrap);
    receipt.bootstrap_fd_closed = (unsafe { libc::fcntl(bootstrap_fd, libc::F_GETFD) }) == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    drop(executable);
    receipt.cgroup_removed = cgroup.remove().unwrap_or(false);
    receipt.private_root_removed = receipt.cgroup_removed && root.remove().unwrap_or(false);
    receipt.identity_lease_released =
        receipt.private_root_removed && identity.release().unwrap_or(false);
    if !receipt.sealed_input_fds_closed
        || !receipt.bootstrap_fd_closed
        || !receipt.identity_lease_released
    {
        if !receipt.identity_lease_released {
            identity.retain_for_recovery();
        }
        return Err(REFUSAL.into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&receipt).map_err(|_| REFUSAL)?
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_policy_is_thread_compatible_but_process_bounded() {
        let required = libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM;
        assert_ne!(required & libc::CLONE_THREAD, 0);
        assert_eq!(PIDS_MAX, 16);
        assert_eq!(CPU_MAX, "100000 100000");
    }

    #[test]
    fn result_contract_rejects_unknown_fields() {
        let value = serde_json::json!({
            "schema_version": "bluefire.strix-worker-kernel-self-test-result.v1",
            "sealed_inputs_read": true,
            "sealed_inputs_immutable": true,
            "private_roots_writable": true,
            "host_root_absent": true,
            "proc_absent": true,
            "same_tgid_thread_allowed": true,
            "thread_tid_distinct": true,
            "clone3_enosys": true,
            "non_thread_clone_refused": true,
            "fork_refused": true,
            "vfork_refused": true,
            "exec_refused": true,
            "public_network_refused": true,
            "metadata_network_refused": true,
            "controller_relay_allowed": true,
            "controller_control_path_allowed": true,
            "unexpected": true
        });
        assert!(serde_json::from_value::<WorkerResult>(value).is_err());
    }
}
