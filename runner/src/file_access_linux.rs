//! Fresh owner inspection and credential-authenticated fixed non-owner IPC.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::Read;
use std::mem::{size_of, size_of_val, zeroed};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{require, FileAccessBinding, MAX_REPORT, REFUSAL};
use crate::canonical::{canonical_hash, canonical_json, sha256_hex};

fn bounded(path: &str, maximum: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| REFUSAL)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSAL)?;
    require(bytes.len() as u64 <= maximum)?;
    Ok(bytes)
}

fn start_ticks(pid: u32) -> Result<u64, String> {
    let bytes = bounded(&format!("/proc/{pid}/stat"), 4096)?;
    let value = std::str::from_utf8(&bytes).map_err(|_| REFUSAL)?;
    value
        .rsplit_once(')')
        .ok_or(REFUSAL)?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or(REFUSAL)?
        .parse()
        .map_err(|_| REFUSAL.into())
}

fn owner(binding: &FileAccessBinding) -> Result<Value, String> {
    let bytes = bounded("/proc/self/status", 16384)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| REFUSAL)?;
    let status: BTreeMap<_, _> = text
        .lines()
        .filter_map(|line| line.split_once(':'))
        .collect();
    for name in ["Uid", "Gid"] {
        require(
            status
                .get(name)
                .ok_or(REFUSAL)?
                .split_whitespace()
                .collect::<Vec<_>>()
                == ["1000"; 4],
        )?;
    }
    require(
        status.get("Groups").ok_or(REFUSAL)?.trim().is_empty()
            && status.get("NoNewPrivs").ok_or(REFUSAL)?.trim() == "1",
    )?;
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        require(
            u64::from_str_radix(status.get(name).ok_or(REFUSAL)?.trim(), 16)
                .map_err(|_| REFUSAL)?
                == 0,
        )?;
    }
    let mut namespaces = BTreeMap::new();
    for kind in ["mnt", "net", "pid", "ipc"] {
        let value = std::fs::read_link(format!("/proc/self/ns/{kind}"))
            .map_err(|_| REFUSAL)?
            .to_str()
            .ok_or(REFUSAL)?
            .to_owned();
        require(binding.worker.namespaces.get(kind) == Some(&value))?;
        namespaces.insert(kind, value);
    }
    Ok(
        json!({"uid":1000,"gid":1000,"pid":std::process::id(),"start_ticks":start_ticks(std::process::id())?,"namespaces":namespaces}),
    )
}

fn child(parent: &File, name: &str, directory: bool) -> Result<File, String> {
    let name = CString::new(name).map_err(|_| REFUSAL)?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    require(descriptor >= 0)?;
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn root(path: &str) -> Result<File, String> {
    let mut current = File::open("/").map_err(|_| REFUSAL)?;
    for component in Path::new(path).components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                current = child(&current, name.to_str().ok_or(REFUSAL)?, true)?
            }
            _ => return Err(REFUSAL.into()),
        }
    }
    Ok(current)
}

type FileIdentity = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

fn identity(metadata: &Metadata) -> FileIdentity {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.uid(),
        metadata.gid(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn verify_path_identity(
    path: &str,
    base_before: &Metadata,
    parent_before: &Metadata,
    before: &Metadata,
) -> Result<(), String> {
    let base = root(path)?;
    let parent = child(&base, "fixtures", true)?;
    let data = child(&parent, "transformed.jsonl", false)?;
    for (current, expected) in [
        (&data, before),
        (&parent, parent_before),
        (&base, base_before),
    ] {
        require(identity(&current.metadata().map_err(|_| REFUSAL)?) == identity(expected))?;
    }
    Ok(())
}

fn absent_acl(file: &File) -> Result<String, String> {
    for name in ["system.posix_acl_access", "system.posix_acl_default"] {
        let name = CString::new(name).map_err(|_| REFUSAL)?;
        let result =
            unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
        require(
            result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA),
        )?;
    }
    Ok(canonical_hash(
        &json!({"system.posix_acl_access":null,"system.posix_acl_default":null}),
    ))
}

fn resource(binding: &FileAccessBinding, deadline: Instant) -> Result<Value, String> {
    let expected = &binding.resource;
    let base = root(&expected.root)?;
    let base_before = base.metadata().map_err(|_| REFUSAL)?;
    let parent = child(&base, "fixtures", true)?;
    let parent_before = parent.metadata().map_err(|_| REFUSAL)?;
    let data = child(&parent, "transformed.jsonl", false)?;
    let before = data.metadata().map_err(|_| REFUSAL)?;
    for (value, device, inode) in [
        (&base_before, expected.root_device, expected.root_inode),
        (
            &parent_before,
            expected.parent_device,
            expected.parent_inode,
        ),
    ] {
        require(
            value.is_dir()
                && (
                    value.dev(),
                    value.ino(),
                    value.uid(),
                    value.gid(),
                    value.mode() & 0o7777,
                ) == (device, inode, 1000, 1002, 0o2710),
        )?;
    }
    require(
        before.is_file()
            && before.nlink() == 1
            && (
                before.dev(),
                before.ino(),
                before.uid(),
                before.gid(),
                before.len(),
            ) == (expected.device, expected.inode, 1000, 1002, expected.size)
            && format!("{:04o}", before.mode() & 0o7777) == binding.mode,
    )?;
    let acl = absent_acl(&data)?;
    let parent_acl = absent_acl(&parent)?;
    require(
        acl == expected.acl_digest
            && parent_acl == expected.parent_acl_digest
            && absent_acl(&base)? == parent_acl,
    )?;
    let mut bytes = Vec::new();
    (&data)
        .take(expected.size + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSAL)?;
    let digest = format!("sha256:{}", sha256_hex(&bytes));
    let text = std::str::from_utf8(&bytes).map_err(|_| REFUSAL)?;
    let records: Vec<_> = text.lines().collect();
    require(
        bytes.len() as u64 == expected.size
            && digest == expected.sha256
            && records.len() as u64 == expected.record_count,
    )?;
    for line in records {
        require(
            serde_json::from_str::<Value>(line)
                .map_err(|_| REFUSAL)?
                .is_object(),
        )?;
    }
    // Held descriptors alone do not prove that the named resource still resolves to them.
    verify_path_identity(&expected.root, &base_before, &parent_before, &before)?;
    require(
        identity(&data.metadata().map_err(|_| REFUSAL)?) == identity(&before)
            && identity(&parent.metadata().map_err(|_| REFUSAL)?) == identity(&parent_before)
            && identity(&base.metadata().map_err(|_| REFUSAL)?) == identity(&base_before)
            && Instant::now() < deadline,
    )?;
    Ok(
        json!({"root_device":expected.root_device,"root_inode":expected.root_inode,
        "parent_device":expected.parent_device,"parent_inode":expected.parent_inode,
        "device":before.dev(),"inode":before.ino(),"owner_uid":before.uid(),"group_gid":before.gid(),
        "mode":binding.mode,"sha256":digest,"size":bytes.len(),"record_count":expected.record_count,
        "acl_digest":acl,"parent_acl_digest":parent_acl}),
    )
}

#[cfg(test)]
#[path = "file_access_linux_tests.rs"]
mod tests;

fn probe(
    binding: &FileAccessBinding,
    request_hash: &str,
    challenge: &str,
    deadline: Instant,
) -> Result<Value, String> {
    let worker = &binding.worker;
    require(start_ticks(worker.pid)? == worker.start_ticks)?;
    let descriptor = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    require(descriptor >= 0)?;
    let socket = unsafe { File::from_raw_fd(descriptor) };
    let enabled: libc::c_int = 1;
    require(
        unsafe {
            libc::setsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } == 0,
    )?;
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    require(worker.socket_path.len() < address.sun_path.len())?;
    for (target, byte) in address.sun_path.iter_mut().zip(worker.socket_path.bytes()) {
        *target = byte as libc::c_char;
    }
    require(
        unsafe {
            libc::connect(
                descriptor,
                (&address as *const libc::sockaddr_un).cast(),
                size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        } == 0,
    )?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    require(!remaining.is_zero())?;
    let timeout = libc::timeval {
        tv_sec: remaining.as_secs() as libc::time_t,
        tv_usec: remaining.subsec_micros().max(1) as libc::suseconds_t,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        require(
            unsafe {
                libc::setsockopt(
                    descriptor,
                    libc::SOL_SOCKET,
                    option,
                    (&timeout as *const libc::timeval).cast(),
                    size_of::<libc::timeval>() as libc::socklen_t,
                )
            } == 0,
        )?;
    }
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    require(
        flags >= 0
            && unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags & !libc::O_NONBLOCK) } == 0,
    )?;
    let request = json!({"schema_version":"bluefire.file-access-probe-request.v1","operation":"read","launch_nonce":worker.launch_nonce,
        "request_hash":request_hash,"challenge":challenge,"binding":binding});
    let encoded = canonical_json(&request);
    require(
        encoded.len() <= MAX_REPORT
            && unsafe {
                libc::send(
                    descriptor,
                    encoded.as_ptr().cast(),
                    encoded.len(),
                    libc::MSG_NOSIGNAL,
                )
            } == encoded.len() as isize,
    )?;
    let mut payload = vec![0u8; MAX_REPORT + 1];
    let mut control = [0usize; 32];
    let mut vector = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control);
    let received = unsafe { libc::recvmsg(descriptor, &mut message, libc::MSG_CMSG_CLOEXEC) };
    require(received >= 0)?;
    let mut credentials = Vec::new();
    let mut unexpected = false;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let item = &*header;
            if item.cmsg_level == libc::SOL_SOCKET
                && item.cmsg_type == libc::SCM_CREDENTIALS
                && item.cmsg_len == libc::CMSG_LEN(size_of::<libc::ucred>() as u32) as usize
            {
                let peer = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>());
                credentials.push((peer.pid as u32, peer.uid, peer.gid));
            } else {
                unexpected = true;
                if item.cmsg_level == libc::SOL_SOCKET && item.cmsg_type == libc::SCM_RIGHTS {
                    let length = item.cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize)
                        / size_of::<libc::c_int>();
                    for index in 0..length {
                        libc::close(std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<libc::c_int>().add(index),
                        ));
                    }
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    drop(socket);
    require(
        received > 0
            && received as usize <= MAX_REPORT
            && !unexpected
            && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
            && credentials == [(worker.pid, worker.uid, worker.gid)]
            && start_ticks(worker.pid)? == worker.start_ticks
            && Instant::now() < deadline,
    )?;
    payload.truncate(received as usize);
    let response: Value = serde_json::from_slice(&payload).map_err(|_| REFUSAL)?;
    require(
        canonical_json(&response).as_bytes() == payload
            && response.as_object().is_some_and(|row| row.len() == 5)
            && response["schema_version"] == "bluefire.file-access-probe-response.v1"
            && response["request_hash"] == request_hash
            && response["challenge"] == challenge
            && response["binding_digest"]
                == canonical_hash(&serde_json::to_value(binding).map_err(|_| REFUSAL)?),
    )?;
    let result = &response["result"];
    require(
        result.as_object().is_some_and(|row| row.len() == 9)
            && result["read_handles_closed"] == true
            && result["device"] == binding.resource.device
            && result["inode"] == binding.resource.inode
            && result["size"] == binding.resource.size
            && result["mode"] == binding.mode
            && result["principal"]
                == json!({"uid":worker.uid,"gid":worker.gid,"pid":worker.pid,"start_ticks":worker.start_ticks,"namespaces":worker.namespaces}),
    )?;
    match result["outcome"].as_str() {
        Some("allowed") => require(
            result["sha256"] == binding.resource.sha256
                && result["record_count"] == binding.resource.record_count,
        )?,
        Some("permission_denied") => {
            require(result["sha256"].is_null() && result["record_count"].is_null())?
        }
        _ => return Err(REFUSAL.into()),
    }
    Ok(result.clone())
}

pub(super) fn observe(
    binding: &FileAccessBinding,
    request_hash: &str,
    is_owner: bool,
    timeout: Duration,
    execution_started: &Cell<bool>,
) -> Result<Value, String> {
    let deadline = Instant::now()
        .checked_add(timeout.min(Duration::from_secs(5)))
        .ok_or(REFUSAL)?;
    require(Instant::now() < deadline)?;
    execution_started.set(true);
    let principal = owner(binding)?;
    let before = resource(binding, deadline)?;
    let challenge = canonical_hash(&json!({"schema_version":"bluefire.file-access-challenge.v1", "request_hash":request_hash,
        "binding_digest":canonical_hash(&serde_json::to_value(binding).map_err(|_| REFUSAL)?),"launch_nonce":binding.worker.launch_nonce})).trim_start_matches("sha256:").to_string();
    let result = if is_owner {
        json!({"outcome":"allowed","sha256":binding.resource.sha256,"size":binding.resource.size,"record_count":binding.resource.record_count,"principal":principal})
    } else {
        probe(binding, request_hash, &challenge, deadline)?
    };
    require(resource(binding, deadline)? == before && owner(binding)? == principal)?;
    binding.current()?;
    Ok(
        json!({"schema_version":"bluefire.file-access-observation.v1","reader":if is_owner {"owner"} else {"non_owner"},
        "request_hash":request_hash,"challenge":challenge,"binding_digest":canonical_hash(&serde_json::to_value(binding).map_err(|_| REFUSAL)?),
        "resource_id":binding.resource_id,"resource_generation":binding.resource_generation,"control_revision":binding.control_revision,
        "observed_at_ms":crate::contract::utc_now().timestamp_millis(),"outcome":result["outcome"],"sha256":result["sha256"],
        "size":result["size"],"record_count":result["record_count"],"mode":binding.mode,"principal":result["principal"],"resource":before,
        "closure":{"state":"verified_closed","request_hash":request_hash,"challenge":challenge,"principal_digest":canonical_hash(&result["principal"])}}),
    )
}
