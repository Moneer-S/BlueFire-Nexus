//! Immutable runtime materialization and authenticated startup observations.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path};
use std::ptr;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::canonical::canonical_json;

const REFUSAL: &str = "the fixed installed Strix runtime support was refused";
const MANIFEST_SCHEMA: &str = "bluefire.strix-linux-runtime-native-manifest.v1";
const ENVELOPE_SCHEMA: &str = "bluefire.strix-fixed-exec-observation-envelope.v1";
const QUALIFIED_SCHEMA: &str = "bluefire.strix-linux-fixed-exec-receipt.v1";
const INPUT_SEALS: i32 =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
const MAX_MANIFEST: usize = 16 * 1024 * 1024;
const MAX_MEMBERS: usize = 65_536;
const MAX_FILE: u64 = 256 * 1024 * 1024;
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const SO_NETNS_COOKIE: libc::c_int = 71;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryRow {
    path: String,
    mode: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileRow {
    path: String,
    mode: u32,
    size: u64,
    content_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeManifest {
    schema_version: String,
    inventory_digest: String,
    directories: Vec<DirectoryRow>,
    files: Vec<FileRow>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ListenerFact {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) family: i32,
    pub(crate) socket_type: i32,
    pub(crate) accept_conn: bool,
    pub(crate) passcred: bool,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) netns_cookie: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ListenerFacts {
    pub(crate) endpoint_directory_device: u64,
    pub(crate) endpoint_directory_inode: u64,
    pub(crate) endpoint_directory_mode: u32,
    pub(crate) endpoint_directory_uid: u32,
    pub(crate) endpoint_directory_gid: u32,
    pub(crate) endpoint_path: EndpointPathFact,
    pub(crate) control: ListenerFact,
    pub(crate) model: ListenerFact,
    pub(crate) caido: ListenerFact,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct EndpointPathFact {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// The prepared v2 closure hashes Python's ensure_ascii JSON document, including
/// its terminal newline. Keep this local to the inventory: IPC and native
/// manifest identities use BlueFire's ordinary canonical JSON instead.
fn prepared_inventory_bytes(value: &Value) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let canonical = canonical_json(value);
    let mut output = Vec::with_capacity(canonical.len() + 1);
    for scalar in canonical.chars() {
        if scalar.is_ascii() {
            output.push(scalar as u8);
        } else {
            let mut units = [0_u16; 2];
            for unit in scalar.encode_utf16(&mut units).iter().copied() {
                output.extend_from_slice(b"\\u");
                for shift in [12, 8, 4, 0] {
                    output.push(HEX[((unit >> shift) & 0xf) as usize]);
                }
            }
        }
    }
    output.push(b'\n');
    output
}

fn inventory_digest_matches(value: &Value, expected: &str) -> bool {
    digest(&prepared_inventory_bytes(value)) == expected
        || digest(canonical_json(value).as_bytes()) == expected
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_relative(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= 512
        && !path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn read_fd(fd: RawFd, maximum: usize) -> Result<Vec<u8>, String> {
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd, &mut details) } == 0)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFREG
            && details.st_size >= 0
            && details.st_size as usize <= maximum,
    )?;
    let mut bytes = vec![0_u8; details.st_size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = unsafe {
            libc::pread(
                fd,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
                offset as _,
            )
        };
        require(count > 0)?;
        offset += count as usize;
    }
    Ok(bytes)
}

pub(crate) fn open_beneath(root: RawFd, path: &str, directory: bool) -> Result<OwnedFd, String> {
    require(safe_relative(path))?;
    let path = CString::new(path).map_err(|_| REFUSAL)?;
    let how = OpenHow {
        flags: (libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if directory { libc::O_DIRECTORY } else { 0 }) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root,
            path.as_ptr(),
            &how as *const OpenHow,
            size_of::<OpenHow>(),
        ) as RawFd
    };
    require(fd >= 0)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn exact_mode(path: &Path, mode: u32) -> Result<(), String> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    require(unsafe { libc::chmod(path.as_ptr(), mode) } == 0)
}

fn copy_file(source: RawFd, target: &Path, row: &FileRow) -> Result<(), String> {
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(source, &mut details) } == 0)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFREG
            && details.st_nlink == 1
            && details.st_size >= 0
            && details.st_size as u64 == row.size
            && row.size <= MAX_FILE,
    )?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(target)
        .map_err(|_| REFUSAL)?;
    let mut digest = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while offset < row.size {
        let count =
            usize::try_from((row.size - offset).min(buffer.len() as u64)).map_err(|_| REFUSAL)?;
        let read = unsafe { libc::pread(source, buffer.as_mut_ptr().cast(), count, offset as _) };
        require(read > 0)?;
        output
            .write_all(&buffer[..read as usize])
            .map_err(|_| REFUSAL)?;
        digest.update(&buffer[..read as usize]);
        offset += read as u64;
    }
    output.sync_all().map_err(|_| REFUSAL)?;
    require(format!("sha256:{:x}", digest.finalize()) == row.content_digest)?;
    exact_mode(target, row.mode)
}

/// Copy every manifest member through openat2 into a new helper-owned tmpfs.
pub(crate) fn materialize_closure(
    source_root: RawFd,
    manifest_fd: RawFd,
    target_root: &Path,
    expected_manifest_ref: &str,
    expected_inventory_digest: &str,
) -> Result<(), String> {
    require(unsafe { libc::fcntl(manifest_fd, libc::F_GET_SEALS) } == INPUT_SEALS)?;
    let manifest_bytes = read_fd(manifest_fd, MAX_MANIFEST)?;
    require(digest(&manifest_bytes) == expected_manifest_ref)?;
    let value: Value = serde_json::from_slice(&manifest_bytes).map_err(|_| REFUSAL)?;
    require(canonical_json(&value).as_bytes() == manifest_bytes)?;
    let manifest: NativeManifest = serde_json::from_value(value).map_err(|_| REFUSAL)?;
    require(
        manifest.schema_version == MANIFEST_SCHEMA
            && manifest.inventory_digest == expected_inventory_digest
            && valid_digest(&manifest.inventory_digest)
            && manifest.directories.len() <= MAX_MEMBERS
            && manifest.files.len() <= MAX_MEMBERS,
    )?;
    let mut directory_paths = Vec::new();
    for row in &manifest.directories {
        require(safe_relative(&row.path) && row.mode == 0o555)?;
        directory_paths.push(row.path.as_str());
    }
    let mut file_paths = Vec::new();
    for row in &manifest.files {
        require(
            safe_relative(&row.path)
                && matches!(row.mode, 0o444 | 0o555)
                && valid_digest(&row.content_digest),
        )?;
        file_paths.push(row.path.as_str());
    }
    let mut sorted_directories = directory_paths.clone();
    sorted_directories.sort_unstable();
    sorted_directories.dedup();
    require(sorted_directories == directory_paths)?;
    let mut sorted_files = file_paths.clone();
    sorted_files.sort_unstable();
    sorted_files.dedup();
    require(sorted_files == file_paths)?;
    require(!directory_paths.iter().any(|path| file_paths.contains(path)))?;
    for row in &manifest.directories {
        if let Some(parent) = Path::new(&row.path).parent() {
            let parent = parent.to_str().ok_or(REFUSAL)?;
            if !parent.is_empty() {
                require(directory_paths.contains(&parent))?;
            }
        }
    }
    for row in &manifest.files {
        if let Some(parent) = Path::new(&row.path).parent() {
            let parent = parent.to_str().ok_or(REFUSAL)?;
            if !parent.is_empty() {
                require(directory_paths.contains(&parent))?;
            }
        }
    }
    let target = CString::new(target_root.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    let fs_name = CString::new("tmpfs").map_err(|_| REFUSAL)?;
    let options = CString::new("mode=0755,size=4g").map_err(|_| REFUSAL)?;
    require(
        unsafe {
            libc::mount(
                fs_name.as_ptr(),
                target.as_ptr(),
                fs_name.as_ptr(),
                (libc::MS_NOSUID | libc::MS_NODEV) as _,
                options.as_ptr().cast(),
            )
        } == 0,
    )?;
    for row in &manifest.directories {
        let source = open_beneath(source_root, &row.path, true)?;
        let mut details: libc::stat = unsafe { zeroed() };
        require(unsafe { libc::fstat(source.as_raw_fd(), &mut details) } == 0)?;
        require(details.st_mode & libc::S_IFMT == libc::S_IFDIR)?;
        let path = target_root.join(&row.path);
        fs::create_dir(&path).map_err(|_| REFUSAL)?;
        exact_mode(&path, row.mode)?;
    }
    for row in &manifest.files {
        let source = open_beneath(source_root, &row.path, false)?;
        copy_file(source.as_raw_fd(), &target_root.join(&row.path), row)?;
    }
    let total_bytes = manifest.files.iter().try_fold(0_u64, |total, row| {
        total
            .checked_add(row.size)
            .ok_or_else(|| REFUSAL.to_string())
    })?;
    require(total_bytes <= 4 * 1024 * 1024 * 1024)?;
    let inventory = json!({
        "schema_version": "bluefire.strix-linux-runtime-inventory.v1",
        "directories": manifest.directories,
        "files": manifest.files,
        "total_bytes": total_bytes,
    });
    require(inventory_digest_matches(
        &inventory,
        expected_inventory_digest,
    ))
}

pub(crate) fn seal_closure_root(root: &Path) -> Result<(), String> {
    let root = CString::new(root.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    require(
        unsafe {
            libc::mount(
                ptr::null(),
                root.as_ptr(),
                ptr::null(),
                (libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV) as _,
                ptr::null(),
            )
        } == 0,
    )
}

pub(crate) fn send_packet(channel: RawFd, payload: &[u8], rights: &[RawFd]) -> Result<(), String> {
    require(!payload.is_empty() && payload.len() <= 64 * 1024 && rights.len() <= 16)?;
    let mut control = vec![
        0_u8;
        if rights.is_empty() {
            0
        } else {
            unsafe { libc::CMSG_SPACE((rights.len() * size_of::<RawFd>()) as _) as usize }
        }
    ];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    if !rights.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            require(!header.is_null())?;
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN((rights.len() * size_of::<RawFd>()) as _) as usize;
            ptr::copy_nonoverlapping(
                rights.as_ptr().cast(),
                libc::CMSG_DATA(header),
                rights.len() * size_of::<RawFd>(),
            );
            message.msg_controllen = control.len();
        }
    }
    require(
        unsafe { libc::sendmsg(channel, &message, libc::MSG_NOSIGNAL) } == payload.len() as isize,
    )
}

pub(crate) fn receive_packet(
    channel: RawFd,
    right_count: usize,
    expected_credentials: (i32, u32, u32),
) -> Result<(Vec<u8>, Vec<OwnedFd>), String> {
    require(right_count <= 16)?;
    let rights_space = if right_count == 0 {
        0
    } else {
        unsafe { libc::CMSG_SPACE((right_count * size_of::<RawFd>()) as _) as usize }
    };
    let mut control = vec![
        0_u8;
        rights_space
            + unsafe { libc::CMSG_SPACE(size_of::<libc::ucred>() as _) as usize }
    ];
    let mut payload = vec![0_u8; 64 * 1024];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let read = unsafe { libc::recvmsg(channel, &mut message, libc::MSG_CMSG_CLOEXEC) };
    require(read > 0 && message.msg_flags == 0)?;
    payload.truncate(read as usize);
    let mut received = Vec::new();
    let mut credentials = None;
    let mut rights_seen = 0_u8;
    let mut credentials_seen = 0_u8;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                rights_seen = rights_seen.checked_add(1).ok_or(REFUSAL)?;
                let bytes = (*header).cmsg_len - libc::CMSG_LEN(0) as usize;
                require(bytes == right_count * size_of::<RawFd>())?;
                let data = libc::CMSG_DATA(header).cast::<RawFd>();
                for index in 0..right_count {
                    received.push(OwnedFd::from_raw_fd(*data.add(index)));
                }
            } else if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_CREDENTIALS
            {
                credentials_seen = credentials_seen.checked_add(1).ok_or(REFUSAL)?;
                credentials = Some(*libc::CMSG_DATA(header).cast::<libc::ucred>());
            } else {
                return Err(REFUSAL.into());
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    require(credentials_seen == 1 && rights_seen == u8::from(right_count > 0))?;
    let observed = credentials.ok_or(REFUSAL)?;
    require((observed.pid, observed.uid, observed.gid) == expected_credentials)?;
    require(received.len() == right_count)?;
    Ok((payload, received))
}

pub(crate) fn wait_readable(
    channel: RawFd,
    pidfd: RawFd,
    cancellation: RawFd,
    deadline: Instant,
) -> Result<(), String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    require(!remaining.is_zero())?;
    let timeout =
        i32::try_from(remaining.as_millis().min(i32::MAX as u128)).map_err(|_| REFUSAL)?;
    let mut rows = [
        libc::pollfd {
            fd: channel,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: cancellation,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    require(unsafe { libc::poll(rows.as_mut_ptr(), rows.len() as _, timeout) } > 0)?;
    require(rows[0].revents == libc::POLLIN && rows[1].revents == 0 && rows[2].revents == 0)
}

fn descriptor_cloexec(fd: RawFd) -> Result<bool, String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    require(flags >= 0)?;
    Ok(flags & libc::FD_CLOEXEC != 0)
}

fn socket_option(fd: RawFd, name: libc::c_int) -> Result<libc::c_int, String> {
    let mut value = 0;
    let mut size = size_of::<libc::c_int>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                name,
                (&mut value as *mut libc::c_int).cast(),
                &mut size,
            )
        } == 0,
    )?;
    require(size as usize == size_of::<libc::c_int>())?;
    Ok(value)
}

fn netns_cookie(fd: RawFd) -> Result<u64, String> {
    let mut value = 0_u64;
    let mut size = size_of::<u64>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_NETNS_COOKIE,
                (&mut value as *mut u64).cast(),
                &mut size,
            )
        } == 0,
    )?;
    require(value > 0 && size as usize == size_of::<u64>())?;
    Ok(value)
}

fn listener_stat(fd: RawFd) -> Result<(u64, u64), String> {
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd, &mut details) } == 0)?;
    require(details.st_mode & libc::S_IFMT == libc::S_IFSOCK)?;
    Ok((details.st_dev, details.st_ino))
}

fn tcp_fact(fd: RawFd, port: u16) -> Result<ListenerFact, String> {
    let mut address: libc::sockaddr_in = unsafe { zeroed() };
    let mut size = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_in).cast(),
                &mut size,
            )
        } == 0,
    )?;
    let (device, inode) = listener_stat(fd)?;
    require(
        address.sin_family == libc::AF_INET as u16
            && address.sin_port == port.to_be()
            && address.sin_addr.s_addr.to_ne_bytes() == [127, 0, 0, 1]
            && socket_option(fd, libc::SO_TYPE)? == libc::SOCK_STREAM
            && socket_option(fd, libc::SO_DOMAIN)? == libc::AF_INET
            && socket_option(fd, libc::SO_ACCEPTCONN)? == 1
            && socket_option(fd, libc::SO_PASSCRED)? == 0
            && descriptor_cloexec(fd)?,
    )?;
    Ok(ListenerFact {
        device,
        inode,
        family: libc::AF_INET,
        socket_type: libc::SOCK_STREAM,
        accept_conn: true,
        passcred: false,
        address: "127.0.0.1".into(),
        port,
        netns_cookie: netns_cookie(fd)?,
    })
}

fn control_fact(fd: RawFd, expected_path: &str) -> Result<ListenerFact, String> {
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    let mut size = size_of::<libc::sockaddr_un>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_un).cast(),
                &mut size,
            )
        } == 0,
    )?;
    let path = address
        .sun_path
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    let (device, inode) = listener_stat(fd)?;
    require(
        address.sun_family == libc::AF_UNIX as libc::sa_family_t
            && path == expected_path.as_bytes()
            && socket_option(fd, libc::SO_TYPE)? == libc::SOCK_SEQPACKET
            && socket_option(fd, libc::SO_DOMAIN)? == libc::AF_UNIX
            && socket_option(fd, libc::SO_ACCEPTCONN)? == 1
            && socket_option(fd, libc::SO_PASSCRED)? == 1
            && descriptor_cloexec(fd)?,
    )?;
    Ok(ListenerFact {
        device,
        inode,
        family: libc::AF_UNIX,
        socket_type: libc::SOCK_SEQPACKET,
        accept_conn: true,
        passcred: true,
        address: expected_path.into(),
        port: 0,
        netns_cookie: netns_cookie(fd)?,
    })
}

pub(crate) fn verify_listeners(
    endpoint: RawFd,
    control: RawFd,
    model: RawFd,
    caido: RawFd,
    uid: u32,
    gid: u32,
    control_path: &str,
    model_port: u16,
    caido_port: u16,
) -> Result<ListenerFacts, String> {
    let mut directory: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(endpoint, &mut directory) } == 0)?;
    require(
        directory.st_mode & libc::S_IFMT == libc::S_IFDIR
            && directory.st_mode & 0o777 == 0o700
            && directory.st_uid == uid
            && directory.st_gid == gid
            && descriptor_cloexec(endpoint)?,
    )?;
    let mut path: libc::stat = unsafe { zeroed() };
    require(
        unsafe {
            libc::fstatat(
                endpoint,
                b"controller.sock\0".as_ptr().cast(),
                &mut path,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0,
    )?;
    require(
        path.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && path.st_mode & 0o777 == 0o600
            && path.st_uid == uid
            && path.st_gid == gid,
    )?;
    let control = control_fact(control, control_path)?;
    let model = tcp_fact(model, model_port)?;
    let caido = tcp_fact(caido, caido_port)?;
    require(
        control.netns_cookie == model.netns_cookie && model.netns_cookie == caido.netns_cookie,
    )?;
    Ok(ListenerFacts {
        endpoint_directory_device: directory.st_dev,
        endpoint_directory_inode: directory.st_ino,
        endpoint_directory_mode: directory.st_mode & 0o777,
        endpoint_directory_uid: directory.st_uid,
        endpoint_directory_gid: directory.st_gid,
        endpoint_path: EndpointPathFact {
            device: path.st_dev,
            inode: path.st_ino,
            mode: path.st_mode & 0o777,
            uid: path.st_uid,
            gid: path.st_gid,
        },
        control,
        model,
        caido,
    })
}

pub(crate) fn sealed_basis(value: &Value) -> Result<(File, String), String> {
    let bytes = canonical_json(value).into_bytes();
    require(!bytes.is_empty() && bytes.len() <= MAX_MANIFEST)?;
    let name = CString::new("bluefire-strix-native-basis").map_err(|_| REFUSAL)?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        ) as RawFd
    };
    require(fd >= 0)?;
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&bytes).map_err(|_| REFUSAL)?;
    file.sync_all().map_err(|_| REFUSAL)?;
    require(unsafe { libc::fchmod(fd, 0o400) } == 0)?;
    require(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, INPUT_SEALS) } == 0)?;
    Ok((file, digest(&bytes)))
}

fn envelope(payload: &[u8], phase: &str, expected: &Value) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(payload).map_err(|_| REFUSAL)?;
    require(canonical_json(&value).as_bytes() == payload)?;
    let row = value.as_object().ok_or(REFUSAL)?;
    require(row.len() == 4)?;
    require(row.get("schema_version") == Some(&json!(ENVELOPE_SCHEMA)))?;
    require(row.get("phase") == Some(&json!(phase)))?;
    let body = row.get("payload").ok_or(REFUSAL)?;
    require(row.get("payload_ref") == Some(&json!(digest(canonical_json(body).as_bytes()))))?;
    if phase == "armed" {
        require(body == expected)?;
    }
    Ok(body.clone())
}

pub(crate) fn await_two_phase(
    channel: RawFd,
    pidfd: RawFd,
    cancellation: RawFd,
    credentials: (i32, u32, u32),
    deadline: Instant,
    armed: &Value,
    qualified_receipt_base: &Value,
) -> Result<Value, String> {
    wait_readable(channel, pidfd, cancellation, deadline)?;
    let (packet, rights) = receive_packet(channel, 0, credentials)?;
    require(rights.is_empty())?;
    envelope(&packet, "armed", armed)?;
    wait_readable(channel, pidfd, cancellation, deadline)?;
    let (packet, rights) = receive_packet(channel, 0, credentials)?;
    require(rights.is_empty())?;
    let payload = envelope(&packet, "qualified", &Value::Null)?;
    let mut expected = qualified_receipt_base.as_object().cloned().ok_or(REFUSAL)?;
    require(expected.get("schema_version") == Some(&json!(QUALIFIED_SCHEMA)))?;
    for name in [
        "startup_imports_verified",
        "required_threads_verified",
        "exec_process_probes_refused",
        "seccomp_tsync_armed",
        "no_new_privileges",
        "production_activation_eligible",
    ] {
        require(expected.insert(name.into(), Value::Bool(true)).is_none())?;
    }
    let receipt_ref = digest(canonical_json(&Value::Object(expected.clone())).as_bytes());
    require(
        expected
            .insert("receipt_ref".into(), json!(receipt_ref))
            .is_none(),
    )?;
    require(payload == Value::Object(expected))?;
    let row = payload.as_object().ok_or(REFUSAL)?;
    let receipt_ref = row
        .get("receipt_ref")
        .and_then(Value::as_str)
        .ok_or(REFUSAL)?;
    require(valid_digest(receipt_ref))?;
    let mut unsigned = row.clone();
    unsigned.remove("receipt_ref");
    require(receipt_ref == digest(canonical_json(&Value::Object(unsigned)).as_bytes()))?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    require(!remaining.is_zero())?;
    let timeout =
        i32::try_from(remaining.as_millis().min(i32::MAX as u128)).map_err(|_| REFUSAL)?;
    let mut poll = [
        libc::pollfd {
            fd: channel,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        },
        libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: cancellation,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    require(unsafe { libc::poll(poll.as_mut_ptr(), poll.len() as _, timeout) } > 0)?;
    require(
        poll[0].revents & (libc::POLLIN | libc::POLLHUP) != 0
            && poll[1].revents == 0
            && poll[2].revents == 0,
    )?;
    let mut extra = [0_u8; 1];
    require(unsafe { libc::recv(channel, extra.as_mut_ptr().cast(), 1, 0) } == 0)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_inventory_digest_matches_python_unicode_document() {
        // Fixed vectors from tools.strix_runtime_closure_common._document_bytes
        // and the legacy content_hash serializer, not values calculated by Rust.
        let inventory = json!({
            "schema_version": "bluefire.strix-linux-runtime-inventory.v1",
            "directories": [{"path": "runtime", "mode": 365}],
            "files": [{
                "path": "runtime/café-🧪.py",
                "mode": 292,
                "size": 3,
                "content_digest": format!("sha256:{}", "0".repeat(64)),
            }],
            "total_bytes": 3,
        });
        let prepared = prepared_inventory_bytes(&inventory);
        assert!(prepared.is_ascii());
        assert!(prepared.ends_with(b"\n"));
        assert!(String::from_utf8(prepared.clone())
            .unwrap()
            .contains(r"caf\u00e9-\ud83e\uddea.py"));
        let v2 = "sha256:4e5b052c3d73e73e2f2bc5c2989476092773bff98ead02e710c10ef26c604f6b";
        let v1 = "sha256:f3e147c5893c81f645fc5091bbdc69434aa6de4e59143d0e3641a614112b6262";
        assert_eq!(digest(&prepared), v2);
        assert_eq!(digest(canonical_json(&inventory).as_bytes()), v1);
        assert!(inventory_digest_matches(&inventory, v2));
        assert!(inventory_digest_matches(&inventory, v1));
        assert!(!inventory_digest_matches(
            &inventory,
            &format!("sha256:{}", "f".repeat(64)),
        ));
    }
}
