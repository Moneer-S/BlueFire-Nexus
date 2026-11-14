//! Fixed private-root, sealed-input, and launch-socket primitives.
//!
//! No caller-selected guest path or content is accepted.  Production input
//! bytes are delivered through the same three fixed sealed descriptors; this
//! first helper exposes fixed harmless bytes for the kernel self-test.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::ptr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REFUSAL: &str = "the fixed Linux Strix worker boundary was refused";
const ROOT_SIZE: &str = "mode=0755,size=32m";
const INPUT_SEALS: i32 =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
pub(crate) const OBJECTIVE_BYTES: &[u8] = b"{\"objective\":\"bluefire-worker-boundary-self-test\"}";
pub(crate) const CONFIG_BYTES: &[u8] = b"{\"provider\":\"controller-relay-self-test\"}";
pub(crate) const MCP_BYTES: &[u8] = b"{\"tools\":[\"harmless-self-test\"]}";
pub(crate) const LAUNCH_SOCKET_PATH: &str = "/control/launch.sock";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputFact {
    pub(crate) kind: String,
    pub(crate) path: String,
    pub(crate) sha256: String,
    pub(crate) byte_length: u64,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) seals: i32,
    pub(crate) mode: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LaunchSocketFact {
    pub(crate) parent_path: String,
    pub(crate) parent_uid: u32,
    pub(crate) parent_gid: u32,
    pub(crate) parent_mode: u32,
    pub(crate) parent_inode: u64,
    pub(crate) socket_path: String,
    pub(crate) socket_uid: u32,
    pub(crate) socket_gid: u32,
    pub(crate) socket_mode: u32,
    pub(crate) socket_inode: u64,
    pub(crate) descriptor_inode: u64,
    pub(crate) socket_type: String,
    pub(crate) passcred_enabled: bool,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct RootProbe {
    pub(crate) sealed_inputs_read: bool,
    pub(crate) sealed_inputs_immutable: bool,
    pub(crate) private_roots_writable: bool,
    pub(crate) proc_absent: bool,
}

pub(crate) struct SealedInputs {
    files: [File; 3],
    facts: [InputFact; 3],
}

impl SealedInputs {
    pub(crate) fn fds(&self) -> [RawFd; 3] {
        [
            self.files[0].as_raw_fd(),
            self.files[1].as_raw_fd(),
            self.files[2].as_raw_fd(),
        ]
    }

    pub(crate) fn facts(&self) -> Vec<InputFact> {
        self.facts.to_vec()
    }
}

pub(crate) struct RootStaging {
    path: PathBuf,
}

impl RootStaging {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn remove(&mut self) -> Result<bool, String> {
        let path = self.path.clone();
        fs::remove_dir(&path).map_err(|_| REFUSAL)?;
        self.path = PathBuf::new();
        Ok(!path.exists())
    }
}

impl Drop for RootStaging {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

pub(crate) struct OwnedSocket(RawFd);

impl OwnedSocket {
    fn checked(fd: RawFd) -> Result<Self, String> {
        if fd < 0 {
            Err(REFUSAL.into())
        } else {
            Ok(Self(fd))
        }
    }
}

impl AsRawFd for OwnedSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe { libc::close(self.0) };
            self.0 = -1;
        }
    }
}

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn create_input(kind: &str, path: &str, bytes: &[u8]) -> Result<(File, InputFact), String> {
    let name = CString::new(format!("bluefire-strix-{kind}")).map_err(|_| REFUSAL)?;
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        ) as RawFd
    };
    require(raw >= 0)?;
    let mut file = unsafe { File::from_raw_fd(raw) };
    file.write_all(bytes).map_err(|_| REFUSAL)?;
    file.sync_all().map_err(|_| REFUSAL)?;
    require(unsafe { libc::fchmod(raw, 0o444) } == 0)?;
    require(unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, INPUT_SEALS) } == 0)?;
    require(unsafe { libc::fcntl(raw, libc::F_GET_SEALS) } == INPUT_SEALS)?;
    let metadata = file.metadata().map_err(|_| REFUSAL)?;
    require(
        metadata.is_file()
            && metadata.nlink() == 0
            && metadata.mode() & 0o777 == 0o444
            && metadata.len() == bytes.len() as u64
            && metadata.ino() > 0,
    )?;
    Ok((
        file,
        InputFact {
            kind: kind.into(),
            path: path.into(),
            sha256: sha256(bytes),
            byte_length: bytes.len() as u64,
            device: metadata.dev(),
            inode: metadata.ino(),
            seals: INPUT_SEALS,
            mode: 0o444,
        },
    ))
}

pub(crate) fn create_sealed_inputs() -> Result<SealedInputs, String> {
    let (objective, objective_fact) =
        create_input("objective", "/inputs/objective.json", OBJECTIVE_BYTES)?;
    let (config, config_fact) = create_input("config", "/inputs/config.json", CONFIG_BYTES)?;
    let (mcp, mcp_fact) = create_input("mcp", "/inputs/mcp.json", MCP_BYTES)?;
    Ok(SealedInputs {
        files: [objective, config, mcp],
        facts: [objective_fact, config_fact, mcp_fact],
    })
}

pub(crate) fn create_staging_root() -> Result<RootStaging, String> {
    let path = PathBuf::from(format!("/tmp/bluefire-strix-worker-root-{}", unsafe {
        libc::getpid()
    }));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(&path).map_err(|_| REFUSAL)?;
    let staging = RootStaging { path };
    exact_owner(staging.path(), 0, 0)?;
    exact_mode(staging.path(), 0o700)?;
    let metadata = fs::symlink_metadata(staging.path()).map_err(|_| REFUSAL)?;
    require(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o777 == 0o700,
    )?;
    Ok(staging)
}

fn exact_mode(path: &Path, mode: u32) -> Result<(), String> {
    let value = CString::new(path.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    require(unsafe { libc::chmod(value.as_ptr(), mode) } == 0)
}

fn exact_owner(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let value = CString::new(path.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    require(unsafe { libc::chown(value.as_ptr(), uid, gid) } == 0)
}

fn bind_input(root: &Path, fact: &InputFact, fd: RawFd) -> Result<(), String> {
    require(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } == INPUT_SEALS)?;
    let target_path = root.join(fact.path.trim_start_matches('/'));
    File::create(&target_path).map_err(|_| REFUSAL)?;
    let source = CString::new(format!("/proc/self/fd/{fd}")).map_err(|_| REFUSAL)?;
    let target = CString::new(target_path.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    require(
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                ptr::null(),
                libc::MS_BIND as _,
                ptr::null(),
            )
        } == 0,
    )?;
    require(
        unsafe {
            libc::mount(
                ptr::null(),
                target.as_ptr(),
                ptr::null(),
                (libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY
                    | libc::MS_NODEV
                    | libc::MS_NOSUID
                    | libc::MS_NOEXEC) as _,
                ptr::null(),
            )
        } == 0,
    )?;
    let metadata = fs::metadata(&target_path).map_err(|_| REFUSAL)?;
    require(
        metadata.dev() == fact.device
            && metadata.ino() == fact.inode
            && metadata.len() == fact.byte_length
            && metadata.mode() & 0o777 == fact.mode,
    )
}

pub(crate) fn mount_and_pivot(
    root: &Path,
    input_fds: [RawFd; 3],
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    require(
        unsafe {
            libc::mount(
                ptr::null(),
                c"/".as_ptr(),
                ptr::null(),
                (libc::MS_REC | libc::MS_PRIVATE) as _,
                ptr::null(),
            )
        } == 0,
    )?;
    let root_c = CString::new(root.as_os_str().as_bytes()).map_err(|_| REFUSAL)?;
    let tmpfs = CString::new("tmpfs").map_err(|_| REFUSAL)?;
    let options = CString::new(ROOT_SIZE).map_err(|_| REFUSAL)?;
    require(
        unsafe {
            libc::mount(
                tmpfs.as_ptr(),
                root_c.as_ptr(),
                tmpfs.as_ptr(),
                (libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC) as _,
                options.as_ptr().cast(),
            )
        } == 0,
    )?;
    for relative in [
        "inputs",
        "home",
        "home/worker",
        "tmp",
        "config",
        "workspace",
        "control",
        ".old",
    ] {
        fs::create_dir(root.join(relative)).map_err(|_| REFUSAL)?;
    }
    exact_mode(&root.join("inputs"), 0o555)?;
    exact_mode(&root.join("home"), 0o755)?;
    for relative in ["home/worker", "tmp", "config", "workspace", "control"] {
        let path = root.join(relative);
        exact_owner(&path, uid, gid)?;
        exact_mode(&path, 0o700)?;
    }
    let specs = [
        ("objective", "/inputs/objective.json", OBJECTIVE_BYTES),
        ("config", "/inputs/config.json", CONFIG_BYTES),
        ("mcp", "/inputs/mcp.json", MCP_BYTES),
    ];
    for ((kind, path, bytes), fd) in specs.into_iter().zip(input_fds) {
        let metadata = unsafe {
            let mut value: libc::stat = zeroed();
            require(libc::fstat(fd, &mut value) == 0)?;
            value
        };
        let fact = InputFact {
            kind: kind.into(),
            path: path.into(),
            sha256: sha256(bytes),
            byte_length: bytes.len() as u64,
            device: metadata.st_dev,
            inode: metadata.st_ino,
            seals: INPUT_SEALS,
            mode: 0o444,
        };
        require(metadata.st_size as u64 == fact.byte_length && metadata.st_nlink == 0)?;
        bind_input(root, &fact, fd)?;
    }
    require(unsafe { libc::chdir(root_c.as_ptr()) } == 0)?;
    require(unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".old".as_ptr()) } == 0)?;
    require(unsafe { libc::chdir(c"/".as_ptr()) } == 0)?;
    require(unsafe { libc::umount2(c"/.old".as_ptr(), libc::MNT_DETACH) } == 0)?;
    require(unsafe { libc::rmdir(c"/.old".as_ptr()) } == 0)
}

fn unix_address() -> Result<libc::sockaddr_un, String> {
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = LAUNCH_SOCKET_PATH.as_bytes();
    require(bytes.len() < address.sun_path.len())?;
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    Ok(address)
}

pub(crate) fn create_launch_listener(
    uid: u32,
    gid: u32,
) -> Result<(OwnedSocket, LaunchSocketFact), String> {
    require(unsafe {
        libc::getuid() == uid
            && libc::geteuid() == uid
            && libc::getgid() == gid
            && libc::getegid() == gid
    })?;
    require(!Path::new(LAUNCH_SOCKET_PATH).exists())?;
    let listener = OwnedSocket::checked(unsafe {
        libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0)
    })?;
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
    let mut observed_passcred: libc::c_int = 0;
    let mut observed_length = size_of::<libc::c_int>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&mut observed_passcred as *mut libc::c_int).cast(),
                &mut observed_length,
            )
        } == 0,
    )?;
    require(observed_passcred == 1 && observed_length as usize == size_of::<libc::c_int>())?;
    let address = unix_address()?;
    require(
        unsafe {
            libc::bind(
                listener.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        } == 0,
    )?;
    exact_mode(Path::new(LAUNCH_SOCKET_PATH), 0o600)?;
    require(unsafe { libc::listen(listener.as_raw_fd(), 1) } == 0)?;
    let mut bound: libc::sockaddr_un = unsafe { zeroed() };
    let mut bound_length = size_of::<libc::sockaddr_un>() as libc::socklen_t;
    require(
        unsafe {
            libc::getsockname(
                listener.as_raw_fd(),
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
    let parent = fs::symlink_metadata("/control").map_err(|_| REFUSAL)?;
    let socket = fs::symlink_metadata(LAUNCH_SOCKET_PATH).map_err(|_| REFUSAL)?;
    let mut descriptor: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(listener.as_raw_fd(), &mut descriptor) } == 0)?;
    require(
        parent.is_dir()
            && parent.uid() == uid
            && parent.gid() == gid
            && parent.mode() & 0o777 == 0o700
            && socket.file_type().is_socket()
            && socket.uid() == uid
            && socket.gid() == gid
            && socket.mode() & 0o777 == 0o600
            && descriptor.st_uid == uid
            && descriptor.st_gid == gid
            && descriptor.st_mode & libc::S_IFMT == libc::S_IFSOCK,
    )?;
    require(
        bound.sun_family == libc::AF_UNIX as libc::sa_family_t
            && bound_path == LAUNCH_SOCKET_PATH.as_bytes(),
    )?;
    Ok((
        listener,
        LaunchSocketFact {
            parent_path: "/control".into(),
            parent_uid: parent.uid(),
            parent_gid: parent.gid(),
            parent_mode: parent.mode() & 0o777,
            parent_inode: parent.ino(),
            socket_path: LAUNCH_SOCKET_PATH.into(),
            socket_uid: socket.uid(),
            socket_gid: socket.gid(),
            socket_mode: socket.mode() & 0o777,
            socket_inode: socket.ino(),
            descriptor_inode: descriptor.st_ino,
            socket_type: "unix-seqpacket-listener".into(),
            passcred_enabled: true,
        },
    ))
}

pub(crate) fn connect_launch_socket() -> Result<OwnedSocket, String> {
    let socket = OwnedSocket::checked(unsafe {
        libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0)
    })?;
    let address = unix_address()?;
    require(
        unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        } == 0,
    )?;
    Ok(socket)
}

fn read_equals(path: &str, expected: &[u8]) -> bool {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .is_ok()
        && bytes == expected
}

fn immutable(path: &str) -> bool {
    OpenOptions::new().write(true).open(path).is_err() && fs::write(path, b"changed").is_err()
}

fn private_write(path: &str) -> bool {
    fs::write(path, b"ok").is_ok()
        && fs::read(path).ok().as_deref() == Some(b"ok")
        && fs::remove_file(path).is_ok()
}

pub(crate) fn probe_root() -> RootProbe {
    RootProbe {
        sealed_inputs_read: read_equals("/inputs/objective.json", OBJECTIVE_BYTES)
            && read_equals("/inputs/config.json", CONFIG_BYTES)
            && read_equals("/inputs/mcp.json", MCP_BYTES),
        sealed_inputs_immutable: immutable("/inputs/objective.json")
            && immutable("/inputs/config.json")
            && immutable("/inputs/mcp.json"),
        private_roots_writable: private_write("/home/worker/probe")
            && private_write("/tmp/probe")
            && private_write("/config/probe")
            && private_write("/workspace/probe"),
        proc_absent: !Path::new("/proc").exists(),
    }
}
