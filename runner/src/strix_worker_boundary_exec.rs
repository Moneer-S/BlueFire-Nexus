//! Fixed fresh-address-space transition for the Linux worker self-test.
//!
//! The controller chooses no command or path here. The clone child may only
//! re-exec the already opened and digest-checked current runner, with one
//! hidden no-arguments verb, an empty environment, and this fixed descriptor
//! map. A sealed canonical bootstrap binds the private root, disposable
//! identity, helper executable, and the three sealed input objects.

#![cfg(target_os = "linux")]

use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::Write;
use std::mem::zeroed;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canonical::canonical_json;

const REFUSAL: &str = "the fixed Linux Strix worker self-exec was refused";
const SCHEMA: &str = "bluefire.strix-worker-self-exec-bootstrap.v1";
pub(crate) const CHILD_VERB: &str = "__bluefire-strix-worker-boundary-self-test-child";
pub(crate) const CONTROL_FD: RawFd = 20;
pub(crate) const OBJECTIVE_FD: RawFd = 21;
pub(crate) const CONFIG_FD: RawFd = 22;
pub(crate) const MCP_FD: RawFd = 23;
pub(crate) const BOOTSTRAP_FD: RawFd = 24;
const FIXED_FDS: [RawFd; 5] = [CONTROL_FD, OBJECTIVE_FD, CONFIG_FD, MCP_FD, BOOTSTRAP_FD];
const INPUT_SEALS: i32 =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
const MAX_BOOTSTRAP: usize = 16 * 1024;
const MAX_INPUT: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputBinding {
    pub(crate) kind: String,
    pub(crate) digest: String,
    pub(crate) byte_length: u64,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bootstrap {
    schema_version: String,
    private_root: String,
    uid: u32,
    gid: u32,
    helper_executable_digest: String,
    inputs: Vec<InputBinding>,
}

pub(crate) struct BootstrapFile {
    pub(crate) file: File,
    pub(crate) digest: String,
}

pub(crate) struct ChildBootstrap {
    pub(crate) private_root: PathBuf,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) helper_executable_digest: String,
    pub(crate) inputs: Vec<InputBinding>,
    pub(crate) bootstrap_digest: String,
    pub(crate) fresh_address_space: bool,
    pub(crate) environment_empty: bool,
    pub(crate) exact_fd_inventory: bool,
    pub(crate) working_directory_is_root: bool,
}

pub(crate) struct ExecSources {
    pub(crate) executable: RawFd,
    pub(crate) control: RawFd,
    pub(crate) objective: RawFd,
    pub(crate) config: RawFd,
    pub(crate) mcp: RawFd,
    pub(crate) bootstrap: RawFd,
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

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn validate_bootstrap(value: Bootstrap) -> Result<Bootstrap, String> {
    require(value.schema_version == SCHEMA)?;
    require(value.uid == value.gid && (60_000..65_000).contains(&value.uid))?;
    require(valid_digest(&value.helper_executable_digest))?;
    let root = value
        .private_root
        .strip_prefix("/tmp/bluefire-strix-worker-root-")
        .ok_or(REFUSAL)?;
    require(!root.is_empty() && root.bytes().all(|byte| byte.is_ascii_digit()))?;
    require(value.inputs.len() == 3)?;
    for (input, expected) in value.inputs.iter().zip(["objective", "config", "mcp"]) {
        require(input.kind == expected)?;
        require(valid_digest(&input.digest))?;
        require(
            (1..=MAX_INPUT as u64).contains(&input.byte_length)
                && input.device > 0
                && input.inode > 0,
        )?;
    }
    for left in 0..value.inputs.len() {
        for right in (left + 1)..value.inputs.len() {
            require(
                (value.inputs[left].device, value.inputs[left].inode)
                    != (value.inputs[right].device, value.inputs[right].inode),
            )?;
        }
    }
    Ok(value)
}

fn canonical_bytes(value: &Bootstrap) -> Result<Vec<u8>, String> {
    let json = serde_json::to_value(value).map_err(|_| REFUSAL)?;
    let bytes = canonical_json(&json).into_bytes();
    require(!bytes.is_empty() && bytes.len() <= MAX_BOOTSTRAP)?;
    Ok(bytes)
}

fn memfd(name: &str, bytes: &[u8], mode: u32) -> Result<File, String> {
    let name = CString::new(name).map_err(|_| REFUSAL)?;
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
    require(unsafe { libc::fchmod(raw, mode) } == 0)?;
    require(unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, INPUT_SEALS) } == 0)?;
    require(unsafe { libc::fcntl(raw, libc::F_GET_SEALS) } == INPUT_SEALS)?;
    Ok(file)
}

pub(crate) fn build_bootstrap(
    private_root: &Path,
    uid: u32,
    gid: u32,
    helper_executable_digest: &str,
    inputs: Vec<InputBinding>,
) -> Result<BootstrapFile, String> {
    let value = validate_bootstrap(Bootstrap {
        schema_version: SCHEMA.into(),
        private_root: private_root.to_str().ok_or(REFUSAL)?.into(),
        uid,
        gid,
        helper_executable_digest: helper_executable_digest.into(),
        inputs,
    })?;
    let bytes = canonical_bytes(&value)?;
    Ok(BootstrapFile {
        file: memfd("bluefire-strix-worker-bootstrap", &bytes, 0o400)?,
        digest: digest(&bytes),
    })
}

fn fd_bytes(fd: RawFd, maximum: usize) -> Result<Vec<u8>, String> {
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd, &mut details) } == 0)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFREG
            && details.st_size > 0
            && details.st_size as u64 <= maximum as u64,
    )?;
    let mut bytes = vec![0_u8; details.st_size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let read = unsafe {
            libc::pread(
                fd,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
                offset as libc::off_t,
            )
        };
        require(read > 0)?;
        offset += read as usize;
    }
    Ok(bytes)
}

fn fd_binding(fd: RawFd, expected: &InputBinding) -> Result<(), String> {
    require(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } == INPUT_SEALS)?;
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd, &mut details) } == 0)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFREG
            && details.st_ino == expected.inode
            && details.st_dev == expected.device
            && details.st_size >= 0
            && details.st_size as u64 == expected.byte_length,
    )?;
    require(details.st_nlink == 0 && details.st_mode & 0o777 == 0o444)?;
    require(digest(&fd_bytes(fd, MAX_INPUT)?) == expected.digest)
}

fn load_bootstrap_fd(fd: RawFd) -> Result<Bootstrap, String> {
    require(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } == INPUT_SEALS)?;
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd, &mut details) } == 0)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFREG
            && details.st_nlink == 0
            && details.st_mode & 0o777 == 0o400,
    )?;
    let bytes = fd_bytes(fd, MAX_BOOTSTRAP)?;
    let json: Value = serde_json::from_slice(&bytes).map_err(|_| REFUSAL)?;
    require(canonical_json(&json).into_bytes() == bytes)?;
    let value: Bootstrap = serde_json::from_value(json).map_err(|_| REFUSAL)?;
    validate_bootstrap(value)
}

fn file_digest(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|_| REFUSAL)?;
    Ok(digest(&fd_bytes(file.as_raw_fd(), 256 * 1024 * 1024)?))
}

/// Opens the exact current runner image without accepting a caller-selected
/// executable path. The identity check is repeated immediately before exec.
pub(crate) fn open_current_executable() -> Result<File, String> {
    let file = File::open("/proc/self/exe").map_err(|_| REFUSAL)?;
    let opened = file.metadata().map_err(|_| REFUSAL)?;
    let current = fs::metadata("/proc/self/exe").map_err(|_| REFUSAL)?;
    require(
        opened.is_file()
            && opened.dev() == current.dev()
            && opened.ino() == current.ino()
            && opened.len() > 0
            && opened.len() <= 256 * 1024 * 1024,
    )?;
    Ok(file)
}

pub(crate) fn current_executable_digest() -> Result<String, String> {
    file_digest(Path::new("/proc/self/exe"))
}

fn copy_to_fixed(source: RawFd, target: RawFd) -> Result<(), String> {
    require(source >= 100 && target >= 20)?;
    require(unsafe { libc::dup3(source, target, 0) } == target)?;
    require(unsafe { libc::fcntl(target, libc::F_GETFD) } == 0)
}

fn scratch(fd: RawFd) -> Result<RawFd, String> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 100) };
    require(duplicate >= 100)?;
    Ok(duplicate)
}

fn close_except(keep: &[RawFd]) -> Result<(), String> {
    let mut descriptors = Vec::new();
    for entry in fs::read_dir("/proc/self/fd").map_err(|_| REFUSAL)? {
        let entry = entry.map_err(|_| REFUSAL)?;
        if let Ok(fd) = entry.file_name().to_string_lossy().parse::<RawFd>() {
            if !keep.contains(&fd) {
                descriptors.push(fd);
            }
        }
    }
    for fd in descriptors {
        unsafe { libc::close(fd) };
    }
    Ok(())
}

fn connected_unix_seqpacket(fd: RawFd) -> Result<(), String> {
    fn option(fd: RawFd, name: libc::c_int) -> Result<libc::c_int, String> {
        let mut value = 0_i32;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        require(
            unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    name,
                    (&mut value as *mut libc::c_int).cast(),
                    &mut length,
                )
            } == 0,
        )?;
        require(length as usize == std::mem::size_of::<libc::c_int>())?;
        Ok(value)
    }

    require(option(fd, libc::SO_TYPE)? == libc::SOCK_SEQPACKET)?;
    require(option(fd, libc::SO_DOMAIN)? == libc::AF_UNIX)?;
    require(option(fd, libc::SO_ACCEPTCONN)? == 0)?;
    require(option(fd, libc::SO_ERROR)? == 0)?;
    let mut peer: libc::sockaddr_storage = unsafe { zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    require(
        unsafe {
            libc::getpeername(
                fd,
                (&mut peer as *mut libc::sockaddr_storage).cast(),
                &mut length,
            )
        } == 0,
    )?;
    require(peer.ss_family == libc::AF_UNIX as libc::sa_family_t)
}

pub(crate) fn exec_fixed(sources: ExecSources, helper_digest: &str) -> Result<(), String> {
    require(valid_digest(helper_digest))?;
    let executable = scratch(sources.executable)?;
    let control = scratch(sources.control)?;
    let objective = scratch(sources.objective)?;
    let config = scratch(sources.config)?;
    let mcp = scratch(sources.mcp)?;
    let bootstrap = scratch(sources.bootstrap)?;
    let value = load_bootstrap_fd(bootstrap)?;
    connected_unix_seqpacket(control)?;
    for (fd, expected) in [objective, config, mcp]
        .into_iter()
        .zip(value.inputs.iter())
    {
        fd_binding(fd, expected)?;
    }
    require(value.helper_executable_digest == helper_digest)?;
    require(current_executable_digest()? == helper_digest)?;
    let current = fs::metadata("/proc/self/exe").map_err(|_| REFUSAL)?;
    let mut executable_details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(executable, &mut executable_details) } == 0)?;
    require(
        executable_details.st_mode & libc::S_IFMT == libc::S_IFREG
            && executable_details.st_dev == current.dev()
            && executable_details.st_ino == current.ino(),
    )?;
    require(digest(&fd_bytes(executable, 256 * 1024 * 1024)?) == helper_digest)?;
    for (fd, target) in [
        (control, CONTROL_FD),
        (objective, OBJECTIVE_FD),
        (config, CONFIG_FD),
        (mcp, MCP_FD),
        (bootstrap, BOOTSTRAP_FD),
    ] {
        copy_to_fixed(fd, target)?;
    }
    require(unsafe { libc::chdir(c"/".as_ptr()) } == 0)?;
    close_except(&[
        executable,
        CONTROL_FD,
        OBJECTIVE_FD,
        CONFIG_FD,
        MCP_FD,
        BOOTSTRAP_FD,
    ])?;
    require(unsafe { libc::fcntl(executable, libc::F_GETFD) } == libc::FD_CLOEXEC)?;
    let mut expected_inventory = vec![
        executable,
        CONTROL_FD,
        OBJECTIVE_FD,
        CONFIG_FD,
        MCP_FD,
        BOOTSTRAP_FD,
    ];
    expected_inventory.sort_unstable();
    require(fd_inventory()? == expected_inventory)?;
    let executable_name = CString::new("bluefire-runner").map_err(|_| REFUSAL)?;
    let verb = CString::new(CHILD_VERB).map_err(|_| REFUSAL)?;
    let empty = CString::new("").map_err(|_| REFUSAL)?;
    let argv = [executable_name.as_ptr(), verb.as_ptr(), ptr::null()];
    let envp = [ptr::null::<libc::c_char>()];
    let result = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            executable,
            empty.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    require(result == 0)
}

fn fd_inventory() -> Result<Vec<RawFd>, String> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir("/proc/self/fd").map_err(|_| REFUSAL)? {
        let entry = entry.map_err(|_| REFUSAL)?;
        if let Ok(fd) = entry.file_name().to_string_lossy().parse::<RawFd>() {
            candidates.push(fd);
        }
    }
    candidates.retain(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0);
    candidates.sort_unstable();
    candidates.dedup();
    Ok(candidates)
}

pub(crate) fn load_child() -> Result<ChildBootstrap, String> {
    require(std::env::vars_os().next().is_none())?;
    let arguments: Vec<_> = std::env::args_os().collect();
    require(
        arguments.len() == 2
            && arguments[0].as_os_str() == OsStr::new("bluefire-runner")
            && arguments[1].as_os_str() == OsStr::new(CHILD_VERB),
    )?;
    require(fd_inventory()? == FIXED_FDS)?;
    for fd in FIXED_FDS {
        require(unsafe { libc::fcntl(fd, libc::F_GETFD) } == 0)?;
    }
    require(std::env::current_dir().map_err(|_| REFUSAL)? == Path::new("/"))?;
    let bootstrap_digest = digest(&fd_bytes(BOOTSTRAP_FD, MAX_BOOTSTRAP)?);
    let value = load_bootstrap_fd(BOOTSTRAP_FD)?;
    require(file_digest(Path::new("/proc/self/exe"))? == value.helper_executable_digest)?;
    for (fd, expected) in [OBJECTIVE_FD, CONFIG_FD, MCP_FD]
        .into_iter()
        .zip(value.inputs.iter())
    {
        fd_binding(fd, expected)?;
    }
    connected_unix_seqpacket(CONTROL_FD)?;
    Ok(ChildBootstrap {
        private_root: PathBuf::from(&value.private_root),
        uid: value.uid,
        gid: value.gid,
        helper_executable_digest: value.helper_executable_digest,
        inputs: value.inputs,
        bootstrap_digest,
        fresh_address_space: true,
        environment_empty: true,
        exact_fd_inventory: true,
        working_directory_is_root: true,
    })
}

pub(crate) fn input_binding_fd(kind: &str, fd: RawFd) -> Result<InputBinding, String> {
    require(matches!(kind, "objective" | "config" | "mcp"))?;
    require(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } == INPUT_SEALS)?;
    let mut details: libc::stat = unsafe { zeroed() };
    require(unsafe { libc::fstat(fd, &mut details) } == 0)?;
    let bytes = fd_bytes(fd, MAX_INPUT)?;
    require(
        details.st_mode & libc::S_IFMT == libc::S_IFREG
            && details.st_nlink == 0
            && details.st_mode & 0o777 == 0o444,
    )?;
    Ok(InputBinding {
        kind: kind.into(),
        digest: digest(&bytes),
        byte_length: bytes.len() as u64,
        device: details.st_dev,
        inode: details.st_ino,
    })
}
