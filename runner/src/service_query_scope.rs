//! Retained no-follow attachment of the exact owned session-bus pathname.

use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::time::Instant;

use super::QueryReadIssue;
use crate::service_admission::VerifiedServiceAdmission;

const O_NOFOLLOW: i32 = 0x20000;
const O_DIRECTORY: i32 = 0x10000;
const O_CLOEXEC: i32 = 0x80000;
const O_PATH: i32 = 0x200000;

fn budget(deadline: Instant) -> Result<(), QueryReadIssue> {
    if Instant::now() >= deadline {
        Err(QueryReadIssue::Deadline)
    } else {
        Ok(())
    }
}

pub(super) fn validate_identity(
    owner: u32,
    real: u32,
    effective: u32,
    boot: &[u8],
    expected: &str,
) -> Result<(), QueryReadIssue> {
    if owner == 0
        || owner != real
        || owner != effective
        || boot != format!("{expected}\n").as_bytes()
    {
        return Err(QueryReadIssue::ScopeIdentity);
    }
    Ok(())
}

pub(super) fn check_identity(
    admission: &VerifiedServiceAdmission,
    deadline: Instant,
) -> Result<(), QueryReadIssue> {
    budget(deadline)?;
    let binding: serde_json::Value =
        serde_json::from_str(admission.operation_binding().canonical_json())
            .map_err(|_| QueryReadIssue::ScopeIdentity)?;
    let identity = &binding["identity"];
    let matches = identity["owner_uid"] == admission.owner_uid()
        && identity["boot_id"] == admission.boot_id()
        && identity["manager_id"] == admission.manager_id()
        && identity["unit_nonce"] == admission.unit_nonce()
        && identity["authorization_digest"] == admission.scope_digest()
        && identity["runner_profile_id"] == admission.runner_profile_id()
        && identity["workspace_id"] == admission.workspace_id()
        && identity["target_scope_digest"] == admission.target_scope_digest()
        && identity["unit_content_digest"] == admission.unit_content_digest()
        && binding["reviewed_scope_digest"] == admission.scope_digest()
        && binding["manager_installation_digest"] == admission.manager_installation_digest()
        && binding["payload_installation_digest"] == admission.payload_installation_digest();
    let now = crate::contract::utc_now().fixed_offset();
    let expires = match binding["operation"].as_str() {
        Some("create_unit" | "reload" | "enable" | "start") => admission.setup_expires_at(),
        Some("stop" | "disable" | "remove_links" | "remove_unit" | "reload_after_cleanup") => {
            admission.cleanup_expires_at()
        }
        _ => return Err(QueryReadIssue::ScopeIdentity),
    };
    if !matches || now < admission.created_at() || now >= expires {
        return Err(QueryReadIssue::ScopeIdentity);
    }
    let mut boot = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open("/proc/sys/kernel/random/boot_id")
        .and_then(|file| file.take(65).read_to_end(&mut boot))
        .map_err(|_| QueryReadIssue::ScopeIdentity)?;
    // SAFETY: fixed, read-only process identity syscalls.
    validate_identity(
        admission.owner_uid(),
        unsafe { getuid() },
        unsafe { geteuid() },
        &boot,
        admission.boot_id(),
    )?;
    budget(deadline)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    ctime: i64,
    ctime_ns: i64,
}

fn identity(metadata: &Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        links: metadata.nlink(),
        ctime: metadata.ctime(),
        ctime_ns: metadata.ctime_nsec(),
    }
}

pub(super) struct BusAttachment {
    files: Vec<File>,
    identities: Vec<Identity>,
    names: Vec<CString>,
    deadline: Instant,
}

impl BusAttachment {
    pub(super) fn observe(owner: u32, deadline: Instant) -> Result<Self, QueryReadIssue> {
        budget(deadline)?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            .open("/")
            .map_err(|_| QueryReadIssue::BusUnavailable)?;
        Self::from_root(root, owner, deadline)
    }

    fn from_root(root: File, owner: u32, deadline: Instant) -> Result<Self, QueryReadIssue> {
        let mut attachment = Self {
            files: vec![root],
            identities: Vec::new(),
            names: Vec::new(),
            deadline,
        };
        let names = [
            "run".to_string(),
            "user".to_string(),
            owner.to_string(),
            "bus".to_string(),
        ];
        for index in 0..=names.len() {
            budget(deadline)?;
            let metadata = attachment.files[index]
                .metadata()
                .map_err(|_| QueryReadIssue::BusUnavailable)?;
            let protected = if index == 4 {
                metadata.file_type().is_socket() && metadata.uid() == owner && metadata.nlink() == 1
            } else if index == 3 {
                metadata.is_dir() && metadata.uid() == owner && metadata.mode() & 0o7777 == 0o700
            } else {
                metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
            };
            if !protected {
                return Err(QueryReadIssue::BusUnavailable);
            }
            attachment.identities.push(identity(&metadata));
            if index < names.len() {
                let name = CString::new(names[index].as_str())
                    .map_err(|_| QueryReadIssue::BusUnavailable)?;
                let child = open_child(&attachment.files[index], &name, index == 3)?;
                attachment.files.push(child);
                attachment.names.push(name);
            }
        }
        attachment.recheck()?;
        Ok(attachment)
    }

    pub(super) fn recheck(&self) -> Result<(), QueryReadIssue> {
        budget(self.deadline)?;
        for (index, held) in self.files.iter().enumerate() {
            budget(self.deadline)?;
            let metadata = held.metadata().map_err(|_| QueryReadIssue::BusChanged)?;
            if identity(&metadata) != self.identities[index] {
                return Err(QueryReadIssue::BusChanged);
            }
            if index > 0 {
                let attached =
                    open_child(&self.files[index - 1], &self.names[index - 1], index == 4)
                        .map_err(|_| QueryReadIssue::BusChanged)?;
                if identity(
                    &attached
                        .metadata()
                        .map_err(|_| QueryReadIssue::BusChanged)?,
                ) != self.identities[index]
                {
                    return Err(QueryReadIssue::BusChanged);
                }
            }
        }
        budget(self.deadline)
    }
}

fn open_child(parent: &File, name: &CString, socket: bool) -> Result<File, QueryReadIssue> {
    let flags = O_NOFOLLOW | O_CLOEXEC | if socket { O_PATH } else { O_DIRECTORY };
    // SAFETY: the held parent fd and bounded NUL-terminated component are valid;
    // O_PATH observes the socket without connecting or sending any bus message.
    let fd = unsafe { openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(QueryReadIssue::BusUnavailable);
    }
    // SAFETY: openat returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

unsafe extern "C" {
    fn getuid() -> u32;
    fn geteuid() -> u32;
    fn openat(parent: i32, name: *const std::ffi::c_char, flags: i32, ...) -> i32;
}
