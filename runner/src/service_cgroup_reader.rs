//! Bounded cgroup.events acquisition, never authenticated manager or cleanup authority.
//!
//! Reported paths remain untrusted manager claims. This reads only a constrained
//! descendant of the bound user's fixed manager hierarchy on the retained cgroup2
//! mount. Missing resources never become invented empty events or verified absence.

use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::service_admission::VerifiedServiceAdmission;
use crate::service_observer::{ReadOutcome, ReportedPropertyScope, MAX_CGROUP_BYTES};
use crate::service_operation_binding::ServiceOperationBinding;
use crate::service_query_reader::{recheck_admission_identity, QueryReadIssue};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupReadIssue {
    AdmissionUnavailable,
    ScopeIdentity,
    NoReportedGroup,
    Cancelled,
    Deadline,
    Unavailable,
    /// A constrained pathname was missing at this read, not service absence.
    Missing,
    UnsupportedFilesystem,
    Changed,
    OutputLimit,
    Incomplete,
}

/// Complete acquired bytes, with their full binding; not an observer attestation.
pub struct AcquiredCgroupEvents {
    binding: ServiceOperationBinding,
    bytes: Vec<u8>,
}

impl AcquiredCgroupEvents {
    pub fn binding(&self) -> &ServiceOperationBinding {
        &self.binding
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn parser_outcome(&self) -> ReadOutcome<'_> {
        ReadOutcome::Finished {
            bytes: &self.bytes,
            exit_code: 0,
            truncated: false,
        }
    }
}

struct Budget<'a> {
    deadline: Instant,
    cancelled: &'a AtomicBool,
}

impl Budget<'_> {
    fn check(&self) -> Result<(), CgroupReadIssue> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(CgroupReadIssue::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(CgroupReadIssue::Deadline)
        } else {
            Ok(())
        }
    }
}

fn components(
    binding: &ServiceOperationBinding,
    owner: u32,
    nonce: &str,
    scope: &ReportedPropertyScope,
) -> Result<Vec<String>, CgroupReadIssue> {
    if scope.binding() != binding || owner == 0 {
        return Err(CgroupReadIssue::ScopeIdentity);
    }
    let manager = format!("/user.slice/user-{owner}.slice/user@{owner}.service");
    let unit = format!("bluefire-{nonce}.service");
    if scope.manager_control_group != manager {
        return Err(CgroupReadIssue::ScopeIdentity);
    }
    let path = scope
        .unit_control_group
        .as_deref()
        .ok_or(CgroupReadIssue::NoReportedGroup)?;
    if path.len() > 4096
        || !path.starts_with(&format!("{manager}/"))
        || !path.ends_with(&format!("/{unit}"))
    {
        return Err(CgroupReadIssue::ScopeIdentity);
    }
    let parts: Vec<_> = path.split('/').skip(1).collect();
    if parts.len() > 32
        || parts.iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || part.len() > 255
                || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-@".contains(&byte))
        })
    {
        return Err(CgroupReadIssue::ScopeIdentity);
    }
    Ok(parts.into_iter().map(str::to_string).collect())
}

/// This unused prerequisite deliberately accepts no caller path or fresh budget.
/// Future orchestration must authenticate manager identity and query consistency.
#[allow(dead_code)]
pub(crate) fn acquire_cgroup_events(
    admission: &VerifiedServiceAdmission,
    scope: &ReportedPropertyScope,
    cancelled: &AtomicBool,
) -> Result<AcquiredCgroupEvents, CgroupReadIssue> {
    if cancelled.load(Ordering::Acquire) {
        return Err(CgroupReadIssue::Cancelled);
    }
    let manager = admission
        .observation_manager()
        .ok_or(CgroupReadIssue::AdmissionUnavailable)?;
    let budget = Budget { deadline: manager.deadline(), cancelled };
    budget.check()?;
    let parts = components(admission.operation_binding(), admission.owner_uid(), admission.unit_nonce(), scope)?;
    let recheck_admission = || {
        budget.check()?;
        recheck_admission_identity(admission, manager.deadline()).map_err(|issue| {
            if issue == QueryReadIssue::Deadline { CgroupReadIssue::Deadline } else { CgroupReadIssue::ScopeIdentity }
        })?;
        manager.recheck().map_err(|_| CgroupReadIssue::ScopeIdentity)?;
        budget.check()
    };
    recheck_admission()?;
    let mut attachment = Attachment::fixed_root(&budget)?;
    for part in parts {
        attachment.append(&part, true, admission.owner_uid(), &budget)?;
    }
    attachment.append("cgroup.events", false, admission.owner_uid(), &budget)?;
    attachment.recheck(&budget)?;
    attachment.recheck_absolute_root(&budget)?;
    let bytes = attachment.read_events(&budget)?;
    attachment.recheck(&budget)?;
    attachment.recheck_absolute_root(&budget)?;
    recheck_admission()?;
    Ok(AcquiredCgroupEvents { binding: scope.binding().clone(), bytes })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Filesystem {
    kind: i128,
    mount: u64,
    mount_root: bool,
}

fn filesystem(file: &File) -> Result<Filesystem, CgroupReadIssue> {
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    let mut stat = std::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: libc supplies target-correct ABI layouts; both outputs are writable
    // and the file is held. An empty name with AT_EMPTY_PATH inspects that FD.
    let (fs, stat) = unsafe {
        if libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()) != 0
            || libc::statx(file.as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                           libc::STATX_MNT_ID, stat.as_mut_ptr()) != 0
        {
            return Err(CgroupReadIssue::UnsupportedFilesystem);
        }
        (fs.assume_init(), stat.assume_init())
    };
    if stat.stx_mask & libc::STATX_MNT_ID == 0 || stat.stx_mnt_id == 0
        || stat.stx_attributes_mask & libc::STATX_ATTR_MOUNT_ROOT == 0
    {
        return Err(CgroupReadIssue::UnsupportedFilesystem);
    }
    Ok(Filesystem {
        kind: i128::from(fs.f_type),
        mount: stat.stx_mnt_id,
        mount_root: stat.stx_attributes & libc::STATX_ATTR_MOUNT_ROOT != 0,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    filesystem: Filesystem,
}

fn metadata_identity(metadata: &Metadata, fs: Filesystem) -> Identity {
    Identity {
        device: metadata.dev(), inode: metadata.ino(), mode: metadata.mode(),
        uid: metadata.uid(), gid: metadata.gid(),
        // Directory timestamps and child-link counts change with unrelated
        // siblings. A held inode pins identity; only deletion matters here.
        links: if metadata.is_dir() { u64::from(metadata.nlink() != 0) } else { metadata.nlink() },
        filesystem: fs,
    }
}

type Probe = fn(&File) -> Result<Filesystem, CgroupReadIssue>;

fn identity(file: &File, probe: Probe) -> Result<Identity, CgroupReadIssue> {
    let before = file.metadata().map_err(|_| CgroupReadIssue::Unavailable)?;
    let fs = probe(file)?;
    let before = metadata_identity(&before, fs);
    let after = metadata_identity(&file.metadata().map_err(|_| CgroupReadIssue::Unavailable)?, fs);
    if before != after { return Err(CgroupReadIssue::Changed); }
    Ok(before)
}

fn protected(value: &Identity, directory: bool, owner: u32) -> Result<(), CgroupReadIssue> {
    let kind = if directory { libc::S_IFDIR } else { libc::S_IFREG };
    if value.mode & libc::S_IFMT != kind || value.mode & 0o7022 != 0
        || (value.uid != 0 && value.uid != owner) || value.links == 0
        || (!directory && (value.links != 1 || value.mode & 0o222 != 0))
    {
        return Err(CgroupReadIssue::ScopeIdentity);
    }
    Ok(())
}

struct Attachment {
    files: Vec<File>,
    names: Vec<CString>,
    identities: Vec<Identity>,
    cgroup_root: usize,
    probe: Probe,
}

impl Attachment {
    fn fixed_root(budget: &Budget<'_>) -> Result<Self, CgroupReadIssue> {
        budget.check()?;
        let mut attachment = Self {
            files: vec![open_root()?], names: Vec::new(), identities: Vec::new(),
            cgroup_root: 3, probe: filesystem,
        };
        for name in ["sys", "fs", "cgroup"] {
            budget.check()?;
            let last = attachment.files.last().ok_or(CgroupReadIssue::Unavailable)?;
            let observed = identity(last, attachment.probe)?;
            protected(&observed, true, 0)?;
            attachment.identities.push(observed);
            let name = CString::new(name).map_err(|_| CgroupReadIssue::ScopeIdentity)?;
            let child = open_child(last, &name, true)?;
            attachment.files.push(child);
            attachment.names.push(name);
        }
        let root = identity(attachment.files.last().ok_or(CgroupReadIssue::Unavailable)?, attachment.probe)?;
        protected(&root, true, 0)?;
        if root.filesystem.kind != i128::from(libc::CGROUP2_SUPER_MAGIC) || !root.filesystem.mount_root {
            return Err(CgroupReadIssue::UnsupportedFilesystem);
        }
        attachment.identities.push(root);
        budget.check()?;
        Ok(attachment)
    }

    fn append(&mut self, name: &str, directory: bool, owner: u32, budget: &Budget<'_>) -> Result<(), CgroupReadIssue> {
        budget.check()?;
        let name = CString::new(name).map_err(|_| CgroupReadIssue::ScopeIdentity)?;
        let child = open_child(self.files.last().ok_or(CgroupReadIssue::Unavailable)?, &name, directory)?;
        let observed = identity(&child, self.probe)?;
        protected(&observed, directory, owner)?;
        let root = &self.identities[self.cgroup_root];
        if observed.filesystem.kind != i128::from(libc::CGROUP2_SUPER_MAGIC)
            || observed.filesystem.mount != root.filesystem.mount || observed.device != root.device
        { return Err(CgroupReadIssue::UnsupportedFilesystem); }
        self.files.push(child);
        self.names.push(name);
        self.identities.push(observed);
        budget.check()
    }

    fn recheck(&self, budget: &Budget<'_>) -> Result<(), CgroupReadIssue> {
        for (index, held) in self.files.iter().enumerate() {
            budget.check()?;
            if identity(held, self.probe)? != self.identities[index] {
                return Err(CgroupReadIssue::Changed);
            }
            if index > 0 {
                let directory = self.identities[index].mode & libc::S_IFMT == libc::S_IFDIR;
                let named = open_child(&self.files[index - 1], &self.names[index - 1], directory)?;
                if identity(&named, self.probe)? != self.identities[index] {
                    return Err(CgroupReadIssue::Changed);
                }
            }
        }
        budget.check()
    }

    fn recheck_absolute_root(&self, budget: &Budget<'_>) -> Result<(), CgroupReadIssue> {
        budget.check()?;
        if identity(&open_root()?, self.probe)? != self.identities[0] {
            return Err(CgroupReadIssue::Changed);
        }
        budget.check()
    }

    fn read_events(&self, budget: &Budget<'_>) -> Result<Vec<u8>, CgroupReadIssue> {
        budget.check()?;
        let held = self.files.last().ok_or(CgroupReadIssue::Unavailable)?;
        let expected = self.identities.last().ok_or(CgroupReadIssue::Unavailable)?;
        // The O_PATH leaf is already a regular cgroup2 file. Reopen that held
        // object, never an unchecked replacement at its previous pathname.
        let mut events = OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(format!("/proc/self/fd/{}", held.as_raw_fd()))
            .map_err(|_| CgroupReadIssue::Unavailable)?;
        if identity(&events, self.probe)? != *expected {
            return Err(CgroupReadIssue::Changed);
        }
        let bytes = read_complete(&mut events, budget)?;
        if identity(&events, self.probe)? != *expected {
            return Err(CgroupReadIssue::Changed);
        }
        budget.check()?;
        Ok(bytes)
    }
}

fn open_root() -> Result<File, CgroupReadIssue> {
    OpenOptions::new().read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/").map_err(|_| CgroupReadIssue::Unavailable)
}

fn open_child(parent: &File, name: &CString, directory: bool) -> Result<File, CgroupReadIssue> {
    let flags = libc::O_NOFOLLOW | libc::O_CLOEXEC
        | if directory { libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK } else { libc::O_PATH };
    // SAFETY: held directory descriptor and a bounded NUL-terminated single
    // component. An O_PATH leaf cannot trigger FIFO/device opening behavior;
    // its type and actual filesystem are verified before a read handle opens.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            CgroupReadIssue::Missing
        } else { CgroupReadIssue::Unavailable });
    }
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_complete(reader: &mut impl Read, budget: &Budget<'_>) -> Result<Vec<u8>, CgroupReadIssue> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; MAX_CGROUP_BYTES + 1];
    loop {
        budget.check()?;
        let remaining = chunk.len() - bytes.len();
        let size = reader.read(&mut chunk[..remaining]).map_err(|_: io::Error| CgroupReadIssue::Unavailable)?;
        if size == 0 { break; }
        bytes.extend_from_slice(&chunk[..size]);
        if bytes.len() > MAX_CGROUP_BYTES { return Err(CgroupReadIssue::OutputLimit); }
    }
    budget.check()?;
    if bytes.is_empty() || !bytes.ends_with(b"\n") { return Err(CgroupReadIssue::Incomplete); }
    Ok(bytes)
}

#[cfg(test)]
#[path = "service_cgroup_reader_tests.rs"]
mod tests;
