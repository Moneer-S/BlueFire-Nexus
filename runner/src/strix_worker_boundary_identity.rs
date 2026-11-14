//! Disposable numeric identity and capability drop for the fixed worker.

#![cfg(target_os = "linux")]

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::ptr;

const REFUSAL: &str = "the fixed Linux Strix worker boundary was refused";

pub(crate) struct IdentityLease {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) inode: u64,
    path: PathBuf,
    file: Option<File>,
    retain_on_drop: bool,
}

impl Drop for IdentityLease {
    fn drop(&mut self) {
        self.file.take();
        if !self.retain_on_drop {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl IdentityLease {
    pub(crate) fn retain_for_recovery(&mut self) {
        self.retain_on_drop = true;
    }

    pub(crate) fn release(&mut self) -> Result<bool, String> {
        self.file.take();
        let path = self.path.clone();
        fs::remove_file(&path).map_err(|_| REFUSAL)?;
        self.path = PathBuf::new();
        Ok(!path.exists())
    }
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(REFUSAL.into())
    }
}

fn process_identity_in_use(candidate: u32) -> Result<bool, String> {
    for entry in fs::read_dir("/proc").map_err(|_| REFUSAL)? {
        let entry = entry.map_err(|_| REFUSAL)?;
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let status = match fs::read_to_string(entry.path().join("status")) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(REFUSAL.into()),
        };
        for prefix in ["Uid:\t", "Gid:\t"] {
            if status
                .lines()
                .find(|row| row.starts_with(prefix))
                .is_some_and(|row| {
                    row[prefix.len()..]
                        .split_whitespace()
                        .any(|field| field.parse::<u32>().ok() == Some(candidate))
                })
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(crate) fn acquire() -> Result<IdentityLease, String> {
    let passwd = fs::read_to_string("/etc/passwd").map_err(|_| REFUSAL)?;
    let group = fs::read_to_string("/etc/group").map_err(|_| REFUSAL)?;
    for candidate in 60_000_u32..65_000 {
        let user = passwd.lines().any(|row| {
            row.split(':').nth(2).and_then(|value| value.parse().ok()) == Some(candidate)
        });
        let group_used = group.lines().any(|row| {
            row.split(':').nth(2).and_then(|value| value.parse().ok()) == Some(candidate)
        });
        if user || group_used || process_identity_in_use(candidate)? {
            continue;
        }
        let path = PathBuf::from(format!("/tmp/bluefire-strix-worker-uid-{candidate}.lease"));
        let file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(REFUSAL.into()),
        };
        // Establish the unlink-on-drop owner immediately after the exclusive
        // create. Every subsequent validation is fallible, so holding the raw
        // File and pathname separately here would strand a root-owned lease on
        // an early return.
        let mut lease = IdentityLease {
            uid: candidate,
            gid: candidate,
            inode: 0,
            path,
            file: Some(file),
            retain_on_drop: false,
        };
        if process_identity_in_use(candidate)? {
            drop(lease);
            continue;
        }
        let metadata = lease
            .file
            .as_ref()
            .ok_or(REFUSAL)?
            .metadata()
            .map_err(|_| REFUSAL)?;
        require(metadata.uid() == 0 && metadata.nlink() == 1 && metadata.mode() & 0o777 == 0o600)?;
        lease.inode = metadata.ino();
        return Ok(lease);
    }
    Err(REFUSAL.into())
}

pub(crate) fn drop_privileges(uid: u32, gid: u32) -> Result<(), String> {
    require(unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } == 0)?;
    require(unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 0, 0, 0, 0) } == 0)?;
    require(
        unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } == 0,
    )?;
    for capability in 0..64 {
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
        if result != 0 {
            require(std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL))?;
        }
    }
    require(unsafe { libc::setgroups(0, ptr::null()) } == 0)?;
    require(unsafe { libc::setresgid(gid, gid, gid) } == 0)?;
    require(unsafe { libc::setresuid(uid, uid, uid) } == 0)?;
    require(unsafe {
        libc::getuid() == uid
            && libc::geteuid() == uid
            && libc::getgid() == gid
            && libc::getegid() == gid
    })?;
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapData::default(), CapData::default()];
    require(
        unsafe {
            libc::syscall(
                libc::SYS_capset,
                &mut header as *mut CapHeader,
                data.as_mut_ptr(),
            )
        } == 0,
    )?;
    require(
        unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut header as *mut CapHeader,
                data.as_mut_ptr(),
            )
        } == 0,
    )?;
    require(
        data.iter()
            .all(|row| row.effective == 0 && row.permitted == 0 && row.inheritable == 0),
    )?;
    require(unsafe { libc::prctl(libc::PR_GET_KEEPCAPS, 0, 0, 0, 0) } == 0)?;
    require(unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } == 0)?;
    require(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0)?;
    require(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0)
}
