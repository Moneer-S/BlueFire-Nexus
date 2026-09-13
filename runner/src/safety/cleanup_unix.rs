use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::Path;

use super::{metadata_is_link_or_reparse, CleanupEntryOpenError, CleanupIdentity, OwnedPathKind};
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
compile_error!("Linux cleanup is supported only on x86_64 and aarch64 targets");
#[cfg(target_os = "linux")]
use std::ffi::c_long;
use std::ffi::{c_char, c_int, CString};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "linux")]
const O_CLOEXEC: c_int = 0x0008_0000;
#[cfg(target_os = "linux")]
const O_DIRECTORY: c_int = 0x0001_0000;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: c_int = 0x0002_0000;
#[cfg(target_os = "linux")]
const O_NONBLOCK: c_int = 0x0000_0800;
#[cfg(target_os = "linux")]
const AT_REMOVEDIR: c_int = 0x0200;
#[cfg(target_os = "linux")]
const ELOOP_ERRNO: i32 = 40;

#[cfg(target_os = "macos")]
const O_CLOEXEC: c_int = 0x0100_0000;
#[cfg(target_os = "macos")]
const O_DIRECTORY: c_int = 0x0010_0000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW: c_int = 0x0000_0100;
#[cfg(target_os = "macos")]
const O_NONBLOCK: c_int = 0x0000_0004;
#[cfg(target_os = "macos")]
const AT_REMOVEDIR: c_int = 0x0080;
#[cfg(target_os = "macos")]
const ELOOP_ERRNO: i32 = 62;

const O_RDONLY: c_int = 0;

extern "C" {
    #[link_name = "open"]
    fn c_open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn openat(directory: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn fchmod(descriptor: c_int, mode: u32) -> c_int;
    fn geteuid() -> u32;
    fn unlinkat(directory: c_int, path: *const c_char, flags: c_int) -> c_int;
    #[cfg(target_os = "linux")]
    fn syscall(number: c_long, ...) -> c_long;
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_RENAMEAT2: c_long = 316;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_RENAMEAT2: c_long = 276;

fn portable_name(name: &OsStr, subject: &str) -> Result<CString, String> {
    CString::new(name.as_bytes()).map_err(|_| format!("{subject} contains NUL"))
}

fn owned_fd(result: c_int, subject: &str) -> Result<File, String> {
    if result < 0 {
        Err(format!(
            "cannot open {subject}: {}",
            io::Error::last_os_error()
        ))
    } else {
        // SAFETY: a successful open/openat result is an owned descriptor.
        Ok(unsafe { File::from_raw_fd(result) })
    }
}

pub(super) fn open_root(path: &Path) -> Result<File, String> {
    let path = portable_name(path.as_os_str(), "cleanup root")?;
    // SAFETY: `path` is NUL terminated and no mode argument is required
    // because O_CREAT is absent.
    let descriptor = unsafe {
        c_open(
            path.as_ptr(),
            O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW,
        )
    };
    owned_fd(descriptor, "cleanup root directory")
}

pub(super) fn open_directory(parent: &File, name: &OsStr) -> Result<Option<File>, String> {
    let name = portable_name(name, "cleanup directory component")?;
    // SAFETY: `name` is a single NUL-terminated component and `parent`
    // remains alive for the call.
    let descriptor = unsafe {
        openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW,
        )
    };
    if descriptor >= 0 {
        // SAFETY: a successful openat result is an owned descriptor.
        return Ok(Some(unsafe { File::from_raw_fd(descriptor) }));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(format!("cannot open cleanup directory component: {error}"))
    }
}

pub(super) fn open_entry(
    parent: &File,
    name: &OsStr,
    _kind: &OwnedPathKind,
) -> Result<Option<File>, CleanupEntryOpenError> {
    let name = portable_name(name, "cleanup entry").map_err(CleanupEntryOpenError::Unsafe)?;
    // O_NONBLOCK prevents an attacker-controlled FIFO replacement from
    // blocking cleanup while the descriptor is inspected and rejected.
    let descriptor = unsafe {
        openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        )
    };
    if descriptor >= 0 {
        // SAFETY: a successful openat result is an owned descriptor.
        return Ok(Some(unsafe { File::from_raw_fd(descriptor) }));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(None)
    } else {
        let message = format!("cannot open cleanup entry without traversal: {error}");
        if error.raw_os_error() == Some(ELOOP_ERRNO) {
            Err(CleanupEntryOpenError::Unsafe(message))
        } else {
            Err(CleanupEntryOpenError::Retryable(message))
        }
    }
}

pub(super) fn identity(file: &File) -> Result<CleanupIdentity, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect opened cleanup object: {error}"))?;
    Ok(CleanupIdentity {
        volume: metadata.dev(),
        object: metadata.ino() as u128,
    })
}

pub(super) fn enforce_owner_private_directory(directory: &File) -> Result<(), String> {
    // SAFETY: `directory` remains alive and supplies a valid descriptor.
    let changed = unsafe { fchmod(directory.as_raw_fd(), 0o700) };
    if changed != 0 {
        return Err(format!(
            "cannot make runner state directory owner-private: {}",
            io::Error::last_os_error()
        ));
    }
    let metadata = directory
        .metadata()
        .map_err(|error| format!("cannot inspect hardened runner state directory: {error}"))?;
    // SAFETY: geteuid has no preconditions.
    let effective_user = unsafe { geteuid() };
    if !metadata.is_dir()
        || metadata_is_link_or_reparse(&metadata)
        || metadata.uid() != effective_user
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(
            "runner state directory is not owned by the effective user with mode 0700".to_string(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn rename_no_replace(
    source_directory: &File,
    source_name: &OsStr,
    _source: &File,
    destination_directory: &File,
    destination_name: &OsStr,
) -> Result<(), String> {
    const RENAME_NOREPLACE: u32 = 1;
    let old = portable_name(source_name, "cleanup source")?;
    let new = portable_name(destination_name, "cleanup destination")?;
    // SAFETY: both names are NUL-terminated basenames and both directory
    // descriptors remain alive for the call. Calling the kernel primitive
    // directly keeps the runner linkable with both glibc and static musl;
    // some libc implementations do not export a renameat2 wrapper.
    let moved = unsafe {
        syscall(
            SYS_RENAMEAT2,
            source_directory.as_raw_fd(),
            old.as_ptr(),
            destination_directory.as_raw_fd(),
            new.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if moved == 0 {
        Ok(())
    } else {
        Err(format!(
            "cannot quarantine owned path without overwrite: {}",
            io::Error::last_os_error()
        ))
    }
}

#[cfg(target_os = "macos")]
pub(super) fn rename_no_replace(
    source_directory: &File,
    source_name: &OsStr,
    _source: &File,
    destination_directory: &File,
    destination_name: &OsStr,
) -> Result<(), String> {
    const RENAME_EXCL: u32 = 0x0000_0004;
    extern "C" {
        fn renameatx_np(
            old_directory: c_int,
            old_path: *const c_char,
            new_directory: c_int,
            new_path: *const c_char,
            flags: u32,
        ) -> c_int;
    }
    let old = portable_name(source_name, "cleanup source")?;
    let new = portable_name(destination_name, "cleanup destination")?;
    // SAFETY: both names are NUL-terminated basenames and both directory
    // descriptors remain alive for the call.
    let moved = unsafe {
        renameatx_np(
            source_directory.as_raw_fd(),
            old.as_ptr(),
            destination_directory.as_raw_fd(),
            new.as_ptr(),
            RENAME_EXCL,
        )
    };
    if moved == 0 {
        Ok(())
    } else {
        Err(format!(
            "cannot quarantine owned path without overwrite: {}",
            io::Error::last_os_error()
        ))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn rename_no_replace(
    _source_directory: &File,
    _source_name: &OsStr,
    _source: &File,
    _destination_directory: &File,
    _destination_name: &OsStr,
) -> Result<(), String> {
    Err("atomic descriptor-relative cleanup quarantine is unavailable on this platform".into())
}

pub(super) fn remove_entry(
    directory: &File,
    name: &OsStr,
    kind: &OwnedPathKind,
    _entry: File,
) -> Result<(), String> {
    let name = portable_name(name, "cleanup quarantine")?;
    let flags = if *kind == OwnedPathKind::Directory {
        AT_REMOVEDIR
    } else {
        0
    };
    // POSIX has no portable unlink-by-fd operation. The directory fd
    // removes the intermediate-parent race; the caller performs a final
    // inode comparison immediately before this unlinkat. A hostile
    // same-UID process able to rewrite the runner-private staging leaf can
    // still race that final comparison, so cleanup fails closed whenever
    // an identity mismatch is observed and does not claim a stronger OS
    // guarantee.
    let removed = unsafe { unlinkat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if removed == 0 {
        Ok(())
    } else {
        Err(format!(
            "cannot remove quarantined owned path: {}",
            io::Error::last_os_error()
        ))
    }
}

pub(super) fn sync(directory: &File) -> Result<(), String> {
    directory
        .sync_all()
        .map_err(|error| format!("cannot sync runner directory: {error}"))
}
