use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::contract::{
    sha256_hex, utc_now, ExecutionManifest, NetworkDestination, RunnerProfile, TargetScope,
};

const RECEIPT_SCHEMA: &str = "bluefire.receipt/v1";
const RECEIPT_COMMIT_SCHEMA: &str = "bluefire.receipt-commit/v1";
pub const RECEIPT_PROTOCOL_VERSION: &str = "bluefire.runner-receipt-wal.v2";
const STATE_DIR: &str = ".bluefire";
const RECEIPT_DIR: &str = "receipts";
const RECEIPT_COMMIT_DIR: &str = "receipt-commits";
const STAGING_DIR: &str = "staging";
const MAX_RECEIPT_BYTES: u64 = 256 * 1024;

#[derive(Debug)]
pub struct SafeRoot {
    root: PathBuf,
}

#[derive(Debug)]
pub struct PreparedPath {
    pub absolute: PathBuf,
    pub relative: String,
    pub created_directories: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReceiptIntent {
    receipt_id: String,
    runner_profile_id: String,
    workspace_id: String,
}

impl ReceiptIntent {
    pub fn id(&self) -> &str {
        &self.receipt_id
    }
}

#[derive(Debug)]
struct StateDirs {
    receipts: PathBuf,
    commits: PathBuf,
    staging: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OwnedPathKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedPath {
    pub relative_path: String,
    pub kind: OwnedPathKind,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRecord {
    pub schema_version: String,
    pub receipt_id: String,
    pub request_hash: String,
    pub action_id: String,
    pub runner_profile_id: String,
    pub workspace_id: String,
    pub created_at: chrono::DateTime<Utc>,
    pub paths: Vec<OwnedPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptCommitRecord {
    schema_version: String,
    receipt_id: String,
    runner_profile_id: String,
    workspace_id: String,
    committed_at: chrono::DateTime<Utc>,
}

fn receipt_identity(
    request_hash: &str,
    action_id: &str,
    runner_profile_id: &str,
    workspace_id: &str,
    created_at: &chrono::DateTime<Utc>,
    paths: &[OwnedPath],
) -> String {
    let identity = serde_json::json!({
        "schema_version": RECEIPT_SCHEMA,
        "request_hash": request_hash,
        "action_id": action_id,
        "runner_profile_id": runner_profile_id,
        "workspace_id": workspace_id,
        "created_at": created_at,
        "paths": paths,
    });
    sha256_hex(crate::contract::canonical_json(&identity).as_bytes())
}

fn metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn invalid_windows_name(component: &str) -> bool {
    let trimmed = component.trim_end_matches(['.', ' ']);
    let base = trimmed.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync runner directory: {error}"))
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), String> {
    // Windows does not expose a generally usable directory FlushFileBuffers
    // operation. Publication uses MoveFileExW(MOVEFILE_WRITE_THROUGH) below,
    // which provides the corresponding write-through rename guarantee.
    Ok(())
}

#[cfg(unix)]
fn publish_no_replace(source: &Path, destination: &Path, parent: &Path) -> Result<(), String> {
    fs::hard_link(source, destination)
        .map_err(|error| format!("cannot publish durable file without overwrite: {error}"))?;
    sync_directory(parent)?;
    fs::remove_file(source)
        .map_err(|error| format!("cannot remove durable staging file: {error}"))?;
    let source_parent = source
        .parent()
        .ok_or_else(|| "durable staging file has no parent".to_string())?;
    sync_directory(source_parent)
}

#[cfg(windows)]
fn publish_no_replace(source: &Path, destination: &Path, _parent: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }

    let existing = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let new = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // MOVEFILE_REPLACE_EXISTING is deliberately absent: publication must fail
    // closed when any object already occupies the final path.
    let moved = unsafe { MoveFileExW(existing.as_ptr(), new.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if moved == 0 {
        Err(format!(
            "cannot publish durable file without overwrite: {}",
            io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct CleanupDirectory {
    path: PathBuf,
    // Windows must retain every ancestor handle: omitting FILE_SHARE_DELETE
    // prevents a parent from being renamed out from under the next full-path
    // open. Unix operations resolve names from the final descriptor, but the
    // whole chain is retained as a useful identity record for tests/debugging.
    handles: Vec<File>,
}

impl CleanupDirectory {
    fn handle(&self) -> &File {
        self.handles
            .last()
            .expect("a cleanup directory always contains its root handle")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CleanupIdentity {
    volume: u64,
    object: u128,
}

#[derive(Debug)]
struct CleanupEntry {
    file: File,
    identity: CleanupIdentity,
}

struct CleanupQuarantine<'a> {
    normalized: &'a str,
    source_directory: Option<&'a CleanupDirectory>,
    source_name: &'a str,
    staging_directory: &'a CleanupDirectory,
    quarantine_name: &'a str,
    owned: &'a OwnedPath,
}

#[cfg(unix)]
mod cleanup_platform {
    use super::*;
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

    const O_RDONLY: c_int = 0;

    extern "C" {
        #[link_name = "open"]
        fn c_open(path: *const c_char, flags: c_int, ...) -> c_int;
        fn openat(directory: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
        fn fchmod(descriptor: c_int, mode: u32) -> c_int;
        fn geteuid() -> u32;
        fn unlinkat(directory: c_int, path: *const c_char, flags: c_int) -> c_int;
    }

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

    pub fn open_root(path: &Path) -> Result<File, String> {
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

    pub fn open_directory(parent: &File, name: &OsStr) -> Result<Option<File>, String> {
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

    pub fn open_entry(
        parent: &File,
        name: &OsStr,
        _kind: &OwnedPathKind,
    ) -> Result<Option<File>, String> {
        let name = portable_name(name, "cleanup entry")?;
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
            Err(format!(
                "cannot open cleanup entry without traversal: {error}"
            ))
        }
    }

    pub fn identity(file: &File) -> Result<CleanupIdentity, String> {
        let metadata = file
            .metadata()
            .map_err(|error| format!("cannot inspect opened cleanup object: {error}"))?;
        Ok(CleanupIdentity {
            volume: metadata.dev(),
            object: metadata.ino() as u128,
        })
    }

    pub fn enforce_owner_private_directory(directory: &File) -> Result<(), String> {
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
                "runner state directory is not owned by the effective user with mode 0700"
                    .to_string(),
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn rename_no_replace(
        source_directory: &File,
        source_name: &OsStr,
        _source: &File,
        destination_directory: &File,
        destination_name: &OsStr,
    ) -> Result<(), String> {
        const RENAME_NOREPLACE: u32 = 1;
        extern "C" {
            fn renameat2(
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
            renameat2(
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
    pub fn rename_no_replace(
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
    pub fn rename_no_replace(
        _source_directory: &File,
        _source_name: &OsStr,
        _source: &File,
        _destination_directory: &File,
        _destination_name: &OsStr,
    ) -> Result<(), String> {
        Err("atomic descriptor-relative cleanup quarantine is unavailable on this platform".into())
    }

    pub fn remove_entry(
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

    pub fn sync(directory: &File) -> Result<(), String> {
        directory
            .sync_all()
            .map_err(|error| format!("cannot sync runner directory: {error}"))
    }
}

#[cfg(windows)]
mod cleanup_platform {
    use super::*;
    use std::ffi::c_void;
    use std::mem::{align_of, offset_of, size_of};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    const DELETE: u32 = 0x0001_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_DISPOSITION_INFO_CLASS: u32 = 4;
    const FILE_RENAME_INFORMATION_CLASS: u32 = 10;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    struct ByHandleFileInformation {
        attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[repr(C)]
    struct FileRenameInfoLayout {
        replace_if_exists: u8,
        root_directory: *mut c_void,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    #[repr(C)]
    struct IoStatusBlock {
        status: *mut c_void,
        information: usize,
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            file: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
        fn SetFileInformationByHandle(
            file: *mut c_void,
            information_class: u32,
            information: *mut c_void,
            information_size: u32,
        ) -> i32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtSetInformationFile(
            file: *mut c_void,
            status: *mut IoStatusBlock,
            information: *mut c_void,
            information_size: u32,
            information_class: u32,
        ) -> i32;
    }

    pub fn open_root(path: &Path) -> Result<File, String> {
        open_directory_path(path)
            .map_err(|error| format!("cannot open cleanup root directory: {error}"))
    }

    fn open_directory_path(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            // Omitting FILE_SHARE_DELETE pins this directory name. Holding
            // every ancestor this way prevents junction/reparse replacement
            // between validation and a child open.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    pub fn open_directory(_parent: &File, path: &OsStr) -> Result<Option<File>, String> {
        match open_directory_path(Path::new(path)) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("cannot open cleanup directory component: {error}")),
        }
    }

    pub fn open_entry(
        _parent: &File,
        path: &OsStr,
        kind: &OwnedPathKind,
    ) -> Result<Option<File>, String> {
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if *kind == OwnedPathKind::Directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            };
        let access = DELETE
            | FILE_READ_ATTRIBUTES
            | if *kind == OwnedPathKind::File {
                GENERIC_READ
            } else {
                0
            };
        match OpenOptions::new()
            .access_mode(access)
            // Files deny both writes and deletion while their exact opened
            // handle is validated, renamed, and disposed. Directories allow
            // child cleanup but remain pinned against rename/deletion.
            .share_mode(
                FILE_SHARE_READ
                    | if *kind == OwnedPathKind::Directory {
                        FILE_SHARE_WRITE
                    } else {
                        0
                    },
            )
            .custom_flags(flags)
            .open(Path::new(path))
        {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!(
                "cannot open cleanup entry without traversal: {error}"
            )),
        }
    }

    pub fn identity(file: &File) -> Result<CleanupIdentity, String> {
        let mut information = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let result =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
        if result == 0 {
            return Err(format!(
                "cannot identify opened cleanup object: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: GetFileInformationByHandle initialized the structure after
        // returning success.
        let information = unsafe { information.assume_init() };
        Ok(CleanupIdentity {
            volume: information.volume_serial_number as u64,
            object: ((information.file_index_high as u128) << 32)
                | information.file_index_low as u128,
        })
    }

    pub fn rename_no_replace(
        _source_directory: &File,
        _source_name: &OsStr,
        source: &File,
        destination_directory: &File,
        destination_name: &OsStr,
    ) -> Result<(), String> {
        let name = destination_name.encode_wide().collect::<Vec<_>>();
        if name.is_empty() || name.contains(&0) {
            return Err("cleanup destination name is invalid".to_string());
        }
        let name_offset = offset_of!(FileRenameInfoLayout, file_name);
        let byte_count = name_offset
            .checked_add(name.len().saturating_mul(size_of::<u16>()))
            .ok_or_else(|| "cleanup rename buffer is too large".to_string())?;
        let word_count = byte_count.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; word_count];
        let buffer = storage.as_mut_ptr().cast::<u8>();
        // SAFETY: `storage` is pointer-aligned and sized for each write. The
        // destination name is copied after the fixed FILE_RENAME_INFO fields.
        unsafe {
            buffer.cast::<u8>().write(0);
            buffer
                .add(offset_of!(FileRenameInfoLayout, root_directory))
                .cast::<*mut c_void>()
                .write(destination_directory.as_raw_handle());
            buffer
                .add(offset_of!(FileRenameInfoLayout, file_name_length))
                .cast::<u32>()
                .write((name.len() * size_of::<u16>()) as u32);
            std::ptr::copy_nonoverlapping(
                name.as_ptr().cast::<u8>(),
                buffer.add(name_offset),
                name.len() * size_of::<u16>(),
            );
        }
        debug_assert_eq!(buffer.align_offset(align_of::<FileRenameInfoLayout>()), 0);
        let mut status = IoStatusBlock {
            status: std::ptr::null_mut(),
            information: 0,
        };
        let moved = unsafe {
            NtSetInformationFile(
                source.as_raw_handle(),
                &mut status,
                buffer.cast(),
                (word_count * size_of::<usize>()) as u32,
                FILE_RENAME_INFORMATION_CLASS,
            )
        };
        if moved == 0 {
            Ok(())
        } else {
            Err(format!(
                "cannot quarantine owned path without overwrite: NTSTATUS 0x{:08x}",
                moved as u32
            ))
        }
    }

    pub fn remove_entry(
        _directory: &File,
        _name: &OsStr,
        _kind: &OwnedPathKind,
        entry: File,
    ) -> Result<(), String> {
        let mut delete_file: u8 = 1;
        let removed = unsafe {
            SetFileInformationByHandle(
                entry.as_raw_handle(),
                FILE_DISPOSITION_INFO_CLASS,
                (&mut delete_file as *mut u8).cast(),
                size_of::<u8>() as u32,
            )
        };
        if removed == 0 {
            return Err(format!(
                "cannot remove quarantined owned path by handle: {}",
                io::Error::last_os_error()
            ));
        }
        drop(entry);
        Ok(())
    }

    pub fn sync(_directory: &File) -> Result<(), String> {
        // The receipt WAL makes a lost rename retryable after a crash. Windows
        // has no generally usable directory FlushFileBuffers operation.
        Ok(())
    }
}

fn valid_receipt_id(receipt_id: &str) -> bool {
    receipt_id.len() == 64
        && receipt_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Normalize a platform-independent, sandbox-relative path. Both slash styles
/// are treated as separators so a manifest cannot be safe on one host but
/// traverse on another.
pub fn normalize_relative(raw: &str, allow_root: bool) -> Result<String, String> {
    if raw.is_empty() || raw.contains('\0') {
        return Err("path is empty or contains NUL".to_string());
    }
    if raw.starts_with('/') || raw.starts_with('\\') || raw.contains(':') {
        return Err(
            "absolute, drive-relative, UNC, device, and stream paths are forbidden".to_string(),
        );
    }
    let portable = raw.replace('\\', "/");
    if portable == "." && allow_root {
        return Ok(".".to_string());
    }
    if portable.ends_with('/') || portable.contains("//") {
        return Err("empty path components are forbidden".to_string());
    }

    let mut components = Vec::new();
    for component in portable.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err("dot and empty path components are forbidden".to_string());
        }
        if component.eq_ignore_ascii_case(STATE_DIR) {
            return Err("the runner state directory is reserved".to_string());
        }
        if component.ends_with('.') || component.ends_with(' ') || invalid_windows_name(component) {
            return Err(
                "a path component is not portable or is a reserved device name".to_string(),
            );
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err("path has no usable components".to_string());
    }
    Ok(components.join("/"))
}

pub fn path_in_scope(path: &str, scope: &[String]) -> Result<bool, String> {
    let path = normalize_relative(path, true)?;
    for candidate in scope {
        let candidate = normalize_relative(candidate, true)?;
        if candidate == "."
            || path == candidate
            || path
                .strip_prefix(candidate.as_str())
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn scope_is_subset(requested: &TargetScope, allowed: &TargetScope) -> Result<bool, String> {
    for requested_path in &requested.filesystem {
        if !path_in_scope(requested_path, &allowed.filesystem)? {
            return Ok(false);
        }
    }
    for requested_destination in &requested.network {
        if !allowed.network.contains(requested_destination) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn validate_loopback_destination(destination: &NetworkDestination) -> Result<IpAddr, String> {
    if destination.port < 1024 {
        return Err("network destination port must be between 1024 and 65535".to_string());
    }
    if destination.host != "127.0.0.1" && destination.host != "::1" {
        return Err("network destination must use an exact reviewed loopback host".to_string());
    }
    let address: IpAddr = destination
        .host
        .parse()
        .map_err(|_| "network destinations must be literal IP addresses".to_string())?;
    if !address.is_loopback() {
        return Err("only literal loopback destinations are permitted".to_string());
    }
    Ok(address)
}

impl SafeRoot {
    pub fn open(configured_root: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(configured_root)
            .map_err(|error| format!("sandbox root is unavailable: {error}"))?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err("sandbox root must not be a symlink or reparse point".to_string());
        }
        if !metadata.is_dir() {
            return Err("sandbox root is not a directory".to_string());
        }
        let root = fs::canonicalize(configured_root)
            .map_err(|error| format!("sandbox root cannot be canonicalized: {error}"))?;
        Ok(Self { root })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    fn verify_contained(&self, candidate: &Path) -> Result<(), String> {
        let canonical = fs::canonicalize(candidate)
            .map_err(|error| format!("path cannot be canonicalized: {error}"))?;
        if !canonical.starts_with(&self.root) {
            return Err("canonical path escapes the sandbox root".to_string());
        }
        Ok(())
    }

    fn resolve_existing_components(&self, relative: &str) -> Result<Option<PathBuf>, String> {
        let normalized = normalize_relative(relative, true)?;
        if normalized == "." {
            return Ok(Some(self.root.clone()));
        }
        let mut current = self.root.clone();
        for component in normalized.split('/') {
            current.push(component);
            let metadata = match fs::symlink_metadata(&current) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(format!("cannot inspect path component: {error}")),
            };
            if metadata_is_link_or_reparse(&metadata) {
                return Err("symlink and reparse-point traversal is forbidden".to_string());
            }
            self.verify_contained(&current)?;
        }
        Ok(Some(current))
    }

    fn verify_existing_components(&self, relative: &str) -> Result<PathBuf, String> {
        self.resolve_existing_components(relative)?
            .ok_or_else(|| "path component is unavailable".to_string())
    }

    pub fn resolve_existing(&self, relative: &str) -> Result<PathBuf, String> {
        self.verify_existing_components(relative)
    }

    pub fn path_is_absent(&self, relative: &str) -> Result<bool, String> {
        Ok(self.resolve_existing_components(relative)?.is_none())
    }

    pub fn prepare_new_file(&self, relative: &str) -> Result<PreparedPath, String> {
        let normalized = normalize_relative(relative, false)?;
        let components = normalized.split('/').collect::<Vec<_>>();
        let mut current = self.root.clone();
        let mut created_directories = Vec::new();
        let mut parent_missing = false;

        for (index, component) in components.iter().enumerate() {
            current.push(component);
            let is_final = index + 1 == components.len();
            if parent_missing {
                if !is_final {
                    created_directories.push(components[..=index].join("/"));
                }
                continue;
            }
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata_is_link_or_reparse(&metadata) {
                        return Err("symlink and reparse-point traversal is forbidden".to_string());
                    }
                    if is_final {
                        return Err(
                            "destination already exists; overwrite is forbidden".to_string()
                        );
                    }
                    if !metadata.is_dir() {
                        return Err("a destination parent is not a directory".to_string());
                    }
                    self.verify_contained(&current)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if !is_final {
                        created_directories.push(components[..=index].join("/"));
                        parent_missing = true;
                    }
                }
                Err(error) => return Err(format!("cannot inspect destination: {error}")),
            }
        }

        Ok(PreparedPath {
            absolute: current,
            relative: normalized,
            created_directories,
        })
    }

    fn workspace_id(&self) -> String {
        let portable = self.root.to_string_lossy().replace('\\', "/");
        sha256_hex(portable.as_bytes())
    }

    #[cfg(unix)]
    fn enforce_owner_private_state_dirs(&self) -> Result<(), String> {
        let root = cleanup_platform::open_root(&self.root)?;
        let state = cleanup_platform::open_directory(&root, OsStr::new(STATE_DIR))?
            .ok_or_else(|| "runner state directory disappeared before hardening".to_string())?;
        cleanup_platform::enforce_owner_private_directory(&state)?;
        for name in [RECEIPT_DIR, RECEIPT_COMMIT_DIR, STAGING_DIR] {
            let directory = cleanup_platform::open_directory(&state, OsStr::new(name))?
                .ok_or_else(|| format!("runner state child {name} disappeared before hardening"))?;
            cleanup_platform::enforce_owner_private_directory(&directory)?;
        }
        Ok(())
    }

    fn ensure_state_dirs(&self) -> Result<StateDirs, String> {
        let state = self.root.join(STATE_DIR);
        let receipts = state.join(RECEIPT_DIR);
        let commits = state.join(RECEIPT_COMMIT_DIR);
        let staging = state.join(STAGING_DIR);
        for path in [&state, &receipts, &commits, &staging] {
            match fs::symlink_metadata(path) {
                Ok(metadata) => {
                    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
                        return Err("runner state path is unsafe".to_string());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::DirBuilderExt;
                        let mut builder = fs::DirBuilder::new();
                        builder.mode(0o700);
                        builder.create(path).map_err(|error| {
                            format!("cannot create owner-private runner state path: {error}")
                        })?;
                    }
                    #[cfg(not(unix))]
                    fs::create_dir(path)
                        .map_err(|error| format!("cannot create runner state path: {error}"))?;
                    let parent = path
                        .parent()
                        .ok_or_else(|| "runner state path has no parent".to_string())?;
                    sync_directory(parent)?;
                }
                Err(error) => return Err(format!("cannot inspect runner state path: {error}")),
            }
            self.verify_contained(path)?;
        }
        #[cfg(unix)]
        self.enforce_owner_private_state_dirs()?;
        Ok(StateDirs {
            receipts,
            commits,
            staging,
        })
    }

    fn atomic_persist_new(
        &self,
        staging_directory: &Path,
        destination_directory: &Path,
        destination: &Path,
        temporary_name: &str,
        bytes: &[u8],
    ) -> Result<(), String> {
        let temporary = staging_directory.join(temporary_name);
        let mut temporary_created = false;
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|error| format!("cannot create durable metadata staging file: {error}"))?;
            temporary_created = true;
            file.write_all(bytes)
                .map_err(|error| format!("cannot write durable metadata: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("cannot sync durable metadata: {error}"))?;
            publish_no_replace(&temporary, destination, destination_directory)
        })();
        if result.is_err() && temporary_created {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn begin_receipt(
        &self,
        manifest: &ExecutionManifest,
        profile: &RunnerProfile,
        paths: Vec<OwnedPath>,
    ) -> Result<ReceiptIntent, String> {
        if paths.is_empty() {
            return Err("a receipt must own at least one created path".to_string());
        }
        let mut unique_paths = BTreeSet::new();
        let intended_files = paths
            .iter()
            .filter(|owned| owned.kind == OwnedPathKind::File)
            .map(|owned| normalize_relative(&owned.relative_path, false))
            .collect::<Result<Vec<_>, _>>()?;
        for owned in &paths {
            let normalized = normalize_relative(&owned.relative_path, false)?;
            if normalized != owned.relative_path {
                return Err("receipt paths must use normalized separators".to_string());
            }
            if !unique_paths.insert(normalized) {
                return Err("a receipt cannot own the same path twice".to_string());
            }
            match owned.kind {
                OwnedPathKind::File => {
                    ensure_path_authorized(manifest, &owned.relative_path)?;
                    let digest = owned
                        .sha256
                        .as_deref()
                        .ok_or_else(|| "owned file intent lacks a content hash".to_string())?;
                    if !valid_receipt_id(digest) || owned.size.is_none() {
                        return Err("owned file intent has invalid content metadata".to_string());
                    }
                }
                OwnedPathKind::Directory => {
                    if !intended_files.iter().any(|file| {
                        file.strip_prefix(owned.relative_path.as_str())
                            .is_some_and(|suffix| suffix.starts_with('/'))
                    }) {
                        return Err("owned directory intent is not an ancestor of an owned file"
                            .to_string());
                    }
                    if owned.sha256.is_some() || owned.size.is_some() {
                        return Err(
                            "owned directory intent has unexpected file metadata".to_string()
                        );
                    }
                }
            }
        }
        let created_at = utc_now();
        let workspace_id = self.workspace_id();
        let receipt_id = receipt_identity(
            &manifest.request_hash,
            &manifest.action_id,
            &profile.profile_id,
            &workspace_id,
            &created_at,
            &paths,
        );
        let record = ReceiptRecord {
            schema_version: RECEIPT_SCHEMA.to_string(),
            receipt_id: receipt_id.clone(),
            request_hash: manifest.request_hash.clone(),
            action_id: manifest.action_id.clone(),
            runner_profile_id: profile.profile_id.clone(),
            workspace_id,
            created_at,
            paths,
        };
        let encoded = serde_json::to_vec_pretty(&record)
            .map_err(|error| format!("cannot serialize receipt: {error}"))?;
        if encoded.len() as u64 > MAX_RECEIPT_BYTES {
            return Err("receipt exceeds its size limit".to_string());
        }
        let dirs = self.ensure_state_dirs()?;
        let receipt_path = dirs.receipts.join(format!("{receipt_id}.json"));
        self.atomic_persist_new(
            &dirs.staging,
            &dirs.receipts,
            &receipt_path,
            &format!(".{receipt_id}.intent.tmp"),
            &encoded,
        )?;
        Ok(ReceiptIntent {
            receipt_id,
            runner_profile_id: profile.profile_id.clone(),
            workspace_id: self.workspace_id(),
        })
    }

    fn staging_name(&self, receipt_id: &str, relative_path: &str) -> String {
        let path_id = sha256_hex(relative_path.as_bytes());
        format!("{receipt_id}-{path_id}.stage")
    }

    fn staging_path(&self, receipt_id: &str, relative_path: &str) -> PathBuf {
        self.root
            .join(STATE_DIR)
            .join(STAGING_DIR)
            .join(self.staging_name(receipt_id, relative_path))
    }

    fn create_planned_directories(&self, target: &PreparedPath) -> Result<(), String> {
        for directory in &target.created_directories {
            let absolute = self
                .root
                .join(directory.replace('/', std::path::MAIN_SEPARATOR_STR));
            match fs::symlink_metadata(&absolute) {
                Ok(metadata) => {
                    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
                        return Err("destination parent failed safety verification".to_string());
                    }
                    self.verify_contained(&absolute)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let parent = absolute
                        .parent()
                        .ok_or_else(|| "destination parent has no parent".to_string())?;
                    self.verify_contained(parent)?;
                    fs::create_dir(&absolute)
                        .map_err(|error| format!("cannot create destination parent: {error}"))?;
                    let metadata = fs::symlink_metadata(&absolute)
                        .map_err(|error| format!("cannot verify destination parent: {error}"))?;
                    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
                        return Err("new destination parent failed safety verification".to_string());
                    }
                    self.verify_contained(&absolute)?;
                    sync_directory(parent)?;
                }
                Err(error) => return Err(format!("cannot inspect destination parent: {error}")),
            }
        }
        Ok(())
    }

    fn receipt_owns_file(
        &self,
        intent: &ReceiptIntent,
        target: &PreparedPath,
        bytes: &[u8],
    ) -> Result<(), String> {
        let record = self
            .load_receipt(intent.id())?
            .ok_or_else(|| "durable receipt intent is unavailable".to_string())?;
        if record.runner_profile_id != intent.runner_profile_id
            || record.workspace_id != intent.workspace_id
            || intent.workspace_id != self.workspace_id()
        {
            return Err("durable receipt intent identity is invalid".to_string());
        }
        let expected_hash = sha256_hex(bytes);
        if record.paths.iter().any(|owned| {
            owned.relative_path == target.relative
                && owned.kind == OwnedPathKind::File
                && owned.sha256.as_deref() == Some(expected_hash.as_str())
                && owned.size == Some(bytes.len() as u64)
        }) {
            Ok(())
        } else {
            Err("durable receipt intent does not own the exact destination bytes".to_string())
        }
    }

    /// Materialize one intent-owned file without ever exposing partial bytes
    /// at its final path. The fully-synced staging inode is hard-linked into
    /// place with no-overwrite semantics, so every published file is either
    /// absent or hash-identical to its durable pre-effect intent.
    pub fn write_new(
        &self,
        target: &PreparedPath,
        bytes: &[u8],
        intent: &ReceiptIntent,
    ) -> Result<(), String> {
        self.receipt_owns_file(intent, target, bytes)?;
        self.create_planned_directories(target)?;
        let parent = target
            .absolute
            .parent()
            .ok_or_else(|| "destination has no parent".to_string())?;
        self.verify_contained(parent)?;

        let dirs = self.ensure_state_dirs()?;
        let staging_path = self.staging_path(intent.id(), &target.relative);
        let mut staging = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging_path)
            .map_err(|error| format!("cannot create receipt-owned staging file: {error}"))?;
        staging
            .write_all(bytes)
            .map_err(|error| format!("cannot write receipt-owned staging file: {error}"))?;
        staging
            .sync_all()
            .map_err(|error| format!("cannot sync receipt-owned staging file: {error}"))?;
        sync_directory(&dirs.staging)?;

        publish_no_replace(&staging_path, &target.absolute, parent)?;
        let metadata = fs::symlink_metadata(&target.absolute)
            .map_err(|error| format!("cannot verify destination: {error}"))?;
        if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
            return Err("destination failed post-write safety verification".to_string());
        }
        self.verify_contained(&target.absolute)?;
        if metadata.len() != bytes.len() as u64
            || hash_file(&target.absolute, bytes.len() as u64)? != sha256_hex(bytes)
        {
            return Err("published destination differs from its durable intent".to_string());
        }

        sync_directory(&dirs.staging)
    }

    pub fn commit_receipt(
        &self,
        intent: &ReceiptIntent,
        profile: &RunnerProfile,
    ) -> Result<String, String> {
        let record = self
            .load_receipt(intent.id())?
            .ok_or_else(|| "durable receipt intent is unavailable".to_string())?;
        if record.runner_profile_id != profile.profile_id {
            return Err("receipt intent belongs to another runner profile".to_string());
        }
        let workspace_id = self.workspace_id();
        if intent.runner_profile_id != profile.profile_id
            || intent.workspace_id != workspace_id
            || record.workspace_id != workspace_id
        {
            return Err("receipt intent belongs to another workspace".to_string());
        }
        for owned in &record.paths {
            let absolute = match self.resolve_existing_components(&owned.relative_path) {
                Ok(Some(absolute)) => absolute,
                Ok(None) => return Err("a receipt-owned path is missing during commit".to_string()),
                Err(error) => return Err(format!("cannot validate committed path: {error}")),
            };
            let metadata = fs::symlink_metadata(&absolute)
                .map_err(|error| format!("cannot inspect committed path: {error}"))?;
            match owned.kind {
                OwnedPathKind::File => {
                    if metadata_is_link_or_reparse(&metadata)
                        || !metadata.is_file()
                        || owned.size != Some(metadata.len())
                    {
                        return Err("an existing path differs from its receipt intent".to_string());
                    }
                    let actual_hash = hash_file(&absolute, metadata.len())?;
                    if owned.sha256.as_deref() != Some(actual_hash.as_str()) {
                        return Err("an existing path differs from its receipt intent".to_string());
                    }
                }
                OwnedPathKind::Directory => {
                    if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
                        return Err(
                            "an existing directory differs from its receipt intent".to_string()
                        );
                    }
                }
            }
        }
        let commit = ReceiptCommitRecord {
            schema_version: RECEIPT_COMMIT_SCHEMA.to_string(),
            receipt_id: intent.id().to_string(),
            runner_profile_id: profile.profile_id.clone(),
            workspace_id: workspace_id.clone(),
            committed_at: utc_now(),
        };
        let encoded = serde_json::to_vec_pretty(&commit)
            .map_err(|error| format!("cannot serialize receipt commit: {error}"))?;
        let dirs = self.ensure_state_dirs()?;
        let commit_path = dirs.commits.join(format!("{}.json", intent.id()));
        match fs::symlink_metadata(&commit_path) {
            Ok(metadata) if !metadata_is_link_or_reparse(&metadata) && metadata.is_file() => {
                if metadata.len() > MAX_RECEIPT_BYTES {
                    return Err("receipt commit exceeds its size limit".to_string());
                }
                self.verify_contained(&commit_path)?;
                let existing: ReceiptCommitRecord = serde_json::from_slice(
                    &fs::read(&commit_path)
                        .map_err(|error| format!("cannot read receipt commit: {error}"))?,
                )
                .map_err(|error| format!("receipt commit schema is invalid: {error}"))?;
                if existing.schema_version != RECEIPT_COMMIT_SCHEMA
                    || existing.receipt_id != intent.id()
                    || existing.runner_profile_id != profile.profile_id
                    || existing.workspace_id != workspace_id
                {
                    return Err("receipt commit identity is invalid".to_string());
                }
                return Ok(intent.id().to_string());
            }
            Ok(_) => return Err("receipt commit path is unsafe".to_string()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect receipt commit: {error}")),
        }
        self.atomic_persist_new(
            &dirs.staging,
            &dirs.commits,
            &commit_path,
            &format!(".{}.commit.tmp", intent.id()),
            &encoded,
        )?;
        Ok(intent.id().to_string())
    }

    pub fn load_receipt(&self, receipt_id: &str) -> Result<Option<ReceiptRecord>, String> {
        if !valid_receipt_id(receipt_id) {
            return Err("receipt ID must be a 64-character hexadecimal digest".to_string());
        }
        let receipt_path = self
            .root
            .join(STATE_DIR)
            .join(RECEIPT_DIR)
            .join(format!("{receipt_id}.json"));
        let metadata = match fs::symlink_metadata(&receipt_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("cannot inspect receipt: {error}")),
        };
        if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
            return Err("receipt is not a regular runner-owned file".to_string());
        }
        if metadata.len() > MAX_RECEIPT_BYTES {
            return Err("receipt exceeds its size limit".to_string());
        }
        self.verify_contained(&receipt_path)?;
        let bytes =
            fs::read(&receipt_path).map_err(|error| format!("cannot read receipt: {error}"))?;
        let record: ReceiptRecord = serde_json::from_slice(&bytes)
            .map_err(|error| format!("receipt schema is invalid: {error}"))?;
        if record.schema_version != RECEIPT_SCHEMA || record.receipt_id != receipt_id {
            return Err("receipt identity is invalid".to_string());
        }
        let expected = receipt_identity(
            &record.request_hash,
            &record.action_id,
            &record.runner_profile_id,
            &record.workspace_id,
            &record.created_at,
            &record.paths,
        );
        if expected != receipt_id {
            return Err("receipt content digest is invalid".to_string());
        }
        if record.workspace_id != self.workspace_id() {
            return Err("receipt belongs to another workspace".to_string());
        }
        Ok(Some(record))
    }

    pub fn receipt_commit_exists(&self, receipt_id: &str) -> Result<bool, String> {
        if !valid_receipt_id(receipt_id) {
            return Err("receipt ID must be a 64-character hexadecimal digest".to_string());
        }
        let commit_path = self
            .root
            .join(STATE_DIR)
            .join(RECEIPT_COMMIT_DIR)
            .join(format!("{receipt_id}.json"));
        let metadata = match fs::symlink_metadata(&commit_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(format!("cannot inspect receipt commit: {error}")),
        };
        if metadata_is_link_or_reparse(&metadata) || !metadata.is_file() {
            return Err("receipt commit is not a regular runner-owned file".to_string());
        }
        if metadata.len() > MAX_RECEIPT_BYTES {
            return Err("receipt commit exceeds its size limit".to_string());
        }
        self.verify_contained(&commit_path)?;
        Ok(true)
    }

    pub fn delete_receipt(&self, receipt_id: &str) -> Result<(), String> {
        if !valid_receipt_id(receipt_id) {
            return Err("receipt ID must be a 64-character hexadecimal digest".to_string());
        }
        let Some(root) = self.open_cleanup_directory(&[])? else {
            return Ok(());
        };
        let Some(state) = self.open_cleanup_child_directory(&root, STATE_DIR)? else {
            return Ok(());
        };

        // Open and pin every state parent before deleting any recovery data.
        // A malformed/replaced parent therefore fails closed while the receipt
        // and commit records are still available for a later retry.
        let staging = self.open_cleanup_child_directory(&state, STAGING_DIR)?;
        let commits = self.open_cleanup_child_directory(&state, RECEIPT_COMMIT_DIR)?;
        let receipts = self.open_cleanup_child_directory(&state, RECEIPT_DIR)?;

        if let Some(staging) = staging.as_ref() {
            for name in [
                format!(".{receipt_id}.intent.tmp"),
                format!(".{receipt_id}.commit.tmp"),
            ] {
                self.remove_optional_cleanup_file(staging, &name, "receipt temporary")?;
            }
        }
        let metadata_name = format!("{receipt_id}.json");
        if let Some(commits) = commits.as_ref() {
            self.remove_optional_cleanup_file(commits, &metadata_name, "receipt commit")?;
        }
        if let Some(receipts) = receipts.as_ref() {
            self.remove_optional_cleanup_file(receipts, &metadata_name, "receipt intent")?;
        }

        // Per-path staging files are deleted only by remove_staging_for_owned,
        // which derives their exact name from an authenticated receipt entry.
        // An otherwise matching stage file with no surviving intent is
        // unproven and is deliberately retained. Empty owner-private state
        // directories are also retained so cleanup never unlinks an unpinned
        // replacement directory.
        Ok(())
    }

    pub fn remove_staging_for_owned(
        &self,
        receipt_id: &str,
        owned: &OwnedPath,
    ) -> Result<(), String> {
        if !valid_receipt_id(receipt_id) {
            return Err("receipt ID must be a 64-character hexadecimal digest".to_string());
        }
        if owned.kind != OwnedPathKind::File {
            return Ok(());
        }
        let Some(root) = self.open_cleanup_directory(&[])? else {
            return Ok(());
        };
        let Some(state) = self.open_cleanup_child_directory(&root, STATE_DIR)? else {
            return Ok(());
        };
        let Some(staging) = self.open_cleanup_child_directory(&state, STAGING_DIR)? else {
            return Ok(());
        };
        self.remove_optional_cleanup_file(
            &staging,
            &self.staging_name(receipt_id, &owned.relative_path),
            "receipt-owned staging file",
        )?;
        Ok(())
    }

    fn open_cleanup_directory(
        &self,
        components: &[&str],
    ) -> Result<Option<CleanupDirectory>, String> {
        let root = cleanup_platform::open_root(&self.root)?;
        let root_metadata = root
            .metadata()
            .map_err(|error| format!("cannot inspect opened cleanup root: {error}"))?;
        if metadata_is_link_or_reparse(&root_metadata) || !root_metadata.is_dir() {
            return Err("opened cleanup root is unsafe".to_string());
        }
        let mut directory = CleanupDirectory {
            path: self.root.clone(),
            handles: vec![root],
        };
        for component in components {
            let Some(opened) = self.open_cleanup_child_directory(&directory, component)? else {
                return Ok(None);
            };
            directory = opened;
        }
        Ok(Some(directory))
    }

    fn open_cleanup_child_directory(
        &self,
        parent: &CleanupDirectory,
        name: &str,
    ) -> Result<Option<CleanupDirectory>, String> {
        let path = parent.path.join(name);
        #[cfg(unix)]
        let opened = cleanup_platform::open_directory(parent.handle(), OsStr::new(name))?;
        #[cfg(windows)]
        let opened = cleanup_platform::open_directory(parent.handle(), path.as_os_str())?;
        let Some(opened) = opened else {
            return Ok(None);
        };
        let metadata = opened
            .metadata()
            .map_err(|error| format!("cannot inspect opened cleanup directory: {error}"))?;
        if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
            return Err("cleanup directory traversal encountered an unsafe object".to_string());
        }
        let mut handles = Vec::with_capacity(parent.handles.len() + 1);
        for handle in &parent.handles {
            handles.push(
                handle
                    .try_clone()
                    .map_err(|error| format!("cannot retain cleanup ancestor handle: {error}"))?,
            );
        }
        handles.push(opened);
        Ok(Some(CleanupDirectory { path, handles }))
    }

    fn open_cleanup_parent(
        &self,
        normalized: &str,
    ) -> Result<(Option<CleanupDirectory>, String), String> {
        let mut components = normalized.split('/').collect::<Vec<_>>();
        let leaf = components
            .pop()
            .ok_or_else(|| "cleanup path has no final component".to_string())?
            .to_string();
        Ok((self.open_cleanup_directory(&components)?, leaf))
    }

    fn open_cleanup_entry(
        &self,
        directory: &CleanupDirectory,
        name: &str,
        kind: &OwnedPathKind,
    ) -> Result<Option<CleanupEntry>, String> {
        #[cfg(unix)]
        let opened = cleanup_platform::open_entry(directory.handle(), OsStr::new(name), kind)?;
        #[cfg(windows)]
        let opened = cleanup_platform::open_entry(
            directory.handle(),
            directory.path.join(name).as_os_str(),
            kind,
        )?;
        let Some(file) = opened else {
            return Ok(None);
        };
        let metadata = file
            .metadata()
            .map_err(|error| format!("cannot inspect opened cleanup entry: {error}"))?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err("cleanup entry is a link or reparse point".to_string());
        }
        match kind {
            OwnedPathKind::File if !metadata.is_file() => {
                return Err("cleanup file was replaced with another object type".to_string());
            }
            OwnedPathKind::Directory if !metadata.is_dir() => {
                return Err("cleanup directory was replaced with another object type".to_string());
            }
            _ => {}
        }
        let identity = cleanup_platform::identity(&file)?;
        Ok(Some(CleanupEntry { file, identity }))
    }

    fn validate_cleanup_entry(
        &self,
        entry: &CleanupEntry,
        owned: &OwnedPath,
    ) -> Result<(), String> {
        let metadata = entry
            .file
            .metadata()
            .map_err(|error| format!("cannot inspect opened owned path: {error}"))?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err("opened owned path became a link or reparse point".to_string());
        }
        match owned.kind {
            OwnedPathKind::File => {
                if !metadata.is_file() || owned.size != Some(metadata.len()) {
                    return Err("owned file identity changed; cleanup refused".to_string());
                }
                let expected = owned
                    .sha256
                    .as_deref()
                    .ok_or_else(|| "owned file receipt lacks a content hash".to_string())?;
                if hash_opened_file(&entry.file, metadata.len())? != expected {
                    return Err("owned file content changed; cleanup refused".to_string());
                }
                let after = entry.file.metadata().map_err(|error| {
                    format!("cannot reinspect opened owned file after hashing: {error}")
                })?;
                if after.len() != metadata.len()
                    || cleanup_platform::identity(&entry.file)? != entry.identity
                {
                    return Err("owned file changed while it was validated".to_string());
                }
            }
            OwnedPathKind::Directory => {
                if !metadata.is_dir() {
                    return Err("owned directory identity changed; cleanup refused".to_string());
                }
            }
        }
        Ok(())
    }

    fn rename_cleanup_entry(
        &self,
        source_directory: &CleanupDirectory,
        source_name: &str,
        source: &CleanupEntry,
        destination_directory: &CleanupDirectory,
        destination_name: &str,
    ) -> Result<(), String> {
        cleanup_platform::rename_no_replace(
            source_directory.handle(),
            OsStr::new(source_name),
            &source.file,
            destination_directory.handle(),
            OsStr::new(destination_name),
        )
    }

    fn remove_cleanup_entry(
        &self,
        directory: &CleanupDirectory,
        name: &str,
        kind: &OwnedPathKind,
        entry: CleanupEntry,
    ) -> Result<(), String> {
        #[cfg(unix)]
        {
            let current = self
                .open_cleanup_entry(directory, name, kind)?
                .ok_or_else(|| "cleanup quarantine disappeared before removal".to_string())?;
            if current.identity != entry.identity {
                return Err(
                    "cleanup quarantine was replaced before removal; replacement retained"
                        .to_string(),
                );
            }
        }
        cleanup_platform::remove_entry(directory.handle(), OsStr::new(name), kind, entry.file)
    }

    fn remove_optional_cleanup_file(
        &self,
        directory: &CleanupDirectory,
        name: &str,
        subject: &str,
    ) -> Result<bool, String> {
        let Some(entry) = self
            .open_cleanup_entry(directory, name, &OwnedPathKind::File)
            .map_err(|error| format!("cannot inspect {subject}: {error}"))?
        else {
            return Ok(false);
        };
        self.remove_cleanup_entry(directory, name, &OwnedPathKind::File, entry)
            .map_err(|error| format!("cannot remove {subject}: {error}"))?;
        cleanup_platform::sync(directory.handle())?;
        Ok(true)
    }

    fn cleanup_quarantine_name(&self, receipt_id: &str, owned: &OwnedPath) -> String {
        let identity = sha256_hex(format!("{receipt_id}\0{}", owned.relative_path).as_bytes());
        format!("cleanup-{identity}.quarantine")
    }

    fn restore_changed_quarantine(
        &self,
        context: &CleanupQuarantine<'_>,
        quarantine: CleanupEntry,
        validation_error: String,
    ) -> String {
        let Some(source_directory) = context.source_directory else {
            return format!(
                "{validation_error}; changed object remains quarantined because its original parent is absent"
            );
        };
        match self.open_cleanup_entry(source_directory, context.source_name, &context.owned.kind) {
            Ok(None) => {}
            Ok(Some(_)) => {
                return format!(
                    "{validation_error}; changed object remains quarantined because the public path is occupied"
                );
            }
            Err(error) => {
                return format!(
                    "{validation_error}; changed object remains quarantined because the public path is unsafe: {error}"
                );
            }
        }
        match self.rename_cleanup_entry(
            context.staging_directory,
            context.quarantine_name,
            &quarantine,
            source_directory,
            context.source_name,
        ) {
            Ok(()) => {
                let durability_error = cleanup_platform::sync(context.staging_directory.handle())
                    .and_then(|()| cleanup_platform::sync(source_directory.handle()))
                    .err();
                match durability_error {
                    Some(error) => format!(
                        "{validation_error}; changed object was restored without overwrite but directory durability verification failed: {error}"
                    ),
                    None => format!(
                        "{validation_error}; changed object was restored without overwrite and retained"
                    ),
                }
            }
            Err(error) => format!(
                "{validation_error}; changed object remains quarantined because it could not be restored without overwrite: {error}"
            ),
        }
    }

    fn remove_validated_quarantine(
        &self,
        context: &CleanupQuarantine<'_>,
        quarantine: CleanupEntry,
    ) -> Result<Option<String>, String> {
        if let Err(error) = self.validate_cleanup_entry(&quarantine, context.owned) {
            return Err(self.restore_changed_quarantine(context, quarantine, error));
        }
        self.remove_cleanup_entry(
            context.staging_directory,
            context.quarantine_name,
            &context.owned.kind,
            quarantine,
        )?;
        cleanup_platform::sync(context.staging_directory.handle())?;
        if let Some(source_directory) = context.source_directory {
            match self.open_cleanup_entry(
                source_directory,
                context.source_name,
                &context.owned.kind,
            ) {
                Ok(None) => {}
                Ok(Some(_)) => {
                    return Err(
                        "owned public path was replaced while its quarantined object was removed; replacement retained"
                            .to_string(),
                    );
                }
                Err(error) => {
                    return Err(format!(
                        "owned public path could not be verified from its pinned parent after quarantine removal: {error}"
                    ));
                }
            }
        }
        Ok(Some(context.normalized.to_string()))
    }

    pub fn remove_owned(
        &self,
        receipt_id: &str,
        owned: &OwnedPath,
    ) -> Result<Option<String>, String> {
        if !valid_receipt_id(receipt_id) {
            return Err("receipt ID must be a 64-character hexadecimal digest".to_string());
        }
        let normalized = normalize_relative(&owned.relative_path, false)?;
        self.ensure_state_dirs()?;
        let staging_directory = self
            .open_cleanup_directory(&[STATE_DIR, STAGING_DIR])?
            .ok_or_else(|| "runner cleanup staging directory is unavailable".to_string())?;
        let (source_directory, source_name) = self.open_cleanup_parent(&normalized)?;
        let quarantine_name = self.cleanup_quarantine_name(receipt_id, owned);

        if let Some(quarantine) =
            self.open_cleanup_entry(&staging_directory, &quarantine_name, &owned.kind)?
        {
            let context = CleanupQuarantine {
                normalized: &normalized,
                source_directory: source_directory.as_ref(),
                source_name: &source_name,
                staging_directory: &staging_directory,
                quarantine_name: &quarantine_name,
                owned,
            };
            return self.remove_validated_quarantine(&context, quarantine);
        }

        let Some(source_directory) = source_directory else {
            return Ok(None);
        };
        let Some(source) = self.open_cleanup_entry(&source_directory, &source_name, &owned.kind)?
        else {
            return Ok(None);
        };
        self.validate_cleanup_entry(&source, owned)?;
        self.rename_cleanup_entry(
            &source_directory,
            &source_name,
            &source,
            &staging_directory,
            &quarantine_name,
        )?;
        cleanup_platform::sync(source_directory.handle())?;
        cleanup_platform::sync(staging_directory.handle())?;
        let context = CleanupQuarantine {
            normalized: &normalized,
            source_directory: Some(&source_directory),
            source_name: &source_name,
            staging_directory: &staging_directory,
            quarantine_name: &quarantine_name,
            owned,
        };

        #[cfg(windows)]
        let quarantine = source;
        #[cfg(unix)]
        let quarantine = {
            let moved = self
                .open_cleanup_entry(&staging_directory, &quarantine_name, &owned.kind)?
                .ok_or_else(|| "cleanup quarantine disappeared after atomic move".to_string())?;
            if moved.identity != source.identity {
                return Err(self.restore_changed_quarantine(
                    &context,
                    moved,
                    "owned path identity changed before quarantine; cleanup refused".to_string(),
                ));
            }
            moved
        };
        self.remove_validated_quarantine(&context, quarantine)
    }
}

fn hash_opened_file(file: &File, max_bytes: u64) -> Result<String, String> {
    let mut file = file
        .try_clone()
        .map_err(|error| format!("cannot clone opened file for hashing: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot seek opened file for hashing: {error}"))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash opened file: {error}"))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err("file exceeds the hashing byte limit".to_string());
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

pub fn read_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("cannot inspect file: {error}"))?;
    if !metadata.is_file() {
        return Err("path is not a regular file".to_string());
    }
    if metadata.len() > max_bytes {
        return Err("file exceeds the action's artifact byte limit".to_string());
    }
    let file = File::open(path).map_err(|error| format!("cannot open file: {error}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read file: {error}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err("file grew beyond the action's artifact byte limit".to_string());
    }
    Ok(bytes)
}

pub fn hash_file(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|error| format!("cannot open file for hashing: {error}"))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash file: {error}"))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err("file exceeds the hashing byte limit".to_string());
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

pub fn owned_file(relative: String, bytes: &[u8]) -> OwnedPath {
    OwnedPath {
        relative_path: relative,
        kind: OwnedPathKind::File,
        sha256: Some(sha256_hex(bytes)),
        size: Some(bytes.len() as u64),
    }
}

pub fn owned_directories(directories: &[String]) -> Vec<OwnedPath> {
    directories
        .iter()
        .rev()
        .map(|relative_path| OwnedPath {
            relative_path: relative_path.clone(),
            kind: OwnedPathKind::Directory,
            sha256: None,
            size: None,
        })
        .collect()
}

pub fn ensure_path_authorized(manifest: &ExecutionManifest, path: &str) -> Result<(), String> {
    if path_in_scope(path, &manifest.target_scope.filesystem)? {
        Ok(())
    } else {
        Err("path is outside the manifest's declared filesystem scope".to_string())
    }
}

pub fn ensure_network_authorized(
    manifest: &ExecutionManifest,
    profile: &RunnerProfile,
    destination: &NetworkDestination,
) -> Result<IpAddr, String> {
    let address = validate_loopback_destination(destination)?;
    if !manifest.target_scope.network.contains(destination) {
        return Err("destination is outside the manifest's declared network scope".to_string());
    }
    if !profile.target_scope.network.contains(destination) {
        return Err("destination is outside the runner profile's network scope".to_string());
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolated_test_root(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bluefire-safety-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn rejects_portable_traversal_and_absolute_forms() {
        for path in [
            "../escape",
            "..\\escape",
            "/absolute",
            "\\\\server\\share",
            "C:\\escape",
            "C:relative",
            "safe//file",
            "safe/./file",
            ".bluefire/receipts/x",
            "safe/CON.txt",
        ] {
            assert!(normalize_relative(path, false).is_err(), "accepted {path}");
        }
        assert_eq!(
            normalize_relative("safe\\file.txt", false).unwrap(),
            "safe/file.txt"
        );
    }

    #[test]
    fn scope_checks_component_boundaries() {
        let allowed = vec!["artifacts".to_string()];
        assert!(path_in_scope("artifacts/a.txt", &allowed).unwrap());
        assert!(!path_in_scope("artifacts-other/a.txt", &allowed).unwrap());
    }

    #[test]
    fn loopback_requires_literal_address() {
        assert!(validate_loopback_destination(&NetworkDestination {
            host: "127.0.0.1".to_string(),
            port: 8080,
        })
        .is_ok());
        assert!(validate_loopback_destination(&NetworkDestination {
            host: "localhost".to_string(),
            port: 8080,
        })
        .is_err());
        assert!(validate_loopback_destination(&NetworkDestination {
            host: "192.0.2.1".to_string(),
            port: 8080,
        })
        .is_err());
        assert!(validate_loopback_destination(&NetworkDestination {
            host: "127.0.0.2".to_string(),
            port: 8080,
        })
        .is_err());
        assert!(validate_loopback_destination(&NetworkDestination {
            host: "127.0.0.1".to_string(),
            port: 1023,
        })
        .is_err());
        assert!(validate_loopback_destination(&NetworkDestination {
            host: "::1".to_string(),
            port: 1024,
        })
        .is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_anchor_denies_an_intermediate_parent_rename() {
        let root = isolated_test_root("windows-parent-anchor");
        fs::create_dir_all(root.join("pinned/child")).unwrap();
        let safe_root = SafeRoot::open(&root).unwrap();
        let anchor = safe_root
            .open_cleanup_directory(&["pinned", "child"])
            .unwrap()
            .unwrap();

        let attempted = fs::rename(root.join("pinned"), root.join("replacement"));
        assert!(
            attempted.is_err(),
            "an ancestor with a no-share-delete handle was renamed"
        );
        assert!(root.join("pinned/child").is_dir());

        drop(anchor);
        fs::rename(root.join("pinned"), root.join("replacement")).unwrap();
        drop(safe_root);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_metadata_cleanup_deletes_the_exact_opened_file_handle() {
        let root = isolated_test_root("windows-metadata-handle");
        fs::create_dir_all(root.join(".bluefire/receipts")).unwrap();
        let receipt_name = format!("{}.json", "a".repeat(64));
        let receipt_path = root.join(".bluefire/receipts").join(&receipt_name);
        fs::write(&receipt_path, b"receipt metadata").unwrap();
        let safe_root = SafeRoot::open(&root).unwrap();
        let receipts = safe_root
            .open_cleanup_directory(&[STATE_DIR, RECEIPT_DIR])
            .unwrap()
            .unwrap();
        let receipt = safe_root
            .open_cleanup_entry(&receipts, &receipt_name, &OwnedPathKind::File)
            .unwrap()
            .unwrap();

        let attempted = fs::rename(&receipt_path, receipt_path.with_extension("replacement"));
        assert!(
            attempted.is_err(),
            "an exact metadata file with a no-share-delete handle was replaced"
        );
        safe_root
            .remove_cleanup_entry(&receipts, &receipt_name, &OwnedPathKind::File, receipt)
            .unwrap();
        assert!(!receipt_path.exists());

        drop(receipts);
        drop(safe_root);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_cleanup_rename_uses_pinned_source_and_staging_directories() {
        use std::os::unix::fs::symlink;

        let root = isolated_test_root("unix-parent-anchor");
        let outside_source = isolated_test_root("unix-outside-source");
        let outside_staging = isolated_test_root("unix-outside-staging");
        fs::create_dir_all(root.join("source")).unwrap();
        fs::create_dir_all(root.join(".bluefire/staging")).unwrap();
        fs::create_dir_all(&outside_source).unwrap();
        fs::create_dir_all(&outside_staging).unwrap();
        let bytes = b"receipt-matching-bytes";
        fs::write(root.join("source/owned.bin"), bytes).unwrap();
        fs::write(outside_source.join("owned.bin"), bytes).unwrap();

        let safe_root = SafeRoot::open(&root).unwrap();
        let source = safe_root
            .open_cleanup_directory(&["source"])
            .unwrap()
            .unwrap();
        let staging = safe_root
            .open_cleanup_directory(&[STATE_DIR, STAGING_DIR])
            .unwrap()
            .unwrap();
        let owned = owned_file("source/owned.bin".to_string(), bytes);
        let entry = safe_root
            .open_cleanup_entry(&source, "owned.bin", &owned.kind)
            .unwrap()
            .unwrap();

        fs::rename(root.join("source"), root.join("source-detached")).unwrap();
        fs::rename(
            root.join(".bluefire/staging"),
            root.join(".bluefire/staging-detached"),
        )
        .unwrap();
        symlink(&outside_source, root.join("source")).unwrap();
        symlink(&outside_staging, root.join(".bluefire/staging")).unwrap();

        safe_root
            .rename_cleanup_entry(&source, "owned.bin", &entry, &staging, "captured.bin")
            .unwrap();
        assert_eq!(fs::read(outside_source.join("owned.bin")).unwrap(), bytes);
        assert!(!outside_staging.join("captured.bin").exists());
        assert!(!root.join("source-detached/owned.bin").exists());
        assert_eq!(
            fs::read(root.join(".bluefire/staging-detached/captured.bin")).unwrap(),
            bytes
        );

        drop(entry);
        drop(staging);
        drop(source);
        drop(safe_root);
        fs::remove_file(root.join("source")).unwrap();
        fs::remove_file(root.join(".bluefire/staging")).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside_source).unwrap();
        fs::remove_dir_all(outside_staging).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_metadata_cleanup_uses_pinned_state_children_after_public_swap() {
        use std::os::unix::fs::symlink;

        let root = isolated_test_root("unix-metadata-anchor");
        let outside = isolated_test_root("unix-outside-metadata");
        fs::create_dir_all(root.join(".bluefire/staging")).unwrap();
        fs::create_dir_all(root.join(".bluefire/receipts")).unwrap();
        fs::create_dir_all(root.join(".bluefire/receipt-commits")).unwrap();
        fs::create_dir_all(outside.join("staging")).unwrap();
        fs::create_dir_all(outside.join("receipts")).unwrap();
        fs::create_dir_all(outside.join("receipt-commits")).unwrap();
        let receipt_id = "a".repeat(64);
        let temporary_name = format!(".{receipt_id}.intent.tmp");
        let metadata_name = format!("{receipt_id}.json");
        for parent in [root.join(".bluefire/staging"), outside.join("staging")] {
            fs::write(parent.join(&temporary_name), b"temporary metadata").unwrap();
        }
        for parent in [
            root.join(".bluefire/receipts"),
            outside.join("receipts"),
            root.join(".bluefire/receipt-commits"),
            outside.join("receipt-commits"),
        ] {
            fs::write(parent.join(&metadata_name), b"durable metadata").unwrap();
        }

        let safe_root = SafeRoot::open(&root).unwrap();
        let cleanup_root = safe_root.open_cleanup_directory(&[]).unwrap().unwrap();
        let state = safe_root
            .open_cleanup_child_directory(&cleanup_root, STATE_DIR)
            .unwrap()
            .unwrap();
        let staging = safe_root
            .open_cleanup_child_directory(&state, STAGING_DIR)
            .unwrap()
            .unwrap();
        let receipts = safe_root
            .open_cleanup_child_directory(&state, RECEIPT_DIR)
            .unwrap()
            .unwrap();
        let commits = safe_root
            .open_cleanup_child_directory(&state, RECEIPT_COMMIT_DIR)
            .unwrap()
            .unwrap();

        fs::rename(root.join(STATE_DIR), root.join(".bluefire-detached")).unwrap();
        symlink(&outside, root.join(STATE_DIR)).unwrap();

        safe_root
            .remove_optional_cleanup_file(&staging, &temporary_name, "receipt temporary")
            .unwrap();
        safe_root
            .remove_optional_cleanup_file(&commits, &metadata_name, "receipt commit")
            .unwrap();
        safe_root
            .remove_optional_cleanup_file(&receipts, &metadata_name, "receipt intent")
            .unwrap();

        assert!(!root
            .join(".bluefire-detached/staging")
            .join(&temporary_name)
            .exists());
        assert!(!root
            .join(".bluefire-detached/receipts")
            .join(&metadata_name)
            .exists());
        assert!(!root
            .join(".bluefire-detached/receipt-commits")
            .join(&metadata_name)
            .exists());
        assert_eq!(
            fs::read(outside.join("staging").join(&temporary_name)).unwrap(),
            b"temporary metadata"
        );
        assert_eq!(
            fs::read(outside.join("receipts").join(&metadata_name)).unwrap(),
            b"durable metadata"
        );
        assert_eq!(
            fs::read(outside.join("receipt-commits").join(&metadata_name)).unwrap(),
            b"durable metadata"
        );

        drop(commits);
        drop(receipts);
        drop(staging);
        drop(state);
        drop(cleanup_root);
        drop(safe_root);
        fs::remove_file(root.join(STATE_DIR)).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_state_directories_are_hardened_to_owner_only_by_handle() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = isolated_test_root("unix-private-state");
        fs::create_dir_all(root.join(STATE_DIR)).unwrap();
        fs::set_permissions(root.join(STATE_DIR), fs::Permissions::from_mode(0o755)).unwrap();
        let safe_root = SafeRoot::open(&root).unwrap();
        safe_root.ensure_state_dirs().unwrap();

        for relative in [
            STATE_DIR,
            ".bluefire/receipts",
            ".bluefire/receipt-commits",
            ".bluefire/staging",
        ] {
            let metadata = fs::symlink_metadata(root.join(relative)).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o777, 0o700, "unsafe mode on {relative}");
        }

        drop(safe_root);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_post_removal_verification_uses_the_pinned_source_parent() {
        let root = isolated_test_root("unix-pinned-postcheck");
        fs::create_dir_all(root.join("source")).unwrap();
        fs::create_dir_all(root.join(".bluefire/staging")).unwrap();
        let bytes = b"receipt-owned-bytes";
        fs::write(root.join("source/owned.bin"), bytes).unwrap();

        let safe_root = SafeRoot::open(&root).unwrap();
        let source = safe_root
            .open_cleanup_directory(&["source"])
            .unwrap()
            .unwrap();
        let staging = safe_root
            .open_cleanup_directory(&[STATE_DIR, STAGING_DIR])
            .unwrap()
            .unwrap();
        let owned = owned_file("source/owned.bin".to_string(), bytes);
        let opened = safe_root
            .open_cleanup_entry(&source, "owned.bin", &owned.kind)
            .unwrap()
            .unwrap();
        safe_root
            .rename_cleanup_entry(&source, "owned.bin", &opened, &staging, "captured.bin")
            .unwrap();
        let captured = safe_root
            .open_cleanup_entry(&staging, "captured.bin", &owned.kind)
            .unwrap()
            .unwrap();

        fs::write(root.join("source/owned.bin"), b"replacement-retained").unwrap();
        fs::rename(root.join("source"), root.join("source-detached")).unwrap();
        fs::create_dir(root.join("source")).unwrap();
        let context = CleanupQuarantine {
            normalized: "source/owned.bin",
            source_directory: Some(&source),
            source_name: "owned.bin",
            staging_directory: &staging,
            quarantine_name: "captured.bin",
            owned: &owned,
        };

        let error = safe_root
            .remove_validated_quarantine(&context, captured)
            .unwrap_err();
        assert!(error.contains("replacement retained"), "{error}");
        assert!(!root.join(".bluefire/staging/captured.bin").exists());
        assert_eq!(
            fs::read(root.join("source-detached/owned.bin")).unwrap(),
            b"replacement-retained"
        );
        assert!(!root.join("source/owned.bin").exists());

        drop(opened);
        drop(staging);
        drop(source);
        drop(safe_root);
        fs::remove_dir_all(root).unwrap();
    }
}
