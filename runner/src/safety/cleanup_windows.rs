use std::ffi::OsStr;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;

use super::{metadata_is_link_or_reparse, CleanupEntryOpenError, CleanupIdentity, OwnedPathKind};
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
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
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

#[link(name = "kernel32")]
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

pub(super) fn open_root(path: &Path) -> Result<File, String> {
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

pub(super) fn open_directory(_parent: &File, path: &OsStr) -> Result<Option<File>, String> {
    match open_directory_path(Path::new(path)) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot open cleanup directory component: {error}")),
    }
}

pub(super) fn open_entry(
    _parent: &File,
    path: &OsStr,
    kind: &OwnedPathKind,
) -> Result<Option<File>, CleanupEntryOpenError> {
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
        Err(error) => {
            let message = format!("cannot open cleanup entry without traversal: {error}");
            // A file-to-directory or file-to-junction replacement can
            // make the exact access request fail with AccessDenied before
            // common metadata validation sees the concrete object. Probe
            // attributes through a reparse-point handle solely to classify
            // that observable replacement; never use this weaker handle
            // to validate, rename, or delete an expected object.
            match OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(Path::new(path))
            {
                Ok(probe) => match probe.metadata() {
                    Ok(metadata)
                        if metadata_is_link_or_reparse(&metadata)
                            || matches!(
                                kind,
                                OwnedPathKind::File if !metadata.is_file()
                            )
                            || matches!(
                                kind,
                                OwnedPathKind::Directory if !metadata.is_dir()
                            ) =>
                    {
                        Err(CleanupEntryOpenError::Unsafe(
                            "cleanup entry was replaced with an unsafe object".to_string(),
                        ))
                    }
                    Ok(_) => Err(CleanupEntryOpenError::Retryable(message)),
                    Err(probe_error) => Err(CleanupEntryOpenError::Retryable(format!(
                        "{message}; cannot classify cleanup entry: {probe_error}"
                    ))),
                },
                Err(probe_error) if probe_error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(probe_error) => Err(CleanupEntryOpenError::Retryable(format!(
                    "{message}; cannot classify cleanup entry: {probe_error}"
                ))),
            }
        }
    }
}

pub(super) fn identity(file: &File) -> Result<CleanupIdentity, String> {
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
        object: ((information.file_index_high as u128) << 32) | information.file_index_low as u128,
    })
}

pub(super) fn rename_no_replace(
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

pub(super) fn remove_entry(
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

pub(super) fn sync(_directory: &File) -> Result<(), String> {
    // The receipt WAL makes a lost rename retryable after a crash. Windows
    // has no generally usable directory FlushFileBuffers operation.
    Ok(())
}
