use super::*;
use std::ffi::c_void;
use std::mem::{offset_of, size_of, MaybeUninit};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const DELETE_ACCESS: u32 = 0x0001_0000;
const FILE_DISPOSITION_INFO_CLASS: u32 = 4;
const FILE_RENAME_INFO_CLASS: u32 = 3;

#[repr(C)]
struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

#[repr(C)]
struct ByHandleFileInformation {
    file_attributes: u32,
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
struct FileDispositionInformation {
    delete_file: i32,
}

#[repr(C)]
struct FileRenameInformation {
    replace_if_exists: u8,
    root_directory: *mut c_void,
    file_name_length: u32,
    file_name: [u16; 1],
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

fn number_of_links(file: &File) -> Result<u32, WitnessFailure> {
    let mut information = MaybeUninit::<ByHandleFileInformation>::uninit();
    // SAFETY: the file handle is live for the call and \`information\` points
    // to writable storage of the exact structure required by the API.
    let succeeded = unsafe {
        GetFileInformationByHandle(file.as_raw_handle().cast(), information.as_mut_ptr())
    };
    if succeeded == 0 {
        return Err(WitnessFailure::failed(format!(
            "cannot inspect cancellation control object identity: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: a successful call initialized the entire structure.
    Ok(unsafe { information.assume_init() }.number_of_links)
}

fn verify_directory(file: &File, subject: &str) -> Result<(), WitnessFailure> {
    let metadata = file
        .metadata()
        .map_err(|error| WitnessFailure::failed(format!("cannot inspect {subject}: {error}")))?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(WitnessFailure::blocked(format!(
            "{subject} is not a regular non-reparse directory"
        )));
    }
    Ok(())
}

fn verify_regular_single_link(file: &File, subject: &str) -> Result<(), WitnessFailure> {
    let metadata = file
        .metadata()
        .map_err(|error| WitnessFailure::failed(format!("cannot inspect {subject}: {error}")))?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || number_of_links(file)? != 1
    {
        return Err(WitnessFailure::blocked(format!(
            "{subject} is not a regular single-link non-reparse file"
        )));
    }
    Ok(())
}

pub fn open_directory_pinned(
    path: &Path,
    subject: &str,
    delete_access: bool,
    share_delete: bool,
) -> Result<File, WitnessFailure> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(
            FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 },
        )
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    if delete_access {
        options.access_mode(GENERIC_READ | DELETE_ACCESS);
    }
    let file = options
        .open(path)
        .map_err(|error| WitnessFailure::failed(format!("cannot open {subject}: {error}")))?;
    verify_directory(&file, subject)?;
    Ok(file)
}

pub fn create_new_pinned(path: &Path, subject: &str) -> Result<File, WitnessFailure> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .access_mode(GENERIC_WRITE | DELETE_ACCESS)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                WitnessFailure::blocked(format!("{subject} already exists"))
            } else {
                WitnessFailure::failed(format!("cannot create {subject}: {error}"))
            }
        })?;
    if let Err(error) = verify_regular_single_link(&file, subject) {
        let _ = mark_delete_on_close(&file, subject);
        return Err(error);
    }
    Ok(file)
}

pub enum RequestOpen {
    MissingOrBusy,
    Open(File),
}

pub fn open_existing_pinned(path: &Path, subject: &str) -> Result<File, WitnessFailure> {
    let file = OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ | DELETE_ACCESS)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| WitnessFailure::failed(format!("cannot open {subject}: {error}")))?;
    verify_regular_single_link(&file, subject)?;
    Ok(file)
}

pub fn open_request_pinned(path: &Path) -> Result<RequestOpen, WitnessFailure> {
    let file = match OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ | DELETE_ACCESS)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(RequestOpen::MissingOrBusy)
        }
        // A cooperating writer may still be publishing the request. It
        // closes quickly, after which this exclusive identity pin succeeds.
        Err(error) if error.raw_os_error() == Some(32) => return Ok(RequestOpen::MissingOrBusy),
        Err(error) => {
            return Err(WitnessFailure::failed(format!(
                "cannot open the cancellation request: {error}"
            )))
        }
    };
    verify_regular_single_link(&file, "the cancellation request")?;
    Ok(RequestOpen::Open(file))
}

pub fn rename_no_replace(
    file: &File,
    final_path: &Path,
    subject: &str,
) -> Result<(), WitnessFailure> {
    let name = final_path.as_os_str().encode_wide().collect::<Vec<_>>();
    if name.is_empty() || name.contains(&0) {
        return Err(WitnessFailure::failed(format!(
            "cannot publish {subject}: the fixed final name is invalid"
        )));
    }
    let name_offset = offset_of!(FileRenameInformation, file_name);
    // Include a zero UTF-16 code unit after the length-delimited name.
    // Some local filesystems consume that terminator even though it is
    // excluded from FileNameLength.
    let byte_count = name_offset + (name.len() + 1) * size_of::<u16>();
    let mut storage = vec![0_usize; byte_count.div_ceil(size_of::<usize>())];
    let buffer = storage.as_mut_ptr().cast::<u8>();
    // SAFETY: \`storage\` is aligned and sized for the fixed rename fields
    // plus every UTF-16 code unit copied into the trailing name buffer.
    unsafe {
        buffer.write(0);
        buffer
            .add(offset_of!(FileRenameInformation, root_directory))
            .cast::<*mut c_void>()
            .write(std::ptr::null_mut());
        buffer
            .add(offset_of!(FileRenameInformation, file_name_length))
            .cast::<u32>()
            .write((name.len() * size_of::<u16>()) as u32);
        std::ptr::copy_nonoverlapping(
            name.as_ptr().cast::<u8>(),
            buffer.add(name_offset),
            name.len() * size_of::<u16>(),
        );
    }
    let moved = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FILE_RENAME_INFO_CLASS,
            buffer.cast(),
            (storage.len() * size_of::<usize>()) as u32,
        )
    };
    if moved != 0 {
        return verify_regular_single_link(file, subject);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::AlreadyExists {
        Err(WitnessFailure::blocked(format!("{subject} already exists")))
    } else {
        Err(WitnessFailure::failed(format!(
            "cannot atomically publish {subject}: {error}"
        )))
    }
}

pub fn mark_delete_on_close(file: &File, subject: &str) -> Result<(), WitnessFailure> {
    let mut disposition = FileDispositionInformation { delete_file: 1 };
    // SAFETY: the handle was opened with DELETE access and is live. The
    // disposition structure has the exact size required by the
    // FileDispositionInfo contract.
    let succeeded = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FILE_DISPOSITION_INFO_CLASS,
            (&mut disposition as *mut FileDispositionInformation).cast(),
            std::mem::size_of::<FileDispositionInformation>() as u32,
        )
    };
    if succeeded == 0 {
        Err(WitnessFailure::failed(format!(
            "cannot mark {subject} for exact deletion: {}",
            io::Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}
