//! Exact Win32 declarations, no remote/share/authentication functions.
use std::ffi::c_void;

pub type Handle = *mut c_void;
pub const INVALID_HANDLE: Handle = -1isize as Handle;

#[repr(C)]
#[derive(Default)]
pub struct FileBasicInfo {
    pub creation: i64,
    pub access: i64,
    pub write: i64,
    pub change: i64,
    pub attributes: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct FileStandardInfo {
    pub allocation: i64,
    pub size: i64,
    pub links: u32,
    pub delete_pending: u8,
    pub directory: u8,
}

#[repr(C)]
#[derive(Default)]
pub struct FileIdInfo {
    pub volume: u64,
    pub id: [u8; 16],
}

#[repr(C)]
#[derive(Default)]
pub struct FileAttributeTagInfo {
    pub attributes: u32,
    pub tag: u32,
}

#[link(name = "kernel32")]
extern "system" {
    pub fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *const c_void,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    pub fn CloseHandle(handle: Handle) -> i32;
    pub fn GetLastError() -> u32;
    pub fn GetDriveTypeW(root: *const u16) -> u32;
    pub fn GetFileType(handle: Handle) -> u32;
    pub fn GetFileInformationByHandleEx(
        handle: Handle,
        class: u32,
        data: *mut c_void,
        size: u32,
    ) -> i32;
    pub fn GetFinalPathNameByHandleW(handle: Handle, path: *mut u16, size: u32, flags: u32) -> u32;
    pub fn GetVolumeInformationByHandleW(
        handle: Handle,
        label: *mut u16,
        label_size: u32,
        serial: *mut u32,
        component: *mut u32,
        flags: *mut u32,
        filesystem: *mut u16,
        filesystem_size: u32,
    ) -> i32;
    pub fn ReadFile(
        handle: Handle,
        data: *mut u8,
        size: u32,
        count: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    pub fn GetKernelObjectSecurity(
        handle: Handle,
        information: u32,
        descriptor: *mut c_void,
        size: u32,
        required: *mut u32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn documented_file_information_layouts() {
        assert_eq!(std::mem::size_of::<FileBasicInfo>(), 40);
        assert_eq!(std::mem::size_of::<FileStandardInfo>(), 24);
        assert_eq!(std::mem::size_of::<FileIdInfo>(), 24);
        assert_eq!(std::mem::size_of::<FileAttributeTagInfo>(), 8);
    }
}
