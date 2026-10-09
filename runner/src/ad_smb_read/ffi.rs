//! Fixed Win32 ABI from Microsoft WinSDK headers; no dynamic symbol loading.
use std::ffi::c_void;

pub(super) type Handle = *mut c_void;
pub(super) const INVALID_HANDLE: Handle = -1isize as Handle;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct Luid {
    pub low: u32,
    pub high: i32,
}
#[repr(C)]
#[derive(Default)]
pub(super) struct TokenStatistics {
    pub token_id: Luid,
    pub authentication_id: Luid,
    pub expiration_time: i64,
    pub token_type: u32,
    pub impersonation_level: u32,
    pub dynamic_charged: u32,
    pub dynamic_available: u32,
    pub group_count: u32,
    pub privilege_count: u32,
    pub modified_id: Luid,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct TokenUser {
    pub sid: *mut u8,
    pub attributes: u32,
}

// WinBase.h's post-Win8 union occupies 16 ULONGs, not an additional structure.
#[repr(C)]
#[derive(Default)]
pub(super) struct RemoteProtocolInfo {
    pub version: u16,
    pub size: u16,
    pub protocol: u32,
    pub major: u16,
    pub minor: u16,
    pub revision: u16,
    pub reserved: u16,
    pub flags: u32,
    pub generic: [u32; 8],
    pub specific: [u32; 16],
}
#[repr(C)]
#[derive(Default)]
pub(super) struct FileStandardInfo {
    pub allocation_size: i64,
    pub end_of_file: i64,
    pub number_of_links: u32,
    pub delete_pending: u8,
    pub directory: u8,
}
#[repr(C)]
#[derive(Default)]
pub(super) struct FileIdInfo {
    pub volume_serial: u64,
    pub id: [u8; 16],
}
#[repr(C)]
#[derive(Default)]
pub(super) struct FileAttributeTagInfo {
    pub attributes: u32,
    pub reparse_tag: u32,
}

#[link(name = "advapi32")]
extern "system" {
    pub(super) fn LogonUserW(
        user: *const u16,
        domain: *const u16,
        password: *const u16,
        logon_type: u32,
        provider: u32,
        token: *mut Handle,
    ) -> i32;
    pub(super) fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    pub(super) fn OpenThreadToken(
        thread: Handle,
        access: u32,
        open_as_self: i32,
        token: *mut Handle,
    ) -> i32;
    pub(super) fn GetTokenInformation(
        token: Handle,
        class: u32,
        buffer: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    pub(super) fn ImpersonateLoggedOnUser(token: Handle) -> i32;
    pub(super) fn RevertToSelf() -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    pub(super) fn GetCurrentProcess() -> Handle;
    pub(super) fn GetCurrentThread() -> Handle;
    pub(super) fn GetCurrentThreadId() -> u32;
    pub(super) fn GetLastError() -> u32;
    pub(super) fn CloseHandle(handle: Handle) -> i32;
    pub(super) fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *const c_void,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    pub(super) fn GetFileInformationByHandleEx(
        handle: Handle,
        class: u32,
        buffer: *mut c_void,
        length: u32,
    ) -> i32;
    pub(super) fn GetFileType(handle: Handle) -> u32;
    pub(super) fn GetFinalPathNameByHandleW(
        handle: Handle,
        output: *mut u16,
        length: u32,
        flags: u32,
    ) -> u32;
    pub(super) fn ReadFile(
        handle: Handle,
        buffer: *mut u8,
        length: u32,
        count: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}

#[link(name = "mpr", kind = "raw-dylib")]
extern "system" {
    pub(super) fn WNetCancelConnection2W(name: *const u16, flags: u32, force: i32) -> u32;
}

#[cfg(test)]
mod abi_tests {
    use super::*;
    #[test]
    fn fixed_windows_struct_sizes() {
        assert_eq!(std::mem::size_of::<Luid>(), 8);
        assert_eq!(std::mem::size_of::<TokenStatistics>(), 56);
        assert_eq!(std::mem::size_of::<RemoteProtocolInfo>(), 116);
        assert_eq!(std::mem::align_of::<RemoteProtocolInfo>(), 4);
        assert_eq!(std::mem::size_of::<FileStandardInfo>(), 24);
        assert_eq!(std::mem::size_of::<FileIdInfo>(), 24);
        assert_eq!(std::mem::size_of::<FileAttributeTagInfo>(), 8);
    }
}
