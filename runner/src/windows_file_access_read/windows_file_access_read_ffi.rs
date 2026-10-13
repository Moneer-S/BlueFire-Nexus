//! Fixed WinSDK ABI. No dynamic loading, process launch, ACL or account mutation.
use std::ffi::c_void;
pub(super) type Handle = *mut c_void;
pub(super) const INVALID_HANDLE: Handle = -1isize as Handle;
// WinSDK processthreadsapi.h FORCEINLINE GetCurrentProcessToken():
// (HANDLE)(LONG_PTR)-4. Windows 8+ pseudo-handle grants TOKEN_QUERY without
// opening the owner's token through its DACL while a reader is impersonated.
// It is never owned or passed to CloseHandle.
pub(super) const CURRENT_PROCESS_TOKEN: Handle = -4isize as Handle;
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(super) struct Luid {
    pub low: u32,
    pub high: i32,
}
impl Luid {
    pub fn value(self) -> u64 {
        ((self.high as u32 as u64) << 32) | self.low as u64
    }
}
#[repr(C)]
#[derive(Default)]
pub(super) struct TokenStatistics {
    pub token_id: Luid,
    pub authentication_id: Luid,
    pub expiration: i64,
    pub token_type: u32,
    pub level: u32,
    pub dynamic_charged: u32,
    pub dynamic_available: u32,
    pub groups: u32,
    pub privileges: u32,
    pub modified: Luid,
}
#[repr(C)]
pub(super) struct TokenUser {
    pub sid: *const u8,
    pub attributes: u32,
}
#[repr(C)]
#[derive(Default)]
pub(super) struct FileBasicInfo {
    pub created: i64,
    pub accessed: i64,
    pub written: i64,
    pub changed: i64,
    pub attributes: u32,
}
#[repr(C)]
#[derive(Default)]
pub(super) struct FileStandardInfo {
    pub allocation: i64,
    pub size: i64,
    pub links: u32,
    pub delete_pending: u8,
    pub directory: u8,
}
#[repr(C)]
#[derive(Default)]
pub(super) struct FileIdInfo {
    pub volume: u64,
    pub id: [u8; 16],
}
#[repr(C)]
#[derive(Default)]
pub(super) struct FileTagInfo {
    pub attributes: u32,
    pub tag: u32,
}

#[link(name = "advapi32")]
extern "system" {
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
    pub(super) fn LogonUserW(
        user: *const u16,
        domain: *const u16,
        password: *const u16,
        kind: u32,
        provider: u32,
        token: *mut Handle,
    ) -> i32;
    pub(super) fn ImpersonateLoggedOnUser(token: Handle) -> i32;
    pub(super) fn RevertToSelf() -> i32;
    pub(super) fn LookupPrivilegeValueW(
        system: *const u16,
        name: *const u16,
        value: *mut Luid,
    ) -> i32;
    pub(super) fn GetSecurityInfo(
        handle: Handle,
        kind: u32,
        selected: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    pub(super) fn IsValidSecurityDescriptor(descriptor: *const c_void) -> i32;
    pub(super) fn GetSecurityDescriptorLength(descriptor: *const c_void) -> u32;
}
#[link(name = "kernel32")]
extern "system" {
    pub(super) fn GetCurrentThread() -> Handle;
    pub(super) fn GetCurrentThreadId() -> u32;
    pub(super) fn GetLastError() -> u32;
    pub(super) fn CloseHandle(handle: Handle) -> i32;
    pub(super) fn LocalFree(pointer: *mut c_void) -> *mut c_void;
    pub(super) fn GetDriveTypeW(root: *const u16) -> u32;
    pub(super) fn CreateFileW(
        path: *const u16,
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
    pub(super) fn GetFinalPathNameByHandleW(
        handle: Handle,
        buffer: *mut u16,
        length: u32,
        flags: u32,
    ) -> u32;
    pub(super) fn GetFileType(handle: Handle) -> u32;
    pub(super) fn GetVolumeInformationByHandleW(
        handle: Handle,
        label: *mut u16,
        label_length: u32,
        serial: *mut u32,
        component: *mut u32,
        flags: *mut u32,
        filesystem: *mut u16,
        filesystem_length: u32,
    ) -> i32;
    pub(super) fn ReadFile(
        handle: Handle,
        buffer: *mut u8,
        length: u32,
        count: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_struct_sizes() {
        assert_eq!(CURRENT_PROCESS_TOKEN as isize, -4);
        assert_eq!(std::mem::size_of::<TokenStatistics>(), 56);
        assert_eq!(std::mem::size_of::<FileBasicInfo>(), 40);
        assert_eq!(std::mem::size_of::<FileStandardInfo>(), 24);
        assert_eq!(std::mem::size_of::<FileIdInfo>(), 24);
        assert_eq!(std::mem::size_of::<FileTagInfo>(), 8);
    }
}
