use std::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct ShareInfo502 {
    pub name: *mut u16,
    pub share_type: u32,
    pub remark: *mut u16,
    pub permissions: u32,
    pub maximum_uses: u32,
    pub current_uses: u32,
    pub path: *mut u16,
    pub password: *mut u16,
    pub reserved: u32,
    pub descriptor: *mut c_void,
}

#[repr(C)]
pub(super) struct ShareInfo1501 {
    pub descriptor: *mut c_void,
}

#[link(name = "netapi32", kind = "raw-dylib")]
extern "system" {
    pub(super) fn NetShareGetInfo(
        server: *const u16,
        name: *const u16,
        level: u32,
        buffer: *mut *mut u8,
    ) -> u32;
    pub(super) fn NetShareSetInfo(
        server: *const u16,
        name: *const u16,
        level: u32,
        buffer: *const u8,
        parameter_error: *mut u32,
    ) -> u32;
    pub(super) fn NetApiBufferSize(buffer: *mut c_void, bytes: *mut u32) -> u32;
    pub(super) fn NetApiBufferFree(buffer: *mut c_void) -> u32;
}
