use std::ffi::c_void;

#[repr(C)]
#[derive(Default)]
pub(super) struct AclSizeInformation {
    pub ace_count: u32,
    pub bytes_in_use: u32,
    pub bytes_free: u32,
}

#[link(name = "advapi32")]
extern "system" {
    pub(super) fn IsValidSecurityDescriptor(descriptor: *const c_void) -> i32;
    pub(super) fn GetSecurityDescriptorControl(
        descriptor: *const c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    pub(super) fn GetSecurityDescriptorLength(descriptor: *const c_void) -> u32;
    pub(super) fn GetSecurityDescriptorOwner(
        descriptor: *const c_void,
        owner: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    pub(super) fn GetSecurityDescriptorGroup(
        descriptor: *const c_void,
        group: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    pub(super) fn GetSecurityDescriptorDacl(
        descriptor: *const c_void,
        present: *mut i32,
        acl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    pub(super) fn GetSecurityDescriptorSacl(
        descriptor: *const c_void,
        present: *mut i32,
        acl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    pub(super) fn IsValidAcl(acl: *const c_void) -> i32;
    pub(super) fn GetAclInformation(
        acl: *const c_void,
        information: *mut AclSizeInformation,
        length: u32,
        class: u32,
    ) -> i32;
    pub(super) fn GetAce(acl: *const c_void, index: u32, ace: *mut *mut c_void) -> i32;
    pub(super) fn DeleteAce(acl: *mut c_void, index: u32) -> i32;
    pub(super) fn IsValidSid(sid: *const c_void) -> i32;
    pub(super) fn GetLengthSid(sid: *const c_void) -> u32;
    pub(super) fn ConvertSidToStringSidW(sid: *const c_void, output: *mut *mut u16) -> i32;
    pub(super) fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor: *const c_void,
        revision: u32,
        information: u32,
        output: *mut *mut u16,
        length: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    pub(super) fn LocalFree(memory: *mut c_void) -> *mut c_void;
}
