use std::ffi::c_void;

pub type Handle = *mut c_void;

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: Handle,
    pub object_name: *mut UnicodeString,
    pub attributes: u32,
    pub security_descriptor: Handle,
    pub security_quality_of_service: Handle,
}

#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
pub struct DnsDomainInfo {
    pub name: UnicodeString,
    pub dns_domain_name: UnicodeString,
    pub dns_forest_name: UnicodeString,
    pub domain_guid: Guid,
    pub sid: Handle,
}

#[repr(C)]
pub struct VersionInfo {
    pub size: u32,
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub platform_id: u32,
    pub service_pack: [u16; 128],
    pub service_pack_major: u16,
    pub service_pack_minor: u16,
    pub suite_mask: u16,
    pub product_type: u8,
    pub reserved: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileTime {
    pub low: u32,
    pub high: u32,
}

#[link(name = "kernel32")]
extern "system" {
    pub fn GetComputerNameExW(format: i32, buffer: *mut u16, size: *mut u32) -> i32;
    pub fn GetCurrentProcess() -> Handle;
    pub fn IsWow64Process2(
        process: Handle,
        process_machine: *mut u16,
        native_machine: *mut u16,
    ) -> i32;
    pub fn LocalFree(memory: Handle) -> Handle;
}

#[link(name = "ntdll")]
extern "system" {
    pub fn RtlGetVersion(version: *mut VersionInfo) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    pub fn LsaOpenPolicy(
        system: *mut UnicodeString,
        attributes: *mut ObjectAttributes,
        access: u32,
        policy: *mut Handle,
    ) -> i32;
    pub fn LsaQueryInformationPolicy(policy: Handle, class: i32, buffer: *mut Handle) -> i32;
    pub fn LsaFreeMemory(buffer: Handle) -> i32;
    pub fn LsaClose(policy: Handle) -> i32;
    pub fn IsValidSid(sid: Handle) -> i32;
    pub fn GetLengthSid(sid: Handle) -> u32;
    pub fn ConvertSidToStringSidW(sid: Handle, text: *mut *mut u16) -> i32;
    pub fn RegGetValueW(
        key: Handle,
        subkey: *const u16,
        value: *const u16,
        flags: u32,
        kind: *mut u32,
        data: Handle,
        bytes: *mut u32,
    ) -> i32;
    pub fn RegOpenKeyExW(
        key: Handle,
        subkey: *const u16,
        options: u32,
        access: u32,
        result: *mut Handle,
    ) -> i32;
    pub fn RegQueryInfoKeyW(
        key: Handle,
        class: *mut u16,
        class_chars: *mut u32,
        reserved: *mut u32,
        subkeys: *mut u32,
        max_subkey: *mut u32,
        max_class: *mut u32,
        values: *mut u32,
        max_value_name: *mut u32,
        max_value_data: *mut u32,
        security_bytes: *mut u32,
        last_write: *mut FileTime,
    ) -> i32;
    pub fn RegEnumValueW(
        key: Handle,
        index: u32,
        name: *mut u16,
        name_chars: *mut u32,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        bytes: *mut u32,
    ) -> i32;
    pub fn RegCloseKey(key: Handle) -> i32;
}
