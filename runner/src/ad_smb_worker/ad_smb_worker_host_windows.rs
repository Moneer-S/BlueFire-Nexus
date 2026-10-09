use super::{ffi::*, require, Facts, PolicyValue, MAX_DATA, MAX_NAME, MAX_VALUES};
use crate::ad_smb_worker::{wire::Packet, Code, Result};
use std::{mem::size_of, ptr};

struct Owned {
    pointer: Handle,
    release: unsafe extern "system" fn(Handle) -> i32,
}

impl Owned {
    fn close(&mut self) -> Result<()> {
        if !self.pointer.is_null() {
            require(unsafe { (self.release)(self.pointer) } == 0)?;
            self.pointer = ptr::null_mut();
        }
        Ok(())
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn checked<T>(packet: &Packet, call: impl FnOnce() -> Result<T>) -> Result<T> {
    packet.current()?;
    let result = call();
    packet.current()?;
    result
}

pub(super) fn observe(packet: &Packet, client: bool) -> Result<Facts> {
    let fqdn = checked(packet, || {
        let mut buffer = [0_u16; 256];
        let mut count = buffer.len() as u32;
        require(unsafe { GetComputerNameExW(7, buffer.as_mut_ptr(), &mut count) } != 0)?;
        require((1..=253).contains(&count) && buffer[count as usize] == 0)?;
        text(&buffer[..count as usize])
    })?;
    let (process_machine, native_machine) = checked(packet, || {
        let mut process = 0;
        let mut native = 0;
        require(unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) } != 0)?;
        Ok((process, native))
    })?;
    let (version, product_type) = checked(packet, || {
        let mut version: VersionInfo = unsafe { std::mem::zeroed() };
        version.size = size_of::<VersionInfo>() as u32;
        require(unsafe { RtlGetVersion(&mut version) } == 0)?;
        require(version.platform_id == 2)?;
        Ok((
            [version.major, version.minor, version.build, 0],
            version.product_type,
        ))
    })?;
    let mut version = version;
    version[3] = checked(packet, revision)?;
    let (domain_dns, domain_sid) = domain(packet)?;
    let policy = if client {
        registry_policy(packet)?
    } else {
        Vec::new()
    };
    packet.current()?;
    Ok(Facts {
        fqdn,
        domain_dns,
        domain_sid,
        process_machine,
        native_machine,
        version,
        product_type,
        policy,
    })
}

fn text(units: &[u16]) -> Result<String> {
    require(!units.is_empty() && !units.contains(&0))?;
    String::from_utf16(units).map_err(|_| Code::PreconditionFailed)
}

fn machine_key() -> Handle {
    // Predefined HKEY_LOCAL_MACHINE is sign-extended on 64-bit Windows.
    (-2_147_483_646_isize) as Handle
}

fn revision() -> Result<u32> {
    // UBR is a supported local configuration premise, not an OS attestation API.
    let key = wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    let name = wide("UBR");
    let mut revision = 0_u32;
    let mut kind = 0;
    let mut bytes = 4;
    require(
        unsafe {
            RegGetValueW(
                machine_key(),
                key.as_ptr(),
                name.as_ptr(),
                0x2001_0010,
                &mut kind,
                (&mut revision as *mut u32).cast(),
                &mut bytes,
            )
        } == 0,
    )?;
    require(kind == 4 && bytes == 4 && revision <= 99_999_999)?;
    Ok(revision)
}

unsafe fn domain_text(value: &UnicodeString) -> Result<String> {
    require(
        !value.buffer.is_null()
            && value.length > 0
            && value.length % 2 == 0
            && value.length <= 506
            && value.maximum_length >= value.length
            && value.maximum_length <= 512
            && value.maximum_length % 2 == 0,
    )?;
    text(std::slice::from_raw_parts(
        value.buffer,
        usize::from(value.length / 2),
    ))
}

unsafe extern "system" fn free_local(pointer: Handle) -> i32 {
    if LocalFree(pointer).is_null() {
        0
    } else {
        1
    }
}

fn sid(packet: &Packet, pointer: Handle) -> Result<String> {
    checked(packet, || {
        require(!pointer.is_null() && unsafe { IsValidSid(pointer) } != 0)
    })?;
    checked(packet, || {
        require((8..=68).contains(&unsafe { GetLengthSid(pointer) }))
    })?;
    let mut buffer = ptr::null_mut();
    packet.current()?;
    require(unsafe { ConvertSidToStringSidW(pointer, &mut buffer) } != 0 && !buffer.is_null())?;
    let mut allocation = Owned {
        pointer: buffer.cast(),
        release: free_local,
    };
    let result = (|| {
        packet.current()?;
        // The documented conversion allocates a NUL-terminated numeric SID.
        let mut length = 0;
        while length < 185 && unsafe { *buffer.add(length) } != 0 {
            length += 1;
        }
        require(length > 0 && length < 185)?;
        text(unsafe { std::slice::from_raw_parts(buffer, length) })
    })();
    let closed = allocation.close();
    closed?;
    result
}

fn domain(packet: &Packet) -> Result<(String, String)> {
    let mut attributes: ObjectAttributes = unsafe { std::mem::zeroed() };
    attributes.length = size_of::<ObjectAttributes>() as u32;
    let mut handle = ptr::null_mut();
    packet.current()?;
    require(
        unsafe { LsaOpenPolicy(ptr::null_mut(), &mut attributes, 1, &mut handle) } == 0
            && !handle.is_null(),
    )?;
    let mut policy = Owned {
        pointer: handle,
        release: LsaClose,
    };
    let result = (|| {
        packet.current()?;
        let mut pointer = ptr::null_mut();
        require(
            unsafe { LsaQueryInformationPolicy(handle, 12, &mut pointer) } == 0
                && !pointer.is_null(),
        )?;
        let mut allocation = Owned {
            pointer,
            release: LsaFreeMemory,
        };
        let result = (|| {
            packet.current()?;
            // Only a successful local LSA allocation is dereferenced; no packet offsets enter here.
            let info = unsafe { &*pointer.cast::<DnsDomainInfo>() };
            let dns = unsafe { domain_text(&info.dns_domain_name) }?;
            Ok((dns, sid(packet, info.sid)?))
        })();
        let closed = allocation.close();
        closed?;
        result
    })();
    let closed = policy.close();
    closed?;
    result
}

fn registry_state(packet: &Packet, key: Handle) -> Result<(u32, FileTime)> {
    checked(packet, || {
        let mut count = 0;
        let mut name_max = 0;
        let mut data_max = 0;
        let mut written = FileTime { low: 0, high: 0 };
        require(
            unsafe {
                RegQueryInfoKeyW(
                    key,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut count,
                    &mut name_max,
                    &mut data_max,
                    ptr::null_mut(),
                    &mut written,
                )
            } == 0,
        )?;
        require(
            (1..=MAX_VALUES as u32).contains(&count)
                && name_max <= MAX_NAME as u32
                && data_max <= MAX_DATA as u32,
        )?;
        Ok((count, written))
    })
}

fn registry_policy(packet: &Packet) -> Result<Vec<PolicyValue>> {
    let path = wide("SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths");
    let mut handle = ptr::null_mut();
    packet.current()?;
    require(
        unsafe { RegOpenKeyExW(machine_key(), path.as_ptr(), 0, 0x0101, &mut handle) } == 0
            && !handle.is_null(),
    )?;
    let mut key = Owned {
        pointer: handle,
        release: RegCloseKey,
    };
    let result = (|| {
        let before = registry_state(packet, handle)?;
        let mut values = Vec::with_capacity(before.0 as usize);
        for index in 0..=before.0 {
            let entry = checked(packet, || {
                let mut name = [0_u16; MAX_NAME + 1];
                let mut data = [0_u8; MAX_DATA];
                let mut name_chars = name.len() as u32;
                let mut bytes = data.len() as u32;
                let mut kind = 0;
                let status = unsafe {
                    RegEnumValueW(
                        handle,
                        index,
                        name.as_mut_ptr(),
                        &mut name_chars,
                        ptr::null_mut(),
                        &mut kind,
                        data.as_mut_ptr(),
                        &mut bytes,
                    )
                };
                if index == before.0 {
                    require(status == 259)?;
                    return Ok(None);
                }
                require(
                    status == 0
                        && name_chars > 0
                        && name_chars <= MAX_NAME as u32
                        && bytes <= MAX_DATA as u32,
                )?;
                Ok(Some(PolicyValue {
                    name: text(&name[..name_chars as usize])?,
                    kind,
                    data: data[..bytes as usize].to_vec(),
                }))
            })?;
            if let Some(entry) = entry {
                values.push(entry);
            }
        }
        require(registry_state(packet, handle)? == before && values.len() == before.0 as usize)?;
        Ok(values)
    })();
    let closed = key.close();
    closed?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_host_abi_sizes_match_x64_headers_without_calls() {
        assert_eq!(size_of::<UnicodeString>(), 16);
        assert_eq!(size_of::<ObjectAttributes>(), 48);
        assert_eq!(size_of::<DnsDomainInfo>(), 72);
        assert_eq!(size_of::<VersionInfo>(), 284);
        assert_eq!(size_of::<FileTime>(), 8);
        assert_eq!(std::mem::align_of::<DnsDomainInfo>(), 8);
    }

    #[test]
    fn failed_owned_release_preserves_pointer_for_bounded_drop_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "system" fn release(_: Handle) -> i32 {
            if CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
                1
            } else {
                0
            }
        }
        CALLS.store(0, Ordering::SeqCst);
        let mut owned = Owned {
            pointer: std::ptr::dangling_mut::<u8>().cast(),
            release,
        };
        assert_eq!(owned.close(), Err(Code::PreconditionFailed));
        assert!(!owned.pointer.is_null());
        drop(owned);
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
    }
}
