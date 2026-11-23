//! Local read-only handles. See Microsoft CreateFileW, GetKernelObjectSecurity,
//! GetVolumeInformationByHandleW and FILE_ID_INFO documentation.
use super::ffi::*;
use super::{Backend, ObjectFacts, SelectedSecurity, SELECTED_SECURITY_INFORMATION};
use crate::ad_smb_descriptor::{Descriptor, MAX_DESCRIPTOR_BYTES};
use sha2::{Digest, Sha256};
use std::mem::size_of;
use std::ptr::{null, null_mut};

#[derive(Default)]
pub(super) struct WindowsBackend {
    handles: Vec<Handle>,
}

fn error(stage: &str) -> String {
    format!("{stage}: Win32 status {}", unsafe { GetLastError() })
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

impl Backend for WindowsBackend {
    fn fixed_drive(&mut self, drive: &str) -> Result<(), String> {
        if unsafe { GetDriveTypeW(wide(drive).as_ptr()) } != 3 {
            return Err("generated root is not on a fixed local drive".into());
        }
        Ok(())
    }

    fn open(&mut self, path: &str, directory: bool) -> Result<(), String> {
        if self.handles.len() >= 6 {
            return Err("local handle bound exceeded".into());
        }
        // READ_CONTROL and attributes; files additionally read data. No write,
        // delete, privilege changes or write/delete sharing, including ancestors.
        let access = 0x0002_0080 | u32::from(!directory);
        let flags = 0x0020_0000 | if directory { 0x0200_0000 } else { 0x80 };
        let handle =
            unsafe { CreateFileW(wide(path).as_ptr(), access, 1, null(), 3, flags, null_mut()) };
        if handle == INVALID_HANDLE {
            return Err(error("open generated object"));
        }
        self.handles.push(handle);
        Ok(())
    }

    fn facts(&mut self, index: usize) -> Result<ObjectFacts, String> {
        let handle = *self.handles.get(index).ok_or("owned handle missing")?;
        let mut basic = FileBasicInfo::default();
        let mut standard = FileStandardInfo::default();
        let mut identity = FileIdInfo::default();
        let mut attributes = FileAttributeTagInfo::default();
        info(handle, 0, &mut basic)?;
        info(handle, 1, &mut standard)?;
        info(handle, 18, &mut identity)?;
        info(handle, 9, &mut attributes)?;
        if standard.size < 0 || basic.attributes != attributes.attributes {
            return Err("inconsistent local file information".into());
        }
        let mut name = [0u16; 512];
        let length =
            unsafe { GetFinalPathNameByHandleW(handle, name.as_mut_ptr(), name.len() as u32, 0) };
        if length == 0 {
            return Err(error("final path"));
        }
        if length as usize >= name.len() {
            return Err("final path exceeds bound".into());
        }
        let final_path = String::from_utf16(&name[..length as usize])
            .map_err(|_| "final path is not valid UTF16")?;
        let mut fs = [0u16; 32];
        let mut flags = 0;
        if unsafe {
            GetVolumeInformationByHandleW(
                handle,
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                &mut flags,
                fs.as_mut_ptr(),
                fs.len() as u32,
            )
        } == 0
        {
            return Err(error("volume information"));
        }
        let length = fs
            .iter()
            .position(|value| *value == 0)
            .ok_or("filesystem name exceeds bound")?;
        Ok(ObjectFacts {
            final_path,
            volume_serial: format!("{:016x}", identity.volume),
            file_id: hex::encode(identity.id),
            directory: standard.directory != 0,
            size: standard.size as u64,
            links: standard.links,
            attributes: attributes.attributes,
            reparse_tag: attributes.tag,
            creation_time: basic.creation,
            last_write_time: basic.write,
            change_time: basic.change,
            ntfs: fs[..length] == [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16]
                && flags & 8 != 0,
            disk_file: unsafe { GetFileType(handle) } == 1,
            delete_pending: standard.delete_pending != 0,
            selected_security: security(handle, index >= 3)?,
        })
    }

    fn read(&mut self, index: usize, output: &mut [u8]) -> Result<usize, String> {
        if !(4..=5).contains(&index) || output.is_empty() || output.len() > 8192 {
            return Err("read is outside the finite file/buffer recipe".into());
        }
        let handle = *self.handles.get(index).ok_or("owned handle missing")?;
        let mut count = 0;
        if unsafe {
            ReadFile(
                handle,
                output.as_mut_ptr(),
                output.len() as u32,
                &mut count,
                null_mut(),
            )
        } == 0
        {
            return Err(error("read generated content"));
        }
        if count as usize > output.len() {
            return Err("native read count exceeds buffer".into());
        }
        Ok(count as usize)
    }

    fn close(&mut self) -> bool {
        self.handles
            .retain(|handle| unsafe { CloseHandle(*handle) } == 0);
        self.handles.is_empty()
    }
}

impl Drop for WindowsBackend {
    fn drop(&mut self) {
        // One bounded best-effort retry only. Its result cannot upgrade the receipt.
        for handle in &self.handles {
            unsafe {
                CloseHandle(*handle);
            }
        }
    }
}

fn info<T>(handle: Handle, class: u32, output: &mut T) -> Result<(), String> {
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            class,
            (output as *mut T).cast(),
            size_of::<T>() as u32,
        )
    } == 0
    {
        return Err(error("held object metadata"));
    }
    Ok(())
}

fn security(handle: Handle, finite: bool) -> Result<SelectedSecurity, String> {
    let mut needed = 0;
    if unsafe {
        GetKernelObjectSecurity(
            handle,
            SELECTED_SECURITY_INFORMATION,
            null_mut(),
            0,
            &mut needed,
        )
    } != 0
        || unsafe { GetLastError() } != 122
        || !(20..=MAX_DESCRIPTOR_BYTES as u32).contains(&needed)
    {
        return Err("selected security descriptor size refused".into());
    }
    // Kernel-produced self-relative bytes, not caller-authored pointer data.
    // The aligned allocation is fixed after the bounded size query; no retries.
    let mut storage = vec![0u32; (needed as usize).div_ceil(4)];
    let capacity = needed;
    if unsafe {
        GetKernelObjectSecurity(
            handle,
            SELECTED_SECURITY_INFORMATION,
            storage.as_mut_ptr().cast(),
            capacity,
            &mut needed,
        )
    } == 0
    {
        return Err(error("selected security descriptor"));
    }
    if !(20..=capacity).contains(&needed) {
        return Err("selected descriptor size changed".into());
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), needed as usize) };
    if bytes[0] != 1 || u16::from_le_bytes([bytes[2], bytes[3]]) & 0x8000 == 0 {
        return Err("kernel descriptor is not self relative".into());
    }
    let projection = if finite {
        Some(Descriptor::from_bytes(bytes)?.projection().clone())
    } else {
        None
    };
    Ok(SelectedSecurity {
        security_information: SELECTED_SECURITY_INFORMATION,
        binary_hex: hex::encode(bytes),
        sha256: format!("sha256:{:x}", Sha256::digest(bytes)),
        finite_descriptor: projection,
        sacl_observed: false,
    })
}
