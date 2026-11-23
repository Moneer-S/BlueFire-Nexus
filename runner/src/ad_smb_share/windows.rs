use super::buffer::BufferView;
use super::ffi;
use super::{
    digest, validate_metadata, Descriptor, LocalShareTarget, ShareMetadata, ShareObservation,
    MAX_NET_API_BYTES,
};
use std::mem::size_of;
use std::ptr::{null, null_mut};

struct Allocation {
    pointer: *mut u8,
}

impl Allocation {
    fn release(&mut self) -> Result<(), String> {
        self.release_with(|pointer| unsafe { ffi::NetApiBufferFree(pointer.cast()) })
    }

    fn release_with(&mut self, free: impl FnOnce(*mut u8) -> u32) -> Result<(), String> {
        if self.pointer.is_null() {
            return Ok(());
        }
        if free(self.pointer) != 0 {
            return Err("NetAPI allocation release was not confirmed".into());
        }
        self.pointer = null_mut();
        Ok(())
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

fn with_info<T>(
    name: &[u16],
    level: u32,
    parse: impl FnOnce(BufferView<'_>, *mut u8) -> Result<T, String>,
) -> Result<T, String> {
    let mut allocation = Allocation {
        pointer: null_mut(),
    };
    // The server argument is always NULL: remote targets are not part of this API.
    let status =
        unsafe { ffi::NetShareGetInfo(null(), name.as_ptr(), level, &mut allocation.pointer) };
    let result = if status != 0 || allocation.pointer.is_null() {
        Err("local share information is unavailable".into())
    } else {
        let mut length = 0_u32;
        let sized = unsafe { ffi::NetApiBufferSize(allocation.pointer.cast(), &mut length) };
        if sized != 0
            || length == 0
            || length as usize > MAX_NET_API_BYTES
            || (allocation.pointer as usize)
                .checked_add(length as usize)
                .is_none()
        {
            Err("local NetAPI allocation length is unavailable or excessive".into())
        } else {
            // Only the OS-returned allocation is materialized; embedded pointers remain integers.
            let bytes = unsafe { std::slice::from_raw_parts(allocation.pointer, length as usize) };
            BufferView::new(bytes, allocation.pointer as usize)
                .and_then(|view| parse(view, allocation.pointer))
        }
    };
    allocation.release()?;
    result
}

pub(super) fn observe(target: &LocalShareTarget) -> Result<ShareObservation, String> {
    let name: Vec<u16> = target.name.encode_utf16().chain(Some(0)).collect();
    let (mut metadata, current_uses, descriptor) = with_info(&name, 502, |view, pointer| {
        view.range(
            pointer as usize,
            size_of::<ffi::ShareInfo502>(),
            std::mem::align_of::<ffi::ShareInfo502>(),
        )?;
        let info = unsafe { std::ptr::read_unaligned(pointer.cast::<ffi::ShareInfo502>()) };
        if info.reserved != 0 || !view.utf16(info.password as usize, 0, true)?.is_empty() {
            return Err("unsupported local share reserved or legacy password field".into());
        }
        let name = view.utf16(info.name as usize, 35, false)?;
        let path = view.utf16(info.path as usize, 64, false)?;
        let remark = view.utf16(info.remark as usize, 512, true)?;
        let descriptor = Descriptor::from_bytes(view.descriptor(info.descriptor as usize)?)?;
        Ok((
            ShareMetadata {
                name,
                local_path: path,
                share_type: info.share_type,
                flags: 0,
                client_cache_flags: 0,
                encrypt_data_flag: false,
                permissions: info.permissions,
                maximum_uses: info.maximum_uses,
                remark_digest: digest(remark.as_bytes()),
            },
            info.current_uses,
            descriptor,
        ))
    })?;
    // This pair of reads is not an atomic share snapshot or an ownership guarantee.
    let flags = with_info(&name, 1005, |view, pointer| {
        let bytes = view.range(pointer as usize, 4, 4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().map_err(|_| "invalid share flags")?,
        ))
    })?;
    metadata.flags = flags;
    metadata.client_cache_flags = flags & 0x30;
    metadata.encrypt_data_flag = flags & 0x8000 != 0;
    validate_metadata(target, &metadata)?;
    Ok(ShareObservation {
        target: LocalShareTarget {
            name: target.name.clone(),
            path: target.path.clone(),
        },
        metadata,
        current_uses,
        descriptor,
    })
}

pub(super) fn set_descriptor(target: &LocalShareTarget, descriptor: &[u8]) -> u32 {
    // This private setter is reachable only with a natively derived exact pair.
    let mut aligned = vec![0_u64; descriptor.len().div_ceil(8)];
    unsafe {
        std::ptr::copy_nonoverlapping(
            descriptor.as_ptr(),
            aligned.as_mut_ptr().cast::<u8>(),
            descriptor.len(),
        );
    }
    let info = ffi::ShareInfo1501 {
        descriptor: aligned.as_mut_ptr().cast(),
    };
    let name: Vec<u16> = target.name.encode_utf16().chain(Some(0)).collect();
    let mut parameter_error = 0_u32;
    unsafe {
        ffi::NetShareSetInfo(
            null(),
            name.as_ptr(),
            1501,
            (&info as *const ffi::ShareInfo1501).cast(),
            &mut parameter_error,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_release_retains_pointer_until_one_successful_owned_cleanup() {
        let mut bytes = [0_u8; 8];
        let pointer = bytes.as_mut_ptr();
        // A failed assertion must not pass synthetic stack memory to the native Drop.
        let mut owned = std::mem::ManuallyDrop::new(Allocation { pointer });
        let mut calls = 0;
        assert!(owned
            .release_with(|actual| {
                assert_eq!(actual, pointer);
                calls += 1;
                5
            })
            .is_err());
        assert_eq!(owned.pointer, pointer);
        assert!(owned
            .release_with(|actual| {
                assert_eq!(actual, pointer);
                calls += 1;
                0
            })
            .is_ok());
        assert!(owned.pointer.is_null());
        assert!(owned
            .release_with(|_| panic!("already released allocation retried"))
            .is_ok());
        assert_eq!(calls, 2);
    }
}
