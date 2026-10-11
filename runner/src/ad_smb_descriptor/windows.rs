use super::ffi::*;
use super::{
    base64, canonical_sid, digest, dword, frame, AceProjection, DaclProjection, Descriptor,
    DescriptorProjection, Frame, SUPPORTED_READ_MASK,
};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;

struct Buffer {
    words: Vec<u64>,
    length: usize,
}

impl Buffer {
    fn new(bytes: &[u8]) -> Self {
        let mut value = Self {
            words: vec![0; bytes.len().div_ceil(8)],
            length: bytes.len(),
        };
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                value.words.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
        value
    }

    fn pointer(&self) -> *mut c_void {
        self.words.as_ptr().cast_mut().cast()
    }

    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }
}

struct Local(*mut u16);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

fn require(value: bool) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err("native descriptor validation refused the input".into())
    }
}

fn sid(buffer: &Buffer, offset: usize, length: usize) -> Result<String, String> {
    let pointer = unsafe { buffer.pointer().cast::<u8>().add(offset).cast() };
    unsafe {
        require(IsValidSid(pointer) != 0 && GetLengthSid(pointer) as usize == length)?;
        let mut text = ptr::null_mut();
        require(ConvertSidToStringSidW(pointer, &mut text) != 0 && !text.is_null())?;
        let allocation = Local(text);
        let mut count = 0;
        // A valid SID has at most 15 subauthorities, each at most ten decimal digits.
        while count < 192 && *allocation.0.add(count) != 0 {
            count += 1;
        }
        require(count < 192)?;
        let value = String::from_utf16(std::slice::from_raw_parts(allocation.0, count))
            .map_err(|_| "native SID conversion was invalid")?;
        canonical_sid(&value)?;
        Ok(value)
    }
}

fn acl(buffer: &Buffer, layout: &Frame) -> Result<*mut c_void, String> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut pointer = ptr::null_mut();
    unsafe {
        require(
            GetSecurityDescriptorDacl(buffer.pointer(), &mut present, &mut pointer, &mut defaulted)
                != 0
                && present == 1
                && defaulted == 0
                && pointer == buffer.pointer().cast::<u8>().add(layout.acl.start).cast(),
        )?;
        require(IsValidAcl(pointer) != 0)?;
    }
    Ok(pointer)
}

pub(super) fn inspect(bytes: &[u8], layout: Frame) -> Result<Descriptor, String> {
    let buffer = Buffer::new(bytes);
    unsafe {
        require(IsValidSecurityDescriptor(buffer.pointer()) != 0)?;
        let mut control = 0;
        let mut revision = 0;
        require(
            GetSecurityDescriptorControl(buffer.pointer(), &mut control, &mut revision) != 0
                && control == layout.control
                && revision == 1
                && GetSecurityDescriptorLength(buffer.pointer()) as usize == bytes.len(),
        )?;
        let mut present = 0;
        let mut defaulted = 0;
        let mut pointer = ptr::null_mut();
        require(
            GetSecurityDescriptorSacl(buffer.pointer(), &mut present, &mut pointer, &mut defaulted)
                != 0
                && present == 0
                && pointer.is_null()
                && defaulted == 0,
        )?;
        for (range, is_owner) in [(&layout.owner, true), (&layout.group, false)] {
            let ok = if is_owner {
                GetSecurityDescriptorOwner(buffer.pointer(), &mut pointer, &mut defaulted)
            } else {
                GetSecurityDescriptorGroup(buffer.pointer(), &mut pointer, &mut defaulted)
            };
            require(
                ok != 0
                    && defaulted == 0
                    && pointer == buffer.pointer().cast::<u8>().add(range.start).cast(),
            )?;
        }
    }
    let pointer = acl(&buffer, &layout)?;
    let mut info = AclSizeInformation::default();
    unsafe {
        require(
            GetAclInformation(
                pointer,
                &mut info,
                size_of::<AclSizeInformation>() as u32,
                2,
            ) != 0
                && info.ace_count as usize == layout.aces.len()
                && info.bytes_in_use as usize + info.bytes_free as usize == layout.acl.len(),
        )?;
    }
    let mut aces: Vec<AceProjection> = Vec::new();
    for (index, range) in layout.aces.iter().enumerate() {
        let mut ace = ptr::null_mut();
        unsafe {
            require(
                GetAce(pointer, index as u32, &mut ace) != 0
                    && ace == buffer.pointer().cast::<u8>().add(range.start).cast(),
            )?;
        }
        let trustee = sid(&buffer, range.start + 8, range.len() - 8)?;
        require(!aces.iter().any(|item| item.trustee_sid == trustee))?;
        aces.push(AceProjection {
            ace_type: "access_allowed",
            flags: 0,
            trustee_sid: trustee,
            smb_right: if dword(bytes, range.start + 4)? == SUPPORTED_READ_MASK {
                "Read"
            } else {
                "Full"
            },
            raw_ace_digest: digest(&bytes[range.clone()]),
        });
    }
    Ok(Descriptor {
        bytes: bytes.to_vec(),
        projection: DescriptorProjection {
            binary_b64: base64(bytes),
            sha256: digest(bytes),
            revision: 1,
            control: layout.control,
            owner_sid: sid(&buffer, layout.owner.start, layout.owner.len())?,
            group_sid: sid(&buffer, layout.group.start, layout.group.len())?,
            dacl: DaclProjection { revision: 2, aces },
            sacl: None,
        },
    })
}

pub(super) fn remove(original: &Descriptor, probe: &str) -> Result<Descriptor, String> {
    let layout = frame(original.bytes())?;
    let mut buffer = Buffer::new(original.bytes());
    acl(&buffer, &layout)?;
    let pointer = unsafe {
        buffer
            .words
            .as_mut_ptr()
            .cast::<u8>()
            .add(layout.acl.start)
            .cast()
    };
    let index = original
        .projection
        .dacl
        .aces
        .iter()
        .position(|ace| ace.trustee_sid == probe)
        .ok_or("missing probe entry")?;
    unsafe {
        require(DeleteAce(pointer, index as u32) != 0)?;
    }
    let mut info = AclSizeInformation::default();
    unsafe {
        require(
            GetAclInformation(
                pointer,
                &mut info,
                size_of::<AclSizeInformation>() as u32,
                2,
            ) != 0
                && info.ace_count == 2
                && info.bytes_in_use as usize <= layout.acl.len()
                && info.bytes_in_use as usize + info.bytes_free as usize == layout.acl.len(),
        )?;
        // DeleteAce leaves free capacity. Do not retain the removed ACE in that slack.
        ptr::write_bytes(
            pointer.cast::<u8>().add(info.bytes_in_use as usize),
            0,
            info.bytes_free as usize,
        );
    }
    let after = Descriptor::from_bytes(buffer.bytes())?;
    let mut expected = original.projection.clone();
    expected.dacl.aces.remove(index);
    expected.binary_b64.clone_from(&after.projection.binary_b64);
    expected.sha256.clone_from(&after.projection.sha256);
    require(after.projection == expected && after.bytes != original.bytes)?;
    Ok(after)
}

pub(super) fn sddl(descriptor: &Descriptor) -> Result<String, String> {
    let buffer = Buffer::new(descriptor.bytes());
    let mut text = ptr::null_mut();
    let mut length = 0;
    unsafe {
        require(
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                buffer.pointer(),
                1,
                7,
                &mut text,
                &mut length,
            ) != 0
                && !text.is_null(),
        )?;
        let allocation = Local(text);
        require(length > 0 && length <= 65_536 && *allocation.0.add(length as usize - 1) == 0)?;
        String::from_utf16(std::slice::from_raw_parts(
            allocation.0,
            length as usize - 1,
        ))
        .map_err(|_| "native SDDL conversion was invalid".into())
    }
}
