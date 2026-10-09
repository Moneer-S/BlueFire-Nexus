//! Bounds-only decoding before native descriptor parsing; never dereferences addresses.

use super::MAX_NET_API_BYTES;
use crate::ad_smb_descriptor::MAX_DESCRIPTOR_BYTES;

pub(super) struct BufferView<'a> {
    bytes: &'a [u8],
    base: usize,
}

impl<'a> BufferView<'a> {
    pub(super) fn new(bytes: &'a [u8], base: usize) -> Result<Self, String> {
        if bytes.is_empty()
            || bytes.len() > MAX_NET_API_BYTES
            || base == 0
            || base.checked_add(bytes.len()).is_none()
        {
            return Err("NetAPI allocation is outside the supported bound".into());
        }
        Ok(Self { bytes, base })
    }

    pub(super) fn range(
        &self,
        address: usize,
        count: usize,
        alignment: usize,
    ) -> Result<&'a [u8], String> {
        let offset = address
            .checked_sub(self.base)
            .ok_or("NetAPI pointer precedes allocation")?;
        let end = offset.checked_add(count).ok_or("NetAPI range overflow")?;
        if !address.is_multiple_of(alignment) {
            return Err("NetAPI pointer alignment is invalid".into());
        }
        self.bytes
            .get(offset..end)
            .ok_or_else(|| "NetAPI pointer exceeds allocation".into())
    }

    pub(super) fn utf16(
        &self,
        address: usize,
        maximum: usize,
        nullable: bool,
    ) -> Result<String, String> {
        if address == 0 && nullable {
            return Ok(String::new());
        }
        let mut words = Vec::new();
        for index in 0..=maximum {
            let at = address
                .checked_add(index.checked_mul(2).ok_or("UTF16 range overflow")?)
                .ok_or("UTF16 range overflow")?;
            let bytes = self.range(at, 2, 2)?;
            let word = u16::from_le_bytes([bytes[0], bytes[1]]);
            if word == 0 {
                return String::from_utf16(&words)
                    .map_err(|_| "NetAPI text is invalid UTF16".into());
            }
            words.push(word);
        }
        Err("NetAPI text exceeds its bound".into())
    }

    pub(super) fn descriptor(&self, address: usize) -> Result<&'a [u8], String> {
        let header = self.range(address, 20, 4)?;
        let control = u16::from_le_bytes([header[2], header[3]]);
        if header[..2] != [1, 0] || ![0x8004, 0x9004].contains(&control) || number(header, 12)? != 0
        {
            return Err("NetAPI descriptor is not a supported self-relative frame".into());
        }
        let mut size = 20;
        for offset in [4, 8] {
            let relative = number(header, offset)?;
            let start = address
                .checked_add(relative)
                .ok_or("descriptor address overflow")?;
            let sid = self.range(start, 8, 4)?;
            if relative < 20 || sid[0] != 1 || !(1..=15).contains(&sid[1]) {
                return Err("invalid descriptor SID frame".into());
            }
            let length = 8 + usize::from(sid[1]) * 4;
            self.range(start, length, 4)?;
            size = size.max(
                relative
                    .checked_add(length)
                    .ok_or("descriptor length overflow")?,
            );
        }
        let relative = number(header, 16)?;
        let start = address
            .checked_add(relative)
            .ok_or("descriptor address overflow")?;
        let acl = self.range(start, 8, 4)?;
        let length = usize::from(u16::from_le_bytes([acl[2], acl[3]]));
        if relative < 20 || length < 8 {
            return Err("invalid descriptor ACL frame".into());
        }
        self.range(start, length, 4)?;
        size = size.max(
            relative
                .checked_add(length)
                .ok_or("descriptor length overflow")?,
        );
        if size > MAX_DESCRIPTOR_BYTES {
            return Err("descriptor exceeds its byte bound".into());
        }
        self.range(address, size, 4)
    }
}

fn number(bytes: &[u8], offset: usize) -> Result<usize, String> {
    let data: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or("truncated descriptor offset")?
        .try_into()
        .map_err(|_| "invalid descriptor offset")?;
    Ok(u32::from_le_bytes(data) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_foreign_unaligned_overflow_and_unterminated_pointers_without_dereference() {
        let bytes = [b'a', 0, b'b', 0, 0, 0, 0, 0];
        let view = BufferView::new(&bytes, 0x1000).unwrap();
        assert_eq!(view.utf16(0x1000, 2, false).unwrap(), "ab");
        for address in [0, 0xffe, 0x1001, 0x1008, usize::MAX] {
            assert!(view.utf16(address, 2, false).is_err());
        }
        assert!(view.utf16(0x1000, 1, false).is_err());
        assert!(view.range(0x1000, usize::MAX, 4).is_err());
        assert!(BufferView::new(&bytes, usize::MAX - 2).is_err());
    }

    #[test]
    fn rejects_absolute_and_hostile_descriptor_offsets_before_native_calls() {
        let mut bytes = [0_u8; 64];
        bytes[0] = 1;
        assert!(BufferView::new(&bytes, 0x1000)
            .unwrap()
            .descriptor(0x1000)
            .is_err());
        bytes[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(BufferView::new(&bytes, 0x1000)
            .unwrap()
            .descriptor(0x1000)
            .is_err());
        bytes[4..8].copy_from_slice(&20_u32.to_le_bytes());
        bytes[20] = 1;
        bytes[21] = 255;
        assert!(BufferView::new(&bytes, 0x1000)
            .unwrap()
            .descriptor(0x1000)
            .is_err());
    }
}
