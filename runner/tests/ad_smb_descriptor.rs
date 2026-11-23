use bluefire_runner::ad_smb_descriptor::{Descriptor, MAX_DESCRIPTOR_BYTES};

#[test]
fn refuses_missing_oversized_and_absolute_descriptors() {
    for bytes in [Vec::new(), vec![0; 19], vec![0; MAX_DESCRIPTOR_BYTES + 1]] {
        assert!(Descriptor::from_bytes(&bytes).is_err());
    }
    let mut header = vec![0; 20];
    header[0] = 1;
    header[2..4].copy_from_slice(&4_u16.to_le_bytes());
    assert!(Descriptor::from_bytes(&header).is_err());
    header[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
    header[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Descriptor::from_bytes(&header).is_err());
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use bluefire_runner::ad_smb_descriptor::{SUPPORTED_FULL_MASK, SUPPORTED_READ_MASK};
    use std::ffi::c_void;
    use std::ptr;

    const PROBE: &str = "S-1-5-21-101-202-303-1001";
    const LEGITIMATE: &str = "S-1-5-21-101-202-303-1002";
    const CONTROLLER: &str = "S-1-5-21-101-202-303-1003";

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            output: *mut *mut c_void,
            length: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    // This fixture text is authored here, with numeric SIDs only. No user SDDL API.
    fn fixture(protected: bool, reader_owner: bool) -> Vec<u8> {
        let owner = if reader_owner { PROBE } else { CONTROLLER };
        let flags = if protected { "P" } else { "" };
        let sddl = format!(
            "O:{owner}G:{CONTROLLER}D:{flags}(A;;0x1200a9;;;{PROBE})(A;;0x1200a9;;;{LEGITIMATE})(A;;0x1f01ff;;;{CONTROLLER})"
        );
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut pointer = ptr::null_mut();
        let mut length = 0;
        unsafe {
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    1,
                    &mut pointer,
                    &mut length
                ),
                0
            );
            assert!(!pointer.is_null());
            let result = std::slice::from_raw_parts(pointer.cast::<u8>(), length as usize).to_vec();
            assert!(LocalFree(pointer).is_null());
            result
        }
    }

    fn number(bytes: &[u8], offset: usize) -> usize {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
    }

    #[test]
    fn native_projection_preserves_the_full_reviewed_binary() {
        for protected in [false, true] {
            let bytes = fixture(protected, false);
            let descriptor = Descriptor::from_bytes(&bytes).unwrap();
            let value = descriptor.projection();
            assert_eq!(descriptor.bytes(), bytes);
            assert_eq!(value.control, if protected { 0x9004 } else { 0x8004 });
            assert_eq!(value.revision, 1);
            assert_eq!(value.owner_sid, CONTROLLER);
            assert_eq!(value.group_sid, CONTROLLER);
            assert!(value.sacl.is_none());
            assert_eq!(value.dacl.revision, 2);
            assert_eq!(value.dacl.aces.len(), 3);
            assert_eq!(value.dacl.aces[0].trustee_sid, PROBE);
            assert_eq!(value.dacl.aces[0].smb_right, "Read");
            assert_eq!(value.dacl.aces[2].smb_right, "Full");
            assert_eq!(value.sha256.len(), 71);
            assert!(!value.binary_b64.is_empty());
            let json = serde_json::to_value(value).unwrap();
            assert_eq!(json.as_object().unwrap().len(), 8);
            assert!(descriptor.diagnostic_sddl().unwrap().contains(PROBE));
        }
        // Exact documented file-rights union, not an observed SMB cmdlet mapping.
        assert_eq!(
            SUPPORTED_READ_MASK,
            0x0010_0000 | 0x0002_0000 | 0x80 | 0x20 | 0x8 | 0x1
        );
        assert_eq!(SUPPORTED_FULL_MASK, 0x001f_0000 | 0x1ff);
    }

    #[test]
    fn proposal_removes_exactly_probe_without_changing_other_components() {
        for protected in [false, true] {
            let before = Descriptor::from_bytes(&fixture(protected, false)).unwrap();
            let after = before
                .propose_probe_removal(PROBE, LEGITIMATE, CONTROLLER)
                .unwrap();
            let mut expected = before.projection().clone();
            expected.dacl.aces.remove(0);
            expected.sha256.clone_from(&after.projection().sha256);
            expected
                .binary_b64
                .clone_from(&after.projection().binary_b64);
            assert_eq!(*after.projection(), expected);
            assert_ne!(before.bytes(), after.bytes());
            assert_eq!(
                after.projection().dacl.aces,
                before.projection().dacl.aces[1..]
            );
            assert!(!after.diagnostic_sddl().unwrap().contains(PROBE));
            assert!(after
                .propose_probe_removal(PROBE, LEGITIMATE, CONTROLLER)
                .is_err());
            assert_eq!(
                Descriptor::from_bytes(after.bytes()).unwrap().projection(),
                after.projection()
            );
        }
    }

    #[test]
    fn emits_synthetic_native_projection_for_python_contract_validation() {
        let before = Descriptor::from_bytes(&fixture(false, false)).unwrap();
        let after = before
            .propose_probe_removal(PROBE, LEGITIMATE, CONTROLLER)
            .unwrap();
        let value = serde_json::json!({
            "schema_version": "bluefire.ad-smb-synthetic-descriptor-fixture.v1",
            "authenticated_share_claim": false,
            "before": before.projection(),
            "after": after.projection(),
        });
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(encoded.len() <= 128 * 1024);
        println!("BLUEFIRE_AD_DESCRIPTOR_FIXTURE_V1={encoded}");
    }

    #[test]
    fn proposal_uses_the_matching_ace_not_a_fixed_position() {
        let mut bytes = fixture(false, false);
        let first = number(&bytes, 16) + 8;
        let size = u16::from_le_bytes(bytes[first + 2..first + 4].try_into().unwrap()) as usize;
        let original_first = bytes[first..first + size].to_vec();
        bytes.copy_within(first + 2 * size..first + 3 * size, first);
        bytes[first + 2 * size..first + 3 * size].copy_from_slice(&original_first);
        let before = Descriptor::from_bytes(&bytes).unwrap();
        assert_eq!(before.projection().dacl.aces[2].trustee_sid, PROBE);
        let after = before
            .propose_probe_removal(PROBE, LEGITIMATE, CONTROLLER)
            .unwrap();
        assert_eq!(
            after.projection().dacl.aces,
            before.projection().dacl.aces[..2]
        );
    }

    #[test]
    fn refuses_wrong_roles_duplicates_domains_and_reader_ownership() {
        let before = Descriptor::from_bytes(&fixture(false, false)).unwrap();
        for (probe, legitimate, controller) in [
            (PROBE, PROBE, CONTROLLER),
            (CONTROLLER, LEGITIMATE, PROBE),
            ("S-1-5-21-999-202-303-1001", LEGITIMATE, CONTROLLER),
            ("S-1-5-21-101-202-303-01001", LEGITIMATE, CONTROLLER),
            ("S-1-5-21-101-202-303-999", LEGITIMATE, CONTROLLER),
        ] {
            assert!(before
                .propose_probe_removal(probe, legitimate, controller)
                .is_err());
        }
        let reader_owned = Descriptor::from_bytes(&fixture(false, true)).unwrap();
        assert!(reader_owned
            .propose_probe_removal(PROBE, LEGITIMATE, CONTROLLER)
            .is_err());
        let mut duplicate = fixture(false, false);
        let ace = number(&duplicate, 16) + 8;
        let size = u16::from_le_bytes(duplicate[ace + 2..ace + 4].try_into().unwrap()) as usize;
        duplicate.copy_within(ace..ace + size, ace + size);
        assert!(Descriptor::from_bytes(&duplicate).is_err());
    }

    #[test]
    fn refuses_unsupported_ace_semantics_before_native_conversion() {
        let original = fixture(false, false);
        let ace = number(&original, 16) + 8;
        for kind in [1, 5, 6, 9, 11, 17] {
            let mut bytes = original.clone();
            bytes[ace] = kind;
            assert!(Descriptor::from_bytes(&bytes).is_err());
        }
        for flags in [1, 2, 8, 16, 64, 128] {
            let mut bytes = original.clone();
            bytes[ace + 1] = flags;
            assert!(Descriptor::from_bytes(&bytes).is_err());
        }
        for mask in [0x0012_0089_u32, 0x8000_0000, 0x1000_0000, 0, 0x001f_ffff] {
            let mut bytes = original.clone();
            bytes[ace + 4..ace + 8].copy_from_slice(&mask.to_le_bytes());
            assert!(Descriptor::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn refuses_truncation_aliasing_offsets_sacl_and_unaccounted_bytes() {
        let original = fixture(false, false);
        for length in 0..original.len() {
            assert!(Descriptor::from_bytes(&original[..length]).is_err());
        }
        for slot in [4, 8, 16] {
            for offset in [0_u32, 1, 19, u32::MAX] {
                let mut bytes = original.clone();
                bytes[slot..slot + 4].copy_from_slice(&offset.to_le_bytes());
                assert!(Descriptor::from_bytes(&bytes).is_err());
            }
        }
        let mut overlap = original.clone();
        overlap.copy_within(4..8, 8);
        assert!(Descriptor::from_bytes(&overlap).is_err());
        let mut sacl = original.clone();
        sacl[2] |= 0x10;
        assert!(Descriptor::from_bytes(&sacl).is_err());
        let mut tail = original;
        tail.push(0);
        assert!(Descriptor::from_bytes(&tail).is_err());
    }
}
