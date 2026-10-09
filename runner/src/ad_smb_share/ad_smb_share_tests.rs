use super::*;

const ID: &str = "0123456789abcdef0123456789abcdef";

fn target() -> LocalShareTarget {
    LocalShareTarget::new(ID, 'C').unwrap()
}

fn metadata() -> ShareMetadata {
    ShareMetadata {
        name: target().name,
        local_path: target().path,
        share_type: 0,
        flags: 0x30,
        client_cache_flags: 0x30,
        encrypt_data_flag: false,
        permissions: 0,
        maximum_uses: u32::MAX,
        remark_digest: digest(b"synthetic descriptor fixture"),
    }
}

#[test]
fn target_is_derived_from_only_canonical_generated_id_and_drive() {
    assert_eq!(target().name(), format!("bf_{ID}"));
    assert_eq!(target().path(), format!("C:\\BlueFire\\AD\\{ID}"));
    for id in [
        "",
        "0123456789ABCDEF0123456789ABCDEF",
        "../0123456789abcdef0123456789abc",
        "0123456789abcdef0123456789abcdeg",
    ] {
        assert!(LocalShareTarget::new(id, 'C').is_err());
    }
    for drive in ['A', 'B', 'c', '\\', ':', '0'] {
        assert!(LocalShareTarget::new(ID, drive).is_err());
    }
}

#[test]
fn metadata_refuses_remote_administrative_dfs_ca_unknown_flags_and_path_aliases() {
    assert!(validate_metadata(&target(), &metadata()).is_ok());
    for flags in [1, 2, 0x4000, 0x1_0000, 0x8000_0000] {
        let mut row = metadata();
        row.flags |= flags;
        assert!(validate_metadata(&target(), &row).is_err());
    }
    for kind in [1, 2, 3, 0x8000_0000, 0x4000_0000] {
        let mut row = metadata();
        row.share_type = kind;
        assert!(validate_metadata(&target(), &row).is_err());
    }
    for path in [
        format!("\\\\server\\bf_{ID}"),
        format!("C:\\BlueFire\\AD\\{ID}\\"),
        format!("c:\\BlueFire\\AD\\{ID}"),
    ] {
        let mut row = metadata();
        row.local_path = path;
        assert!(validate_metadata(&target(), &row).is_err());
    }
    let mut row = metadata();
    row.name.push('$');
    assert!(validate_metadata(&target(), &row).is_err());
    let mut row = metadata();
    row.client_cache_flags = 0;
    assert!(validate_metadata(&target(), &row).is_err());
}

#[test]
fn branch_cache_flag_does_not_change_client_cache_metadata() {
    for cache_flags in [0, 0x10, 0x20, 0x30] {
        let mut row = metadata();
        row.flags = cache_flags | 0x2000;
        row.client_cache_flags = cache_flags;
        assert!(validate_metadata(&target(), &row).is_ok());
        row.client_cache_flags |= 0x2000;
        assert!(validate_metadata(&target(), &row).is_err());
    }
}

#[test]
fn encryption_flag_is_supported_as_share_metadata_not_client_session_proof() {
    let mut row = metadata();
    row.flags |= 0x8000;
    row.encrypt_data_flag = true;
    assert!(validate_metadata(&target(), &row).is_ok());
    assert_eq!(row.client_cache_flags, 0x30);
    row.encrypt_data_flag = false;
    assert!(validate_metadata(&target(), &row).is_err());
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::collections::VecDeque;
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

    fn fixture() -> Vec<u8> {
        // Numeric authored fixture conversion only; no share or domain API is called.
        let text = format!("O:{CONTROLLER}G:{CONTROLLER}D:(A;;0x1200a9;;;{PROBE})(A;;0x1200a9;;;{LEGITIMATE})(A;;0x1f01ff;;;{CONTROLLER})");
        let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
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

    fn observation(bytes: &[u8]) -> ShareObservation {
        ShareObservation {
            target: target(),
            metadata: metadata(),
            current_uses: 0,
            descriptor: Descriptor::from_bytes(bytes).unwrap(),
        }
    }

    fn prepared() -> PreparedShareChange {
        observation(&fixture())
            .propose_probe_removal(PROBE, LEGITIMATE, CONTROLLER)
            .unwrap()
    }

    struct Fake {
        reads: VecDeque<Result<ShareObservation, String>>,
        calls: Vec<&'static str>,
        writes: Vec<Vec<u8>>,
        status: u32,
        expire_observe: Option<std::rc::Rc<std::cell::Cell<bool>>>,
        expire_set: Option<std::rc::Rc<std::cell::Cell<bool>>>,
    }

    impl Backend for Fake {
        fn observe(&mut self, selected: &LocalShareTarget) -> Result<ShareObservation, String> {
            assert_eq!(selected, &target());
            self.calls.push("observe");
            if let Some(clock) = &self.expire_observe {
                clock.set(false);
            }
            self.reads
                .pop_front()
                .expect("unexpected observation replay")
        }
        fn set_descriptor(&mut self, selected: &LocalShareTarget, descriptor: &[u8]) -> u32 {
            assert_eq!(selected, &target());
            self.calls.push("set1501");
            self.writes.push(descriptor.to_vec());
            if let Some(clock) = &self.expire_set {
                clock.set(false);
            }
            self.status
        }
    }

    fn fake(reads: Vec<Result<ShareObservation, String>>, status: u32) -> Fake {
        Fake {
            reads: reads.into(),
            calls: Vec::new(),
            writes: Vec::new(),
            status,
            expire_observe: None,
            expire_set: None,
        }
    }

    #[test]
    fn original_deadline_crossing_preimage_read_prevents_set_and_late_set_is_unknown() {
        let current = std::rc::Rc::new(std::cell::Cell::new(true));
        let change = prepared();
        let mut backend = fake(vec![Ok(observation(change.before_descriptor()))], 0);
        backend.expire_observe = Some(current.clone());
        let proof = write_pair_timed(&mut backend, &change.pair, false, &|| current.get());
        assert_eq!(proof.state, ShareWriteState::NotAttempted);
        assert!(!proof.write_attempted && backend.writes.is_empty());
        current.set(true);
        let mut backend = fake(vec![Ok(observation(change.before_descriptor()))], 0);
        backend.expire_set = Some(current.clone());
        let proof = write_pair_timed(&mut backend, &change.pair, false, &|| current.get());
        assert_eq!(proof.state, ShareWriteState::Unknown);
        assert!(proof.write_attempted && proof.readback.is_none());
        assert_eq!(backend.calls, ["observe", "set1501"]);
    }

    #[test]
    fn preimage_drift_or_unavailable_refuses_before_one_time_set() {
        let change = prepared();
        let mut changed = observation(change.before_descriptor());
        changed.metadata.maximum_uses = 17;
        for read in [Ok(changed), Err("unavailable".into())] {
            let mut backend = fake(vec![read], 0);
            let attempted = prepared().apply_with(&mut backend);
            assert_eq!(attempted.proof.state, ShareWriteState::NotAttempted);
            assert!(!attempted.proof.write_attempted);
            assert!(backend.writes.is_empty());
            assert_eq!(backend.calls, ["observe"]);
        }
    }

    #[test]
    fn exact_apply_and_reverse_pair_each_use_one_set_and_fresh_readback() {
        let change = prepared();
        let before = change.before_descriptor().to_vec();
        let after = change.after_descriptor().to_vec();
        let mut post = observation(&after);
        post.current_uses = 3;
        let mut backend = fake(vec![Ok(observation(&before)), Ok(post)], 0);
        let attempted = change.apply_with(&mut backend);
        assert_eq!(attempted.proof.state, ShareWriteState::ReadbackMatched);
        assert_eq!(backend.writes, [after.clone()]);
        assert_eq!(backend.calls, ["observe", "set1501", "observe"]);
        let mut restore = fake(vec![Ok(observation(&after)), Ok(observation(&before))], 0);
        let proof = attempted.rollback.rollback_with(&mut restore);
        assert_eq!(proof.state, ShareWriteState::ReadbackMatched);
        assert_eq!(restore.writes, [before]);
        assert_eq!(restore.calls, ["observe", "set1501", "observe"]);
    }

    #[test]
    fn failed_set_response_remains_unknown_even_with_matching_readback_and_never_retries() {
        let change = prepared();
        let mut backend = fake(
            vec![
                Ok(observation(change.before_descriptor())),
                Ok(observation(change.after_descriptor())),
            ],
            5,
        );
        let attempted = change.apply_with(&mut backend);
        assert_eq!(attempted.proof.state, ShareWriteState::Unknown);
        assert!(attempted.proof.write_attempted);
        assert_eq!(attempted.proof.set_status, Some(5));
        assert!(attempted.proof.readback.is_some());
        assert_eq!(backend.calls, ["observe", "set1501", "observe"]);
        assert_eq!(backend.writes.len(), 1);
    }

    #[test]
    fn missing_or_changed_readback_never_becomes_confirmed_success() {
        let change = prepared();
        let mut changed = observation(change.after_descriptor());
        changed.metadata.flags = 0;
        for read in [Err("readback unavailable".into()), Ok(changed)] {
            let change = prepared();
            let mut backend = fake(vec![Ok(observation(change.before_descriptor())), read], 0);
            let attempted = change.apply_with(&mut backend);
            assert_eq!(attempted.proof.state, ShareWriteState::Unknown);
            assert!(attempted.proof.write_attempted);
            assert_eq!(backend.writes.len(), 1);
        }
    }

    #[test]
    fn semantically_equivalent_but_reencoded_post_descriptor_is_not_exact_readback() {
        let change = prepared();
        let mut reencoded = change.after_descriptor().to_vec();
        let owner = reencoded[4..8].to_vec();
        let group = reencoded[8..12].to_vec();
        reencoded[4..8].copy_from_slice(&group);
        reencoded[8..12].copy_from_slice(&owner);
        assert_ne!(reencoded, change.after_descriptor());
        let decoded = Descriptor::from_bytes(&reencoded).unwrap();
        assert_eq!(decoded.projection().owner_sid, CONTROLLER);
        assert_eq!(decoded.projection().group_sid, CONTROLLER);
        let mut backend = fake(
            vec![
                Ok(observation(change.before_descriptor())),
                Ok(observation(&reencoded)),
            ],
            0,
        );
        assert_eq!(
            change.apply_with(&mut backend).proof.state,
            ShareWriteState::Unknown
        );
        assert_eq!(backend.writes.len(), 1);
    }

    #[test]
    fn rollback_refuses_if_current_state_is_not_the_derived_hardened_preimage() {
        let change = prepared();
        let before = change.before_descriptor().to_vec();
        let mut backend = fake(
            vec![
                Ok(observation(&before)),
                Ok(observation(change.after_descriptor())),
            ],
            0,
        );
        let attempted = change.apply_with(&mut backend);
        let mut restore = fake(vec![Ok(observation(&before))], 0);
        let proof = attempted.rollback.rollback_with(&mut restore);
        assert_eq!(proof.state, ShareWriteState::NotAttempted);
        assert!(!proof.write_attempted);
        assert!(restore.writes.is_empty());
    }

    #[test]
    fn reconstructed_reviewed_pair_requires_native_derivation_and_correct_direction() {
        let original = prepared();
        let before = original.before_descriptor();
        let after = original.after_descriptor();
        let roles = [PROBE, LEGITIMATE, CONTROLLER];
        assert!(observation(before)
            .reviewed_change(before, after, roles)
            .is_ok());
        assert!(observation(after)
            .reviewed_rollback(before, after, roles)
            .is_ok());
        assert!(observation(after)
            .reviewed_change(before, after, roles)
            .is_err());
        assert!(observation(before)
            .reviewed_rollback(before, after, roles)
            .is_err());
        assert!(observation(before)
            .reviewed_change(before, before, roles)
            .is_err());
        assert!(observation(before)
            .reviewed_change(before, after, [LEGITIMATE, PROBE, CONTROLLER])
            .is_err());
    }

    #[test]
    fn reconstructed_restore_rechecks_metadata_and_never_writes_arbitrary_bytes() {
        let original = prepared();
        let before = original.before_descriptor();
        let after = original.after_descriptor();
        let restored = observation(after)
            .reviewed_rollback(before, after, [PROBE, LEGITIMATE, CONTROLLER])
            .unwrap();
        let mut changed = observation(after);
        changed.metadata.maximum_uses -= 1;
        let mut backend = fake(vec![Ok(changed)], 0);
        assert_eq!(
            restored.rollback_with(&mut backend).state,
            ShareWriteState::NotAttempted
        );
        assert!(backend.writes.is_empty());
    }

    fn emit_write_case(case: &str, status: u32) {
        let inputs: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/ad_smb_native_corpus_inputs.json"
        ))
        .unwrap();
        let request = &inputs["cases"][case]["packet"]["manifest"]["params"]["ad_smb_request"];
        let before = hex::decode(inputs["descriptor_hex"].as_str().unwrap()).unwrap();
        let observe = |bytes: &[u8]| {
            let mut observed = observation(bytes);
            observed.metadata.flags = 0x8030;
            observed.metadata.encrypt_data_flag = true;
            observed
        };
        let change = observe(&before)
            .propose_probe_removal(PROBE, LEGITIMATE, CONTROLLER)
            .unwrap();
        let after = change.after_descriptor().to_vec();
        let mut backend = fake(vec![Ok(observe(&before)), Ok(observe(&after))], status);
        let attempted = change.apply_with(&mut backend);
        assert_eq!(backend.calls, ["observe", "set1501", "observe"]);
        assert_eq!(backend.writes, [after]);
        assert_eq!(
            attempted.proof.state,
            if status == 0 {
                ShareWriteState::ReadbackMatched
            } else {
                ShareWriteState::Unknown
            }
        );
        assert!(attempted.proof.readback.is_some());
        let marker = serde_json::json!({"schema_version":"bluefire.ad-smb-synthetic-native-case.v1","synthetic_only":true,"case":case,"operation":request["step"],"request_digest":digest(&serde_json::to_vec(request).unwrap()),"result":attempted.proof});
        let serialized = serde_json::to_string(&marker).unwrap();
        assert!(serialized.len() <= 131072);
        println!("BF_AD_NATIVE_CORPUS_V1 {serialized}");
    }

    #[test]
    fn emits_synthetic_matched_write_for_python_workflow() {
        emit_write_case("matched_write", 0);
    }

    #[test]
    fn emits_synthetic_unknown_write_for_python_workflow() {
        emit_write_case("unknown_write", 5);
    }
}
