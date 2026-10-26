//! Fake kernel boundary only: no descriptors, identities, ACLs, or subprocesses.

use super::*;

fn credentials(uid: u32) -> Credentials {
    Credentials {
        real_uid: uid,
        effective_uid: uid,
        saved_uid: uid,
        real_gid: 501,
        effective_gid: 501,
        saved_gid: 501,
        groups: vec![501],
    }
}

#[test]
fn native_startup_failure_codes_are_reserved_and_stage_propagation_is_closed() {
    use native::StartupFailureStage as Stage;

    let stages = [
        (Stage::RuntimeSupportedCheck, 80),
        (Stage::InitialClockOrDeadline, 81),
        (Stage::InitialDescriptorInventory, 82),
        (Stage::ReadonlyDescriptor, 83),
        (Stage::CredentialSelection, 84),
        (Stage::PostDropDescriptorInventory, 85),
        (Stage::InitialResourceValidation, 86),
        (Stage::ChannelInitialization, 87),
    ];
    let mut codes = Vec::new();
    for (stage, code) in stages {
        assert_eq!(stage.exit_code(), code);
        assert!((80..=87).contains(&code));
        assert!(![0, 2, 3, 4].contains(&code));
        assert_eq!(native::startup_step(stage, Ok(7)), Ok(7));
        assert_eq!(native::startup_step(stage, Err::<(), ()>(())), Err(stage));
        codes.push(code);
    }
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes, (80..=87).collect::<Vec<_>>());
}

fn request(operation: &str) -> Request {
    let bytes = b"{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n";
    let binding = Binding {
        schema_version: "bluefire.macos-file-access-binding.v1".into(),
        enrollment_id: format!("file-enrollment-{}", "1".repeat(32)),
        generation: format!("file-generation-{}", "2".repeat(32)),
        custody_digest: format!("sha256:{}", "3".repeat(64)),
        issued_at_ms: 1000,
        expires_at_ms: 901000,
        original_deadline_ns: 900000001000,
        owner: credentials(501),
        reader: credentials(502),
        directory: Directory {
            device: 1,
            inode: 10,
            owner_uid: 0,
            group_gid: 501,
            mode: "0550".into(),
        },
        resource: Resource {
            device: 1,
            inode: 11,
            owner_uid: 501,
            group_gid: 501,
            size_bytes: bytes.len() as u64,
            record_count: 8,
            sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
        },
        control_revision: 1,
        mode: "0640".into(),
    };
    Request {
        schema_version: "bluefire.macos-file-access-request.v1".into(),
        binding_digest: canonical_hash(&serde_json::to_value(&binding).unwrap()),
        binding,
        request_id: "5".repeat(64),
        sequence: 1,
        operation: operation.into(),
        issued_at_ms: 1000,
        expires_at_ms: 6000,
        issued_monotonic_ns: 1000,
        deadline_ns: 5000001000,
    }
}

struct Fake {
    clock: Clock,
    principal: Credentials,
    facts: Facts,
    directory: Directory,
    bytes: Vec<u8>,
    opens: usize,
    closes: usize,
    applies: usize,
    held_reads: usize,
    denied: bool,
    open_unknown: bool,
    close_unknown: bool,
    held_unknown: bool,
    drift_on_read: bool,
    late_principal: bool,
    late_apply: bool,
}

impl Fake {
    fn new(request: &Request, owner: bool) -> Self {
        let resource = &request.binding.resource;
        Self {
            clock: Clock {
                wall_ms: 1000,
                monotonic_ns: 1000,
            },
            principal: if owner {
                request.binding.owner.clone()
            } else {
                request.binding.reader.clone()
            },
            facts: Facts {
                device: resource.device,
                inode: resource.inode,
                owner_uid: resource.owner_uid,
                group_gid: resource.group_gid,
                mode: request.binding.mode.clone(),
                size: resource.size_bytes,
                links: 1,
                modified_ns: 1,
                changed_ns: 1,
            },
            directory: request.binding.directory.clone(),
            bytes: b"{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n".to_vec(),
            opens: 0,
            closes: 0,
            applies: 0,
            held_reads: 0,
            denied: false,
            open_unknown: false,
            close_unknown: false,
            held_unknown: false,
            drift_on_read: false,
            late_principal: false,
            late_apply: false,
        }
    }
}

impl Backend for Fake {
    fn clock(&mut self) -> Result<Clock, ()> {
        Ok(self.clock)
    }
    fn principal(&mut self) -> Result<Credentials, ()> {
        if self.late_principal && self.held_reads > 0 {
            self.clock.monotonic_ns = 5000001000;
        }
        Ok(self.principal.clone())
    }
    fn directory(&mut self) -> Result<Directory, ()> {
        Ok(self.directory.clone())
    }
    fn open_leaf(&mut self) -> Result<i32, OpenFailure> {
        self.opens += 1;
        if self.denied {
            Err(OpenFailure::Denied)
        } else if self.open_unknown {
            Err(OpenFailure::Unknown)
        } else {
            Ok(7)
        }
    }
    fn facts(&mut self, _: i32) -> Result<Facts, ()> {
        Ok(self.facts.clone())
    }
    fn read(&mut self, handle: i32, _: usize, _: u64) -> Result<Vec<u8>, ()> {
        if handle == 3 {
            self.held_reads += 1;
        }
        if self.drift_on_read {
            self.facts.changed_ns += 1;
        }
        Ok(self.bytes.clone())
    }
    fn close_read(&mut self, _: i32) -> Result<(), ()> {
        self.closes += 1;
        if self.close_unknown {
            Err(())
        } else {
            Ok(())
        }
    }
    fn held_leaf(&mut self) -> Result<i32, ()> {
        Ok(3)
    }
    fn set_mode(&mut self, _: i32, mode: &str) -> Result<(), ()> {
        self.applies += 1;
        self.facts.mode = mode.into();
        self.facts.changed_ns += 1;
        if self.late_apply {
            self.clock.monotonic_ns = 5000001000;
        }
        Ok(())
    }
    fn close_held(&mut self) -> Result<(), ()> {
        if self.held_unknown {
            Err(())
        } else {
            Ok(())
        }
    }
}

#[test]
fn reader_success_is_fresh_and_locally_closed_not_custody_proof() {
    let request = request("read_reader");
    let mut backend = Fake::new(&request, false);
    let result = Session::new().execute(&mut backend, Entry::Reader, &request);
    assert_eq!(result.outcome, "allowed");
    assert!(result.fresh_read.is_some());
    assert!(result.held_control.is_none());
    assert!(!result.prevention_proven);
    assert_eq!(result.custody, "requires_original_creator_evidence");
    assert_eq!(
        (
            backend.opens,
            backend.closes,
            backend.held_reads,
            backend.applies
        ),
        (1, 1, 0, 0)
    );
}

#[test]
fn owner_success_still_uses_fresh_open_not_held_leaf() {
    let request = request("read_owner");
    let mut backend = Fake::new(&request, true);
    let result = Session::new().execute(&mut backend, Entry::Reader, &request);
    assert_eq!(result.outcome, "allowed");
    assert_eq!(
        (backend.opens, backend.closes, backend.held_reads),
        (1, 1, 0)
    );
    assert!(result.held_control.is_none());
}

#[test]
fn reader_cannot_assert_owner_role_or_control_entry() {
    let request = request("read_owner");
    let mut backend = Fake::new(&request, false);
    assert_eq!(
        Session::new()
            .execute(&mut backend, Entry::Reader, &request)
            .outcome,
        "refused"
    );
    assert_eq!(backend.opens, 0);
    backend.principal = credentials(501);
    assert_eq!(
        Session::new()
            .execute(&mut backend, Entry::OwnerControl, &request)
            .outcome,
        "refused"
    );
    assert_eq!(backend.held_reads, 0);
}

#[test]
fn denial_has_no_inode_and_requires_creator_namespace_evidence() {
    let request = request("read_reader");
    let mut backend = Fake::new(&request, false);
    backend.denied = true;
    let result = Session::new().execute(&mut backend, Entry::Reader, &request);
    assert_eq!(result.outcome, "denied");
    assert!(result.fresh_read.is_none());
    assert!(result.held_control.is_none());
    assert_eq!(result.request_handle_cleanup, "not_opened");
    assert!(!result.prevention_proven);
}

#[test]
fn ambiguous_open_is_unknown_not_permission_denial() {
    let request = request("read_reader");
    let mut backend = Fake::new(&request, false);
    backend.open_unknown = true;
    assert_eq!(
        Session::new()
            .execute(&mut backend, Entry::Reader, &request)
            .outcome,
        "unknown"
    );
}

#[test]
fn read_drift_and_failed_close_cannot_publish_success() {
    for close_unknown in [false, true] {
        let request = request("read_reader");
        let mut backend = Fake::new(&request, false);
        backend.close_unknown = close_unknown;
        backend.drift_on_read = !close_unknown;
        let result = Session::new().execute(&mut backend, Entry::Reader, &request);
        assert_eq!(result.outcome, "unknown");
        assert!(result.fresh_read.is_none());
        assert_eq!(backend.closes, 1);
    }
}

#[test]
fn harden_and_rollback_preserve_held_bytes_not_fresh_owner_read() {
    for (operation, before, after) in [("harden", "0640", "0600"), ("rollback", "0600", "0640")] {
        let mut request = request(operation);
        request.binding.mode = before.into();
        request.binding_digest = canonical_hash(&serde_json::to_value(&request.binding).unwrap());
        let mut backend = Fake::new(&request, true);
        let result = Session::new().execute(&mut backend, Entry::OwnerControl, &request);
        assert_eq!(result.outcome, "mode_changed");
        assert_eq!(result.held_control.unwrap()["after_mode"], after);
        assert!(result.fresh_read.is_none());
        assert_eq!(
            (backend.applies, backend.opens, backend.held_reads),
            (1, 0, 2)
        );
    }
}

#[test]
fn final_original_deadline_guard_prevents_setter_after_metadata() {
    let request = request("harden");
    let mut backend = Fake::new(&request, true);
    backend.late_principal = true;
    assert_eq!(
        Session::new()
            .execute(&mut backend, Entry::OwnerControl, &request)
            .outcome,
        "refused"
    );
    assert_eq!(backend.applies, 0);
}

#[test]
fn late_setter_is_unknown_and_cannot_replay_or_automatically_rollback() {
    let mut request = request("harden");
    let mut backend = Fake::new(&request, true);
    backend.late_apply = true;
    let mut session = Session::new();
    assert_eq!(
        session
            .execute(&mut backend, Entry::OwnerControl, &request)
            .outcome,
        "unknown"
    );
    assert_eq!(backend.applies, 1);
    assert_eq!(
        session
            .execute(&mut backend, Entry::OwnerControl, &request)
            .outcome,
        "refused"
    );
    request.sequence = 2;
    request.request_id = "6".repeat(64);
    assert_eq!(
        session
            .execute(&mut backend, Entry::OwnerControl, &request)
            .outcome,
        "refused"
    );
    assert_eq!(backend.applies, 1);
}

#[test]
fn cleanup_is_local_only_and_uncertainty_is_not_promoted() {
    let request = request("close");
    for unknown in [false, true] {
        let mut backend = Fake::new(&request, false);
        backend.held_unknown = unknown;
        let result = Session::new().execute(&mut backend, Entry::Reader, &request);
        assert_eq!(result.outcome, if unknown { "unknown" } else { "closed" });
        assert_eq!(
            result.held_handle_cleanup,
            if unknown { "unknown" } else { "closed" }
        );
        assert!(!result.prevention_proven);
    }
}

#[test]
fn expiry_equality_role_and_binding_substitution_do_not_open() {
    let original = request("read_reader");
    let mut backend = Fake::new(&original, false);
    backend.clock.monotonic_ns = original.deadline_ns;
    assert_eq!(
        Session::new()
            .execute(&mut backend, Entry::Reader, &original)
            .outcome,
        "refused"
    );
    backend.clock.monotonic_ns = original.issued_monotonic_ns;
    let mut session = Session::new();
    assert_eq!(
        session
            .execute(&mut backend, Entry::Reader, &original)
            .outcome,
        "allowed"
    );
    let mut replacement = original.clone();
    replacement.sequence = 2;
    replacement.request_id = "6".repeat(64);
    replacement.binding.generation = format!("file-generation-{}", "7".repeat(32));
    replacement.binding_digest =
        canonical_hash(&serde_json::to_value(&replacement.binding).unwrap());
    assert_eq!(
        session
            .execute(&mut backend, Entry::Reader, &replacement)
            .outcome,
        "refused"
    );
    assert_eq!(backend.opens, 1);
}

#[test]
fn wire_rejects_duplicate_nonfinite_bool_int_extra_and_bounds() {
    let original = serde_json::to_string(&request("read_reader")).unwrap();
    let duplicate = format!("{{\"sequence\":1,{}", &original[1..]);
    assert!(decode_request(duplicate.as_bytes()).is_err());
    for raw in [b"NaN".as_slice(), b"Infinity".as_slice(), b"{}".as_slice()] {
        assert!(decode_request(raw).is_err());
    }
    let mut value = serde_json::to_value(request("read_reader")).unwrap();
    for replacement in [json!(true), json!(0), json!(65)] {
        value["sequence"] = replacement;
        assert!(decode_request(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    value["sequence"] = json!(1);
    value["path"] = json!("not-an-input");
    assert!(decode_request(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(decode_request(&vec![b' '; MAX_MESSAGE + 1]).is_err());
}

#[test]
fn fixed_commands_accept_only_distinct_inherited_numeric_handles() {
    let args = ["--directory-fd", "3", "--channel-fd", "4"].map(String::from);
    assert_eq!(native::descriptors(&args, Entry::Reader).unwrap(), (3, 4));
    for invalid in [
        ["--directory-fd", "03", "--channel-fd", "4"],
        ["--directory-fd", "3", "--channel-fd", "3"],
        ["--directory-fd", "2", "--channel-fd", "4"],
        ["--leaf-fd", "3", "--channel-fd", "4"],
    ] {
        assert!(native::descriptors(&invalid.map(String::from), Entry::Reader).is_err());
    }
}

#[test]
fn self_inventory_rejects_smuggled_duplicate_missing_or_wrong_type_descriptors() {
    let rows = [(0, 1), (1, 6), (2, 6), (3, 1), (4, 2)];
    assert!(native::inventory(&rows, 3, 4, None).is_ok());
    assert!(native::inventory(&rows[..4], 3, 4, None).is_err());
    let mut extra = rows.to_vec();
    extra.push((9, 1));
    assert!(native::inventory(&extra, 3, 4, None).is_err());
    assert!(native::inventory(&extra, 3, 4, Some(9)).is_ok());
    extra[0] = (1, 1);
    assert!(native::inventory(&extra, 3, 4, Some(9)).is_err());
    let mut wrong = rows;
    wrong[0].1 = 2;
    assert!(native::inventory(&wrong, 3, 4, None).is_err());
}

#[test]
fn capability_support_is_not_live_readiness_or_prevention() {
    let value = capability_document(false);
    assert_eq!(value["live_ready"], false);
    assert_eq!(value["scope"], "protocol_support_only");
    assert_eq!(value["monotonic_clock"], "darwin-mach-absolute-ns");
}

#[test]
fn mach_absolute_time_conversion_is_checked_floor_without_a_process_origin() {
    assert_eq!(native::absolute_nanos(7, 125, 3), Ok(291));
    assert_eq!(native::absolute_nanos(7, 1, 1), Ok(7));
    assert!(native::absolute_nanos(1, 0, 1).is_err());
    assert!(native::absolute_nanos(1, 1, 0).is_err());
    assert!(native::absolute_nanos(u64::MAX, 2, 1).is_err());
}

fn startup_args() -> Vec<String> {
    [
        "--directory-fd",
        "3",
        "--channel-fd",
        "4",
        "--original-deadline-ns",
        "900000001000",
        "--uid",
        "502",
        "--gid",
        "501",
        "--groups",
        "501,502",
    ]
    .map(String::from)
    .to_vec()
}

#[test]
fn startup_recipe_is_closed_canonical_nonroot_and_immutable() {
    let args = startup_args();
    let recipe = native::recipe(&args, Entry::Reader).unwrap();
    assert_eq!(
        (recipe.uid, recipe.gid, recipe.original_deadline_ns),
        (502, 501, 900000001000)
    );
    for (index, replacement) in [
        (5, "0"),
        (5, "01"),
        (7, "0"),
        (7, "-1"),
        (9, "4294967295"),
        (11, "502,501"),
        (11, "501,501"),
        (11, "0,501"),
        (11, "502"),
        (11, "501,"),
    ] {
        let mut invalid = args.clone();
        invalid[index] = replacement.into();
        assert!(native::recipe(&invalid, Entry::Reader).is_err());
    }
    let mut extra = args;
    extra.extend(["--path".into(), "not-an-input".into()]);
    assert!(native::recipe(&extra, Entry::Reader).is_err());
}

struct DropFake {
    current: Credentials,
    calls: Vec<&'static str>,
    fail: Option<&'static str>,
    wrong_saved: bool,
}

impl native::CredentialDrop for DropFake {
    fn observe(&mut self) -> Result<Credentials, ()> {
        self.calls.push("observe");
        if self.fail == Some("observe") {
            return Err(());
        }
        let mut actual = self.current.clone();
        if self.wrong_saved && actual.effective_uid > 0 {
            actual.saved_uid = 0;
        }
        Ok(actual)
    }
    fn set_groups(&mut self, groups: &[u32]) -> Result<(), ()> {
        self.calls.push("groups");
        if self.fail == Some("groups") {
            return Err(());
        }
        self.current.groups = groups.to_vec();
        Ok(())
    }
    fn set_gid(&mut self, gid: u32) -> Result<(), ()> {
        self.calls.push("gid");
        if self.fail == Some("gid") {
            return Err(());
        }
        self.current.real_gid = gid;
        self.current.effective_gid = gid;
        self.current.saved_gid = gid;
        Ok(())
    }
    fn set_uid(&mut self, uid: u32) -> Result<(), ()> {
        self.calls.push("uid");
        if self.fail == Some("uid") {
            return Err(());
        }
        self.current.real_uid = uid;
        self.current.effective_uid = uid;
        self.current.saved_uid = uid;
        Ok(())
    }
}

fn root_drop_fake() -> DropFake {
    DropFake {
        current: Credentials {
            real_uid: 0,
            effective_uid: 0,
            saved_uid: 0,
            real_gid: 0,
            effective_gid: 0,
            saved_gid: 0,
            groups: vec![0],
        },
        calls: Vec::new(),
        fail: None,
        wrong_saved: false,
    }
}

#[test]
fn root_drop_is_groups_then_gid_then_uid_and_observes_all_saved_ids() {
    let recipe = native::recipe(&startup_args(), Entry::Reader).unwrap();
    let mut backend = root_drop_fake();
    assert!(native::select_principal(&mut backend, &recipe).is_ok());
    assert_eq!(
        backend.calls,
        ["observe", "groups", "gid", "uid", "observe"]
    );
    assert_eq!(backend.current.groups, [501, 502]);
    let mut backend = root_drop_fake();
    backend.wrong_saved = true;
    assert!(native::select_principal(&mut backend, &recipe).is_err());
    assert_eq!(
        backend.calls,
        ["observe", "groups", "gid", "uid", "observe"]
    );
}

#[test]
fn partial_unknown_drop_stops_without_retry_regain_or_socket_read() {
    let recipe = native::recipe(&startup_args(), Entry::Reader).unwrap();
    for (failure, calls) in [
        ("observe", vec!["observe"]),
        ("groups", vec!["observe", "groups"]),
        ("gid", vec!["observe", "groups", "gid"]),
        ("uid", vec!["observe", "groups", "gid", "uid"]),
    ] {
        let mut backend = root_drop_fake();
        backend.fail = Some(failure);
        assert!(native::select_principal(&mut backend, &recipe).is_err());
        assert_eq!(backend.calls, calls);
    }
}

#[test]
fn nonroot_startup_only_accepts_exact_observed_identity_without_changes() {
    let recipe = native::recipe(&startup_args(), Entry::Reader).unwrap();
    let mut backend = root_drop_fake();
    backend.current = credentials(502);
    backend.current.groups = vec![501, 502];
    assert!(native::select_principal(&mut backend, &recipe).is_ok());
    assert_eq!(backend.calls, ["observe", "observe"]);
    backend.calls.clear();
    backend.current.saved_uid = 0;
    assert!(native::select_principal(&mut backend, &recipe).is_err());
    assert_eq!(backend.calls, ["observe"]);
}

#[test]
fn idle_review_does_not_expire_in_five_seconds_or_renew_original_deadline() {
    let original = native::original_deadline(1000, 900000001000).unwrap();
    assert_eq!(original, 900000001000);
    assert_eq!(
        native::frame_deadline(original, 10000001000),
        Ok(15000001000)
    );
    assert_eq!(native::frame_deadline(original, original - 1), Ok(original));
    assert!(native::frame_deadline(original, original).is_err());
    assert!(native::original_deadline(1000, 900000001001).is_err());
    assert!(native::original_deadline(original, original).is_err());
}
