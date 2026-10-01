//! Authored ordinary-file fixtures only: no live cgroup, mount or service operation.

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;
use crate::service_observer::ObservationTarget;

const EVENTS: &[u8] = b"populated 1\nfrozen 0\n";
const NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const MANAGER: &str = "/user.slice/user-1000.slice/user@1000.service";

fn binding(index: usize) -> ServiceOperationBinding {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests_platform/fixtures/service_operation_binding_v1.json"
    ))
    .unwrap();
    ServiceOperationBinding::from_json(
        &serde_json::to_vec(&fixture["valid"][index]["document"]).unwrap(),
    )
    .unwrap()
}

fn scope(binding: &ServiceOperationBinding) -> ReportedPropertyScope {
    let unit = format!("bluefire-{NONCE}.service");
    let owner = format!("Id=user@1000.service\nLoadState=loaded\nActiveState=active\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nMainPID=42\nControlGroup={MANAGER}\n");
    let manager = format!("ControlGroup={MANAGER}\nUnitPath=/usr/lib/systemd/user\n");
    let unit = format!("Id={unit}\nNames={unit}\nLoadState=loaded\nActiveState=active\nControlGroup={MANAGER}/app.slice/{unit}\nFragmentPath=/usr/lib/systemd/user/{unit}\nDropInPaths=\nUnitFileState=disabled\nTransient=no\nNeedDaemonReload=no\n");
    ObservationTarget::from_binding(binding)
        .unwrap()
        .parse_property_scope(
            finished(owner.as_bytes()),
            finished(manager.as_bytes()),
            finished(unit.as_bytes()),
        )
        .unwrap()
}

fn finished(bytes: &[u8]) -> ReadOutcome<'_> {
    ReadOutcome::Finished {
        bytes,
        exit_code: 0,
        truncated: false,
    }
}

fn budget(cancelled: &AtomicBool) -> Budget<'_> {
    Budget {
        deadline: Instant::now() + Duration::from_secs(2),
        cancelled,
    }
}

#[test]
fn complete_binding_and_exact_manager_hierarchy_select_the_only_unit_path() {
    let first = binding(0);
    let reported = scope(&first);
    assert_eq!(
        components(&first, 1000, NONCE, &reported).unwrap(),
        [
            "user.slice",
            "user-1000.slice",
            "user@1000.service",
            "app.slice",
            "bluefire-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service",
        ]
    );
    // Same manager, owner and unit, but a different operation/journal binding.
    assert_eq!(
        components(&binding(1), 1000, NONCE, &reported),
        Err(CgroupReadIssue::ScopeIdentity)
    );
    let mut changed: serde_json::Value = serde_json::from_str(first.canonical_json()).unwrap();
    changed["identity"]["workspace_id"] = serde_json::json!("other-workspace");
    changed["identity_digest"] =
        serde_json::json!(crate::canonical::canonical_hash(&changed["identity"]));
    let changed =
        ServiceOperationBinding::from_json(&serde_json::to_vec(&changed).unwrap()).unwrap();
    assert_eq!(
        components(&changed, 1000, NONCE, &reported),
        Err(CgroupReadIssue::ScopeIdentity)
    );
    assert_eq!(
        components(&first, 1001, NONCE, &reported),
        Err(CgroupReadIssue::ScopeIdentity)
    );
    assert_eq!(
        components(&first, 0, NONCE, &reported),
        Err(CgroupReadIssue::ScopeIdentity)
    );
    let mut reported = reported;
    reported.manager_control_group = "/other/user@1000.service".into();
    assert_eq!(
        components(&first, 1000, NONCE, &reported),
        Err(CgroupReadIssue::ScopeIdentity)
    );
}

#[test]
fn traversal_aliases_excessive_depth_and_missing_group_cannot_become_empty_events() {
    let binding = binding(0);
    for middle in [
        "..",
        ".",
        "",
        "app.slice/../../other",
        "app\\slice",
        "app%2fslice",
    ] {
        let mut reported = scope(&binding);
        reported.unit_control_group = Some(format!("{MANAGER}/{middle}/bluefire-{NONCE}.service"));
        assert_eq!(
            components(&binding, 1000, NONCE, &reported),
            Err(CgroupReadIssue::ScopeIdentity)
        );
    }
    let mut reported = scope(&binding);
    reported.unit_control_group = Some(format!(
        "{MANAGER}/{}/bluefire-{NONCE}.service",
        "a/".repeat(32)
    ));
    assert_eq!(
        components(&binding, 1000, NONCE, &reported),
        Err(CgroupReadIssue::ScopeIdentity)
    );
    reported.unit_control_group = None;
    assert_eq!(
        components(&binding, 1000, NONCE, &reported),
        Err(CgroupReadIssue::NoReportedGroup)
    );
}

#[test]
fn complete_events_require_bounded_bytes_and_actual_eof() {
    let cancelled = AtomicBool::new(false);
    let mut input = EVENTS;
    assert_eq!(
        read_complete(&mut input, &budget(&cancelled)).unwrap(),
        EVENTS
    );
    for bytes in [b"".as_slice(), b"populated 0\nfrozen 0".as_slice()] {
        let mut input = bytes;
        assert_eq!(
            read_complete(&mut input, &budget(&cancelled)),
            Err(CgroupReadIssue::Incomplete)
        );
    }
    let bytes = vec![b'x'; MAX_CGROUP_BYTES + 1];
    assert_eq!(
        read_complete(&mut bytes.as_slice(), &budget(&cancelled)),
        Err(CgroupReadIssue::OutputLimit)
    );
    struct NoEof(bool);
    impl Read for NoEof {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            self.0 = true;
            output[..EVENTS.len()].copy_from_slice(EVENTS);
            Ok(EVENTS.len())
        }
    }
    assert_eq!(
        read_complete(&mut NoEof(false), &budget(&cancelled)),
        Err(CgroupReadIssue::Unavailable)
    );
}

#[test]
fn cancelled_or_spent_budget_never_reads_or_renews_and_late_cancellation_refuses() {
    struct MustNotRead;
    impl Read for MustNotRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("read after refusal");
        }
    }
    let cancelled = AtomicBool::new(true);
    assert_eq!(
        read_complete(&mut MustNotRead, &budget(&cancelled)),
        Err(CgroupReadIssue::Cancelled)
    );
    cancelled.store(false, Ordering::Release);
    let expired = Budget {
        deadline: Instant::now(),
        cancelled: &cancelled,
    };
    assert_eq!(
        read_complete(&mut MustNotRead, &expired),
        Err(CgroupReadIssue::Deadline)
    );
    struct CancelAtEof<'a>(&'a AtomicBool, bool);
    impl Read for CancelAtEof<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.1 {
                self.0.store(true, Ordering::Release);
                return Ok(0);
            }
            self.1 = true;
            output[..EVENTS.len()].copy_from_slice(EVENTS);
            Ok(EVENTS.len())
        }
    }
    assert_eq!(
        read_complete(&mut CancelAtEof(&cancelled, false), &budget(&cancelled)),
        Err(CgroupReadIssue::Cancelled)
    );
    let admission =
        crate::service_admission::reservation_test_admission(1000, "authored", "unused");
    let reported = scope(&binding(0));
    assert!(matches!(
        acquire_cgroup_events(&admission, &reported, &cancelled),
        Err(CgroupReadIssue::Cancelled)
    ));
    cancelled.store(false, Ordering::Release);
    assert!(matches!(
        acquire_cgroup_events(&admission, &reported, &cancelled),
        Err(CgroupReadIssue::AdmissionUnavailable)
    ));
}

// A closed test-only filesystem witness lets ordinary temporary files exercise
// the real no-follow opens, descriptor reads and rechecks without mounting or
// writing any cgroup. Production always uses libc fstatfs/statx instead.
fn fixture_filesystem(_: &File) -> Result<Filesystem, CgroupReadIssue> {
    Ok(Filesystem {
        kind: i128::from(libc::CGROUP2_SUPER_MAGIC),
        mount: 7,
        mount_root: true,
    })
}

fn other_mount(file: &File) -> Result<Filesystem, CgroupReadIssue> {
    let mut fs = fixture_filesystem(file)?;
    fs.mount = 8;
    Ok(fs)
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "bluefire-cgroup-fixture-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let root = std::env::temp_dir().join(name);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(root.join("unit")).unwrap();
        std::fs::set_permissions(root.join("unit"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::fs::write(root.join("unit/cgroup.events"), EVENTS).unwrap();
        std::fs::set_permissions(
            root.join("unit/cgroup.events"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        Self { root }
    }

    fn root_attachment(&self) -> Attachment {
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&self.root)
            .unwrap();
        let observed = identity(&root, fixture_filesystem).unwrap();
        Attachment {
            files: vec![root],
            names: vec![],
            identities: vec![observed],
            cgroup_root: 0,
            probe: fixture_filesystem,
        }
    }

    fn attach(&self, budget: &Budget<'_>) -> Attachment {
        let mut attached = self.root_attachment();
        let owner = attached.identities[0].uid;
        attached.append("unit", true, owner, budget).unwrap();
        attached
            .append("cgroup.events", false, owner, budget)
            .unwrap();
        attached
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn held_descriptor_reads_complete_events_and_ignores_unrelated_sibling_churn() {
    let fixture = Fixture::new();
    let cancel = AtomicBool::new(false);
    let budget = budget(&cancel);
    let attached = fixture.attach(&budget);
    std::fs::create_dir(fixture.root.join("sibling")).unwrap();
    std::fs::create_dir(fixture.root.join("unit/sibling")).unwrap();
    attached.recheck(&budget).unwrap();
    assert_eq!(attached.read_events(&budget).unwrap(), EVENTS);
    attached.recheck(&budget).unwrap();
    let binding = binding(0);
    let captured = AcquiredCgroupEvents {
        binding: binding.clone(),
        bytes: EVENTS.to_vec(),
    };
    assert_eq!(captured.binding(), &binding);
    assert_eq!(captured.bytes(), EVENTS);
    assert!(matches!(
        captured.parser_outcome(),
        ReadOutcome::Finished {
            exit_code: 0,
            truncated: false,
            ..
        }
    ));
}

#[test]
fn replaced_named_directory_or_events_cannot_reuse_a_held_success() {
    for directory in [false, true] {
        let fixture = Fixture::new();
        let cancel = AtomicBool::new(false);
        let budget = budget(&cancel);
        let attached = fixture.attach(&budget);
        if directory {
            std::fs::rename(fixture.root.join("unit"), fixture.root.join("old")).unwrap();
            std::fs::create_dir(fixture.root.join("unit")).unwrap();
        } else {
            std::fs::rename(
                fixture.root.join("unit/cgroup.events"),
                fixture.root.join("unit/old.events"),
            )
            .unwrap();
            std::fs::write(fixture.root.join("unit/cgroup.events"), EVENTS).unwrap();
        }
        assert_eq!(attached.recheck(&budget), Err(CgroupReadIssue::Changed));
    }
}

#[test]
fn symlinks_missing_files_hardlinks_and_wrong_types_refuse_without_content_reads() {
    for variation in 0..5 {
        let fixture = Fixture::new();
        let cancel = AtomicBool::new(false);
        let budget = budget(&cancel);
        let leaf = fixture.root.join("unit/cgroup.events");
        match variation {
            0 => {
                std::fs::rename(fixture.root.join("unit"), fixture.root.join("other")).unwrap();
                symlink("other", fixture.root.join("unit")).unwrap();
            }
            1 => {
                std::fs::remove_file(&leaf).unwrap();
                symlink("other", &leaf).unwrap();
            }
            2 => {
                std::fs::hard_link(&leaf, fixture.root.join("alias")).unwrap();
            }
            3 => {
                std::fs::remove_file(&leaf).unwrap();
                std::fs::create_dir(&leaf).unwrap();
            }
            _ => {
                std::fs::remove_file(&leaf).unwrap();
            }
        }
        let mut attached = fixture.root_attachment();
        let owner = attached.identities[0].uid;
        let result = attached
            .append("unit", true, owner, &budget)
            .and_then(|_| attached.append("cgroup.events", false, owner, &budget));
        assert!(result.is_err());
        if variation == 4 {
            assert_eq!(result, Err(CgroupReadIssue::Missing));
        }
    }
}

#[test]
fn wrong_filesystem_or_mount_substitution_never_becomes_a_cgroup_capture() {
    let fixture = Fixture::new();
    let cancel = AtomicBool::new(false);
    let budget = budget(&cancel);
    let mut attached = fixture.root_attachment();
    let owner = attached.identities[0].uid;
    attached.probe = filesystem;
    assert_eq!(
        attached.append("unit", true, owner, &budget),
        Err(CgroupReadIssue::UnsupportedFilesystem)
    );
    let mut attached = fixture.root_attachment();
    attached.probe = other_mount;
    assert_eq!(
        attached.append("unit", true, owner, &budget),
        Err(CgroupReadIssue::UnsupportedFilesystem)
    );
    let mut attached = fixture.attach(&budget);
    attached.probe = other_mount;
    assert_eq!(attached.recheck(&budget), Err(CgroupReadIssue::Changed));
}

#[test]
fn owner_mode_and_file_identity_changes_refuse_even_when_paths_match() {
    let fixture = Fixture::new();
    let cancel = AtomicBool::new(false);
    let budget = budget(&cancel);
    let attached = fixture.attach(&budget);
    std::fs::set_permissions(
        fixture.root.join("unit"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert_eq!(attached.recheck(&budget), Err(CgroupReadIssue::Changed));
    let mut observed = attached.identities[1].clone();
    observed.uid = 12345;
    assert_eq!(
        protected(&observed, true, 54321),
        Err(CgroupReadIssue::ScopeIdentity)
    );
}
