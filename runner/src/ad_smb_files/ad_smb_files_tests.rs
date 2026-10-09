use super::*;
use crate::ad_smb_descriptor::DaclProjection;

fn target() -> LocalShareTarget {
    LocalShareTarget::new("0123456789abcdef0123456789abcdef", 'C').unwrap()
}

fn facts(index: usize, path: &str) -> ObjectFacts {
    ObjectFacts {
        final_path: format!("\\\\?\\{path}"),
        volume_serial: "fedcba9876543210".into(),
        file_id: format!("{:032x}", index + 1),
        directory: index < 4,
        size: if index < 4 { 0 } else { 3 },
        links: 1,
        attributes: if index < 4 { 0x10 } else { 0x80 },
        reparse_tag: 0,
        creation_time: 1,
        last_write_time: 2,
        change_time: 3,
        ntfs: true,
        disk_file: true,
        delete_pending: false,
        selected_security: SelectedSecurity {
            security_information: 7,
            binary_hex: "00".repeat(20),
            sha256: "synthetic".into(),
            finite_descriptor: (index >= 3).then(|| DescriptorProjection {
                binary_b64: "synthetic".into(),
                sha256: "synthetic".into(),
                revision: 1,
                control: 0x9004,
                owner_sid: "S-1-5-18".into(),
                group_sid: "S-1-5-18".into(),
                dacl: DaclProjection {
                    revision: 2,
                    aces: vec![],
                },
                sacl: None,
            }),
            sacl_observed: false,
        },
    }
}

struct Fake {
    before: Vec<ObjectFacts>,
    after: Vec<ObjectFacts>,
    opened: Vec<String>,
    reads: usize,
    positions: [usize; 2],
    fail_open: Option<usize>,
    remote: bool,
    closed: bool,
    close_calls: usize,
    extra_content: bool,
    short_content: bool,
    facts_calls: usize,
    fail_facts_call: Option<usize>,
    fail_read_call: Option<usize>,
}

impl Fake {
    fn new() -> Self {
        let before: Vec<_> = recipe(&target())
            .iter()
            .enumerate()
            .map(|(index, path)| facts(index, path))
            .collect();
        Self {
            after: before.clone(),
            before,
            opened: vec![],
            reads: 0,
            positions: [0, 0],
            fail_open: None,
            remote: false,
            closed: true,
            close_calls: 0,
            extra_content: false,
            short_content: false,
            facts_calls: 0,
            fail_facts_call: None,
            fail_read_call: None,
        }
    }
}

impl Backend for Fake {
    fn fixed_drive(&mut self, drive: &str) -> Result<(), String> {
        assert_eq!(drive, "C:\\");
        if self.remote {
            return Err("not fixed".into());
        }
        Ok(())
    }
    fn open(&mut self, path: &str, directory: bool) -> Result<(), String> {
        if self.fail_open == Some(self.opened.len()) {
            return Err("open refused".into());
        }
        assert_eq!(directory, self.opened.len() < 4);
        self.opened.push(path.into());
        Ok(())
    }
    fn facts(&mut self, index: usize) -> Result<ObjectFacts, String> {
        assert!(index < self.opened.len());
        self.facts_calls += 1;
        if self.fail_facts_call == Some(self.facts_calls) {
            return Err("synthetic held-facts failure".into());
        }
        Ok(if self.reads == 0 {
            &self.before[index]
        } else {
            &self.after[index]
        }
        .clone())
    }
    fn read(&mut self, index: usize, output: &mut [u8]) -> Result<usize, String> {
        assert_eq!(self.opened.len(), 6);
        assert!((4..6).contains(&index));
        assert!(!output.is_empty() && output.len() <= 8192);
        self.reads += 1;
        if self.fail_read_call == Some(self.reads) {
            return Err("synthetic read failure".into());
        }
        let content: &[u8] = if self.short_content {
            b"x"
        } else if self.extra_content {
            b"x\n\ny"
        } else {
            b"x\n\n"
        };
        let position = &mut self.positions[index - 4];
        let count = output.len().min(content.len() - *position);
        output[..count].copy_from_slice(&content[*position..*position + count]);
        *position += count;
        Ok(count)
    }
    fn close(&mut self) -> bool {
        self.close_calls += 1;
        self.closed
    }
}

#[test]
fn fixed_objects_held_before_bounded_reads_and_all_facts_rechecked() {
    let mut fake = Fake::new();
    let result = observe_with(&target(), &mut fake);
    assert!(result.issue.is_none());
    assert!(result.owned_handles_closed);
    let observed = result.observation.unwrap();
    assert_eq!(fake.opened, recipe(&target()));
    assert_eq!(fake.reads, 4);
    assert_eq!(fake.close_calls, 1);
    assert_eq!(observed.files.len(), 2);
    assert_eq!(
        observed.files[0].sha256,
        format!("sha256:{:x}", Sha256::digest(b"x\n\n"))
    );
    assert_eq!(observed.objects[0].volume_serial, "fedcba9876543210");
    assert!(!observed.authenticated_member_identity);
    assert!(!observed.effective_access_proved);
    assert!(observed
        .objects
        .iter()
        .all(|row| !row.selected_security.sacl_observed));
    let serialized = serde_json::to_value(observed).unwrap();
    assert!(serialized["files"][0].get("content").is_none());
}

#[test]
fn only_fixed_local_recipe_can_be_constructed() {
    for id in [
        "../escape",
        "0123456789ABCDEF0123456789abcdef",
        "0123456789abcdef0123456789abcdeg",
    ] {
        assert!(LocalShareTarget::new(id, 'C').is_err());
    }
    assert!(LocalShareTarget::new("0123456789abcdef0123456789abcdef", 'A').is_err());
    let mut fake = Fake::new();
    fake.remote = true;
    assert!(observe_with(&target(), &mut fake).observation.is_none());
    assert!(fake.opened.is_empty());
    assert_eq!(fake.close_calls, 1);
}

#[test]
fn partial_open_is_closed_without_any_content_read() {
    for failed in 0..6 {
        let mut fake = Fake::new();
        fake.fail_open = Some(failed);
        assert!(observe_with(&target(), &mut fake).observation.is_none());
        assert_eq!(fake.reads, 0);
        assert_eq!(fake.close_calls, 1);
    }
}

#[test]
fn unsafe_or_drifted_facts_refuse_before_reads() {
    let changes: [fn(&mut ObjectFacts); 11] = [
        |row| row.volume_serial = "0000000000000001".into(),
        |row| row.file_id = "00000000000000000000000000000001".into(),
        |row| row.final_path.push('x'),
        |row| row.reparse_tag = 1,
        |row| row.attributes |= 0x400,
        |row| row.links = 2,
        |row| row.directory = true,
        |row| row.ntfs = false,
        |row| row.disk_file = false,
        |row| row.delete_pending = true,
        |row| row.selected_security.sacl_observed = true,
    ];
    for change in changes {
        let mut fake = Fake::new();
        change(&mut fake.before[4]);
        assert!(observe_with(&target(), &mut fake).observation.is_none());
        assert_eq!(fake.reads, 0);
        assert_eq!(fake.close_calls, 1);
    }
}

#[test]
fn aggregate_size_and_content_growth_or_truncation_refuse() {
    let mut fake = Fake::new();
    fake.before[4].size = MAX_CONTENT_BYTES;
    assert!(observe_with(&target(), &mut fake).observation.is_none());
    assert_eq!(fake.reads, 0);
    for extra in [true, false] {
        let mut fake = Fake::new();
        fake.extra_content = extra;
        fake.short_content = !extra;
        assert!(observe_with(&target(), &mut fake).observation.is_none());
        assert_eq!(fake.close_calls, 1);
    }
}

#[test]
fn any_ancestor_or_generated_object_security_drift_refuses() {
    for index in 0..6 {
        let mut fake = Fake::new();
        fake.after[index]
            .selected_security
            .binary_hex
            .push_str("00");
        assert!(observe_with(&target(), &mut fake).observation.is_none());
        assert_eq!(fake.close_calls, 1);
    }
}

#[test]
fn any_held_identity_or_metadata_drift_refuses() {
    let changes: [fn(&mut ObjectFacts); 6] = [
        |row| row.volume_serial = "0000000000000001".into(),
        |row| row.file_id = "000000000000000000000000000000ff".into(),
        |row| row.last_write_time += 1,
        |row| row.change_time += 1,
        |row| row.attributes ^= 0x20,
        |row| row.size += 1,
    ];
    for index in 0..6 {
        for change in changes {
            let mut fake = Fake::new();
            change(&mut fake.after[index]);
            assert!(observe_with(&target(), &mut fake).observation.is_none());
            assert_eq!(fake.close_calls, 1);
        }
    }
}

#[test]
fn every_facts_or_read_error_still_closes_owned_handles() {
    for call in 1..=12 {
        let mut fake = Fake::new();
        fake.fail_facts_call = Some(call);
        let result = observe_with(&target(), &mut fake);
        assert!(result.observation.is_none());
        assert!(result.owned_handles_closed);
        assert_eq!(fake.close_calls, 1);
    }
    for call in 1..=4 {
        let mut fake = Fake::new();
        fake.fail_read_call = Some(call);
        let result = observe_with(&target(), &mut fake);
        assert!(result.observation.is_none());
        assert!(result.owned_handles_closed);
        assert_eq!(fake.close_calls, 1);
    }
}

#[test]
fn cleanup_failure_does_not_upgrade_observation_to_ready() {
    let mut fake = Fake::new();
    fake.closed = false;
    let result = observe_with(&target(), &mut fake);
    assert!(result.observation.is_some());
    assert_eq!(
        result.issue.as_deref(),
        Some("owned_handle_cleanup_unknown")
    );
    assert!(!result.owned_handles_closed);
}

#[test]
fn expired_cooperative_deadline_refuses() {
    assert!(current(Instant::now().checked_sub(Duration::from_secs(6)).unwrap()).is_err());
}
