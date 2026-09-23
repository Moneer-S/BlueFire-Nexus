//! Pinned read-only inputs selected from committed creation receipts.

use std::fs::File;
use std::time::Instant;

#[cfg(unix)]
use super::{
    normalize_relative, receipt_identity, valid_receipt_id, ReceiptRecord, MAX_RECEIPT_BYTES,
    RECEIPT_COMMIT_DIR, RECEIPT_DIR, RECEIPT_SCHEMA, STATE_DIR,
};
use super::{CleanupIdentity, OwnedPathKind, SafeRoot};
#[cfg(unix)]
use crate::receipt_store::DurableReceiptCommit;
#[cfg(unix)]
use std::io::Read;

#[cfg(unix)]
const MAX_PINNED_INPUT_BYTES: u64 = 128 * 1024 * 1024;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// An opened receipt-owned regular file whose identity can be checked again
/// after a supervised external operation.
#[derive(Debug)]
pub struct OwnedReceiptInput {
    file: File,
    identity: CleanupIdentity,
    relative_path: String,
    expected_sha256: String,
    expected_size: u64,
}

impl OwnedReceiptInput {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn recheck_bytes(&self) -> Result<(), String> {
        self.recheck_bytes_with_deadline(None)
    }

    pub fn recheck_bytes_until(&self, deadline: Instant) -> Result<(), String> {
        self.recheck_bytes_with_deadline(Some(deadline))
    }

    fn recheck_bytes_with_deadline(&self, deadline: Option<Instant>) -> Result<(), String> {
        check_deadline(deadline)?;
        let metadata = self
            .file
            .metadata()
            .map_err(|error| format!("cannot inspect pinned receipt input: {error}"))?;
        validate_current_metadata(&metadata, self.expected_size, self.identity)?;
        if super::hash_opened_file_until(&self.file, self.expected_size, deadline)?
            != self.expected_sha256
        {
            return Err("pinned receipt input content changed".to_string());
        }
        check_deadline(deadline)?;
        let after = self
            .file
            .metadata()
            .map_err(|error| format!("cannot reinspect pinned receipt input: {error}"))?;
        validate_current_metadata(&after, self.expected_size, self.identity)?;
        stable_metadata(&metadata, &after)
    }

    pub fn recheck_attachment(&self, root: &SafeRoot) -> Result<(), String> {
        self.recheck_attachment_with_deadline(root, None)
    }

    pub fn recheck_attachment_until(
        &self,
        root: &SafeRoot,
        deadline: Instant,
    ) -> Result<(), String> {
        self.recheck_attachment_with_deadline(root, Some(deadline))
    }

    fn recheck_attachment_with_deadline(
        &self,
        root: &SafeRoot,
        deadline: Option<Instant>,
    ) -> Result<(), String> {
        check_deadline(deadline)?;
        let (parent, name) = root.open_cleanup_parent(&self.relative_path)?;
        let parent = parent.ok_or_else(|| "receipt input parent disappeared".to_string())?;
        let opened = root
            .open_cleanup_entry(&parent, &name, &OwnedPathKind::File)
            .map_err(String::from)?
            .ok_or_else(|| "receipt input path disappeared".to_string())?;
        let current = identity(&opened.file)?;
        if current != self.identity {
            return Err("receipt input path was replaced after pinning".to_string());
        }
        self.recheck_bytes_with_deadline(deadline)
    }
}

#[cfg(unix)]
impl SafeRoot {
    pub fn open_committed_receipt_input(
        &self,
        receipt_id: &str,
        profile_id: &str,
        expected_relative_path: &str,
        expected_sha256: &str,
        expected_size: u64,
    ) -> Result<OwnedReceiptInput, String> {
        self.open_committed_receipt_input_until_inner(
            receipt_id,
            profile_id,
            expected_relative_path,
            expected_sha256,
            expected_size,
            None,
        )
    }

    pub fn open_committed_receipt_input_until(
        &self,
        receipt_id: &str,
        profile_id: &str,
        expected_relative_path: &str,
        expected_sha256: &str,
        expected_size: u64,
        deadline: Instant,
    ) -> Result<OwnedReceiptInput, String> {
        self.open_committed_receipt_input_until_inner(
            receipt_id,
            profile_id,
            expected_relative_path,
            expected_sha256,
            expected_size,
            Some(deadline),
        )
    }

    fn open_committed_receipt_input_until_inner(
        &self,
        receipt_id: &str,
        profile_id: &str,
        expected_relative_path: &str,
        expected_sha256: &str,
        expected_size: u64,
        deadline: Option<Instant>,
    ) -> Result<OwnedReceiptInput, String> {
        check_deadline(deadline)?;
        if !valid_receipt_id(receipt_id) {
            return Err("receipt input ID is invalid".to_string());
        }
        if expected_sha256.len() != 64
            || !expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err("receipt input content hash is invalid".to_string());
        }
        if !(1..=MAX_PINNED_INPUT_BYTES).contains(&expected_size) {
            return Err("receipt input size is outside its bound".to_string());
        }
        let relative = normalize_relative(expected_relative_path, false)?;
        if relative != expected_relative_path {
            return Err("receipt input path is not normalized".to_string());
        }
        let commit_bytes = self
            .read_input_authority_until(RECEIPT_COMMIT_DIR, receipt_id, deadline)?
            .ok_or_else(|| "receipt input requires a committed receipt".to_string())?;
        let commit = DurableReceiptCommit::decode(&commit_bytes)
            .map_err(|error| format!("receipt commit schema is invalid: {error}"))?;
        if !commit.has_identity(receipt_id, profile_id, &self.workspace_id()) {
            return Err("receipt input requires a matching committed receipt".to_string());
        }
        let record_bytes = self
            .read_input_authority_until(RECEIPT_DIR, receipt_id, deadline)?
            .ok_or_else(|| "receipt input receipt is unavailable".to_string())?;
        let record: ReceiptRecord = serde_json::from_slice(&record_bytes)
            .map_err(|error| format!("receipt schema is invalid: {error}"))?;
        if record.schema_version != RECEIPT_SCHEMA
            || record.receipt_id != receipt_id
            || record.runner_profile_id != profile_id
            || record.workspace_id != self.workspace_id()
            || receipt_identity(
                &record.request_hash,
                &record.action_id,
                &record.runner_profile_id,
                &record.workspace_id,
                &record.created_at,
                &record.paths,
            ) != receipt_id
        {
            return Err("receipt input authority identity is invalid".to_string());
        }
        let matches = record.paths.iter().filter(|owned| {
            owned.relative_path == relative
                && owned.kind == OwnedPathKind::File
                && owned.sha256.as_deref() == Some(expected_sha256)
                && owned.size == Some(expected_size)
        });
        let owned = matches.collect::<Vec<_>>();
        if owned.len() != 1 {
            return Err("receipt does not own exactly the expected input".to_string());
        }
        check_deadline(deadline)?;
        let (parent, name) = self.open_cleanup_parent(&relative)?;
        let parent = parent.ok_or_else(|| "receipt input parent is unavailable".to_string())?;
        let entry = self
            .open_cleanup_entry(&parent, &name, &OwnedPathKind::File)
            .map_err(String::from)?
            .ok_or_else(|| "receipt input is absent".to_string())?;
        self.validate_cleanup_entry(&entry, owned[0])?;
        let metadata = entry
            .file
            .metadata()
            .map_err(|error| format!("cannot inspect receipt input: {error}"))?;
        let input = OwnedReceiptInput {
            file: entry.file,
            identity: identity_from_entry(&metadata)?,
            relative_path: relative,
            expected_sha256: expected_sha256.to_string(),
            expected_size,
        };
        input.recheck_bytes_with_deadline(deadline)?;
        Ok(input)
    }

    /// Read authority from a bounded, no-follow handle, never a caller path.
    #[cfg(unix)]
    fn read_input_authority_until(
        &self,
        directory: &str,
        receipt_id: &str,
        deadline: Option<Instant>,
    ) -> Result<Option<Vec<u8>>, String> {
        check_deadline(deadline)?;
        let relative = format!("{STATE_DIR}/{directory}/{receipt_id}.json");
        let (parent, name) = self.open_cleanup_parent(&relative)?;
        let Some(parent) = parent else {
            return Ok(None);
        };
        let Some(entry) = self
            .open_cleanup_entry(&parent, &name, &OwnedPathKind::File)
            .map_err(String::from)?
        else {
            return Ok(None);
        };
        let before = entry
            .file
            .metadata()
            .map_err(|error| format!("cannot inspect input authority: {error}"))?;
        if before.len() > MAX_RECEIPT_BYTES {
            return Err("input authority exceeds its size limit".to_string());
        }
        validate_current_metadata(&before, before.len(), entry.identity)?;
        let mut bytes = Vec::new();
        check_deadline(deadline)?;
        (&entry.file)
            .take(MAX_RECEIPT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read input authority: {error}"))?;
        if bytes.len() as u64 != before.len() {
            return Err("input authority changed size while reading".to_string());
        }
        check_deadline(deadline)?;
        let after = entry
            .file
            .metadata()
            .map_err(|error| format!("cannot reinspect input authority: {error}"))?;
        validate_current_metadata(&after, before.len(), entry.identity)?;
        stable_metadata(&before, &after)?;
        Ok(Some(bytes))
    }
}

#[cfg(not(unix))]
impl SafeRoot {
    pub fn open_committed_receipt_input(
        &self,
        _receipt_id: &str,
        _profile_id: &str,
        _expected_relative_path: &str,
        _expected_sha256: &str,
        _expected_size: u64,
    ) -> Result<OwnedReceiptInput, String> {
        Err("receipt-owned input pinning is unavailable on this platform".to_string())
    }

    pub fn open_committed_receipt_input_until(
        &self,
        _receipt_id: &str,
        _profile_id: &str,
        _expected_relative_path: &str,
        _expected_sha256: &str,
        _expected_size: u64,
        _deadline: Instant,
    ) -> Result<OwnedReceiptInput, String> {
        Err("receipt-owned input pinning is unavailable on this platform".to_string())
    }
}

fn identity(file: &File) -> Result<CleanupIdentity, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect pinned receipt input: {error}"))?;
    identity_from_entry(&metadata)
}

fn check_deadline(deadline: Option<Instant>) -> Result<(), String> {
    if deadline.is_some_and(|limit| Instant::now() >= limit) {
        Err("receipt input operation exceeded its monotonic deadline".to_string())
    } else {
        Ok(())
    }
}

fn identity_from_entry(metadata: &std::fs::Metadata) -> Result<CleanupIdentity, String> {
    #[cfg(unix)]
    {
        Ok(CleanupIdentity {
            volume: metadata.dev(),
            object: metadata.ino() as u128,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err("receipt-owned input pinning is unavailable on this platform".to_string())
    }
}

fn validate_current_metadata(
    metadata: &std::fs::Metadata,
    expected_size: u64,
    expected_identity: CleanupIdentity,
) -> Result<(), String> {
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err("pinned receipt input changed type or size".to_string());
    }
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions.
    if metadata.nlink() != 1 || metadata.uid() != unsafe { geteuid() } {
        return Err(
            "pinned receipt input is no longer a current-user single-link file".to_string(),
        );
    }
    if identity_from_entry(metadata)? != expected_identity {
        return Err("pinned receipt input identity changed".to_string());
    }
    Ok(())
}

fn stable_metadata(before: &std::fs::Metadata, after: &std::fs::Metadata) -> Result<(), String> {
    #[cfg(unix)]
    if (
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err("receipt input changed during verification".to_string());
    }
    #[cfg(not(unix))]
    let _ = (before, after);
    Ok(())
}

#[cfg(unix)]
extern "C" {
    fn geteuid() -> u32;
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::{owned_file, utc_now};
    use super::*;
    use std::fs;
    use std::io::{Read, Seek, Write};
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn fixture_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "bluefire-owned-input-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn recheck_bytes_accepts_pinned_current_user_file() {
        let path = fixture_path("valid");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(b"receipt input").unwrap();
        let metadata = file.metadata().unwrap();
        let input = OwnedReceiptInput {
            identity: CleanupIdentity {
                volume: metadata.dev(),
                object: metadata.ino() as u128,
            },
            file,
            relative_path: "fixtures/transformed.jsonl".to_string(),
            expected_sha256: crate::contract::sha256_hex(b"receipt input"),
            expected_size: 13,
        };
        assert!(input.recheck_bytes().is_ok());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn recheck_bytes_rejects_hardlink_after_pin() {
        let path = fixture_path("hardlink");
        let alias = path.with_extension("alias");
        std::fs::write(&path, b"receipt input").unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        let file = File::open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        let input = OwnedReceiptInput {
            identity: CleanupIdentity {
                volume: metadata.dev(),
                object: metadata.ino() as u128,
            },
            file,
            relative_path: "fixtures/transformed.jsonl".to_string(),
            expected_sha256: crate::contract::sha256_hex(b"receipt input"),
            expected_size: 13,
        };
        assert!(input.recheck_bytes().is_err());
        let _ = std::fs::remove_file(alias);
        let _ = std::fs::remove_file(path);
    }

    struct Fixture {
        root: SafeRoot,
        record: ReceiptRecord,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let path = fixture_path(label);
            fs::create_dir(&path).unwrap();
            let root = SafeRoot::open(&path).unwrap();
            fs::create_dir(path.join("fixtures")).unwrap();
            fs::write(path.join("fixtures/input.jsonl"), b"receipt input").unwrap();
            let mut record = ReceiptRecord {
                schema_version: RECEIPT_SCHEMA.into(),
                receipt_id: String::new(),
                request_hash: "a".repeat(64),
                action_id: "sandbox.fixture.transform.v1".into(),
                runner_profile_id: "profile.test.v1".into(),
                workspace_id: root.workspace_id(),
                created_at: utc_now(),
                paths: vec![owned_file("fixtures/input.jsonl".into(), b"receipt input")],
            };
            record.receipt_id = receipt_identity(
                &record.request_hash,
                &record.action_id,
                &record.runner_profile_id,
                &record.workspace_id,
                &record.created_at,
                &record.paths,
            );
            let dirs = root.ensure_state_dirs().unwrap();
            fs::write(
                dirs.receipts.join(format!("{}.json", record.receipt_id)),
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
            let commit = DurableReceiptCommit::new(
                &record.receipt_id,
                &record.runner_profile_id,
                &record.workspace_id,
                utc_now(),
            );
            fs::write(
                dirs.commits.join(format!("{}.json", record.receipt_id)),
                commit.encode_pretty().unwrap(),
            )
            .unwrap();
            Self { root, record }
        }

        fn pin(&self) -> Result<OwnedReceiptInput, String> {
            self.root.open_committed_receipt_input(
                &self.record.receipt_id,
                &self.record.runner_profile_id,
                "fixtures/input.jsonl",
                &crate::contract::sha256_hex(b"receipt input"),
                13,
            )
        }

        fn authority_path(&self, directory: &str) -> std::path::PathBuf {
            self.root
                .path()
                .join(STATE_DIR)
                .join(directory)
                .join(format!("{}.json", self.record.receipt_id))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(self.root.path()).unwrap();
        }
    }

    #[test]
    fn committed_input_survives_metadata_only_change_and_remains_cleanup_owned() {
        let fixture = Fixture::new("committed");
        let input = fixture.pin().unwrap();
        assert!(input.recheck_attachment(&fixture.root).is_ok());
        let path = fixture.root.path().join("fixtures/input.jsonl");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(input.recheck_bytes().is_ok());
        assert!(input.recheck_attachment(&fixture.root).is_ok());
        fixture
            .root
            .remove_owned(&fixture.record.receipt_id, &fixture.record.paths[0])
            .unwrap();
        assert!(!path.exists());
        assert!(input.recheck_attachment(&fixture.root).is_err());
    }

    #[test]
    fn receipt_verification_preserves_the_consumers_file_offset() {
        let fixture = Fixture::new("offset");
        let input = fixture.pin().unwrap();
        let mut consumer = input.file().try_clone().unwrap();
        assert_eq!(consumer.stream_position().unwrap(), 0);
        let mut prefix = [0_u8; 7];
        consumer.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"receipt");
        input.recheck_bytes().unwrap();
        input.recheck_attachment(&fixture.root).unwrap();
        assert_eq!(consumer.stream_position().unwrap(), 7);
        let mut remainder = String::new();
        consumer.read_to_string(&mut remainder).unwrap();
        assert_eq!(remainder, " input");
        // A failed verification must preserve the cursor as well.
        fs::write(
            fixture.root.path().join("fixtures/input.jsonl"),
            b"changed input",
        )
        .unwrap();
        assert!(input.recheck_bytes().is_err());
        assert_eq!(consumer.stream_position().unwrap(), 13);
    }

    #[test]
    fn expired_deadlines_refuse_pin_and_rechecks_before_effects() {
        let fixture = Fixture::new("expired-deadline");
        let expired = Instant::now() - Duration::from_millis(1);
        let hash = crate::contract::sha256_hex(b"receipt input");
        assert!(fixture
            .root
            .open_committed_receipt_input_until(
                &fixture.record.receipt_id,
                &fixture.record.runner_profile_id,
                "fixtures/input.jsonl",
                &hash,
                13,
                expired,
            )
            .is_err());

        let input = fixture.pin().unwrap();
        assert!(input.recheck_bytes_until(expired).is_err());
        assert!(input
            .recheck_attachment_until(&fixture.root, expired)
            .is_err());
        assert_eq!(
            fs::read(fixture.root.path().join("fixtures/input.jsonl")).unwrap(),
            b"receipt input"
        );
    }

    #[test]
    fn deadline_rechecks_preserve_consumer_offset() {
        let fixture = Fixture::new("deadline-offset");
        let input = fixture.pin().unwrap();
        let mut consumer = input.file().try_clone().unwrap();
        let mut prefix = [0_u8; 7];
        consumer.read_exact(&mut prefix).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        input.recheck_bytes_until(deadline).unwrap();
        input
            .recheck_attachment_until(&fixture.root, deadline)
            .unwrap();
        assert_eq!(consumer.stream_position().unwrap(), 7);
        let mut remainder = String::new();
        consumer.read_to_string(&mut remainder).unwrap();
        assert_eq!(remainder, " input");
    }

    #[test]
    fn deadline_pin_rejects_authority_profile_mismatch_without_touching_input() {
        let fixture = Fixture::new("deadline-authority-mismatch");
        let hash = crate::contract::sha256_hex(b"receipt input");
        let result = fixture.root.open_committed_receipt_input_until(
            &fixture.record.receipt_id,
            "profile.other.v1",
            "fixtures/input.jsonl",
            &hash,
            13,
            Instant::now() + Duration::from_secs(1),
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(fixture.root.path().join("fixtures/input.jsonl")).unwrap(),
            b"receipt input"
        );
    }

    #[test]
    fn missing_forged_oversized_or_linked_authority_is_refused() {
        for kind in [
            "missing",
            "schema",
            "profile",
            "workspace",
            "receipt",
            "oversize",
            "symlink",
            "hardlink",
            "receipt-content",
            "receipt-link",
        ] {
            let fixture = Fixture::new(kind);
            let commit_path = fixture.authority_path(RECEIPT_COMMIT_DIR);
            match kind {
                "missing" => fs::remove_file(&commit_path).unwrap(),
                "oversize" => {
                    fs::write(&commit_path, vec![b' '; MAX_RECEIPT_BYTES as usize + 1]).unwrap()
                }
                "symlink" | "hardlink" | "receipt-link" => {
                    let path = if kind == "receipt-link" {
                        fixture.authority_path(RECEIPT_DIR)
                    } else {
                        commit_path.clone()
                    };
                    let alias = fixture.root.path().join("alias");
                    fs::rename(&path, &alias).unwrap();
                    if kind == "hardlink" {
                        fs::hard_link(&alias, &path).unwrap();
                    } else {
                        symlink(&alias, &path).unwrap();
                    }
                }
                "receipt-content" => {
                    let mut changed = fixture.record.clone();
                    changed.action_id = "other.action.v1".into();
                    fs::write(
                        fixture.authority_path(RECEIPT_DIR),
                        serde_json::to_vec(&changed).unwrap(),
                    )
                    .unwrap();
                }
                _ => {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&fs::read(&commit_path).unwrap()).unwrap();
                    let field = match kind {
                        "schema" => "schema_version",
                        "profile" => "runner_profile_id",
                        "workspace" => "workspace_id",
                        _ => "receipt_id",
                    };
                    value[field] = "forged".into();
                    fs::write(&commit_path, serde_json::to_vec(&value).unwrap()).unwrap();
                }
            }
            assert!(fixture.pin().is_err(), "accepted {kind}");
            assert_eq!(
                fs::read(fixture.root.path().join("fixtures/input.jsonl")).unwrap(),
                b"receipt input"
            );
        }
    }

    #[test]
    fn expected_input_must_match_the_receipt_exactly() {
        let fixture = Fixture::new("parameters");
        let hash = crate::contract::sha256_hex(b"receipt input");
        for (id, profile, path, digest, size) in [
            (
                "../escape",
                "profile.test.v1",
                "fixtures/input.jsonl",
                hash.as_str(),
                13,
            ),
            (
                fixture.record.receipt_id.as_str(),
                "profile.other.v1",
                "fixtures/input.jsonl",
                hash.as_str(),
                13,
            ),
            (
                fixture.record.receipt_id.as_str(),
                "profile.test.v1",
                "../input.jsonl",
                hash.as_str(),
                13,
            ),
            (
                fixture.record.receipt_id.as_str(),
                "profile.test.v1",
                "fixtures/other.jsonl",
                hash.as_str(),
                13,
            ),
            (
                fixture.record.receipt_id.as_str(),
                "profile.test.v1",
                "fixtures/input.jsonl",
                "invalid",
                13,
            ),
            (
                fixture.record.receipt_id.as_str(),
                "profile.test.v1",
                "fixtures/input.jsonl",
                hash.as_str(),
                12,
            ),
            (
                fixture.record.receipt_id.as_str(),
                "profile.test.v1",
                "fixtures/input.jsonl",
                hash.as_str(),
                0,
            ),
        ] {
            assert!(fixture
                .root
                .open_committed_receipt_input(id, profile, path, digest, size)
                .is_err());
        }
    }

    #[test]
    fn input_changes_and_attachment_replacement_are_refused() {
        for kind in [
            "bytes",
            "size",
            "symlink",
            "hardlink",
            "replacement",
            "parent-link",
            "missing",
        ] {
            let fixture = Fixture::new(kind);
            let input = fixture.pin().unwrap();
            let path = fixture.root.path().join("fixtures/input.jsonl");
            match kind {
                "bytes" => fs::write(&path, b"changed input").unwrap(),
                "size" => fs::write(&path, b"short").unwrap(),
                "hardlink" => fs::hard_link(&path, fixture.root.path().join("alias")).unwrap(),
                "missing" => fs::remove_file(&path).unwrap(),
                "parent-link" => {
                    fs::rename(
                        fixture.root.path().join("fixtures"),
                        fixture.root.path().join("original"),
                    )
                    .unwrap();
                    symlink("original", fixture.root.path().join("fixtures")).unwrap();
                }
                _ => {
                    let original = fixture.root.path().join("original");
                    fs::rename(&path, &original).unwrap();
                    if kind == "symlink" {
                        symlink(&original, &path).unwrap();
                    } else {
                        fs::write(&path, b"receipt input").unwrap();
                    }
                }
            }
            assert!(
                input.recheck_attachment(&fixture.root).is_err(),
                "accepted {kind}"
            );
            if kind != "replacement" {
                assert!(fixture.pin().is_err(), "repinned {kind}");
            }
        }
    }
}
