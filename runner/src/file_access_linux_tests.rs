//! Local pathname checks only: no probe process, identity change, or enrolled resource.

use super::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "bluefire-file-path-{}-{}-{}",
            std::process::id(),
            crate::contract::utc_now().timestamp_nanos_opt().unwrap(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let fixture = Self(path);
        fs::create_dir(fixture.root()).unwrap();
        fs::create_dir(fixture.root().join("fixtures")).unwrap();
        fs::write(fixture.data(), b"{\"record\":1}\n").unwrap();
        fixture
    }

    fn root(&self) -> PathBuf {
        self.0.join("resource")
    }

    fn data(&self) -> PathBuf {
        self.root().join("fixtures/transformed.jsonl")
    }

    fn held(&self) -> (File, File, File) {
        let base = root(self.root().to_str().unwrap()).unwrap();
        let parent = child(&base, "fixtures", true).unwrap();
        let data = child(&parent, "transformed.jsonl", false).unwrap();
        (base, parent, data)
    }

    fn verify(&self, held: &(File, File, File)) -> Result<(), String> {
        verify_path_identity(
            self.root().to_str().unwrap(),
            &held.0.metadata().unwrap(),
            &held.1.metadata().unwrap(),
            &held.2.metadata().unwrap(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn unchanged_named_chain_matches_held_descriptors() {
    let fixture = Fixture::new();
    assert!(fixture.verify(&fixture.held()).is_ok());
}

#[test]
fn final_file_replacement_before_metadata_snapshots_is_refused() {
    let fixture = Fixture::new();
    let held = fixture.held();
    fs::rename(fixture.data(), fixture.0.join("original.jsonl")).unwrap();
    fs::write(fixture.data(), b"{\"record\":1}\n").unwrap();
    // All held metadata snapshots are captured after the replacement, as in the original race.
    let parent_before = identity(&held.1.metadata().unwrap());
    let data_before = identity(&held.2.metadata().unwrap());
    assert!(fixture.verify(&held).is_err());
    assert_eq!(identity(&held.1.metadata().unwrap()), parent_before);
    assert_eq!(identity(&held.2.metadata().unwrap()), data_before);
}

#[test]
fn parent_and_root_replacement_are_refused() {
    for replace_root in [false, true] {
        let fixture = Fixture::new();
        let held = fixture.held();
        let replaced = if replace_root {
            fixture.root()
        } else {
            fixture.root().join("fixtures")
        };
        fs::rename(&replaced, fixture.0.join("original")).unwrap();
        fs::create_dir(&replaced).unwrap();
        if replace_root {
            fs::create_dir(replaced.join("fixtures")).unwrap();
        }
        fs::write(fixture.data(), b"{\"record\":1}\n").unwrap();
        assert!(fixture.verify(&held).is_err());
    }
}

#[test]
fn missing_file_and_symlink_replacement_are_refused() {
    let fixture = Fixture::new();
    let held = fixture.held();
    let original = fixture.0.join("original.jsonl");
    fs::rename(fixture.data(), &original).unwrap();
    assert!(fixture.verify(&held).is_err());
    std::os::unix::fs::symlink(original, fixture.data()).unwrap();
    assert!(fixture.verify(&held).is_err());
}
