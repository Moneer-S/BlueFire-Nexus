//! Public native entrypoint refusals; no service manager or payload executes.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

static SERIAL: AtomicU64 = AtomicU64::new(0);

struct RequestFiles {
    root: PathBuf,
}
impl RequestFiles {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "bluefire-service-boundary-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests_platform/fixtures/owned_service_admission_v1.json"
        ))
        .unwrap();
        for name in ["manifest", "profile"] {
            fs::write(
                root.join(format!("{name}.json")),
                serde_json::to_vec(&fixture[name]).unwrap(),
            )
            .unwrap();
        }
        Self { root }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bluefire-runner"));
        command
            .args(["execute", "--manifest"])
            .arg(self.root.join("manifest.json"))
            .arg("--profile")
            .arg(self.root.join("profile.json"))
            .arg("--json")
            .env_remove("BLUEFIRE_SERVICE_CONTEXT_FD")
            .env_remove("BLUEFIRE_SERVICE_ENVELOPE_FD");
        command
    }
}
impl Drop for RequestFiles {
    fn drop(&mut self) {
        // Only the two exact fixture files and their newly allocated directory.
        for name in ["manifest.json", "profile.json"] {
            fs::remove_file(self.root.join(name)).unwrap();
        }
        fs::remove_dir(&self.root).unwrap();
    }
}

#[test]
fn service_cli_without_host_channel_refuses_before_reservation() {
    let files = RequestFiles::new();
    let output = files.command().output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["error"]["code"], "service_admission_required");
    assert_eq!(result["status"], "refused");
    assert_eq!(result["receipt_ids"], serde_json::json!([]));
    assert_eq!(fs::read_dir(&files.root).unwrap().count(), 2);
}

#[test]
fn service_cli_cannot_select_an_arbitrary_context_file_or_key() {
    let files = RequestFiles::new();
    for (context, envelope) in [
        ("123456789", "123456788"),
        ("4", "4"),
        ("self-authored.json", "5"),
    ] {
        let output = files
            .command()
            .env("BLUEFIRE_SERVICE_CONTEXT_FD", context)
            .env("BLUEFIRE_SERVICE_ENVELOPE_FD", envelope)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_dir(&files.root).unwrap().count(), 2);
    }
}
