//! Fixed Linux gzip adapter, adapted from Atomic Red Team T1560.001 test
//! cde3c2af-3485-49eb-9c1f-0ed60e9cc0af. See docs/ATOMIC_GZIP.md and the
//! preserved Red Canary MIT notice. No upstream shell or input defaults run.

use std::time::Duration;

use crate::native_tool_installations::{NativeToolBinding, NativeToolInstallation};
use std::path::Path;

pub(crate) const BINDING: NativeToolBinding = NativeToolBinding {
    adapter_id: "sandbox.collection.atomic-gzip.v1",
    adapter_version: "1.1.0",
    adapter_contract_digest:
        "sha256:dd6aec4a80857571f54097f0e8814f3e4307f50c90f8517bff2714381e1ee4ad",
    tool_id: "gnu.gzip.v1",
};

#[cfg(any(test, target_os = "linux"))]
fn capture(mut stream: impl std::io::Read, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut total = 0_usize;
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count);
        retained.extend_from_slice(&buffer[..count.min(limit.saturating_sub(retained.len()))]);
    }
    Ok((retained, total > limit))
}

pub(crate) struct GzipOutput {
    pub bytes: Vec<u8>,
    pub executable: String,
    pub executable_sha256: String,
    pub installation_digest: String,
    pub tool_version: String,
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum GzipFailureKind {
    Unavailable,
    Failed,
    TimedOut,
}

#[derive(Debug)]
pub(crate) struct GzipError {
    pub kind: GzipFailureKind,
    pub message: String,
}
impl GzipError {
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn failed(message: &str) -> Self {
        Self {
            kind: GzipFailureKind::Failed,
            message: message.into(),
        }
    }
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn timed_out(message: &str) -> Self {
        Self {
            kind: GzipFailureKind::TimedOut,
            message: message.into(),
        }
    }
}
impl From<&str> for GzipError {
    fn from(message: &str) -> Self {
        Self {
            kind: GzipFailureKind::Unavailable,
            message: message.into(),
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn compress(
    installation: &NativeToolInstallation,
    workspace: &Path,
    input: Vec<u8>,
    limit: usize,
    stderr_limit: usize,
    timeout: Duration,
) -> Result<GzipOutput, GzipError> {
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::Instant;

    let started = Instant::now();

    let timeout = timeout.min(Duration::from_secs(5));
    if input.len() > 1_048_576 {
        return Err("The gzip input exceeds its reviewed byte limit.".into());
    }
    let limit = limit.min(1_048_576);
    let stderr_limit = stderr_limit.min(8192);
    // Setup chooses a protected location; dispatch accepts only the compiled
    // adapter binding and an independently reviewed build. Never search PATH or
    // run candidate code to discover its version.
    BINDING
        .check_binding(installation, "linux", std::env::consts::ARCH)
        .map_err(|_| {
            GzipError::from("The gzip installation differs from its reviewed adapter binding.")
        })?;
    let inspected =
        crate::native_tool_inspection::inspect(installation, timeout).map_err(|error| {
            if error.code == "inspection_timeout" {
                GzipError::timed_out(error.message)
            } else {
                GzipError::from(error.message)
            }
        })?;
    inspected.recheck().map_err(|error| {
        if error.code == "inspection_timeout" {
            GzipError::timed_out(error.message)
        } else {
            GzipError::from(error.message)
        }
    })?;
    unsafe extern "C" {
        fn prctl(option: i32, ...) -> i32;
        fn getppid() -> i32;
    }
    if started.elapsed() >= timeout {
        return Err(GzipError::timed_out(
            "The gzip execution deadline has elapsed.",
        ));
    }
    let mut command = Command::new(format!("/proc/self/fd/{}", inspected.fd()));
    command
        .arg0(&installation.installation_location)
        .args(["-n", "-c"])
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir(workspace)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let expected_parent = std::process::id() as i32;
    // SAFETY: the child performs only async-signal-safe fixed syscalls. The
    // parent-death signal handles interrupted/killed runner cancellation.
    unsafe {
        command.pre_exec(move || {
            if getppid() != expected_parent
                || prctl(1, 9, 0_usize, 0_usize, 0_usize) != 0
                || prctl(38, 1, 0_usize, 0_usize, 0_usize) != 0
                || getppid() != expected_parent
            {
                return Err(std::io::Error::from_raw_os_error(3));
            }
            Ok(())
        });
    }
    struct Reap(Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Reap(
        command
            .spawn()
            .map_err(|_| "Cannot start the reviewed system gzip utility.")?,
    );
    // Linux resolves the ELF through this open descriptor before close-on-exec.
    // Keep the inspected identity alive through output verification.
    let mut stdin = child
        .0
        .stdin
        .take()
        .ok_or_else(|| GzipError::failed("Gzip stdin is unavailable."))?;
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| GzipError::failed("Gzip stdout is unavailable."))?;
    let stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| GzipError::failed("Gzip stderr is unavailable."))?;
    let writer = thread::spawn(move || stdin.write_all(&input));
    let out = thread::spawn(move || capture(stdout, limit));
    let err = thread::spawn(move || capture(stderr, stderr_limit));
    let status = loop {
        match child.0.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(2)),
            Ok(None) => {
                let _ = child.0.kill();
                let _ = child.0.wait();
                break Err(GzipError::timed_out("The gzip execution deadline elapsed."));
            }
            Err(_) => {
                let _ = child.0.kill();
                let _ = child.0.wait();
                break Err(GzipError::failed(
                    "The running gzip process could not be inspected.",
                ));
            }
        }
    };
    let written = writer
        .join()
        .map_err(|_| GzipError::failed("Gzip input worker failed."))?;
    let (bytes, truncated) = out
        .join()
        .map_err(|_| GzipError::failed("Gzip output worker failed."))?
        .map_err(|_| GzipError::failed("Gzip output capture failed."))?;
    let (errors, errors_truncated) = err
        .join()
        .map_err(|_| GzipError::failed("Gzip diagnostic worker failed."))?
        .map_err(|_| GzipError::failed("Gzip diagnostic capture failed."))?;
    let status = status?;
    if started.elapsed() >= timeout {
        return Err(GzipError::timed_out(
            "The gzip execution deadline elapsed before output was complete.",
        ));
    }
    if written.is_err()
        || !status.success()
        || truncated
        || errors_truncated
        || !errors.is_empty()
        || bytes.len() < 18
        || bytes[..4] != [0x1f, 0x8b, 8, 0]
        || bytes[4..8] != [0; 4]
    {
        return Err(GzipError::failed(
            "The gzip utility did not produce a complete bounded no-name gzip stream.",
        ));
    }
    inspected.recheck().map_err(|error| {
        if error.code == "inspection_timeout" {
            GzipError::timed_out(error.message)
        } else {
            GzipError::failed(error.message)
        }
    })?;
    Ok(GzipOutput {
        bytes,
        executable: installation.installation_location.clone(),
        executable_sha256: inspected
            .content_sha256
            .trim_start_matches("sha256:")
            .into(),
        installation_digest: inspected.installation_digest,
        tool_version: installation.tool_version.clone(),
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn compress(
    _installation: &NativeToolInstallation,
    _workspace: &Path,
    _input: Vec<u8>,
    _limit: usize,
    _stderr_limit: usize,
    _timeout: Duration,
) -> Result<GzipOutput, GzipError> {
    Err("The reviewed Atomic gzip adapter is available only on Linux.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_capture_bounds_retained_bytes_and_reports_overflow() {
        let input = vec![0xff; 32769];
        let (output, overflow) = capture(input.as_slice(), 4096).unwrap();
        assert_eq!(output, vec![0xff; 4096]);
        assert!(overflow);
        assert_eq!(capture(input.as_slice(), 0).unwrap(), (vec![], true));
        assert_eq!(capture(&input[..4], 4).unwrap(), (vec![0xff; 4], false));
    }
}
