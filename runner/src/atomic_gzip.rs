//! Fixed Linux gzip adapter, adapted from Atomic Red Team T1560.001 test
//! cde3c2af-3485-49eb-9c1f-0ed60e9cc0af. See docs/ATOMIC_GZIP.md and the
//! preserved Red Canary MIT notice. No upstream shell or input defaults run.

use std::time::Duration;

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
    input: Vec<u8>,
    limit: usize,
    stderr_limit: usize,
    timeout: Duration,
) -> Result<GzipOutput, GzipError> {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::Instant;

    let started = Instant::now();

    // Never search PATH. Pin an already-open, root-owned ELF inode, including
    // its digest, before execution. No caller can supply tool paths or flags.
    let canonical = Path::new("/usr/bin/gzip")
        .canonicalize()
        .or_else(|_| Path::new("/bin/gzip").canonicalize())
        .map_err(|_| "The reviewed system gzip utility is unavailable.")?;
    if canonical != Path::new("/usr/bin/gzip") && canonical != Path::new("/bin/gzip") {
        return Err("The system gzip path resolves outside its reviewed location.".into());
    }
    for parent in canonical.ancestors().skip(1) {
        let metadata = parent
            .metadata()
            .map_err(|_| "Cannot inspect gzip directory ownership.")?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("The system gzip directory is not protected from non-owner writes.".into());
        }
    }
    let mut file =
        File::open(&canonical).map_err(|_| "Cannot open the reviewed system gzip utility.")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect the system gzip utility.")?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o6022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.len() > 16 * 1024 * 1024
    {
        return Err("The system gzip utility has unsupported ownership, mode, or size.".into());
    }
    unsafe extern "C" {
        fn fgetxattr(
            fd: i32,
            name: *const std::os::raw::c_char,
            value: *mut std::ffi::c_void,
            size: usize,
        ) -> isize;
        fn prctl(option: i32, ...) -> i32;
        fn getppid() -> i32;
    }
    // SAFETY: valid open descriptor, static NUL-terminated attribute, size query.
    let capabilities = unsafe {
        fgetxattr(
            file.as_raw_fd(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if capabilities != 0
        && !(capabilities < 0 && std::io::Error::last_os_error().raw_os_error() == Some(61))
    {
        return Err(
            "Cannot establish that the system gzip utility has no file capabilities.".into(),
        );
    }
    let mut executable_bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut executable_bytes)
        .map_err(|_| "Cannot hash the system gzip utility.")?;
    if executable_bytes.len() as u64 != metadata.len() || !executable_bytes.starts_with(b"\x7fELF")
    {
        return Err("The system gzip utility is not a stable ELF executable.".into());
    }
    let executable_sha256 = crate::contract::sha256_hex(&executable_bytes);
    if started.elapsed() >= timeout {
        return Err(GzipError::timed_out(
            "The gzip execution deadline has elapsed.",
        ));
    }
    let mut command = Command::new(format!("/proc/self/fd/{}", file.as_raw_fd()));
    command
        .arg0(&canonical)
        .args(["-n", "-c"])
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/")
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
    drop(file);
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
    Ok(GzipOutput {
        bytes,
        executable: canonical.to_string_lossy().into_owned(),
        executable_sha256,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn compress(
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
