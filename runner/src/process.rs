#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::BTreeMap;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use std::io::{self, Read};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::{Command, Stdio};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::thread;
use std::time::{Duration, Instant};

use crate::contract::{BoundedOutput, ExecutionLimits};

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FixedProcessSpec {
    executable: PathBuf,
    args: Vec<&'static str>,
    environment: BTreeMap<&'static str, String>,
    output_format: &'static str,
}

#[derive(Debug)]
pub(crate) struct ProcessOutcome {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
    pub output_format: &'static str,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn first_reviewed_program(candidates: &[&str]) -> Result<PathBuf, String> {
    for candidate in candidates {
        let path = Path::new(candidate);
        if path
            .metadata()
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
        {
            return path
                .canonicalize()
                .map_err(|error| format!("cannot canonicalize reviewed process tool: {error}"));
        }
    }
    Err("the reviewed operating-system process inventory tool is unavailable".to_string())
}

#[cfg(target_os = "linux")]
fn process_discovery_spec() -> Result<FixedProcessSpec, String> {
    Ok(FixedProcessSpec {
        executable: first_reviewed_program(&["/usr/bin/ps", "/bin/ps"])?,
        args: vec!["-eo", "pid=,ppid=,comm="],
        environment: BTreeMap::from([("LC_ALL", "C".to_string()), ("LANG", "C".to_string())]),
        output_format: "pid ppid command",
    })
}

#[cfg(target_os = "macos")]
fn process_discovery_spec() -> Result<FixedProcessSpec, String> {
    Ok(FixedProcessSpec {
        executable: first_reviewed_program(&["/bin/ps", "/usr/bin/ps"])?,
        args: vec!["-axo", "pid=,ppid=,comm="],
        environment: BTreeMap::from([("LC_ALL", "C".to_string()), ("LANG", "C".to_string())]),
        output_format: "pid ppid command",
    })
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn read_bounded<R: Read>(mut reader: R, limit: usize) -> io::Result<BoundedOutput> {
    let mut retained = Vec::with_capacity(limit.min(16 * 1024));
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        let remaining = limit.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    Ok(BoundedOutput {
        text: String::from_utf8_lossy(&retained).into_owned(),
        total_bytes: total,
        truncated: total > retained.len() as u64,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn run_process_discovery(
    limits: &ExecutionLimits,
    _max_entries: usize,
) -> Result<ProcessOutcome, String> {
    let spec = process_discovery_spec()?;
    let mut command = Command::new(&spec.executable);
    command
        .args(&spec.args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in &spec.environment {
        command.env(name, value);
    }

    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start the reviewed process inventory tool: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "process inventory stdout was not captured".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "process inventory stderr was not captured".to_string())?;
    let stdout_limit = limits.max_stdout_bytes;
    let stderr_limit = limits.max_stderr_bytes;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, stdout_limit));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, stderr_limit));

    let deadline = Duration::from_millis(limits.timeout_ms);
    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if started.elapsed() < deadline => thread::sleep(Duration::from_millis(2)),
            Ok(None) => {
                let _ = child.kill();
                let status = child
                    .wait()
                    .map_err(|error| format!("cannot reap timed-out process inventory: {error}"))?;
                break (status, true);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot inspect process inventory status: {error}"));
            }
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| "process inventory stdout reader panicked".to_string())?
        .map_err(|error| format!("cannot read process inventory stdout: {error}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "process inventory stderr reader panicked".to_string())?
        .map_err(|error| format!("cannot read process inventory stderr: {error}"))?;
    Ok(ProcessOutcome {
        exit_code: status.code(),
        timed_out,
        stdout,
        stderr,
        output_format: spec.output_format,
    })
}

#[cfg(target_os = "windows")]
mod windows_process_api {
    use super::*;
    use std::ffi::c_void;
    use std::mem;

    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    const MAX_PATH: usize = 260;

    #[repr(C)]
    struct ProcessEntry32W {
        dw_size: u32,
        cnt_usage: u32,
        process_id: u32,
        default_heap_id: usize,
        module_id: u32,
        thread_count: u32,
        parent_process_id: u32,
        base_priority: i32,
        flags: u32,
        executable_file: [u16; MAX_PATH],
    }

    #[link(name = "kernel32")]
    extern "system" {
        #[link_name = "CreateToolhelp32Snapshot"]
        fn create_toolhelp32_snapshot(flags: u32, process_id: u32) -> *mut c_void;
        #[link_name = "Process32FirstW"]
        fn process32_first(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        #[link_name = "Process32NextW"]
        fn process32_next(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        #[link_name = "CloseHandle"]
        fn close_handle(handle: *mut c_void) -> i32;
        #[link_name = "GetLastError"]
        fn get_last_error() -> u32;
    }

    struct Snapshot(*mut c_void);

    impl Drop for Snapshot {
        fn drop(&mut self) {
            // SAFETY: `Snapshot` is constructed only from a successful owned
            // CreateToolhelp32Snapshot handle and is closed exactly once here.
            unsafe {
                close_handle(self.0);
            }
        }
    }

    fn empty_output() -> BoundedOutput {
        BoundedOutput {
            text: String::new(),
            total_bytes: 0,
            truncated: false,
        }
    }

    pub(super) fn discover(
        limits: &ExecutionLimits,
        max_entries: usize,
    ) -> Result<ProcessOutcome, String> {
        // SAFETY: The call has no borrowed pointers and returns a new owned
        // snapshot handle, validated against both documented failure values.
        let raw_snapshot = unsafe { create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0) };
        let invalid_handle = (-1_isize) as *mut c_void;
        if raw_snapshot.is_null() || raw_snapshot == invalid_handle {
            // SAFETY: GetLastError has no preconditions.
            let code = unsafe { get_last_error() };
            return Err(format!(
                "cannot open the reviewed Windows process snapshot (error {code})"
            ));
        }
        let snapshot = Snapshot(raw_snapshot);
        // SAFETY: PROCESSENTRY32W is a plain C data structure. Windows requires
        // all fields to be zeroed except `dwSize` before the first call.
        let mut entry: ProcessEntry32W = unsafe { mem::zeroed() };
        entry.dw_size = mem::size_of::<ProcessEntry32W>() as u32;

        // SAFETY: `entry` is correctly sized and writable for the duration of
        // the call; `snapshot` remains live until after enumeration completes.
        let mut available = unsafe { process32_first(snapshot.0, &mut entry) };
        if available == 0 {
            // SAFETY: GetLastError has no preconditions.
            let code = unsafe { get_last_error() };
            return Err(format!(
                "cannot read the reviewed Windows process snapshot (error {code})"
            ));
        }

        let started = Instant::now();
        let deadline = Duration::from_millis(limits.timeout_ms);
        let mut retained = Vec::with_capacity(limits.max_stdout_bytes.min(16 * 1024));
        let mut total = 0_u64;
        let mut record_count = 0_usize;
        let mut timed_out = false;
        while available != 0 {
            if started.elapsed() >= deadline {
                timed_out = true;
                break;
            }
            let name_length = entry
                .executable_file
                .iter()
                .position(|character| *character == 0)
                .unwrap_or(MAX_PATH);
            let name = String::from_utf16_lossy(&entry.executable_file[..name_length])
                .replace(['\r', '\n', '\t'], "_");
            let line = format!(
                "{} {} {}\n",
                entry.process_id, entry.parent_process_id, name
            );
            total = total.saturating_add(line.len() as u64);
            let remaining = limits.max_stdout_bytes.saturating_sub(retained.len());
            retained.extend_from_slice(&line.as_bytes()[..line.len().min(remaining)]);
            record_count += 1;
            if record_count > max_entries {
                break;
            }
            // SAFETY: Same initialized entry and live snapshot invariants as
            // Process32FirstW. The API overwrites the structure in place.
            available = unsafe { process32_next(snapshot.0, &mut entry) };
        }

        let retained_length = retained.len() as u64;
        Ok(ProcessOutcome {
            exit_code: Some(0),
            timed_out,
            stdout: BoundedOutput {
                text: String::from_utf8_lossy(&retained).into_owned(),
                total_bytes: total,
                truncated: total > retained_length || record_count > max_entries,
            },
            stderr: empty_output(),
            output_format: "pid ppid command",
        })
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn run_process_discovery(
    limits: &ExecutionLimits,
    max_entries: usize,
) -> Result<ProcessOutcome, String> {
    windows_process_api::discover(limits, max_entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn process_discovery_spec_is_fixed_and_absolute() {
        let spec = process_discovery_spec().unwrap();
        assert!(spec.executable.is_absolute());
        assert!(!spec.args.is_empty());
        assert!(!spec
            .args
            .iter()
            .any(|arg| matches!(*arg, "sh" | "cmd" | "-c" | "/C")));
        assert!(!spec.environment.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn process_discovery_uses_the_bounded_native_snapshot_api() {
        let limits = ExecutionLimits {
            timeout_ms: 5_000,
            max_stdout_bytes: 8 * 1024,
            max_stderr_bytes: 8 * 1024,
            max_artifact_bytes: 8 * 1024,
            max_files: 16,
        };
        let output = run_process_discovery(&limits, 4).unwrap();
        assert_eq!(output.exit_code, Some(0));
        assert!(!output.stdout.text.is_empty());
        assert!(output.stdout.total_bytes <= 8 * 1024);
        assert_eq!(output.output_format, "pid ppid command");
    }

    #[test]
    fn bounded_reader_drains_but_retains_only_the_limit() {
        let output = read_bounded(&b"abcdefgh"[..], 3).unwrap();
        assert_eq!(output.text, "abc");
        assert_eq!(output.total_bytes, 8);
        assert!(output.truncated);
    }
}
