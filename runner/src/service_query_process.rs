//! Private bounded lifecycle for the fixed descriptor-backed property query.

use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::{QueryChildCleanup, QueryReadIssue};
use crate::native_tool_inspection::InspectedNativeTool;
use crate::service_observer::{ObservationTarget, PropertyQuery, MAX_QUERY_BYTES};

const STDERR_LIMIT: usize = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(2);

pub(super) struct Capture {
    pub bytes: Vec<u8>,
    pub stderr_bytes: usize,
    pub exit_code: Option<i32>,
    pub truncated: bool,
    pub issue: Option<QueryReadIssue>,
    pub cleanup: QueryChildCleanup,
}

pub(super) enum Chunk {
    Bytes(Vec<u8>),
    Pending,
    Eof,
}

/// Private test seam; it is not a command factory or an authority-bearing API.
pub(super) trait Driver {
    fn now(&self) -> Instant;
    fn pause(&mut self, duration: Duration);
    fn read(&mut self, stderr: bool) -> Result<Chunk, QueryReadIssue>;
    fn exited(&mut self) -> Result<bool, QueryReadIssue>;
    fn terminate_group(&mut self) -> bool;
    fn reap(&mut self) -> Result<Option<Option<i32>>, QueryReadIssue>;
    fn group_absent(&mut self) -> bool;
}

fn drain(
    child: &mut impl Driver,
    capture: &mut Capture,
    ended: &mut [bool; 2],
) -> Result<(), QueryReadIssue> {
    // One bounded read per pipe per turn prevents a busy writer from starving
    // the cancellation/deadline checks or the other pipe.
    for (index, stderr) in [false, true].into_iter().enumerate() {
        if ended[index] { continue; }
        match child.read(stderr)? {
            Chunk::Eof => ended[index] = true,
            Chunk::Pending => {},
            Chunk::Bytes(bytes) if stderr => {
                capture.stderr_bytes = capture.stderr_bytes.saturating_add(bytes.len());
                if capture.stderr_bytes > STDERR_LIMIT {
                    capture.truncated = true;
                    return Err(QueryReadIssue::OutputLimit);
                }
            },
            Chunk::Bytes(bytes) => {
                let remaining = MAX_QUERY_BYTES.saturating_sub(capture.bytes.len());
                capture.bytes.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
                if bytes.len() > remaining {
                    capture.truncated = true;
                    return Err(QueryReadIssue::OutputLimit);
                }
            },
        }
    }
    Ok(())
}

pub(super) fn capture(
    child: &mut impl Driver,
    query_end: Instant,
    cleanup_end: Instant,
    cancelled: &AtomicBool,
) -> Capture {
    let mut result = Capture {
        bytes: Vec::new(), stderr_bytes: 0, exit_code: None, truncated: false,
        issue: None, cleanup: QueryChildCleanup::Unknown,
    };
    let mut ended = [false; 2];
    loop {
        let issue = if cancelled.load(Ordering::Acquire) {
            Some(QueryReadIssue::Cancelled)
        } else if child.now() >= query_end {
            Some(QueryReadIssue::Deadline)
        } else {
            drain(child, &mut result, &mut ended).err()
        };
        if let Some(issue) = issue {
            result.issue = Some(issue);
            break;
        }
        match child.exited() {
            Ok(true) => break,
            Ok(false) => child.pause(POLL_INTERVAL.min(query_end.saturating_duration_since(child.now()))),
            Err(issue) => { result.issue = Some(issue); break; },
        }
    }
    // The child has not been reaped: its PID still pins the group identifier.
    // Never signal this numeric group again after releasing that PID.
    let signalled = child.terminate_group();
    let mut reaped = false;
    while child.now() < cleanup_end {
        if let Err(issue) = drain(child, &mut result, &mut ended) {
            result.issue.get_or_insert(issue);
        }
        if !reaped {
            match child.reap() {
                Ok(Some(code)) => { result.exit_code = code; reaped = true; },
                Ok(None) => {},
                Err(issue) => { result.issue.get_or_insert(issue); },
            }
        }
        // This is a read-only absence check after reaping; PID reuse can only
        // turn a proven-empty result into conservative uncertainty.
        if signalled && reaped && ended == [true, true] && child.group_absent() {
            result.cleanup = QueryChildCleanup::ReapedGroupAbsent;
            break;
        }
        child.pause(POLL_INTERVAL.min(cleanup_end.saturating_duration_since(child.now())));
    }
    if result.cleanup == QueryChildCleanup::Unknown {
        result.issue.get_or_insert(QueryReadIssue::CleanupUnknown);
    }
    result
}

pub(super) struct LinuxChild {
    child: Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    start_ticks: Option<u64>,
    signalled: bool,
    reaped: bool,
    output_ready: bool,
}

impl LinuxChild {
    pub(super) fn spawn(
        manager: &InspectedNativeTool,
        target: &ObservationTarget,
        query: PropertyQuery,
    ) -> Result<Self, QueryReadIssue> {
        let mut command = Command::new(format!("/proc/self/fd/{}", manager.fd()));
        command.arg0("systemctl").args(target.query_arguments(query))
            .env_clear().env("LC_ALL", "C").current_dir("/")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if query != PropertyQuery::OwnerManager {
            command.envs(target.user_bus_environment());
        }
        Self::spawn_configured(command, manager.deadline())
    }

    fn spawn_configured(mut command: Command, deadline: Instant) -> Result<Self, QueryReadIssue> {
        let expected_parent = std::process::id() as i32;
        // SAFETY: only fixed async-signal-safe syscalls occur before exec.
        unsafe {
            command.pre_exec(move || {
                if getppid() != expected_parent || setpgid(0, 0) != 0
                    || prctl(1, 9, 0_usize, 0_usize, 0_usize) != 0
                    || prctl(38, 1, 0_usize, 0_usize, 0_usize) != 0
                    || getppid() != expected_parent {
                    return Err(io::Error::from_raw_os_error(3));
                }
                Ok(())
            });
        }
        if Instant::now() >= deadline {
            return Err(QueryReadIssue::Deadline);
        }
        let mut child = command.spawn().map_err(|_| QueryReadIssue::SpawnUnavailable)?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let mut owned = Self { child, stdout, stderr, start_ticks: None, signalled: false, reaped: false, output_ready: true };
        for fd in [owned.stdout.as_raw_fd(), owned.stderr.as_raw_fd()] {
            if !nonblocking(fd) {
                owned.output_ready = false;
            }
        }
        Ok(owned)
    }
}

impl Driver for LinuxChild {
    fn now(&self) -> Instant { Instant::now() }
    fn pause(&mut self, duration: Duration) { std::thread::sleep(duration); }
    fn read(&mut self, stderr: bool) -> Result<Chunk, QueryReadIssue> {
        if !self.output_ready { return Err(QueryReadIssue::OutputUnavailable); }
        let mut bytes = [0_u8; 4096];
        let result = if stderr { self.stderr.read(&mut bytes) } else { self.stdout.read(&mut bytes) };
        match result {
            Ok(0) => Ok(Chunk::Eof),
            Ok(size) => Ok(Chunk::Bytes(bytes[..size].to_vec())),
            Err(issue) if matches!(issue.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => Ok(Chunk::Pending),
            Err(_) => Err(QueryReadIssue::OutputUnavailable),
        }
    }
    fn exited(&mut self) -> Result<bool, QueryReadIssue> {
        let mut bytes = Vec::new();
        std::fs::File::open(format!("/proc/{}/stat", self.child.id()))
            .and_then(|file| file.take(4097).read_to_end(&mut bytes))
            .map_err(|_| QueryReadIssue::ProcessIdentity)?;
        let (exited, ticks) = child_identity(&bytes, self.child.id(), std::process::id())?;
        if self.start_ticks.is_some_and(|expected| expected != ticks) {
            return Err(QueryReadIssue::ProcessIdentity);
        }
        self.start_ticks = Some(ticks);
        Ok(exited)
    }
    fn terminate_group(&mut self) -> bool {
        if self.signalled || self.reaped { return false; }
        self.signalled = true;
        // SAFETY: pre_exec established this group, and the unreaped Child pins
        // its PID. No external PID or group is accepted by this private driver.
        let result = unsafe { kill(-(self.child.id() as i32), 9) };
        let group_signalled = result == 0 || io::Error::last_os_error().raw_os_error() == Some(3);
        // The same unreaped Child still pins this PID if its leader moved to
        // another group. Signal that owned child too, before any try_wait can
        // release the pin; never signal either numeric identity after reaping.
        let child_signalled = match self.child.kill() {
            Ok(()) => true,
            Err(issue) => issue.raw_os_error() == Some(3),
        };
        group_signalled && child_signalled
    }
    fn reap(&mut self) -> Result<Option<Option<i32>>, QueryReadIssue> {
        match self.child.try_wait().map_err(|_| QueryReadIssue::CleanupUnknown)? {
            Some(status) => { self.reaped = true; Ok(Some(status.code())) },
            None => Ok(None),
        }
    }
    fn group_absent(&mut self) -> bool {
        // SAFETY: signal zero observes existence and never sends a signal.
        (unsafe { kill(-(self.child.id() as i32), 0) }) != 0
            && io::Error::last_os_error().raw_os_error() == Some(3)
    }
}

impl Drop for LinuxChild {
    fn drop(&mut self) {
        if !self.reaped {
            if !self.signalled { self.terminate_group(); }
            // No wait(), reader-thread join, or new cleanup deadline in Drop.
            // Failure to reap within capture's budget remains explicitly unknown.
            let _ = self.child.try_wait();
        }
    }
}

pub(super) fn child_identity(bytes: &[u8], pid: u32, parent: u32) -> Result<(bool, u64), QueryReadIssue> {
    if bytes.len() > 4096 { return Err(QueryReadIssue::ProcessIdentity); }
    let text = std::str::from_utf8(bytes).map_err(|_| QueryReadIssue::ProcessIdentity)?;
    let prefix = format!("{pid} (");
    let fields: Vec<_> = text.strip_prefix(&prefix)
        .and_then(|text| text.rsplit_once(") "))
        .ok_or(QueryReadIssue::ProcessIdentity)?.1.split_whitespace().collect();
    if fields.len() < 20 || fields[1] != parent.to_string() || fields[2] != pid.to_string()
        || !matches!(fields[0], "R" | "S" | "D" | "Z" | "T" | "t" | "X" | "x" | "K" | "W" | "P" | "I") {
        return Err(QueryReadIssue::ProcessIdentity);
    }
    let ticks: u64 = fields[19].parse().map_err(|_| QueryReadIssue::ProcessIdentity)?;
    if ticks == 0 || ticks.to_string() != fields[19] { return Err(QueryReadIssue::ProcessIdentity); }
    Ok((matches!(fields[0], "Z" | "X" | "x"), ticks))
}

fn nonblocking(fd: RawFd) -> bool {
    // SAFETY: fd is a held pipe; these fixed commands preserve existing flags.
    unsafe { let flags = fcntl(fd, 3); flags >= 0 && fcntl(fd, 4, flags | 0x800) >= 0 }
}

unsafe extern "C" {
    fn getppid() -> i32;
    fn setpgid(pid: i32, group: i32) -> i32;
    fn prctl(option: i32, ...) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
}

#[cfg(test)]
#[path = "service_query_process_tests.rs"]
mod tests;
