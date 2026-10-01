//! Only the held current test ELF is executed; no manager, bus or service is used.

use std::fs::File;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;

use super::*;

const FIXTURE_ENV: &str = "BLUEFIRE_QUERY_SYSCALL_FIXTURE";
const CHILD_TEST: &str = "service_query_reader::process::tests::authored_query_child";
const READY: &[u8] = b"authored-query-ready\n";

#[derive(Clone, Copy)]
enum Mode {
    Complete,
    StdoutLimit,
    StderrLimit,
    Wait,
    EscapeGroup,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::StdoutLimit => "stdout-limit",
            Self::StderrLimit => "stderr-limit",
            Self::Wait => "wait",
            Self::EscapeGroup => "escape-group",
        }
    }
}

/// The test harness normally calls this as a no-op. Its exact subprocess
/// invocation supplies one closed mode and exits before the harness adds output.
#[test]
fn authored_query_child() {
    let Ok(mode) = std::env::var(FIXTURE_ENV) else {
        return;
    };
    assert!(matches!(
        mode.as_str(),
        "complete" | "stdout-limit" | "stderr-limit" | "wait" | "escape-group"
    ));
    // This fallback also bounds a blocked write if a parent assertion aborts.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(2));
        std::process::exit(71);
    });
    assert_eq!(std::env::current_dir().unwrap(), std::path::Path::new("/"));
    assert_eq!(std::env::var("LC_ALL").unwrap(), "C");
    assert!(std::env::vars_os().all(|(key, _)| key == FIXTURE_ENV || key == "LC_ALL"));
    let mut stdin = Vec::new();
    std::io::stdin().read_to_end(&mut stdin).unwrap();
    assert!(stdin.is_empty());
    // SAFETY: these fixed queries only inspect this authored process.
    unsafe {
        assert_eq!(getpgid(0), std::process::id() as i32);
        assert_eq!(prctl(39, 0_usize, 0_usize, 0_usize, 0_usize), 1);
    }
    // libtest runs this body on a new worker thread. PR_GET_PDEATHSIG is
    // thread-local, so it cannot inspect the exec leader's pre_exec setting
    // here. A separate test observes delivery when the owned creator exits.
    if mode == "escape-group" {
        // SAFETY: this authored child may join only its still-owning test
        // parent's group. No supplied PID or external process is accepted.
        unsafe {
            let parent_group = getpgid(getppid());
            assert!(parent_group > 0 && parent_group != std::process::id() as i32);
            assert_eq!(setpgid(0, parent_group), 0);
        }
    }
    std::io::stdout().write_all(READY).unwrap();
    match mode.as_str() {
        "complete" => std::io::stderr().write_all(b"authored-stderr\n").unwrap(),
        "stdout-limit" => std::io::stdout()
            .write_all(&[b'x'; MAX_QUERY_BYTES + 4096])
            .unwrap(),
        "stderr-limit" => std::io::stderr()
            .write_all(&[b'e'; STDERR_LIMIT + 4096])
            .unwrap(),
        "wait" | "escape-group" => {}
        _ => unreachable!(),
    }
    if mode != "complete" {
        std::thread::sleep(Duration::from_millis(1500));
    }
    std::process::exit(0);
}

/// Delegate every lifecycle operation to the production Linux driver, while
/// witnessing that a still-owned, unreaped PID pins the group before its signal.
struct Fixture<'a> {
    child: LinuxChild,
    cancelled: Option<&'a AtomicBool>,
    seen_stdout: Vec<u8>,
    seen_stderr: Vec<u8>,
    signals: usize,
    witnessed_identity: bool,
    escaped_group: bool,
}

impl<'a> Fixture<'a> {
    fn spawn(mode: Mode, cancelled: Option<&'a AtomicBool>) -> (Self, Instant, Instant) {
        Self::spawn_before(mode, cancelled, Instant::now() + Duration::from_secs(1))
    }

    fn spawn_before(
        mode: Mode,
        cancelled: Option<&'a AtomicBool>,
        deadline: Instant,
    ) -> (Self, Instant, Instant) {
        let (query_end, cleanup_end) =
            super::super::query_deadlines(deadline, Instant::now()).unwrap();
        let image = File::open("/proc/self/exe").unwrap();
        let mut command = Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()));
        command
            .arg0("bluefire-owned-query-fixture")
            .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
            .env_clear()
            .env("LC_ALL", "C")
            .env(FIXTURE_ENV, mode.name())
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = LinuxChild::spawn_configured(command, deadline).unwrap();
        (
            Self {
                child,
                cancelled,
                seen_stdout: Vec::new(),
                seen_stderr: Vec::new(),
                signals: 0,
                witnessed_identity: false,
                escaped_group: matches!(mode, Mode::EscapeGroup),
            },
            query_end,
            cleanup_end,
        )
    }

    fn assert_cleaned(&mut self, result: &Capture) {
        assert_eq!(result.cleanup, QueryChildCleanup::ReapedGroupAbsent);
        assert_eq!(self.signals, 1);
        assert!(self.witnessed_identity);
        assert!(self.child.signalled && self.child.reaped);
        assert!(self.child.group_absent());
        assert!(matches!(self.child.read(false), Ok(Chunk::Eof)));
        assert!(matches!(self.child.read(true), Ok(Chunk::Eof)));
        assert!(
            !self.child.terminate_group(),
            "a reaped PID must never be signalled again"
        );
    }
}

impl Driver for Fixture<'_> {
    fn now(&self) -> Instant {
        self.child.now()
    }
    fn pause(&mut self, duration: Duration) {
        self.child.pause(duration);
    }
    fn read(&mut self, stderr: bool) -> Result<Chunk, QueryReadIssue> {
        let chunk = self.child.read(stderr)?;
        if stderr {
            if let Chunk::Bytes(bytes) = &chunk {
                let remaining = STDERR_LIMIT.saturating_sub(self.seen_stderr.len());
                self.seen_stderr
                    .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
            }
        } else {
            if let Chunk::Bytes(bytes) = &chunk {
                let remaining = MAX_QUERY_BYTES.saturating_sub(self.seen_stdout.len());
                self.seen_stdout
                    .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
                if self
                    .seen_stdout
                    .windows(READY.len())
                    .any(|bytes| bytes == READY)
                {
                    if let Some(cancelled) = self.cancelled {
                        cancelled.store(true, Ordering::Release);
                    }
                }
            }
        }
        Ok(chunk)
    }
    fn exited(&mut self) -> Result<bool, QueryReadIssue> {
        self.child.exited()
    }
    fn terminate_group(&mut self) -> bool {
        assert!(!self.child.reaped);
        if self.escaped_group {
            assert_eq!(self.child.exited(), Err(QueryReadIssue::ProcessIdentity));
        } else {
            self.child
                .exited()
                .expect("the owned child identity must remain inspectable before signalling");
        }
        self.witnessed_identity = true;
        self.signals += 1;
        self.child.terminate_group()
    }
    fn reap(&mut self) -> Result<Option<Option<i32>>, QueryReadIssue> {
        assert_eq!(
            self.signals, 1,
            "group termination must precede the first real reap"
        );
        self.child.reap()
    }
    fn group_absent(&mut self) -> bool {
        self.child.group_absent()
    }
}

impl Drop for Fixture<'_> {
    fn drop(&mut self) {
        if !self.child.reaped {
            // Test failure cleanup uses only the still-held child. This does not
            // change capture's result or refresh its original query deadline.
            if !self.child.signalled {
                self.child.terminate_group();
            }
            let until = Instant::now() + Duration::from_millis(100);
            while Instant::now() < until && !self.child.reaped {
                let _ = self.child.reap();
                if !self.child.reaped {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }
}

#[test]
fn descriptor_exec_captures_actual_pipes_and_reaps_after_group_signal() {
    let (mut fixture, query_end, cleanup_end) = Fixture::spawn(Mode::Complete, None);
    let result = capture(
        &mut fixture,
        query_end,
        cleanup_end,
        &AtomicBool::new(false),
    );
    assert_eq!(result.issue, None);
    assert_eq!(
        result.exit_code,
        Some(0),
        "authored fixture stderr: {}",
        String::from_utf8_lossy(&fixture.seen_stderr)
    );
    assert!(result
        .bytes
        .windows(READY.len())
        .any(|bytes| bytes == READY));
    assert_eq!(result.stderr_bytes, b"authored-stderr\n".len());
    assert!(!result.truncated);
    fixture.assert_cleaned(&result);
}

#[test]
fn actual_stdout_and_stderr_limits_kill_and_reap_the_owned_query() {
    for mode in [Mode::StdoutLimit, Mode::StderrLimit] {
        let (mut fixture, query_end, cleanup_end) = Fixture::spawn(mode, None);
        let result = capture(
            &mut fixture,
            query_end,
            cleanup_end,
            &AtomicBool::new(false),
        );
        assert_eq!(result.issue, Some(QueryReadIssue::OutputLimit));
        assert!(result.truncated);
        assert!(result.bytes.len() <= MAX_QUERY_BYTES);
        match mode {
            Mode::StdoutLimit => assert_eq!(result.bytes.len(), MAX_QUERY_BYTES),
            Mode::StderrLimit => assert!(result.stderr_bytes > STDERR_LIMIT),
            _ => unreachable!(),
        }
        assert_eq!(result.exit_code, None);
        fixture.assert_cleaned(&result);
    }
}

#[test]
fn cancellation_after_actual_child_output_kills_before_reaping() {
    let cancelled = AtomicBool::new(false);
    let (mut fixture, query_end, cleanup_end) = Fixture::spawn(Mode::Wait, Some(&cancelled));
    let result = capture(&mut fixture, query_end, cleanup_end, &cancelled);
    assert!(cancelled.load(Ordering::Acquire));
    assert_eq!(result.issue, Some(QueryReadIssue::Cancelled));
    assert_eq!(result.exit_code, None);
    fixture.assert_cleaned(&result);
}

#[test]
fn actual_waiting_child_consumes_only_the_original_deadline() {
    let (mut fixture, query_end, cleanup_end) = Fixture::spawn(Mode::Wait, None);
    let result = capture(
        &mut fixture,
        query_end,
        cleanup_end,
        &AtomicBool::new(false),
    );
    assert_eq!(result.issue, Some(QueryReadIssue::Deadline));
    assert!(result
        .bytes
        .windows(READY.len())
        .any(|bytes| bytes == READY));
    assert!(Instant::now() >= query_end);
    assert_eq!(result.exit_code, None);
    fixture.assert_cleaned(&result);
}

#[test]
fn creator_thread_exit_kills_the_owned_child_before_any_parent_signal() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let (fixture_tx, fixture_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let creator = std::thread::spawn(move || {
        let fixture = Fixture::spawn_before(Mode::Wait, None, deadline);
        assert!(fixture_tx.send(fixture).is_ok());
        // The creator remains alive until the test has observed the child.
        // A failed test closes the channel; otherwise this same deadline bounds it.
        let _ = release_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    });
    let (mut fixture, query_end, cleanup_end) = fixture_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap();
    while !fixture
        .seen_stdout
        .windows(READY.len())
        .any(|bytes| bytes == READY)
    {
        assert!(Instant::now() < query_end);
        assert!(!fixture.child.exited().unwrap());
        fixture.read(false).unwrap();
        fixture.read(true).unwrap();
        fixture.pause(POLL_INTERVAL.min(query_end.saturating_duration_since(Instant::now())));
    }
    assert!(!fixture.child.exited().unwrap());
    assert!(!creator.is_finished());
    assert_eq!(fixture.signals, 0);
    assert!(!fixture.child.signalled);
    release_tx.send(()).unwrap();
    while !(fixture.child.exited().unwrap() && creator.is_finished()) {
        assert!(Instant::now() < query_end);
        fixture.pause(POLL_INTERVAL.min(query_end.saturating_duration_since(Instant::now())));
    }
    assert!(Instant::now() < query_end);
    assert_eq!(fixture.signals, 0);
    assert!(!fixture.child.signalled && !fixture.child.reaped);
    // No join or renewed wait budget is needed after observed thread completion.
    drop(creator);
    let result = capture(
        &mut fixture,
        query_end,
        cleanup_end,
        &AtomicBool::new(false),
    );
    assert_eq!(result.issue, None);
    assert_eq!(result.exit_code, None);
    fixture.assert_cleaned(&result);
    // try_wait returns the already-reaped status; it cannot signal a reused PID.
    assert_eq!(
        fixture.child.child.try_wait().unwrap().unwrap().signal(),
        Some(9)
    );
}

#[test]
fn changed_group_still_terminates_only_the_pinned_direct_child_before_reaping() {
    let (mut fixture, query_end, cleanup_end) = Fixture::spawn(Mode::EscapeGroup, None);
    let result = capture(
        &mut fixture,
        query_end,
        cleanup_end,
        &AtomicBool::new(false),
    );
    assert_eq!(result.issue, Some(QueryReadIssue::ProcessIdentity));
    assert_eq!(result.exit_code, None);
    assert!(
        Instant::now() < query_end,
        "the escaped leader must not run until timeout"
    );
    fixture.assert_cleaned(&result);
}

unsafe extern "C" {
    fn getpgid(pid: i32) -> i32;
}
