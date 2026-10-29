//! Deterministic lifecycle vectors only; no process, SFTP endpoint or native tool.

use super::*;

struct Fake {
    now: Instant,
    running: bool,
    flood: bool,
    eof: bool,
    absent: bool,
    reaped: bool,
    code: Option<i32>,
    events: Vec<&'static str>,
}

impl Fake {
    fn complete() -> Self {
        Self {
            now: Instant::now(),
            running: false,
            flood: false,
            eof: true,
            absent: true,
            reaped: false,
            code: Some(0),
            events: Vec::new(),
        }
    }
}

impl Driver for Fake {
    fn now(&self) -> Instant {
        self.now
    }
    fn pause(&mut self, duration: Duration) {
        self.now += duration;
    }
    fn read(&mut self, _: bool) -> Result<Chunk, Issue> {
        if self.flood && !self.events.contains(&"signal") {
            Ok(Chunk::Bytes(4096))
        } else if self.eof {
            Ok(Chunk::Eof)
        } else {
            Ok(Chunk::Pending)
        }
    }
    fn exited(&mut self) -> Result<bool, Issue> {
        Ok(!self.running)
    }
    fn terminate(&mut self) -> bool {
        assert!(!self.reaped);
        assert!(!self.events.contains(&"signal"));
        self.events.push("signal");
        true
    }
    fn reap(&mut self) -> Result<Option<Option<i32>>, Issue> {
        assert_eq!(self.events.first(), Some(&"signal"));
        assert!(!self.reaped);
        self.events.push("reap");
        self.reaped = true;
        Ok(Some(self.code))
    }
    fn group_absent(&mut self) -> bool {
        assert!(self.reaped);
        self.events.push("absence");
        self.absent
    }
}

#[test]
fn zero_exit_requires_pipe_eof_reaping_and_group_absence_in_order() {
    let mut driver = Fake::complete();
    let end = driver.now + Duration::from_secs(1);
    let result = supervise(&mut driver, end, &AtomicBool::new(false));
    assert_eq!(result.issue, None);
    assert_eq!(result.cleanup, Cleanup::ReapedClientGroupAbsent);
    assert_eq!(driver.events, ["signal", "reap", "absence"]);
}

#[test]
fn cancellation_and_deadline_still_terminate_before_reaping() {
    for cancelled in [false, true] {
        let mut driver = Fake::complete();
        driver.running = true;
        let end = driver.now + Duration::from_secs(1);
        let result = supervise(&mut driver, end, &AtomicBool::new(cancelled));
        assert_eq!(
            result.issue,
            Some(if cancelled {
                Issue::Cancelled
            } else {
                Issue::Deadline
            })
        );
        assert_eq!(result.cleanup, Cleanup::ReapedClientGroupAbsent);
        assert_eq!(driver.events, ["signal", "reap", "absence"]);
        assert!(driver.now < end);
    }
}

#[test]
fn busy_diagnostics_are_bounded_and_cannot_starve_deadline_or_cleanup() {
    let mut driver = Fake::complete();
    driver.running = true;
    driver.flood = true;
    let end = driver.now + Duration::from_secs(1);
    let result = supervise(&mut driver, end, &AtomicBool::new(false));
    assert_eq!(result.issue, Some(Issue::OutputLimit));
    assert!(result.diagnostics_bytes > MAX_DIAGNOSTIC);
    assert_eq!(result.cleanup, Cleanup::ReapedClientGroupAbsent);
}

#[test]
fn zero_exit_never_hides_unknown_group_or_pipe_cleanup() {
    for pipe_gap in [false, true] {
        let mut driver = Fake::complete();
        driver.eof = !pipe_gap;
        driver.absent = pipe_gap;
        let end = driver.now + Duration::from_secs(1);
        let result = supervise(&mut driver, end, &AtomicBool::new(false));
        assert_eq!(result.issue, Some(Issue::CleanupUnknown));
        assert_eq!(result.cleanup, Cleanup::Unknown);
        assert_eq!(
            driver
                .events
                .iter()
                .filter(|event| **event == "signal")
                .count(),
            1
        );
        assert_eq!(
            driver
                .events
                .iter()
                .filter(|event| **event == "reap")
                .count(),
            1
        );
        assert_eq!(driver.now, end);
    }
}

#[test]
fn protocol_failure_has_no_success_interpretation() {
    let mut driver = Fake::complete();
    driver.code = Some(1);
    let end = driver.now + Duration::from_secs(1);
    let result = supervise(&mut driver, end, &AtomicBool::new(false));
    assert_eq!(result.issue, Some(Issue::ProtocolFailure));
    assert_eq!(result.exit_code, Some(1));
}

#[test]
fn fixed_transport_never_admits_shell_proxy_config_or_background_children() {
    let admission = crate::owned_sftp::tests::fixture("/owned/reports/reconciliation.jsonl");
    let args = arguments(&admission, 11, 12, 13);
    assert!(args
        .windows(2)
        .any(|pair| pair == ["-S", "/proc/self/fd/11"]));
    assert!(args.windows(2).any(|pair| pair == ["-F", "/dev/null"]));
    for fixed in [
        "ProxyCommand=none",
        "ProxyJump=none",
        "PermitLocalCommand=no",
        "RemoteCommand=none",
        "StrictHostKeyChecking=yes",
        "ControlMaster=no",
        "ControlPersist=no",
        "ForkAfterAuthentication=no",
        "IdentityAgent=none",
        "RequestTTY=no",
        "PKCS11Provider=none",
        "SecurityKeyProvider=none",
    ] {
        assert!(args.contains(&fixed.into()));
    }
    assert_eq!(args.last().unwrap(), "bfreader_0123456789abcdef@127.0.0.1");
    assert!(!args
        .iter()
        .any(|arg| arg.contains("/owned/") || arg == "sh" || arg == "-D" || arg == "-J"));
}
