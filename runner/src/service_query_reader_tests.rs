//! Authored byte fixtures and a scripted process driver; no process or bus calls.

use std::collections::VecDeque;

use super::*;
use super::process::{capture, child_identity, Capture, Chunk, Driver};

struct Script {
    now: Instant,
    stdout: VecDeque<Result<Chunk, QueryReadIssue>>,
    stderr: VecDeque<Result<Chunk, QueryReadIssue>>,
    exited: Result<bool, QueryReadIssue>,
    reaps: bool,
    absent: bool,
    signalled: bool,
    terminated: bool,
    events: Vec<&'static str>,
    cancellation: Option<std::sync::Arc<AtomicBool>>,
}

impl Script {
    fn normal(now: Instant) -> Self {
        Self { now, stdout: [Ok(Chunk::Bytes(b"LoadState=loaded\n".to_vec())), Ok(Chunk::Eof)].into(),
            stderr: [Ok(Chunk::Eof)].into(), exited: Ok(true), reaps: true, absent: true,
            signalled: true, terminated: false, events: Vec::new(), cancellation: None }
    }
}

impl Driver for Script {
    fn now(&self) -> Instant { self.now }
    fn pause(&mut self, duration: Duration) {
        assert!(duration <= Duration::from_millis(2));
        self.now += duration;
        if let Some(cancel) = &self.cancellation { cancel.store(true, Ordering::Release); }
    }
    fn read(&mut self, stderr: bool) -> Result<Chunk, QueryReadIssue> {
        self.events.push(if stderr { "stderr" } else { "stdout" });
        let queue = if stderr { &mut self.stderr } else { &mut self.stdout };
        queue.pop_front().unwrap_or(Ok(Chunk::Pending))
    }
    fn exited(&mut self) -> Result<bool, QueryReadIssue> { self.exited }
    fn terminate_group(&mut self) -> bool {
        assert!(!self.terminated);
        self.terminated = true;
        self.events.push("terminate");
        self.signalled
    }
    fn reap(&mut self) -> Result<Option<Option<i32>>, QueryReadIssue> {
        assert!(self.terminated, "reaping would release the group-id pin before signalling");
        self.events.push("reap");
        Ok(self.reaps.then_some(Some(0)))
    }
    fn group_absent(&mut self) -> bool {
        self.events.push("group_absent");
        self.absent
    }
}

fn run(script: &mut Script, cancel: &AtomicBool) -> Capture {
    let started = script.now;
    capture(script, started + Duration::from_millis(10), started + Duration::from_millis(20), cancel)
}

#[test]
fn completed_query_retains_bytes_and_only_proves_the_owned_child_group_cleanup() {
    let mut child = Script::normal(Instant::now());
    let result = run(&mut child, &AtomicBool::new(false));
    assert_eq!(result.bytes, b"LoadState=loaded\n");
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.cleanup, QueryChildCleanup::ReapedGroupAbsent);
    assert_eq!(result.issue, None);
    assert!(!result.truncated);
    assert!(child.events.iter().position(|event| *event == "terminate").unwrap()
        < child.events.iter().position(|event| *event == "reap").unwrap());
}

#[test]
fn cancellation_is_checked_between_bounded_pipe_reads() {
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    let mut child = Script::normal(Instant::now());
    child.exited = Ok(false);
    child.cancellation = Some(cancel.clone());
    let result = run(&mut child, &cancel);
    assert_eq!(result.issue, Some(QueryReadIssue::Cancelled));
    assert_eq!(result.cleanup, QueryChildCleanup::ReapedGroupAbsent);
    assert_eq!(&child.events[..2], ["stdout", "stderr"]);
}

#[test]
fn query_timeout_does_not_refresh_the_cleanup_deadline() {
    let start = Instant::now();
    let mut child = Script::normal(start);
    child.exited = Ok(false);
    child.reaps = false;
    let result = run(&mut child, &AtomicBool::new(false));
    assert_eq!(result.issue, Some(QueryReadIssue::Deadline));
    assert_eq!(result.cleanup, QueryChildCleanup::Unknown);
    assert_eq!(child.now, start + Duration::from_millis(20));
    assert_eq!(child.events.iter().filter(|event| **event == "terminate").count(), 1);
}

#[test]
fn output_limits_preserve_only_bounded_bytes_and_terminate_the_owned_group() {
    for stderr in [false, true] {
        let mut child = Script::normal(Instant::now());
        let oversized = vec![b'x'; crate::service_observer::MAX_QUERY_BYTES + 1];
        if stderr { child.stderr = [Ok(Chunk::Bytes(oversized)), Ok(Chunk::Eof)].into(); }
        else { child.stdout = [Ok(Chunk::Bytes(oversized)), Ok(Chunk::Eof)].into(); }
        let result = run(&mut child, &AtomicBool::new(false));
        assert_eq!(result.issue, Some(QueryReadIssue::OutputLimit));
        assert!(result.truncated);
        assert!(result.bytes.len() <= crate::service_observer::MAX_QUERY_BYTES);
        assert_eq!(result.cleanup, QueryChildCleanup::ReapedGroupAbsent);
    }
}

#[test]
fn pipe_errors_and_child_identity_mismatch_are_not_successful_captures() {
    for issue in [QueryReadIssue::OutputUnavailable, QueryReadIssue::ProcessIdentity] {
        let mut child = Script::normal(Instant::now());
        if issue == QueryReadIssue::OutputUnavailable { child.stdout.push_front(Err(issue)); }
        else { child.exited = Err(issue); }
        let result = run(&mut child, &AtomicBool::new(false));
        assert_eq!(result.issue, Some(issue));
        assert!(child.terminated);
    }
}

#[test]
fn missing_reap_group_absence_signal_or_pipe_eof_remains_unknown() {
    for missing in 0..4 {
        let start = Instant::now();
        let mut child = Script::normal(start);
        match missing {
            0 => child.reaps = false,
            1 => child.absent = false,
            2 => child.signalled = false,
            _ => { child.stderr = [Ok(Chunk::Pending)].into(); },
        }
        let result = run(&mut child, &AtomicBool::new(false));
        assert_eq!(result.cleanup, QueryChildCleanup::Unknown);
        assert_eq!(result.issue, Some(QueryReadIssue::CleanupUnknown));
        assert_eq!(child.now, start + Duration::from_millis(20));
    }
}

#[test]
fn spent_inspection_budget_is_never_extended_or_revived() {
    let now = Instant::now();
    for spent in [Duration::ZERO, Duration::from_millis(124), Duration::from_millis(125)] {
        assert_eq!(query_deadlines(now + spent, now), Err(QueryReadIssue::Deadline));
    }
    let deadline = now + Duration::from_millis(126);
    let (query_end, cleanup_end) = query_deadlines(deadline, now).unwrap();
    assert_eq!(query_end, now + Duration::from_millis(1));
    assert_eq!(cleanup_end, now + Duration::from_millis(101));
    assert_eq!(query_deadlines(deadline, deadline), Err(QueryReadIssue::Deadline));
}

#[test]
fn owner_real_effective_and_boot_identity_must_all_match() {
    let boot = "12345678-1234-1234-1234-123456789abc";
    let raw = format!("{boot}\n");
    assert_eq!(scope::validate_identity(1000, 1000, 1000, raw.as_bytes(), boot), Ok(()));
    for (owner, real, effective, bytes) in [
        (0, 0, 0, raw.as_bytes()), (1000, 1001, 1000, raw.as_bytes()),
        (1000, 1000, 0, raw.as_bytes()), (1000, 1000, 1000, boot.as_bytes()),
        (1000, 1000, 1000, b"other-boot\n".as_slice()),
    ] {
        assert_eq!(scope::validate_identity(owner, real, effective, bytes, boot), Err(QueryReadIssue::ScopeIdentity));
    }
}

fn child_stat(pid: u32, parent: u32, group: u32, state: &str, ticks: &str) -> Vec<u8> {
    let mut fields = vec!["0".to_string(); 20];
    fields[0] = state.into(); fields[1] = parent.to_string(); fields[2] = group.to_string(); fields[19] = ticks.into();
    format!("{pid} (authored ) process) {}\n", fields.join(" ")).into_bytes()
}

#[test]
fn child_stat_requires_the_pinned_pid_parent_group_and_canonical_start_time() {
    assert_eq!(child_identity(&child_stat(42, 7, 42, "S", "100"), 42, 7), Ok((false, 100)));
    assert_eq!(child_identity(&child_stat(42, 7, 42, "Z", "100"), 42, 7), Ok((true, 100)));
    for bytes in [child_stat(43, 7, 42, "S", "100"), child_stat(42, 8, 42, "S", "100"),
        child_stat(42, 7, 43, "S", "100"), child_stat(42, 7, 42, "?", "100"),
        child_stat(42, 7, 42, "S", "0100"), child_stat(42, 7, 42, "S", "0"), vec![b'x'; 4097]] {
        assert_eq!(child_identity(&bytes, 42, 7), Err(QueryReadIssue::ProcessIdentity));
    }
}

#[test]
fn incomplete_capture_never_becomes_finished_parser_input() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("../../tests_platform/fixtures/service_operation_binding_v1.json")).unwrap();
    let binding = ServiceOperationBinding::from_json(&serde_json::to_vec(&fixture["valid"][0]["document"]).unwrap()).unwrap();
    let mut child = Script::normal(Instant::now());
    let mut acquired = AcquiredPropertyQuery { binding, query: PropertyQuery::OwnedUnit,
        capture: run(&mut child, &AtomicBool::new(false)) };
    assert!(matches!(acquired.parser_outcome(), ReadOutcome::Finished { exit_code: 0, truncated: false, .. }));
    acquired.capture.cleanup = QueryChildCleanup::Unknown;
    assert!(matches!(acquired.parser_outcome(), ReadOutcome::Unavailable));
    acquired.capture.cleanup = QueryChildCleanup::ReapedGroupAbsent;
    acquired.capture.issue = Some(QueryReadIssue::ScopeIdentity);
    assert!(matches!(acquired.parser_outcome(), ReadOutcome::Unavailable));
    assert_eq!(acquired.bytes(), b"LoadState=loaded\n");
}

#[test]
fn cancellation_and_missing_retained_admission_refuse_before_any_live_io() {
    let admission = crate::service_admission::reservation_test_admission(1000, "authored", "unused");
    assert!(matches!(acquire_property_query(&admission, PropertyQuery::OwnedUnit, &AtomicBool::new(true)), Err(QueryReadIssue::Cancelled)));
    assert!(matches!(acquire_property_query(&admission, PropertyQuery::OwnedUnit, &AtomicBool::new(false)), Err(QueryReadIssue::AdmissionUnavailable)));
}
