use super::*;
use std::collections::VecDeque;

fn window() -> AuditWindow {
    AuditWindow::new(
        "2026-10-09T00:00:00Z",
        "2026-10-09T00:10:00Z",
        "S-1-5-21-1-2-3-1001",
        "S-1-5-21-1-2-3-1002",
    )
    .unwrap()
}

struct Fake {
    rows: VecDeque<Result<Next, u32>>,
    calls: usize,
    closed: bool,
    close_ok: bool,
}

impl Reader for Fake {
    fn next(&mut self, timeout: u32) -> Result<Next, u32> {
        assert!((1..=1000).contains(&timeout));
        self.calls += 1;
        self.rows.pop_front().unwrap_or(Ok(Next::End))
    }
    fn close(&mut self) -> bool {
        self.closed = true;
        self.close_ok
    }
}

fn fake(rows: Vec<Result<Next, u32>>) -> Fake {
    Fake {
        rows: rows.into(),
        calls: 0,
        closed: false,
        close_ok: true,
    }
}

fn capture(reader: &mut Fake) -> AuditCapture {
    collect(
        reader,
        &window(),
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(60),
    )
}

#[test]
fn fixed_query_normalizes_only_valid_scope_values() {
    let value = AuditWindow::new(
        "2026-10-09T01:00:00.000000100+01:00",
        "2026-10-09T01:01:00+01:00",
        "S-1-5-21-1-2-3-1001",
        "S-1-5-21-1-2-3-1002",
    )
    .unwrap();
    let query = value.query();
    assert!(query.contains("2026-10-09T00:00:00.0000001Z"));
    assert!(query.contains("EventID=5145"));
    assert!(query.contains("EventID=4624"));
    assert_eq!(query.matches("SubjectUserSid").count(), 2);
    assert_eq!(query.matches("TargetUserSid").count(), 2);
    for invalid in [
        "S-1-5-21-1-2-3-01001",
        "S-1-5-21-1-2-3-999",
        "S-1-5-21-1-2-3-1001'] or *",
        "S-1-5-21-1-2-4294967296-1001",
    ] {
        assert!(AuditWindow::new(&value.start, &value.end, invalid, &value.legitimate).is_err());
    }
    assert!(AuditWindow::new(&value.start, &value.end, &value.probe, &value.probe).is_err());
    assert!(AuditWindow::new(
        &value.start,
        &value.end,
        &value.probe,
        "S-1-5-21-4-2-3-1002"
    )
    .is_err());
}

#[test]
fn refuses_unbounded_or_inexact_windows_time() {
    for (start, end) in [
        ("2026-10-09T00:00:00Z", "2026-10-09T00:00:00Z"),
        ("2026-10-09T00:00:01Z", "2026-10-09T00:00:00Z"),
        ("2026-10-09T00:00:00Z", "2026-10-09T01:00:00.0000001Z"),
        ("2026-10-09T00:00:00.000000001Z", "2026-10-09T00:01:00Z"),
        ("2026-10-09T00:00:00Z']", "2026-10-09T00:01:00Z"),
        ("2026-10-09T00:00:00", "2026-10-09T00:01:00Z"),
        ("2026-10-09T00:00:60Z", "2026-10-09T00:01:00Z"),
    ] {
        assert!(AuditWindow::new(start, end, &window().probe, &window().legitimate).is_err());
    }
}

#[test]
fn exhausted_query_is_not_complete_independent_audit_proof() {
    let mut reader = fake(vec![Ok(Next::Event("<Event/>".into()))]);
    let result = capture(&mut reader);
    assert_eq!(result.state, CaptureState::QueryExhausted);
    assert!(result.handles_closed && reader.closed);
    assert_eq!(result.raw_events, ["<Event/>"]);
    assert_eq!(result.utf8_bytes, 8);
    assert!(
        !result.log_continuity_verified
            && !result.authenticated_source_claim
            && !result.independent_evidence_claim
            && !result.effective_access_claim
    );
}

#[test]
fn record_ceiling_remains_partial_without_an_extra_read() {
    for extra in [false, true] {
        let mut reader = fake(
            (0..MAX_EVENTS + usize::from(extra))
                .map(|_| Ok(Next::Event("x".into())))
                .collect(),
        );
        let result = capture(&mut reader);
        assert_eq!(result.raw_events.len(), MAX_EVENTS);
        assert_eq!(reader.calls, MAX_EVENTS);
        assert_eq!(result.state, CaptureState::EventLimit);
        assert!(reader.closed);
    }
}

#[test]
fn caps_total_utf8_and_event_size_without_dropping_retained_prefix() {
    let mut reader = fake(
        (0..65)
            .map(|_| Ok(Next::Event("x".repeat(MAX_EVENT_BYTES))))
            .collect(),
    );
    let result = capture(&mut reader);
    assert_eq!(result.state, CaptureState::ByteLimit);
    assert_eq!(result.utf8_bytes, MAX_TOTAL_BYTES);
    assert_eq!(result.raw_events.len(), 64);
    for bad in [
        String::new(),
        "x".repeat(MAX_EVENT_BYTES + 1),
        "x\0y".into(),
    ] {
        let mut reader = fake(vec![Ok(Next::Event("x".into())), Ok(Next::Event(bad))]);
        let result = capture(&mut reader);
        assert_eq!(result.state, CaptureState::EventRejected);
        assert_eq!(result.raw_events, ["x"]);
    }
}

#[test]
fn failures_and_timeout_are_not_absence() {
    for error in [5, 13, 122, 1460] {
        let mut reader = fake(vec![Ok(Next::Event("x".into())), Err(error)]);
        let result = capture(&mut reader);
        assert_eq!(
            result.state,
            if error == 1460 {
                CaptureState::Deadline
            } else {
                CaptureState::ReadFailed
            }
        );
        assert_eq!(result.system_error, Some(error));
        assert_eq!(result.raw_events, ["x"]);
        assert!(reader.closed);
    }
}

#[test]
fn cancellation_deadline_and_failed_cleanup_are_truthful() {
    for cancelled in [false, true] {
        let mut reader = fake(vec![]);
        let result = collect(
            &mut reader,
            &window(),
            &AtomicBool::new(cancelled),
            Instant::now(),
        );
        assert_eq!(reader.calls, 0);
        assert!(reader.closed);
        assert_eq!(
            result.state,
            if cancelled {
                CaptureState::Cancelled
            } else {
                CaptureState::Deadline
            }
        );
    }
    let mut reader = fake(vec![]);
    reader.close_ok = false;
    let result = capture(&mut reader);
    assert_eq!(result.state, CaptureState::CleanupUnknown);
    assert!(!result.handles_closed);
}
