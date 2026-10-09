//! Member-local, finite Security-log collection. Enrollment and source trust live above this API.

use chrono::{DateTime, Datelike, FixedOffset, Timelike, Utc};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
mod windows;

pub const MAX_EVENTS: usize = 1000;
pub const MAX_EVENT_BYTES: usize = 65_536;
pub const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_SECONDS: u64 = 60;

#[derive(Debug)]
pub struct AuditWindow {
    start: String,
    end: String,
    probe: String,
    legitimate: String,
}

fn principal(value: &str) -> Result<&str, &'static str> {
    if value.len() > 184 {
        return Err("audit SID exceeds its bound");
    }
    let fields: Vec<_> = value.split('-').collect();
    if fields.len() != 8 || fields[..4] != ["S", "1", "5", "21"] {
        return Err("audit principal must be a canonical domain-user SID");
    }
    for field in &fields[4..] {
        let number = field
            .parse::<u32>()
            .map_err(|_| "invalid audit SID component")?;
        if number.to_string() != *field {
            return Err("audit SID components must be canonical");
        }
    }
    if fields[7].parse::<u32>().map_err(|_| "invalid audit RID")? < 1000 {
        return Err("audit principal is outside the domain-user recipe");
    }
    Ok(value.rsplit_once('-').ok_or("missing audit RID")?.0)
}

fn timestamp(value: &str) -> Result<DateTime<FixedOffset>, &'static str> {
    if value.len() > 40 || !value.is_ascii() {
        return Err("audit timestamp is outside its bound");
    }
    let result = DateTime::parse_from_rfc3339(value).map_err(|_| "invalid audit timestamp")?;
    if !(1601..=9999).contains(&result.with_timezone(&Utc).year())
        || result.nanosecond() >= 1_000_000_000
        || result.nanosecond() % 100 != 0
    {
        return Err("audit timestamp requires exact Windows time precision");
    }
    Ok(result)
}

fn utc(value: DateTime<FixedOffset>) -> String {
    let value = value.with_timezone(&Utc);
    format!(
        "{}.{:07}Z",
        value.format("%Y-%m-%dT%H:%M:%S"),
        value.nanosecond() / 100
    )
}

impl AuditWindow {
    pub fn new(
        start: &str,
        end: &str,
        probe: &str,
        legitimate: &str,
    ) -> Result<Self, &'static str> {
        if principal(probe)? != principal(legitimate)? || probe == legitimate {
            return Err("audit requires the two distinct reviewed same-domain readers");
        }
        let start = timestamp(start)?;
        let end = timestamp(end)?;
        let elapsed = end.signed_duration_since(start);
        if elapsed <= chrono::Duration::zero() || elapsed > chrono::Duration::hours(1) {
            return Err("audit window must be positive and at most one hour");
        }
        Ok(Self {
            start: utc(start),
            end: utc(end),
            probe: probe.into(),
            legitimate: legitimate.into(),
        })
    }

    fn query(&self) -> String {
        // Only normalized timestamps and numeric SIDs enter this fixed XPath.
        format!(
            "*[System[Provider[@Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'] and TimeCreated[@SystemTime >= '{}' and @SystemTime <= '{}']] and ((System[EventID=5145] and EventData[Data[@Name='SubjectUserSid']='{}' or Data[@Name='SubjectUserSid']='{}']) or (System[EventID=4624] and EventData[Data[@Name='TargetUserSid']='{}' or Data[@Name='TargetUserSid']='{}']))]",
            self.start, self.end, self.probe, self.legitimate, self.probe, self.legitimate
        )
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    QueryExhausted,
    EventLimit,
    ByteLimit,
    EventRejected,
    Deadline,
    Cancelled,
    ReadFailed,
    CleanupUnknown,
}

#[derive(Debug, Serialize)]
pub struct AuditCapture {
    pub schema_version: &'static str,
    pub channel: &'static str,
    pub window_start: String,
    pub window_end: String,
    pub state: CaptureState,
    pub raw_events: Vec<String>,
    pub utf8_bytes: usize,
    pub system_error: Option<u32>,
    pub handles_closed: bool,
    pub log_continuity_verified: bool,
    pub authenticated_source_claim: bool,
    pub independent_evidence_claim: bool,
    pub effective_access_claim: bool,
}

#[cfg(any(target_os = "windows", test))]
enum Next {
    Event(String),
    End,
}

#[cfg(any(target_os = "windows", test))]
trait Reader {
    fn next(&mut self, timeout_ms: u32, maximum_bytes: usize) -> Result<Next, u32>;
    fn close(&mut self) -> bool;
}

#[cfg(test)]
fn collect(
    reader: &mut impl Reader,
    window: &AuditWindow,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> AuditCapture {
    collect_bounded(
        reader,
        window,
        cancelled,
        deadline,
        MAX_EVENTS,
        MAX_TOTAL_BYTES,
    )
}

#[cfg(any(target_os = "windows", test))]
fn collect_bounded(
    reader: &mut impl Reader,
    window: &AuditWindow,
    cancelled: &AtomicBool,
    deadline: Instant,
    event_limit: usize,
    byte_limit: usize,
) -> AuditCapture {
    let mut capture = AuditCapture {
        schema_version: "bluefire.ad-smb-native-audit-capture.v1",
        channel: "Security",
        window_start: window.start.clone(),
        window_end: window.end.clone(),
        state: CaptureState::ReadFailed,
        raw_events: Vec::new(),
        utf8_bytes: 0,
        system_error: None,
        handles_closed: false,
        log_continuity_verified: false,
        authenticated_source_claim: false,
        independent_evidence_claim: false,
        effective_access_claim: false,
    };
    loop {
        if cancelled.load(Ordering::Acquire) {
            capture.state = CaptureState::Cancelled;
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            capture.state = CaptureState::Deadline;
            break;
        }
        if capture.raw_events.len() == event_limit {
            capture.state = CaptureState::EventLimit;
            break;
        }
        if capture.utf8_bytes == byte_limit {
            capture.state = CaptureState::ByteLimit;
            break;
        }
        let next = reader.next(
            remaining.as_millis().clamp(1, 1000) as u32,
            MAX_EVENT_BYTES.min(byte_limit - capture.utf8_bytes),
        );
        // A deadline crossing during an API call must not become complete collection.
        if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) {
            capture.state = if cancelled.load(Ordering::Acquire) {
                CaptureState::Cancelled
            } else {
                CaptureState::Deadline
            };
            break;
        }
        match next {
            Ok(Next::End) => {
                capture.state = CaptureState::QueryExhausted;
                break;
            }
            Ok(Next::Event(xml)) => {
                if xml.is_empty() || xml.len() > MAX_EVENT_BYTES || xml.contains('\0') {
                    capture.state = CaptureState::EventRejected;
                    break;
                }
                if xml.len() > byte_limit - capture.utf8_bytes {
                    capture.state = CaptureState::ByteLimit;
                    break;
                }
                capture.utf8_bytes += xml.len();
                capture.raw_events.push(xml);
            }
            Err(error) => {
                capture.system_error = Some(error);
                capture.state = if error == 1460 {
                    CaptureState::Deadline
                } else if error == 122 {
                    if byte_limit - capture.utf8_bytes < MAX_EVENT_BYTES {
                        CaptureState::ByteLimit
                    } else {
                        CaptureState::EventRejected
                    }
                } else {
                    CaptureState::ReadFailed
                };
                break;
            }
        }
    }
    capture.handles_closed = reader.close();
    if !capture.handles_closed {
        capture.state = CaptureState::CleanupUnknown;
    }
    capture
}

/// Caller must first authenticate the member, admit this scope and supervise the process.
/// Query exhaustion is not proof against a cleared, overwritten or delayed Security log.
pub fn collect_local(
    window: &AuditWindow,
    cancelled: &AtomicBool,
) -> Result<AuditCapture, &'static str> {
    collect_local_bounded(
        window,
        cancelled,
        Instant::now() + Duration::from_secs(MAX_SECONDS),
        MAX_EVENTS,
        MAX_TOTAL_BYTES,
    )
}

pub(crate) fn collect_local_bounded(
    window: &AuditWindow,
    cancelled: &AtomicBool,
    deadline: Instant,
    event_limit: usize,
    byte_limit: usize,
) -> Result<AuditCapture, &'static str> {
    if !(1..=MAX_EVENTS).contains(&event_limit)
        || !(1..=MAX_TOTAL_BYTES).contains(&byte_limit)
        || Instant::now() >= deadline
    {
        return Err("audit bounds or original deadline invalid");
    }
    if cancelled.load(Ordering::Acquire) {
        return Err("audit collection was cancelled before query");
    }
    #[cfg(target_os = "windows")]
    {
        let mut reader = windows::LocalReader::open(&window.query())?;
        Ok(collect_bounded(
            &mut reader,
            window,
            cancelled,
            deadline,
            event_limit,
            byte_limit,
        ))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = window.query();
        Err("member-local Windows Security collection is unavailable")
    }
}

#[cfg(test)]
#[path = "ad_smb_events/ad_smb_events_tests.rs"]
mod tests;
