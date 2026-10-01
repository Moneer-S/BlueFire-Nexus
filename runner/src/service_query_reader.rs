//! Fixed Linux property acquisition, not independent observation or cleanup authority.
//!
//! No dispatch is registered. A capture says nothing about cgroups, unit files,
//! service-resource absence, or freshness across separate property queries.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::service_admission::VerifiedServiceAdmission;
use crate::service_observer::{ObservationTarget, PropertyQuery, ReadOutcome};
use crate::service_operation_binding::ServiceOperationBinding;

#[path = "service_query_process.rs"]
mod process;
#[path = "service_query_scope.rs"]
mod scope;

const CLEANUP_RESERVE: Duration = Duration::from_millis(100);
const RECHECK_RESERVE: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryReadIssue {
    AdmissionUnavailable,
    Cancelled,
    Deadline,
    ScopeIdentity,
    BusUnavailable,
    BusChanged,
    ManagerChanged,
    SpawnUnavailable,
    ProcessIdentity,
    OutputUnavailable,
    OutputLimit,
    CleanupUnknown,
}

/// This describes only the query child and its owned process group. It does not
/// attest to service cleanup or to descendants which escaped that group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryChildCleanup {
    ReapedGroupAbsent,
    Unknown,
}

pub struct AcquiredPropertyQuery {
    binding: ServiceOperationBinding,
    query: PropertyQuery,
    capture: process::Capture,
}

impl AcquiredPropertyQuery {
    pub fn binding(&self) -> &ServiceOperationBinding {
        &self.binding
    }
    pub fn query(&self) -> PropertyQuery {
        self.query
    }
    pub fn bytes(&self) -> &[u8] {
        &self.capture.bytes
    }
    pub fn stderr_bytes(&self) -> usize {
        self.capture.stderr_bytes
    }
    pub fn exit_code(&self) -> Option<i32> {
        self.capture.exit_code
    }
    pub fn truncated(&self) -> bool {
        self.capture.truncated
    }
    pub fn issue(&self) -> Option<QueryReadIssue> {
        self.capture.issue
    }
    pub fn cleanup(&self) -> QueryChildCleanup {
        self.capture.cleanup
    }
    pub fn parser_outcome(&self) -> ReadOutcome<'_> {
        match (
            self.capture.issue,
            self.capture.cleanup,
            self.capture.exit_code,
        ) {
            (None, QueryChildCleanup::ReapedGroupAbsent, Some(exit_code)) => {
                ReadOutcome::Finished {
                    bytes: &self.capture.bytes,
                    exit_code,
                    truncated: self.capture.truncated,
                }
            }
            _ => ReadOutcome::Unavailable,
        }
    }
}

fn query_deadlines(deadline: Instant, now: Instant) -> Result<(Instant, Instant), QueryReadIssue> {
    let cleanup_end = deadline
        .checked_sub(RECHECK_RESERVE)
        .ok_or(QueryReadIssue::Deadline)?;
    let query_end = cleanup_end
        .checked_sub(CLEANUP_RESERVE)
        .ok_or(QueryReadIssue::Deadline)?;
    if now >= query_end {
        return Err(QueryReadIssue::Deadline);
    }
    Ok((query_end, cleanup_end))
}

/// Consume only the remaining admission inspection budget. The sole selection
/// is a closed property-query enum; command, endpoint, environment, limits and
/// timeout cannot be supplied by a caller. Cancellation grants no authority.
pub fn acquire_property_query(
    admission: &VerifiedServiceAdmission,
    query: PropertyQuery,
    cancelled: &AtomicBool,
) -> Result<AcquiredPropertyQuery, QueryReadIssue> {
    if cancelled.load(Ordering::Acquire) {
        return Err(QueryReadIssue::Cancelled);
    }
    let manager = admission
        .observation_manager()
        .ok_or(QueryReadIssue::AdmissionUnavailable)?;
    let (query_end, cleanup_end) = query_deadlines(manager.deadline(), Instant::now())?;
    manager
        .recheck()
        .map_err(|_| QueryReadIssue::ManagerChanged)?;
    scope::check_identity(admission, manager.deadline())?;
    let bus = scope::BusAttachment::observe(admission.owner_uid(), manager.deadline())?;
    let target = ObservationTarget::from_binding(admission.operation_binding())
        .map_err(|_| QueryReadIssue::ScopeIdentity)?;
    bus.recheck()?;
    manager
        .recheck()
        .map_err(|_| QueryReadIssue::ManagerChanged)?;
    scope::check_identity(admission, manager.deadline())?;
    if cancelled.load(Ordering::Acquire) {
        return Err(QueryReadIssue::Cancelled);
    }
    if Instant::now() >= query_end {
        return Err(QueryReadIssue::Deadline);
    }
    let mut child = process::LinuxChild::spawn(manager, &target, query)?;
    let mut capture = process::capture(&mut child, query_end, cleanup_end, cancelled);
    // Rechecks never revive the original inspection deadline. If freshness
    // cannot still be established, retain bytes but do not present a finished
    // parser input, even when the query itself exited successfully.
    let recheck = scope::check_identity(admission, manager.deadline())
        .and_then(|_| bus.recheck())
        .and_then(|_| {
            manager
                .recheck()
                .map_err(|_| QueryReadIssue::ManagerChanged)
        });
    if let Err(issue) = recheck {
        capture.issue = Some(issue);
    }
    if Instant::now() >= manager.deadline() {
        capture.issue = Some(QueryReadIssue::Deadline);
    }
    if cancelled.load(Ordering::Acquire) {
        capture.issue.get_or_insert(QueryReadIssue::Cancelled);
    }
    Ok(AcquiredPropertyQuery {
        binding: target.binding().clone(),
        query,
        capture,
    })
}

#[cfg(test)]
#[path = "service_query_reader_tests.rs"]
mod tests;
