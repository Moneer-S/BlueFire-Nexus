//! Audit holds and original-task joins for the existing S3 journal.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{canonical_hash, canonical_json};
use crate::s3_access_binding::audit::CollectionContext;
use crate::s3_access_scope::{digest, lower_hex, Scope};
use crate::s3_audit_binding::{AuditWorkflow, WorkflowLimits};

use super::state::{PolicyPosition, Reserved, Retained};
use super::{Error, Result};

/// Explicit audited reservation; never inferred from legacy history.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuditedReservation {
    pub operation: Reserved,
    pub scope: Scope,
    pub audit_workflow: Value,
    pub profile_digest: String,
    pub task: TaskIdentity,
    pub collection: Option<CollectionContext>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct TaskIdentity {
    pub run_id: String,
    pub manifest_digest: String,
    pub deadline: String,
}

impl std::fmt::Debug for AuditedReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditedReservation")
            .field("operation", &self.operation)
            .field("audit_workflow", &self.audit_workflow)
            .field("profile_digest", &self.profile_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(super) struct CheckedAuditedReservation {
    raw: AuditedReservation,
    workflow: AuditWorkflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Phase {
    Baseline,
    Retest,
}

impl Phase {
    fn original(value: &str) -> Result<Self> {
        match value {
            "baseline" => Ok(Self::Baseline),
            "retest" => Ok(Self::Retest),
            _ => Err(Error::Conflict),
        }
    }

    fn audit(value: &str) -> Result<Self> {
        match value {
            "audit_baseline" => Ok(Self::Baseline),
            "audit_retest" => Ok(Self::Retest),
            _ => Err(Error::Conflict),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Reader {
    Probe,
    Legitimate,
}

impl Reader {
    fn weight(self) -> u64 {
        match self {
            Self::Probe => 1,
            Self::Legitimate => 2,
        }
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Ordinary,
    Read(Phase, Reader),
    Audit(Phase),
}

fn kind(operation: &Reserved) -> Result<Kind> {
    match operation.operation.as_str() {
        "probe_read" => Ok(Kind::Read(
            Phase::original(&operation.phase)?,
            Reader::Probe,
        )),
        "legitimate_read" => Ok(Kind::Read(
            Phase::original(&operation.phase)?,
            Reader::Legitimate,
        )),
        "collect_audit" => Ok(Kind::Audit(Phase::audit(&operation.phase)?)),
        "inspect_policy" | "apply_policy" | "rollback_policy" | "reconcile_policy"
        | "prepare_fixture" | "reconcile_fixture" | "cleanup_fixture" => Ok(Kind::Ordinary),
        _ => Err(Error::Conflict),
    }
}

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}

fn add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right).ok_or(Error::Budget)
}

impl AuditedReservation {
    /// A new reservation must join the current verified scope and native profile.
    pub(super) fn checked(
        &self,
        scope: &Scope,
        actual_profile_digest: &str,
    ) -> Result<CheckedAuditedReservation> {
        require(
            canonical_json(&serde_json::to_value(&self.scope).map_err(|_| Error::Corrupt)?)
                == canonical_json(&serde_json::to_value(scope).map_err(|_| Error::Corrupt)?),
        )?;
        require(self.profile_digest == actual_profile_digest)?;
        self.checked_historical()
    }

    /// Saved scope/profile validate historical consistency, never current execution authority.
    pub(super) fn checked_historical(&self) -> Result<CheckedAuditedReservation> {
        let scope = &self.scope;
        let operation = &self.operation;
        require(
            digest(&self.profile_digest)
                && digest(&self.task.manifest_digest)
                && (1..=128).contains(&self.task.run_id.len())
                && self
                    .task
                    .run_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        )?;
        let deadline =
            crate::s3_access_scope::utc_time(&self.task.deadline).map_err(|_| Error::Conflict)?;
        require(
            crate::s3_access_scope::utc_time(&scope.created_at).map_err(|_| Error::Conflict)?
                < deadline
                && deadline
                    <= crate::s3_access_scope::utc_time(&scope.expires_at)
                        .map_err(|_| Error::Conflict)?,
        )?;
        let workflow = AuditWorkflow::from_json(
            canonical_json(&self.audit_workflow).as_bytes(),
            scope,
            &operation.runtime_digest,
            &operation.worker_generation,
        )
        .map_err(|_| Error::Conflict)?;
        require(
            operation.workflow_id == workflow.workflow_id()
                && operation.environment_id == workflow.environment_id()
                && operation.resource_key == workflow.resource_key()
                && operation.scope_digest == workflow.scope_digest()
                && operation.api_limit == scope.limits.api_calls
                && operation.session_limit == scope.limits.sessions
                && operation.business_attempt_limit == scope.limits.business_attempts
                && digest(&operation.request_digest)
                && digest(&operation.approval_digest)
                && lower_hex(&operation.request_id, 64)
                && lower_hex(&operation.launch_id, 64)
                && (1..=128).contains(&operation.operation_id.len())
                && operation.operation_id.as_bytes()[0].is_ascii_alphanumeric()
                && operation
                    .operation_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && operation.revision <= 1_000_000,
        )?;
        let maximum = match operation.operation.as_str() {
            "inspect_policy" | "reconcile_policy" => 2,
            "probe_read" | "apply_policy" | "rollback_policy" => 4,
            "legitimate_read" | "reconcile_fixture" => 5,
            "prepare_fixture" => 6,
            "cleanup_fixture" => 7,
            "collect_audit" => 9,
            _ => return Err(Error::Conflict),
        };
        require(operation.max_sends == maximum)?;
        kind(operation)?;
        if let Some(context) = &self.collection {
            require(
                operation.operation == "collect_audit"
                    && context.deadline == self.task.deadline
                    && operation.phase == format!("audit_{}", context.phase)
                    && operation.operation_id != context.original_operation_id,
            )?;
            context
                .validate(scope, &workflow)
                .map_err(|_| Error::Conflict)?;
        }
        let phase = match operation.operation.as_str() {
            "inspect_policy" => Some("inspect"),
            "apply_policy" => Some("apply"),
            "rollback_policy" => Some("rollback"),
            "reconcile_policy" => Some("reconcile"),
            "prepare_fixture" => Some("prepare"),
            "reconcile_fixture" => Some("reconcile_fixtures"),
            "cleanup_fixture" => Some("cleanup"),
            _ => None,
        };
        if let Some(phase) = phase {
            require(operation.phase == phase)?;
        }
        if let Some(authority) = &operation.fixture_authority_digest {
            require(digest(authority))?;
        }
        if let Some(fixture) = &operation.fixture {
            require(operation.fixture_authority_digest.is_some())?;
            fixture
                .validate(&operation.operation, scope)
                .map_err(|_| Error::Conflict)?;
        } else {
            require(!matches!(
                operation.operation.as_str(),
                "prepare_fixture" | "reconcile_fixture" | "cleanup_fixture"
            ))?;
        }
        Ok(CheckedAuditedReservation {
            raw: self.clone(),
            workflow,
        })
    }
}

impl CheckedAuditedReservation {
    pub(super) fn raw(&self) -> &AuditedReservation {
        &self.raw
    }
    pub(super) fn operation(&self) -> &Reserved {
        &self.raw.operation
    }
    pub(super) fn workflow(&self) -> &AuditWorkflow {
        &self.workflow
    }
    pub(super) fn profile_digest(&self) -> &str {
        &self.raw.profile_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct OriginalRead {
    pub operation_id: String,
    pub request_digest: String,
    pub reservation_digest: String,
    pub worker_result_digest: String,
    pub run_id: String,
    pub manifest_digest: String,
    pub deadline: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AuditHolds {
    pub unbound_audit_batches: u64,
    pub unbound_original_reads: u64,
    pub total_api_commitment: u64,
    pub total_session_commitment: u64,
    pub total_business_commitment: u64,
    pub audit_budget: WorkflowLimits,
    pub original_pair: Option<[OriginalRead; 2]>,
}

#[derive(Clone, Default)]
pub(super) struct AuditState {
    reservations: BTreeMap<String, CheckedAuditedReservation>,
}

#[derive(Default)]
struct Slots {
    reads: BTreeMap<(Phase, Reader), String>,
    phase_operations: BTreeMap<Phase, (String, u64)>,
    audits: BTreeSet<Phase>,
}

impl Slots {
    fn include(&mut self, operation: &Reserved) -> Result<()> {
        match kind(operation)? {
            Kind::Read(phase, reader) => {
                if self.reads.contains_key(&(phase, reader)) {
                    return Err(Error::AlreadyReserved);
                }
                let identity = (operation.operation_id.clone(), operation.revision);
                if let Some(original) = self.phase_operations.get(&phase) {
                    require(original == &identity)?;
                } else {
                    self.phase_operations.insert(phase, identity);
                }
                self.reads
                    .insert((phase, reader), operation.request_digest.clone());
            }
            Kind::Audit(phase) => {
                if !self.audits.insert(phase) {
                    return Err(Error::AlreadyReserved);
                }
            }
            Kind::Ordinary => {}
        }
        Ok(())
    }

    fn remaining_weight(&self) -> u64 {
        [Phase::Baseline, Phase::Retest]
            .into_iter()
            .map(|phase| {
                [Reader::Probe, Reader::Legitimate]
                    .into_iter()
                    .filter(|reader| !self.reads.contains_key(&(phase, *reader)))
                    .map(Reader::weight)
                    .sum::<u64>()
            })
            .sum()
    }

    fn remaining_read_sends(&self) -> u64 {
        [Phase::Baseline, Phase::Retest]
            .into_iter()
            .map(|phase| {
                [(Reader::Probe, 4), (Reader::Legitimate, 5)]
                    .into_iter()
                    .filter(|(reader, _)| !self.reads.contains_key(&(phase, *reader)))
                    .map(|(_, sends)| sends)
                    .sum::<u64>()
            })
            .sum()
    }

    fn pair(
        &self,
        phase: Phase,
        history: &[&Retained],
        reservations: &BTreeMap<String, CheckedAuditedReservation>,
    ) -> Result<[OriginalRead; 2]> {
        let original = |reader| -> Result<OriginalRead> {
            let request = self.reads.get(&(phase, reader)).ok_or(Error::Lifecycle)?;
            let retained = history
                .iter()
                .find(|old| old.reserved.request_digest == *request)
                .ok_or(Error::Corrupt)?;
            if !matches!(retained.completion, Some((_, _, true))) {
                return Err(Error::RecoveryRequired);
            }
            let result = retained
                .completion_result_digest
                .as_ref()
                .ok_or(Error::RecoveryRequired)?;
            let task = &reservations.get(request).ok_or(Error::Conflict)?.raw.task;
            require(
                digest(&retained.digest)
                    && digest(result)
                    && result != &canonical_hash(&Value::Null),
            )?;
            Ok(OriginalRead {
                operation_id: retained.reserved.operation_id.clone(),
                request_digest: request.clone(),
                reservation_digest: retained.digest.clone(),
                worker_result_digest: result.clone(),
                run_id: task.run_id.clone(),
                manifest_digest: task.manifest_digest.clone(),
                deadline: task.deadline.clone(),
            })
        };
        Ok([original(Reader::Probe)?, original(Reader::Legitimate)?])
    }
}

fn history_for<'a>(history: &[&'a Retained], resource: &str) -> Result<Vec<&'a Retained>> {
    if history.len() > 4096 {
        return Err(Error::Budget);
    }
    let history: Vec<_> = history
        .iter()
        .copied()
        .filter(|old| old.reserved.resource_key == resource)
        .collect();
    if history
        .iter()
        .any(|old| !matches!(old.completion, Some((_, _, true))))
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(history)
}

impl AuditState {
    pub(super) fn reservation(&self, request: &str) -> Result<&CheckedAuditedReservation> {
        self.reservations.get(request).ok_or(Error::Conflict)
    }
    pub(super) fn check_legacy(&self, history: &[&Retained], next: &Reserved) -> Result<()> {
        history_for(history, &next.resource_key)?;
        require(
            !self
                .reservations
                .values()
                .any(|old| old.operation().resource_key == next.resource_key),
        )
    }

    /// The caller supplies the unchanged ordinary required_calls/fixture floor, not a DTO value.
    pub(super) fn check_reserve(
        &self,
        history: &[&Retained],
        next: &CheckedAuditedReservation,
        ordinary_required_calls: u64,
    ) -> Result<AuditHolds> {
        let operation = next.operation();
        if self.reservations.contains_key(&operation.request_digest)
            || history.iter().any(|old| {
                old.reserved.request_digest == operation.request_digest
                    || old.reserved.request_id == operation.request_id
                    || old.reserved.launch_id == operation.launch_id
            })
        {
            return Err(Error::AlreadyReserved);
        }
        let history = history_for(history, &operation.resource_key)?;
        let matching: Vec<_> = self
            .reservations
            .values()
            .filter(|old| old.operation().resource_key == operation.resource_key)
            .collect();
        require(matching.len() == history.len())?;
        let mut slots = Slots::default();
        for old in &history {
            let checked = self
                .reservations
                .get(&old.reserved.request_digest)
                .ok_or(Error::Conflict)?;
            let reserved = checked.operation();
            require(
                reserved == &old.reserved
                    && checked.workflow().digest() == next.workflow().digest()
                    && checked.profile_digest() == next.profile_digest()
                    && reserved.fixture_authority_digest == operation.fixture_authority_digest
                    && reserved.revision <= operation.revision
                    && (reserved.operation_id != operation.operation_id
                        || (reserved.phase == operation.phase
                            && reserved.revision == operation.revision
                            && (reserved.operation != operation.operation
                                || reserved.fixture.as_ref().map(|f| &f.purpose)
                                    != operation.fixture.as_ref().map(|f| &f.purpose)))),
            )?;
            if let Kind::Audit(_) = kind(reserved)? {
                require(
                    !old.write_debited
                        && old.fixture_position.is_none()
                        && matches!(old.completion, Some((_, PolicyPosition::Unknown, true))),
                )?;
            }
            slots.include(reserved)?;
        }
        let next_kind = kind(operation)?;
        let original_pair = match next_kind {
            Kind::Audit(phase) => {
                require(ordinary_required_calls == 0 && operation.fixture.is_none())?;
                let originals = slots.pair(phase, &history, &self.reservations)?;
                if let Some(context) = &next.raw.collection {
                    for (expected, actual) in originals.iter().zip(&context.reads) {
                        require(
                            expected.operation_id == context.original_operation_id
                                && expected.request_digest == actual.request_digest
                                && expected.reservation_digest == actual.reservation_digest
                                && expected.worker_result_digest == actual.worker_result_digest
                                && expected.run_id == actual.run_id
                                && expected.manifest_digest == actual.manifest_digest
                                && expected.deadline == actual.deadline,
                        )?;
                    }
                    require(
                        next.raw.task.run_id != originals[0].run_id
                            && next.raw.task.run_id != originals[1].run_id
                            && next.raw.task.manifest_digest != originals[0].manifest_digest
                            && next.raw.task.manifest_digest != originals[1].manifest_digest,
                    )?;
                }
                Some(originals)
            }
            _ => {
                require(ordinary_required_calls >= operation.max_sends)?;
                None
            }
        };
        let prior_audits = slots.audits.len() as u64;
        slots.include(operation)?;
        let historic_calls = history
            .iter()
            .try_fold(0, |total, old| add(total, old.reserved.max_sends))?;
        let unbound_before = 2_u64.checked_sub(prior_audits).ok_or(Error::Corrupt)?;
        // Existing recovery floors may already cover future reads; retain their union.
        let remaining_reads = slots.remaining_read_sends();
        let ordinary = if matches!(next_kind, Kind::Audit(_)) {
            remaining_reads
        } else {
            ordinary_required_calls.max(add(operation.max_sends, remaining_reads)?)
        };
        let calls = add(add(historic_calls, ordinary)?, unbound_before * 9)?;
        let mut sessions = 0;
        let mut attempts = 0;
        for old in &history {
            match kind(&old.reserved)? {
                Kind::Read(_, reader) => {
                    sessions = add(sessions, 1)?;
                    attempts = add(attempts, reader.weight())?;
                }
                Kind::Audit(_) => sessions = add(sessions, 1)?,
                Kind::Ordinary => {}
            }
        }
        match next_kind {
            Kind::Read(_, reader) => {
                sessions = add(sessions, 1)?;
                attempts = add(attempts, reader.weight())?;
            }
            Kind::Audit(_) => sessions = add(sessions, 1)?,
            Kind::Ordinary => {}
        }
        let original_remaining = 4_u64
            .checked_sub(slots.reads.len() as u64)
            .ok_or(Error::Corrupt)?;
        let audit_remaining = 2_u64
            .checked_sub(slots.audits.len() as u64)
            .ok_or(Error::Corrupt)?;
        sessions = add(add(sessions, original_remaining)?, audit_remaining)?;
        attempts = add(attempts, slots.remaining_weight())?;
        if calls > operation.api_limit
            || sessions > operation.session_limit
            || attempts > operation.business_attempt_limit
        {
            return Err(Error::Budget);
        }
        Ok(AuditHolds {
            unbound_audit_batches: audit_remaining,
            unbound_original_reads: original_remaining,
            total_api_commitment: calls,
            total_session_commitment: sessions,
            total_business_commitment: attempts,
            audit_budget: next.workflow().budget().workflow.clone(),
            original_pair,
        })
    }

    /// Integrate only inside the candidate ledger transition committed by its existing append.
    pub(super) fn apply_reservation(
        &mut self,
        history: &[&Retained],
        next: CheckedAuditedReservation,
        ordinary_required_calls: u64,
    ) -> Result<AuditHolds> {
        if self.reservations.len() >= 4096 {
            return Err(Error::Budget);
        }
        let holds = self.check_reserve(history, &next, ordinary_required_calls)?;
        self.reservations
            .insert(next.operation().request_digest.clone(), next);
        Ok(holds)
    }
}

#[cfg(test)]
#[path = "s3_reservation_audit_tests.rs"]
mod tests;
