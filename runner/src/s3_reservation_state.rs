//! Retained S3 ledger transitions. Worker observations are not independent audit.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_hash, canonical_json};

use super::{Error, Result};

pub(super) const SCHEMA: &str = "bluefire.s3-send-entry.v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Reserved {
    pub workflow_id: String,
    pub operation_id: String,
    pub environment_id: String,
    pub resource_key: String,
    pub scope_digest: String,
    pub request_digest: String,
    pub request_id: String,
    pub launch_id: String,
    pub approval_digest: String,
    pub runtime_digest: String,
    pub worker_generation: String,
    pub phase: String,
    pub operation: String,
    pub revision: u64,
    pub max_sends: u64,
    pub api_limit: u64,
    pub session_limit: u64,
    pub business_attempt_limit: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyPosition {
    Before,
    After,
    Drift,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Record {
    Reservation {
        operation: Box<Reserved>,
    },
    Debit {
        reservation_digest: String,
        sequence: u64,
        preview_digest: String,
        is_write: bool,
    },
    Completion {
        reservation_digest: String,
        result_digest: String,
        observed: bool,
        policy_position: PolicyPosition,
        cleanup_verified: bool,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub schema_version: String,
    pub sequence: usize,
    pub previous_hash: String,
    pub record: Record,
}

#[derive(Clone)]
pub(super) struct Retained {
    pub digest: String,
    pub reserved: Reserved,
    pub debits: u64,
    pub write_debited: bool,
    pub completion: Option<(bool, PolicyPosition, bool)>,
}

#[derive(Clone)]
pub(super) struct Ledger {
    pub requests: BTreeMap<String, Retained>,
    pub order: Vec<String>,
    pub entries: usize,
    pub previous_hash: String,
    pub bytes: usize,
}

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(Error::Corrupt)
    }
}

impl Ledger {
    pub fn load(bytes: &[u8], enrollment: &str) -> Result<Self> {
        let mut ledger = Self {
            requests: BTreeMap::new(),
            order: Vec::new(),
            entries: 0,
            bytes: bytes.len(),
            previous_hash: canonical_hash(
                &serde_json::json!({"schema_version":SCHEMA,"enrollment_digest":enrollment}),
            ),
        };
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            require(
                line.len() <= 16 * 1024 && line.last() == Some(&b'\n') && ledger.entries < 4096,
            )?;
            let entry: Entry = serde_json::from_slice(line).map_err(|_| Error::Corrupt)?;
            let value = serde_json::to_value(&entry).map_err(|_| Error::Corrupt)?;
            require(
                canonical_json(&value).as_bytes() == &line[..line.len() - 1]
                    && entry.schema_version == SCHEMA
                    && entry.sequence == ledger.entries + 1
                    && entry.previous_hash == ledger.previous_hash,
            )?;
            let hash = canonical_hash(&value);
            ledger.apply(entry.record, hash.clone())?;
            ledger.entries += 1;
            ledger.previous_hash = hash;
        }
        Ok(ledger)
    }

    pub fn check_reserve(&self, next: &Reserved) -> Result<()> {
        if self.requests.contains_key(&next.request_digest)
            || self.requests.values().any(|old| {
                old.reserved.request_id == next.request_id
                    || old.reserved.launch_id == next.launch_id
            })
        {
            return Err(Error::AlreadyReserved);
        }
        let history: Vec<_> = self
            .order
            .iter()
            .map(|key| &self.requests[key])
            .filter(|old| old.reserved.resource_key == next.resource_key)
            .collect();
        // An unlocked lease or parent-death signal is not worker-absence proof.
        // Read-only cloud reconciliation must also wait for original-task recovery.
        if history
            .iter()
            .any(|old| !matches!(old.completion, Some((_, _, true))))
        {
            return Err(Error::RecoveryRequired);
        }
        for old in &history {
            if old.reserved.workflow_id != next.workflow_id
                || old.reserved.environment_id != next.environment_id
                || old.reserved.scope_digest != next.scope_digest
                || old.reserved.runtime_digest != next.runtime_digest
                || old.reserved.worker_generation != next.worker_generation
                || old.reserved.api_limit != next.api_limit
                || old.reserved.session_limit != next.session_limit
                || old.reserved.business_attempt_limit != next.business_attempt_limit
                || old.reserved.revision > next.revision
                || (old.reserved.operation_id == next.operation_id
                    && (old.reserved.phase != next.phase
                        || old.reserved.operation == next.operation
                        || old.reserved.revision != next.revision))
            {
                return Err(Error::Conflict);
            }
        }
        // Reservations are never refunded, including launches with no send.
        // Per-send debits separately prove what could actually leave the worker.
        let calls: u64 = history.iter().map(|old| old.reserved.max_sends).sum();
        let fixed_sends = match next.operation.as_str() {
            "inspect_policy" | "reconcile_policy" => 2,
            "probe_read" | "apply_policy" | "rollback_policy" => 4,
            "legitimate_read" => 5,
            _ => return Err(Error::Conflict),
        };
        if next.max_sends != fixed_sends {
            return Err(Error::Conflict);
        }
        let rollback_reserved = history.iter().any(|old| old.reserved.phase == "rollback");
        let retest_reserved = history.iter().any(|old| old.reserved.phase == "retest");
        let required_calls = match next.phase.as_str() {
            "apply" => 21,
            "rollback" => 6,
            "reconcile" if !rollback_reserved => 8 + if retest_reserved { 0 } else { 9 },
            "retest" if !rollback_reserved => {
                next.max_sends + 6 + if next.operation == "probe_read" { 5 } else { 0 }
            }
            "baseline" if next.operation == "probe_read" => 9,
            _ => next.max_sends,
        };
        if calls + required_calls > next.api_limit {
            return Err(Error::Budget);
        }
        let sessions = history
            .iter()
            .filter(|old| {
                matches!(
                    old.reserved.operation.as_str(),
                    "probe_read" | "legitimate_read"
                )
            })
            .count() as u64;
        let attempts: u64 = history
            .iter()
            .map(|old| business_attempts(&old.reserved.operation))
            .sum();
        let holds_pair = next.phase == "apply"
            || (matches!(next.phase.as_str(), "baseline" | "retest")
                && next.operation == "probe_read");
        let required_sessions = if holds_pair {
            2
        } else {
            u64::from(matches!(
                next.operation.as_str(),
                "probe_read" | "legitimate_read"
            ))
        };
        let required_attempts = if holds_pair {
            3
        } else {
            business_attempts(&next.operation)
        };
        if sessions + required_sessions > next.session_limit
            || attempts + required_attempts > next.business_attempt_limit
        {
            return Err(Error::Budget);
        }
        let mut position = PolicyPosition::Unknown;
        let mut uncertain_write = false;
        let mut inspected = false;
        let mut baseline_probe = false;
        let mut baseline_legitimate = false;
        for old in &history {
            if old.write_debited {
                uncertain_write = true;
            }
            if let Some((observed, reported_position, cleanup)) = old.completion {
                if cleanup && observed {
                    inspected |= old.reserved.operation == "inspect_policy";
                    baseline_probe |=
                        old.reserved.phase == "baseline" && old.reserved.operation == "probe_read";
                    baseline_legitimate |= old.reserved.phase == "baseline"
                        && old.reserved.operation == "legitimate_read";
                    if matches!(
                        old.reserved.operation.as_str(),
                        "inspect_policy" | "apply_policy" | "rollback_policy" | "reconcile_policy"
                    ) {
                        position = reported_position;
                        uncertain_write = position == PolicyPosition::Unknown
                            || position == PolicyPosition::Drift;
                    }
                }
            }
        }
        if uncertain_write && next.operation != "reconcile_policy" {
            return Err(Error::ReconcileRequired);
        }
        let allowed = match next.phase.as_str() {
            "inspect" => !history.iter().any(|old| old.write_debited),
            "baseline" => inspected && position == PolicyPosition::Before,
            "apply" => {
                baseline_probe
                    && baseline_legitimate
                    && position == PolicyPosition::Before
                    && !history
                        .iter()
                        .any(|old| old.reserved.operation == "apply_policy")
            }
            "retest" => position == PolicyPosition::After,
            "rollback" => {
                position == PolicyPosition::After
                    && !history
                        .iter()
                        .any(|old| old.reserved.operation == "rollback_policy")
            }
            "reconcile" => {
                baseline_probe && baseline_legitimate
                    || history.iter().any(|old| {
                        matches!(
                            old.reserved.operation.as_str(),
                            "apply_policy" | "rollback_policy"
                        )
                    })
            }
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(Error::Lifecycle)
        }
    }

    pub fn apply(&mut self, record: Record, hash: String) -> Result<()> {
        match record {
            Record::Reservation { operation } => {
                self.check_reserve(&operation)?;
                self.order.push(operation.request_digest.clone());
                self.requests.insert(
                    operation.request_digest.clone(),
                    Retained {
                        digest: hash,
                        reserved: *operation,
                        debits: 0,
                        write_debited: false,
                        completion: None,
                    },
                );
            }
            Record::Debit {
                reservation_digest,
                sequence,
                preview_digest,
                is_write,
            } => {
                require(super::digest(&preview_digest))?;
                let retained = self
                    .requests
                    .values_mut()
                    .find(|old| old.digest == reservation_digest)
                    .ok_or(Error::Corrupt)?;
                require(
                    retained.completion.is_none()
                        && sequence == retained.debits + 1
                        && sequence <= retained.reserved.max_sends
                        && is_write
                            == (sequence == 3
                                && matches!(
                                    retained.reserved.operation.as_str(),
                                    "apply_policy" | "rollback_policy"
                                )),
                )?;
                retained.debits = sequence;
                retained.write_debited |= is_write;
            }
            Record::Completion {
                reservation_digest,
                result_digest,
                observed,
                policy_position,
                cleanup_verified,
            } => {
                require(super::digest(&result_digest))?;
                let retained = self
                    .requests
                    .values_mut()
                    .find(|old| old.digest == reservation_digest)
                    .ok_or(Error::Corrupt)?;
                require(retained.completion.is_none() && (!observed || retained.debits > 0))?;
                retained.completion = Some((observed, policy_position, cleanup_verified));
            }
        }
        Ok(())
    }
}

fn business_attempts(operation: &str) -> u64 {
    match operation {
        "probe_read" => 1,
        "legitimate_read" => 2,
        _ => 0,
    }
}
