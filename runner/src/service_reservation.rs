//! Enrollment-owned, append-only service reservations, never effect receipts.
//!
//! Only authenticated native admission may reserve an operation. A reservation
//! surviving interruption is uncertain; neither a request exit nor this ledger
//! proves service ownership, effects or cleanup. Same-account/privileged edits
//! and restoring an older complete filesystem image are outside this boundary.

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use crate::canonical::{canonical_hash, canonical_json, sha256_hex};
use crate::service_admission::VerifiedServiceAdmission;
use crate::service_operation_binding::ServiceOperationBinding;

#[cfg(target_os = "linux")]
#[path = "service_reservation_storage.rs"]
mod storage;

#[cfg(target_os = "linux")]
const SCHEMA: &str = "bluefire.service-reservation-entry.v1";
#[cfg(target_os = "linux")]
const SETUP: [&str; 4] = ["create_unit", "reload", "enable", "start"];
#[cfg(target_os = "linux")]
const CLEANUP: [&str; 5] = [
    "stop",
    "disable",
    "remove_links",
    "remove_unit",
    "reload_after_cleanup",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationError {
    UnsupportedPlatform,
    InvalidConfiguration,
    AdmissionMismatch,
    Expired,
    StorageUnsafe,
    StorageCorrupt,
    StorageIo,
    StorageFull,
    Busy,
    OperationConflict,
    ResourceConflict,
    PriorUncertain,
    LifecycleRefused,
    ReconciliationMismatch,
}

impl fmt::Display for ReservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => "service reservation requires the supported Linux host",
            Self::InvalidConfiguration => "service reservation configuration is invalid",
            Self::AdmissionMismatch => "service reservation differs from authenticated admission",
            Self::Expired => "service operation authority is outside its finite time window",
            Self::StorageUnsafe => "service reservation storage identity or permissions changed",
            Self::StorageCorrupt => "service reservation storage requires recovery",
            Self::StorageIo => "service reservation storage could not be durably committed",
            Self::StorageFull => {
                "service reservation storage is full; retained records cannot be evicted"
            }
            Self::Busy => "service reservation storage is in use",
            Self::OperationConflict => {
                "service operation was already reserved with different contents"
            }
            Self::ResourceConflict => {
                "owned service resource differs from its retained reservation"
            }
            Self::PriorUncertain => "earlier service operation requires independent reconciliation",
            Self::LifecycleRefused => "service operation does not follow the retained lifecycle",
            Self::ReconciliationMismatch => {
                "service reconciliation differs from its exact reservation"
            }
        })
    }
}
impl std::error::Error for ReservationError {}

#[derive(Clone, Copy, Debug)]
pub struct ReservationLimits {
    pub max_bytes: usize,
    pub max_records: usize,
}
impl Default for ReservationLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_records: 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportedOutcome {
    Succeeded,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReconciledDisposition {
    OperationSucceeded,
    OperationFailed,
    CleanupComplete,
}

/// Only the trusted independent-observer path may construct this token. It has
/// deliberately no public deserializer or unchecked constructor.
pub struct VerifiedServiceReconciliation {
    reservation_digest: String,
    disposition: ReconciledDisposition,
    observation_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceReservation {
    digest: String,
    record: ReservedOperation,
}
impl ServiceReservation {
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn operation_id(&self) -> &str {
        &self.record.operation_id
    }
    pub fn task_id(&self) -> &str {
        &self.record.task_id
    }
    pub fn resource_key(&self) -> &str {
        &self.record.resource_key
    }
}

/// A new reservation is single-owner and is never reissued by deduplication.
/// Effect dispatch must consume this value, then still check live target identity.
#[derive(Debug)]
pub struct NewServiceReservation {
    reservation: ServiceReservation,
}
impl NewServiceReservation {
    pub fn reservation(&self) -> &ServiceReservation {
        &self.reservation
    }
    pub fn into_record(self) -> ServiceReservation {
        self.reservation
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReservationState {
    Uncertain,
    Reconciled(ReconciledDisposition),
}

#[derive(Debug)]
pub enum ReservationDecision {
    Reserved(NewServiceReservation),
    Existing {
        reservation: ServiceReservation,
        state: ReservationState,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReservedOperation {
    binding: String,
    binding_digest: String,
    resource_key: String,
    operation_id: String,
    grant_digest: String,
    task_id: String,
    enrollment_digest: String,
}

// This projection only consumes the already closed, validated immutable v1
// binding. It does not replace or widen that document's parser or semantics.
#[cfg(target_os = "linux")]
#[derive(Deserialize)]
struct BindingProjection {
    identity: IdentityProjection,
    identity_digest: String,
    journal_request_id: String,
    journal_revision: u8,
    operation_id: String,
    operation: String,
    reviewed_scope_digest: String,
    manager_installation_digest: String,
    payload_installation_digest: String,
}
#[cfg(target_os = "linux")]
#[derive(Deserialize)]
struct IdentityProjection {
    authorization_digest: String,
    runner_profile_id: String,
    workspace_id: String,
    target_scope_digest: String,
    owner_uid: u32,
    boot_id: String,
    manager_id: String,
    unit_nonce: String,
    unit_content_digest: String,
    created_at: String,
    cleanup_due_at: String,
}
#[cfg(target_os = "linux")]
impl BindingProjection {
    fn parse(binding: &ServiceOperationBinding) -> Result<Self, ReservationError> {
        serde_json::from_str(binding.canonical_json()).map_err(|_| ReservationError::StorageCorrupt)
    }
    fn resource_key(&self) -> String {
        // The unit name persists across manager/boot changes. Those identities
        // belong in the immutable reservation, not in a key that could bypass
        // an unresolved obligation after a manager restart or reboot.
        canonical_hash(
            &serde_json::json!({ "owner_uid": self.identity.owner_uid, "unit_nonce": self.identity.unit_nonce }),
        )
    }
    fn same_resource(&self, previous: &Self) -> bool {
        self.identity_digest == previous.identity_digest
            && self.reviewed_scope_digest == previous.reviewed_scope_digest
            && self.journal_request_id == previous.journal_request_id
            && self.manager_installation_digest == previous.manager_installation_digest
            && self.payload_installation_digest == previous.payload_installation_digest
    }
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerEntry {
    schema_version: String,
    sequence: usize,
    previous_hash: String,
    record: Record,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    Reservation {
        operation: ReservedOperation,
    },
    Outcome {
        reservation_digest: String,
        outcome: ReportedOutcome,
        evidence_digest: String,
    },
    Reconciliation {
        reservation_digest: String,
        disposition: ReconciledDisposition,
        observation_digest: String,
    },
}

#[cfg(target_os = "linux")]
struct Retained {
    reservation: ServiceReservation,
    outcome: Option<(ReportedOutcome, String)>,
    reconciliation: Option<(ReconciledDisposition, String)>,
}
#[cfg(target_os = "linux")]
impl Retained {
    fn state(&self) -> ReservationState {
        self.reconciliation
            .as_ref()
            .map_or(ReservationState::Uncertain, |(disposition, _)| {
                ReservationState::Reconciled(*disposition)
            })
    }
}
#[cfg(target_os = "linux")]
struct Ledger {
    by_operation: BTreeMap<String, Retained>,
    resources: BTreeMap<String, Vec<String>>,
    entries: usize,
    previous_hash: String,
    byte_count: usize,
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
#[cfg(target_os = "linux")]
fn identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
#[cfg(target_os = "linux")]
fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>, ReservationError> {
    serde_json::to_value(value)
        .map(|value| canonical_json(&value).into_bytes())
        .map_err(|_| ReservationError::StorageCorrupt)
}

#[cfg(target_os = "linux")]
impl Ledger {
    fn check_next(&self, next: &BindingProjection) -> Result<(), ReservationError> {
        let history = self.resources.get(&next.resource_key());
        let Some(history) = history else {
            // A cleanup operation cannot manufacture receipt ownership for a
            // previously unreserved service, even when v1 metadata parses.
            return if next.operation == "create_unit" && next.journal_revision == 1 {
                Ok(())
            } else {
                Err(ReservationError::LifecycleRefused)
            };
        };
        let last = &self.by_operation[history.last().expect("nonempty resource history")];
        let previous = BindingProjection::parse(
            &ServiceOperationBinding::from_json(last.reservation.record.binding.as_bytes())
                .map_err(|_| ReservationError::StorageCorrupt)?,
        )?;
        if !next.same_resource(&previous) {
            return Err(ReservationError::ResourceConflict);
        }
        let Some((disposition, _)) = last.reconciliation.as_ref() else {
            return Err(ReservationError::PriorUncertain);
        };
        if next.journal_revision != previous.journal_revision + 2 {
            return Err(ReservationError::LifecycleRefused);
        }
        let permitted = if *disposition == ReconciledDisposition::CleanupComplete {
            false
        } else if let Some(index) = CLEANUP.iter().position(|name| *name == previous.operation) {
            if *disposition == ReconciledDisposition::OperationFailed {
                next.operation == previous.operation
            } else {
                CLEANUP
                    .get(index + 1)
                    .is_some_and(|name| *name == next.operation)
            }
        } else if *disposition == ReconciledDisposition::OperationFailed {
            next.operation == "stop"
        } else {
            next.operation == "stop"
                || SETUP
                    .iter()
                    .position(|name| *name == previous.operation)
                    .and_then(|index| SETUP.get(index + 1))
                    .is_some_and(|name| *name == next.operation)
        };
        if permitted {
            Ok(())
        } else {
            Err(ReservationError::LifecycleRefused)
        }
    }

    fn apply(
        &mut self,
        record: Record,
        hash: String,
        enrollment: &str,
    ) -> Result<(), ReservationError> {
        match record {
            Record::Reservation { operation } => {
                let binding = ServiceOperationBinding::from_json(operation.binding.as_bytes())
                    .map_err(|_| ReservationError::StorageCorrupt)?;
                let projection = BindingProjection::parse(&binding)?;
                if operation.binding != binding.canonical_json()
                    || operation.binding_digest != binding.digest()
                    || operation.resource_key != projection.resource_key()
                    || operation.operation_id != projection.operation_id
                    || operation.enrollment_digest != enrollment
                    || !digest(&operation.grant_digest)
                    || !identifier(&operation.task_id)
                    || projection.reviewed_scope_digest != projection.identity.authorization_digest
                    || self.by_operation.contains_key(&operation.operation_id)
                {
                    return Err(ReservationError::StorageCorrupt);
                }
                self.check_next(&projection)
                    .map_err(|_| ReservationError::StorageCorrupt)?;
                self.resources
                    .entry(operation.resource_key.clone())
                    .or_default()
                    .push(operation.operation_id.clone());
                self.by_operation.insert(
                    operation.operation_id.clone(),
                    Retained {
                        reservation: ServiceReservation {
                            digest: hash,
                            record: operation,
                        },
                        outcome: None,
                        reconciliation: None,
                    },
                );
            }
            Record::Outcome {
                reservation_digest,
                outcome,
                evidence_digest,
            } => {
                if !digest(&evidence_digest) {
                    return Err(ReservationError::StorageCorrupt);
                }
                let retained = self
                    .by_operation
                    .values_mut()
                    .find(|retained| retained.reservation.digest == reservation_digest)
                    .ok_or(ReservationError::StorageCorrupt)?;
                if retained.outcome.is_some() || retained.reconciliation.is_some() {
                    return Err(ReservationError::StorageCorrupt);
                }
                retained.outcome = Some((outcome, evidence_digest));
            }
            Record::Reconciliation {
                reservation_digest,
                disposition,
                observation_digest,
            } => {
                if !digest(&observation_digest) {
                    return Err(ReservationError::StorageCorrupt);
                }
                let retained = self
                    .by_operation
                    .values_mut()
                    .find(|retained| retained.reservation.digest == reservation_digest)
                    .ok_or(ReservationError::StorageCorrupt)?;
                let binding = ServiceOperationBinding::from_json(
                    retained.reservation.record.binding.as_bytes(),
                )
                .map_err(|_| ReservationError::StorageCorrupt)?;
                if disposition == ReconciledDisposition::CleanupComplete
                    && BindingProjection::parse(&binding)?.operation != "reload_after_cleanup"
                {
                    return Err(ReservationError::StorageCorrupt);
                }
                if retained
                    .reconciliation
                    .as_ref()
                    .is_some_and(|(previous, _)| {
                        *previous != ReconciledDisposition::OperationSucceeded
                            || disposition != ReconciledDisposition::CleanupComplete
                    })
                {
                    return Err(ReservationError::StorageCorrupt);
                }
                // Final operation success can later gain a distinct independent
                // cleanup observation; both immutable records remain retained.
                retained.reconciliation = Some((disposition, observation_digest));
            }
        }
        Ok(())
    }

    fn load(bytes: &[u8], enrollment: &str, limit: usize) -> Result<Self, ReservationError> {
        let mut ledger = Self {
            by_operation: BTreeMap::new(),
            resources: BTreeMap::new(),
            entries: 0,
            previous_hash: canonical_hash(
                &serde_json::json!({ "schema_version": SCHEMA, "enrollment_digest": enrollment }),
            ),
            byte_count: bytes.len(),
        };
        if bytes.is_empty() {
            return Ok(ledger);
        }
        for line in bytes.split_inclusive(|byte| *byte == b'\n') {
            if ledger.entries >= limit {
                return Err(ReservationError::StorageFull);
            }
            if line.len() > 16 * 1024 || line.last() != Some(&b'\n') {
                return Err(ReservationError::StorageCorrupt);
            }
            let entry: LedgerEntry =
                serde_json::from_slice(line).map_err(|_| ReservationError::StorageCorrupt)?;
            let canonical = encoded(&entry)?;
            if canonical.as_slice() != &line[..line.len() - 1]
                || entry.schema_version != SCHEMA
                || entry.sequence != ledger.entries + 1
                || entry.previous_hash != ledger.previous_hash
            {
                return Err(ReservationError::StorageCorrupt);
            }
            let hash = format!("sha256:{}", sha256_hex(&canonical));
            ledger.apply(entry.record, hash.clone(), enrollment)?;
            ledger.entries += 1;
            ledger.previous_hash = hash;
        }
        Ok(ledger)
    }
}

pub struct ServiceReservationStore {
    #[cfg(target_os = "linux")]
    enrollment_digest: String,
    #[cfg(target_os = "linux")]
    limits: ReservationLimits,
    #[cfg(target_os = "linux")]
    storage: storage::Storage,
}

impl ServiceReservationStore {
    /// `trusted_root` is existing enrollment setup configuration, never an action
    /// parameter. This function does not create or repair directory permissions.
    pub fn open(
        trusted_root: &Path,
        enrollment_digest: &str,
        limits: ReservationLimits,
    ) -> Result<Self, ReservationError> {
        if !digest(enrollment_digest)
            || !(8192..=8 * 1024 * 1024).contains(&limits.max_bytes)
            || !(1..=4096).contains(&limits.max_records)
        {
            return Err(ReservationError::InvalidConfiguration);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = trusted_root;
            Err(ReservationError::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            let storage =
                storage::Storage::open(trusted_root, enrollment_digest, limits.max_bytes)?;
            let store = Self {
                enrollment_digest: enrollment_digest.into(),
                limits,
                storage,
            };
            let mut lease = store.storage.lease()?;
            Ledger::load(&lease.read()?, enrollment_digest, limits.max_records)?;
            drop(lease);
            Ok(store)
        }
    }

    pub fn reserve(
        &self,
        admission: &VerifiedServiceAdmission,
        binding: &ServiceOperationBinding,
        now: DateTime<FixedOffset>,
    ) -> Result<ReservationDecision, ReservationError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (admission, binding, now);
            Err(ReservationError::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            let projection = BindingProjection::parse(binding)?;
            let identity = &projection.identity;
            if binding.digest() != admission.operation_binding_digest()
                || admission.enrollment_digest() != self.enrollment_digest
                || projection.reviewed_scope_digest != admission.scope_digest()
                || identity.authorization_digest != admission.scope_digest()
                || identity.runner_profile_id != admission.runner_profile_id()
                || identity.target_scope_digest != admission.target_scope_digest()
                || identity.workspace_id != admission.workspace_id()
                || identity.owner_uid != admission.owner_uid()
                || identity.boot_id != admission.boot_id()
                || identity.manager_id != admission.manager_id()
                || identity.unit_nonce != admission.unit_nonce()
                || identity.unit_content_digest != admission.unit_content_digest()
                || projection.manager_installation_digest != admission.manager_installation_digest()
                || projection.payload_installation_digest != admission.payload_installation_digest()
                || DateTime::parse_from_rfc3339(&identity.created_at).ok()
                    != Some(admission.created_at())
                || DateTime::parse_from_rfc3339(&identity.cleanup_due_at).ok()
                    != Some(admission.cleanup_expires_at())
            {
                return Err(ReservationError::AdmissionMismatch);
            }
            let expires = if SETUP.contains(&projection.operation.as_str()) {
                admission.setup_expires_at()
            } else {
                admission.cleanup_expires_at()
            };
            if now < admission.created_at() || now >= expires {
                return Err(ReservationError::Expired);
            }
            if self.storage.owner_uid() != admission.owner_uid() {
                return Err(ReservationError::AdmissionMismatch);
            }
            let operation = ReservedOperation {
                binding: binding.canonical_json().into(),
                binding_digest: binding.digest().into(),
                resource_key: projection.resource_key(),
                operation_id: projection.operation_id.clone(),
                grant_digest: admission.grant_digest().into(),
                task_id: admission.task_id().into(),
                enrollment_digest: self.enrollment_digest.clone(),
            };
            let mut lease = self.storage.lease()?;
            let ledger = Ledger::load(
                &lease.read()?,
                &self.enrollment_digest,
                self.limits.max_records,
            )?;
            if let Some(retained) = ledger.by_operation.get(&operation.operation_id) {
                if retained.reservation.record != operation {
                    return Err(ReservationError::OperationConflict);
                }
                return Ok(ReservationDecision::Existing {
                    reservation: retained.reservation.clone(),
                    state: retained.state(),
                });
            }
            ledger.check_next(&projection)?;
            let hash = self.append(
                &mut lease,
                &ledger,
                Record::Reservation {
                    operation: operation.clone(),
                },
            )?;
            Ok(ReservationDecision::Reserved(NewServiceReservation {
                reservation: ServiceReservation {
                    digest: hash,
                    record: operation,
                },
            }))
        }
    }

    /// Read-only recovery lookup never produces a fresh dispatch reservation.
    pub fn inspect(
        &self,
        operation_id: &str,
    ) -> Result<Option<(ServiceReservation, ReservationState)>, ReservationError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = operation_id;
            Err(ReservationError::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            let mut lease = self.storage.lease()?;
            let ledger = Ledger::load(
                &lease.read()?,
                &self.enrollment_digest,
                self.limits.max_records,
            )?;
            Ok(ledger
                .by_operation
                .get(operation_id)
                .map(|retained| (retained.reservation.clone(), retained.state())))
        }
    }

    /// A process result is retained evidence, not reconciliation or cleanup.
    pub fn record_outcome(
        &self,
        reservation: &ServiceReservation,
        outcome: ReportedOutcome,
        evidence_digest: &str,
    ) -> Result<(), ReservationError> {
        if !digest(evidence_digest) {
            return Err(ReservationError::ReconciliationMismatch);
        }
        self.update(
            reservation,
            Record::Outcome {
                reservation_digest: reservation.digest.clone(),
                outcome,
                evidence_digest: evidence_digest.into(),
            },
        )
    }

    pub fn reconcile(
        &self,
        reservation: &ServiceReservation,
        verified: VerifiedServiceReconciliation,
    ) -> Result<(), ReservationError> {
        if verified.reservation_digest != reservation.digest
            || !digest(&verified.observation_digest)
        {
            return Err(ReservationError::ReconciliationMismatch);
        }
        self.update(
            reservation,
            Record::Reconciliation {
                reservation_digest: verified.reservation_digest,
                disposition: verified.disposition,
                observation_digest: verified.observation_digest,
            },
        )
    }

    fn update(
        &self,
        reservation: &ServiceReservation,
        record: Record,
    ) -> Result<(), ReservationError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (reservation, record);
            Err(ReservationError::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            let mut lease = self.storage.lease()?;
            let mut ledger = Ledger::load(
                &lease.read()?,
                &self.enrollment_digest,
                self.limits.max_records,
            )?;
            let retained = ledger
                .by_operation
                .get(reservation.operation_id())
                .ok_or(ReservationError::ReconciliationMismatch)?;
            if retained.reservation != *reservation {
                return Err(ReservationError::ReconciliationMismatch);
            }
            let same = match &record {
                Record::Outcome {
                    outcome,
                    evidence_digest,
                    ..
                } => retained
                    .outcome
                    .as_ref()
                    .is_some_and(|value| value == &(*outcome, evidence_digest.clone())),
                Record::Reconciliation {
                    disposition,
                    observation_digest,
                    ..
                } => retained
                    .reconciliation
                    .as_ref()
                    .is_some_and(|value| value == &(*disposition, observation_digest.clone())),
                _ => false,
            };
            if same {
                return Ok(());
            }
            // Validate the transition before writing, without changing the
            // retained bytes or releasing this exclusive lease.
            let encoded_record = encoded(&record)?;
            ledger
                .apply(
                    serde_json::from_slice(&encoded_record)
                        .map_err(|_| ReservationError::StorageCorrupt)?,
                    String::new(),
                    &self.enrollment_digest,
                )
                .map_err(|_| ReservationError::ReconciliationMismatch)?;
            self.append(&mut lease, &ledger, record)?;
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn append(
        &self,
        lease: &mut storage::Lease<'_>,
        ledger: &Ledger,
        record: Record,
    ) -> Result<String, ReservationError> {
        if ledger.entries >= self.limits.max_records {
            return Err(ReservationError::StorageFull);
        }
        let entry = LedgerEntry {
            schema_version: SCHEMA.into(),
            sequence: ledger.entries + 1,
            previous_hash: ledger.previous_hash.clone(),
            record,
        };
        let mut bytes = encoded(&entry)?;
        let hash = format!("sha256:{}", sha256_hex(&bytes));
        bytes.push(b'\n');
        lease.append(&bytes, ledger.byte_count)?;
        Ok(hash)
    }
}

#[cfg(test)]
#[path = "service_reservation_tests.rs"]
mod tests;
