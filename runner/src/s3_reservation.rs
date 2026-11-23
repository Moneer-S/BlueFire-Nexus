//! Native single-owner S3 reservations and fsync-before-permit request debits.
//!
//! The whole worker operation retains the exclusive lease. This serializes
//! BlueFire writers, not external AWS writers or malicious same-UID code.

use chrono::{DateTime, FixedOffset};
use serde_json::Value;

use crate::canonical::{canonical_hash, canonical_json};
use crate::reservation_storage::{JournalKind, Lease, Storage};
use crate::s3_access_send::S3SendPreview;
use crate::s3_admission::VerifiedS3Admission;

#[path = "s3_reservation_audit.rs"]
mod audit;
#[path = "s3_reservation_fixture.rs"]
mod fixture;
#[path = "s3_reservation_state.rs"]
mod state;
pub(crate) use state::PolicyPosition;
use state::{Entry, FixturePosition, Ledger, Record, Reserved, SCHEMA};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Storage,
    Corrupt,
    AlreadyReserved,
    Conflict,
    Budget,
    Expired,
    Lifecycle,
    ReconcileRequired,
    RecoveryRequired,
}
type Result<T> = std::result::Result<T, Error>;
impl From<crate::reservation_storage::Error> for Error {
    fn from(_: crate::reservation_storage::Error) -> Self {
        Self::Storage
    }
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(crate) struct S3ReservationStore {
    storage: Storage,
    enrollment: String,
}

impl S3ReservationStore {
    pub(crate) fn open(admission: &VerifiedS3Admission) -> Result<Self> {
        // Parsing the staged collector contract must not enable storage or execution.
        admission
            .binding()
            .assert_dispatch_supported()
            .map_err(|_| Error::Conflict)?;
        let storage = Storage::open(
            admission.ledger_root(),
            admission.enrollment_digest(),
            4 * 1024 * 1024,
            JournalKind::S3,
        )?;
        if storage.owner_uid() != admission.owner_uid() {
            return Err(Error::Storage);
        }
        Ok(Self {
            storage,
            enrollment: admission.enrollment_digest().into(),
        })
    }

    pub(crate) fn reserve<'a>(
        &'a self,
        admission: &'a VerifiedS3Admission,
        now: DateTime<FixedOffset>,
    ) -> Result<S3Reservation<'a>> {
        admission
            .binding()
            .assert_dispatch_supported()
            .map_err(|_| Error::Conflict)?;
        if now >= admission.expires_at() || admission.binding().assert_current(now).is_err() {
            return Err(Error::Expired);
        }
        if admission.enrollment_digest() != self.enrollment {
            return Err(Error::Conflict);
        }
        let binding = admission.binding();
        let operation = Reserved {
            workflow_id: admission.workflow_id().into(),
            operation_id: admission.operation_id().into(),
            environment_id: admission.environment_id().into(),
            resource_key: binding.resource_key(),
            scope_digest: binding.scope_digest().into(),
            request_digest: binding.digest().into(),
            request_id: binding.request_id().into(),
            launch_id: binding.launch_id().into(),
            approval_digest: admission.approval_digest().into(),
            runtime_digest: binding.runtime_digest().into(),
            worker_generation: binding.worker_generation().into(),
            phase: admission.phase().into(),
            operation: binding.operation().into(),
            revision: admission.revision(),
            max_sends: binding.max_sends(),
            api_limit: binding.api_limit(),
            session_limit: binding.session_limit(),
            business_attempt_limit: binding.business_attempt_limit(),
            fixture_authority_digest: admission.fixture_authority_digest().map(str::to_owned),
            fixture: binding.fixture().cloned(),
        };
        let mut lease = self.storage.lease()?;
        let mut ledger = Ledger::load(&lease.read()?, &self.enrollment)?;
        let record = if let Some(workflow) = admission.audit_workflow() {
            let reservation = audit::AuditedReservation {
                operation,
                scope: binding.scope().clone(),
                audit_workflow: workflow.document().map_err(|_| Error::Conflict)?,
                profile_digest: admission.profile_digest().into(),
                task: audit::TaskIdentity {
                    run_id: admission.manifest().run_id.clone(),
                    manifest_digest: admission.manifest_digest().into(),
                    deadline: serde_json::from_str::<Value>(binding.canonical_json())
                        .map_err(|_| Error::Conflict)?["deadline"]
                        .as_str()
                        .ok_or(Error::Conflict)?
                        .into(),
                },
                collection: binding
                    .audit()
                    .map(|collection| collection.context())
                    .transpose()
                    .map_err(|_| Error::Conflict)?,
            };
            reservation.checked(binding.scope(), admission.profile_digest())?;
            ledger.check_audited(&reservation)?;
            Record::AuditedReservation {
                reservation: Box::new(reservation),
            }
        } else {
            ledger.check_reserve(&operation)?;
            Record::Reservation {
                operation: Box::new(operation),
            }
        };
        let reservation_digest = append(&mut lease, &mut ledger, record)?;
        Ok(S3Reservation {
            lease,
            ledger,
            admission,
            reservation_digest,
        })
    }
}

pub(crate) struct S3Reservation<'a> {
    lease: Lease<'a>,
    ledger: Ledger,
    admission: &'a VerifiedS3Admission,
    reservation_digest: String,
}

impl S3Reservation<'_> {
    pub(crate) fn binding(&self) -> &crate::s3_access_binding::S3WorkerBinding {
        self.admission.binding()
    }
    pub(crate) fn baseline_phase(&self) -> bool {
        self.admission.phase() == "baseline"
    }
    pub(crate) fn current(&self, now: DateTime<FixedOffset>) -> bool {
        now < self.admission.expires_at() && self.admission.binding().assert_current(now).is_ok()
    }
    pub(crate) fn digest(&self) -> &str {
        &self.reservation_digest
    }
    pub(crate) fn send_debits(&self) -> u64 {
        self.ledger.requests[self.admission.binding().digest()].debits
    }
    pub(crate) fn write_debited(&self) -> bool {
        self.ledger.requests[self.admission.binding().digest()].write_debited
    }

    pub(crate) fn discovery(&self) -> Option<&crate::s3_access_binding::audit::Discovery> {
        self.ledger.requests[self.binding().digest()]
            .discovery
            .as_ref()
    }

    /// Selection is reusable only after this reservation's journal append has synced.
    pub(crate) fn commit_discovery(
        &mut self,
        frame: &[u8],
        now: DateTime<FixedOffset>,
    ) -> Result<Value> {
        if !self.current(now) {
            return Err(Error::Expired);
        }
        let checked = self.ledger.audit_reservation(self.binding().digest())?;
        let context = checked.raw().collection.as_ref().ok_or(Error::Conflict)?;
        let discovery = crate::s3_access_binding::audit::Discovery::from_context(
            &checked.raw().scope,
            checked.workflow(),
            context,
            self.binding().digest(),
            self.digest(),
            self.send_debits(),
            frame,
        )
        .map_err(|_| Error::Conflict)?;
        append(
            &mut self.lease,
            &mut self.ledger,
            Record::AuditDiscovery {
                reservation_digest: self.reservation_digest.clone(),
                discovery: discovery.document().clone(),
            },
        )?;
        Ok(discovery.acknowledgement())
    }

    /// The permit is returned only after the immutable debit and directory/file
    /// synchronization succeed. A failed/lost pipe write never refunds it.
    pub(crate) fn debit(&mut self, frame: &[u8], now: DateTime<FixedOffset>) -> Result<Value> {
        if now >= self.admission.expires_at()
            || self.admission.binding().assert_current(now).is_err()
        {
            return Err(Error::Expired);
        }
        let preview = if self.binding().audit().is_some() {
            S3SendPreview::from_audit_frame(
                self.binding(),
                frame,
                self.send_debits() + 1,
                self.discovery(),
            )
        } else {
            S3SendPreview::from_frame(self.binding(), frame, self.send_debits() + 1)
        }
        .map_err(|_| Error::Conflict)?;
        append(
            &mut self.lease,
            &mut self.ledger,
            Record::Debit {
                reservation_digest: self.reservation_digest.clone(),
                sequence: preview.sequence(),
                preview_digest: preview.digest().into(),
                is_write: preview.is_write(),
            },
        )?;
        Ok(serde_json::json!({
            "kind":"permit", "request_digest":self.admission.binding().digest(),
            "sequence":preview.sequence(), "send_digest":preview.digest(),
        }))
    }

    pub(crate) fn complete(
        mut self,
        result: &Value,
        observed: bool,
        position: PolicyPosition,
        cleanup_verified: bool,
    ) -> Result<()> {
        let fixture_position = if observed && self.binding().fixture().is_some() {
            Some(FixturePosition {
                state: result["data"]["state"]
                    .as_str()
                    .ok_or(Error::Conflict)?
                    .into(),
                etag: result["data"]["etag"].as_str().map(str::to_owned),
            })
        } else {
            None
        };
        append(
            &mut self.lease,
            &mut self.ledger,
            Record::Completion {
                reservation_digest: self.reservation_digest.clone(),
                result_digest: canonical_hash(result),
                observed,
                policy_position: position,
                cleanup_verified,
                fixture_position,
            },
        )?;
        Ok(())
    }
}

fn encode_entry(entry: Entry) -> Result<(String, Vec<u8>)> {
    let value = serde_json::to_value(entry).map_err(|_| Error::Corrupt)?;
    let mut bytes = canonical_json(&value).into_bytes();
    bytes.push(b'\n');
    if bytes.len() > 16 * 1024 {
        return Err(Error::Budget);
    }
    Ok((canonical_hash(&value), bytes))
}

fn append(lease: &mut Lease<'_>, ledger: &mut Ledger, record: Record) -> Result<String> {
    if ledger.entries >= 4096 {
        return Err(Error::Budget);
    }
    let entry = Entry {
        schema_version: SCHEMA.into(),
        sequence: ledger.entries + 1,
        previous_hash: ledger.previous_hash.clone(),
        record: record.clone(),
    };
    let (hash, bytes) = encode_entry(entry)?;
    // Validate against a replay before writing. The real in-memory transition
    // happens only after fsync; failure leaves retained history uncertain.
    let mut candidate = ledger.clone();
    candidate.apply(record, hash.clone())?;
    let byte_count = ledger.bytes;
    lease.append(&bytes, byte_count)?;
    candidate.entries += 1;
    candidate.previous_hash = hash.clone();
    candidate.bytes += bytes.len();
    *ledger = candidate;
    Ok(hash)
}

#[cfg(test)]
#[path = "s3_reservation_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "s3_reservation_size_tests.rs"]
mod size_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "s3_audit_connected_tests.rs"]
mod connected_tests;
