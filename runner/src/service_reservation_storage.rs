//! Preserve the service ledger's exact schema and error behavior over shared storage.

use super::ReservationError;
use crate::reservation_storage as shared;
use std::path::Path;

fn issue(error: shared::Error) -> ReservationError {
    match error {
        shared::Error::InvalidConfiguration => ReservationError::InvalidConfiguration,
        shared::Error::StorageUnsafe => ReservationError::StorageUnsafe,
        shared::Error::StorageCorrupt => ReservationError::StorageCorrupt,
        shared::Error::StorageIo => ReservationError::StorageIo,
        shared::Error::StorageFull => ReservationError::StorageFull,
        shared::Error::Busy => ReservationError::Busy,
    }
}

pub(super) struct Storage(shared::Storage);
pub(super) struct Lease<'a>(shared::Lease<'a>);

impl Storage {
    pub(super) fn open(
        path: &Path,
        enrollment: &str,
        maximum: usize,
    ) -> Result<Self, ReservationError> {
        shared::Storage::open(path, enrollment, maximum, shared::JournalKind::Service)
            .map(Self)
            .map_err(issue)
    }
    pub(super) fn owner_uid(&self) -> u32 {
        self.0.owner_uid()
    }
    pub(super) fn lease(&self) -> Result<Lease<'_>, ReservationError> {
        self.0.lease().map(Lease).map_err(issue)
    }
}
impl Lease<'_> {
    pub(super) fn read(&mut self) -> Result<Vec<u8>, ReservationError> {
        self.0.read().map_err(issue)
    }
    pub(super) fn append(
        &mut self,
        record: &[u8],
        previous_bytes: usize,
    ) -> Result<(), ReservationError> {
        self.0.append(record, previous_bytes).map_err(issue)
    }
}
