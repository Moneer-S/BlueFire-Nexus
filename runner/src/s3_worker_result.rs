//! Worker result dispatch over the shared pure consistency contracts.

use serde_json::Value;

use crate::s3_access_binding::S3WorkerBinding;
use crate::s3_access_scope::Checked;
use crate::s3_worker_result_contract::result_frame;
pub(crate) use crate::s3_worker_result_contract::{PolicyPosition, WorkerResult};

impl WorkerResult {
    #[cfg(test)]
    pub(crate) fn from_frame(
        binding: &S3WorkerBinding,
        bytes: &[u8],
        debits: u64,
    ) -> Checked<Self> {
        Self::from_frame_with_discovery(binding, bytes, debits, None)
    }

    pub(crate) fn from_frame_with_discovery(
        binding: &S3WorkerBinding,
        bytes: &[u8],
        debits: u64,
        discovery: Option<&crate::s3_access_binding::audit::Discovery>,
    ) -> Checked<Self> {
        let row = result_frame(bytes)?;
        if binding.audit().is_some() {
            let observed =
                crate::s3_access_binding::audit::validate_result(binding, &row, debits, discovery)?;
            return Ok(Self {
                document: row.clone(),
                observed,
                all_objects_read: false,
                policy_position: PolicyPosition::Unknown,
            });
        }
        let request: Value =
            serde_json::from_str(binding.canonical_json()).map_err(|_| "invalid S3 binding")?;
        Self::from_ordinary_result(&request, &row, debits)
    }
}
