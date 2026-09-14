//! Durable receipt-commit schema and identity validation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const RECEIPT_COMMIT_SCHEMA: &str = "bluefire.receipt-commit/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableReceiptCommit {
    schema_version: String,
    receipt_id: String,
    runner_profile_id: String,
    workspace_id: String,
    committed_at: DateTime<Utc>,
}

impl DurableReceiptCommit {
    pub(crate) fn new(
        receipt_id: &str,
        runner_profile_id: &str,
        workspace_id: &str,
        committed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            schema_version: RECEIPT_COMMIT_SCHEMA.to_string(),
            receipt_id: receipt_id.to_string(),
            runner_profile_id: runner_profile_id.to_string(),
            workspace_id: workspace_id.to_string(),
            committed_at,
        }
    }

    pub(crate) fn encode_pretty(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    pub(crate) fn has_identity(
        &self,
        receipt_id: &str,
        runner_profile_id: &str,
        workspace_id: &str,
    ) -> bool {
        self.schema_version == RECEIPT_COMMIT_SCHEMA
            && self.receipt_id == receipt_id
            && self.runner_profile_id == runner_profile_id
            && self.workspace_id == workspace_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_commit_round_trip_preserves_exact_identity() {
        let committed_at = DateTime::parse_from_rfc3339("2026-08-29T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let commit = DurableReceiptCommit::new("receipt", "runner", "workspace", committed_at);
        let decoded = DurableReceiptCommit::decode(&commit.encode_pretty().unwrap()).unwrap();
        assert!(decoded.has_identity("receipt", "runner", "workspace"));
        assert!(!decoded.has_identity("other", "runner", "workspace"));
    }
}
