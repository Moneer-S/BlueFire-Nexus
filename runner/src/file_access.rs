//! Fixed Linux observation action over an independently enrolled resource.

use std::cell::Cell;

use serde_json::Value;

pub(crate) use crate::file_access_contract::{
    require, MAX_REPORT, OWNER_ACTION, PROBE_ACTION, REFUSAL,
};
pub use crate::file_access_contract::{FileAccessBinding, FileAccessResource, FileAccessWorker};

#[cfg(test)]
use crate::canonical::canonical_hash;
#[cfg(test)]
use serde_json::json;

impl FileAccessBinding {
    pub(crate) fn current(&self) -> Result<(), String> {
        self.validate()?;
        let remaining = self.expires_at_ms - crate::contract::utc_now().timestamp_millis();
        require((1..=900_000).contains(&remaining))
    }
}

#[cfg(target_os = "linux")]
#[path = "file_access_linux.rs"]
mod linux;

pub(crate) fn observe(
    binding: &FileAccessBinding,
    request_hash: &str,
    owner: bool,
    timeout: std::time::Duration,
    execution_started: &Cell<bool>,
) -> Result<Value, String> {
    binding.current()?;
    #[cfg(target_os = "linux")]
    {
        linux::observe(binding, request_hash, owner, timeout, execution_started)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (request_hash, owner, timeout, execution_started);
        Err(REFUSAL.into())
    }
}

#[cfg(test)]
#[path = "file_access_tests.rs"]
mod tests;
