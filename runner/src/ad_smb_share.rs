//! Finite member-local share primitives, not admission or effective-access proof.
//!
//! No action registers this component. Callers must separately establish member
//! identity, root file/NTFS identity, privilege, exclusive ownership, durable
//! dispatch and budgets. In-memory consumption is not durable retry protection.

use crate::ad_smb_descriptor::{Descriptor, DescriptorProjection};
use serde::Serialize;
#[cfg(any(target_os = "windows", test))]
use sha2::{Digest, Sha256};
use std::time::Instant;

#[cfg(any(target_os = "windows", test))]
mod buffer;
#[cfg(target_os = "windows")]
mod ffi;
#[cfg(test)]
#[path = "ad_smb_share/ad_smb_share_tests.rs"]
mod tests;
#[cfg(target_os = "windows")]
mod windows;

pub const MAX_NET_API_BYTES: usize = 131_072;
#[cfg(any(target_os = "windows", test))]
const FORBIDDEN_FLAGS: u32 = 0x4003;
#[cfg(any(target_os = "windows", test))]
const SUPPORTED_FLAGS: u32 = 0xbf30;

#[derive(Debug, Eq, PartialEq)]
pub struct LocalShareTarget {
    name: String,
    path: String,
}

impl LocalShareTarget {
    pub fn new(generated_id: &str, drive: char) -> Result<Self, String> {
        if generated_id.len() != 32
            || !generated_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !('C'..='Z').contains(&drive)
        {
            return Err("share target is outside the finite generated recipe".into());
        }
        Ok(Self {
            name: format!("bf_{generated_id}"),
            path: format!("{drive}:\\BlueFire\\AD\\{generated_id}"),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ShareMetadata {
    pub name: String,
    pub local_path: String,
    pub share_type: u32,
    pub flags: u32,
    pub client_cache_flags: u32,
    /// Advertised share flag, not proof of a fresh client's negotiated encryption.
    pub encrypt_data_flag: bool,
    pub permissions: u32,
    pub maximum_uses: u32,
    pub remark_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ShareProjection {
    pub schema_version: &'static str,
    pub metadata: ShareMetadata,
    pub current_uses: u32,
    pub descriptor: DescriptorProjection,
}

pub struct ShareObservation {
    target: LocalShareTarget,
    metadata: ShareMetadata,
    current_uses: u32,
    descriptor: Descriptor,
}

impl ShareObservation {
    pub fn projection(&self) -> ShareProjection {
        ShareProjection {
            schema_version: "bluefire.ad-smb-local-share.v1",
            metadata: self.metadata.clone(),
            current_uses: self.current_uses,
            descriptor: self.descriptor.projection().clone(),
        }
    }

    pub fn propose_probe_removal(
        self,
        probe: &str,
        legitimate: &str,
        controller: &str,
    ) -> Result<PreparedShareChange, String> {
        let after = self
            .descriptor
            .propose_probe_removal(probe, legitimate, controller)?;
        Ok(PreparedShareChange {
            pair: DerivedPair {
                target: self.target,
                metadata: self.metadata,
                before: self.descriptor.bytes().to_vec(),
                after: after.bytes().to_vec(),
            },
        })
    }

    fn reviewed_pair(
        self,
        before: &[u8],
        after: &[u8],
        principals: [&str; 3],
        restore: bool,
    ) -> Result<DerivedPair, String> {
        let parsed = Descriptor::from_bytes(before)?;
        let derived = parsed.propose_probe_removal(principals[0], principals[1], principals[2])?;
        if derived.bytes() != after
            || self.descriptor.bytes() != if restore { after } else { before }
        {
            return Err("reviewed share pair or current preimage differs".into());
        }
        Ok(DerivedPair {
            target: self.target,
            metadata: self.metadata,
            before: before.to_vec(),
            after: after.to_vec(),
        })
    }

    /// Reconstruct only a native-derived removal, never an arbitrary descriptor setter.
    pub(crate) fn reviewed_change(
        self,
        before: &[u8],
        after: &[u8],
        principals: [&str; 3],
    ) -> Result<PreparedShareChange, String> {
        Ok(PreparedShareChange {
            pair: self.reviewed_pair(before, after, principals, false)?,
        })
    }

    /// The current hardened bytes and exact derived pair must both match.
    pub(crate) fn reviewed_rollback(
        self,
        before: &[u8],
        after: &[u8],
        principals: [&str; 3],
    ) -> Result<PreparedShareRollback, String> {
        Ok(PreparedShareRollback {
            pair: self.reviewed_pair(before, after, principals, true)?,
        })
    }
}

struct DerivedPair {
    target: LocalShareTarget,
    metadata: ShareMetadata,
    before: Vec<u8>,
    after: Vec<u8>,
}

pub struct PreparedShareChange {
    pair: DerivedPair,
}
pub struct PreparedShareRollback {
    pair: DerivedPair,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareWriteState {
    NotAttempted,
    ReadbackMatched,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct ShareWriteProof {
    pub state: ShareWriteState,
    pub write_attempted: bool,
    pub set_status: Option<u32>,
    pub readback: Option<ShareProjection>,
    pub issue: Option<&'static str>,
}

pub struct ShareChangeAttempt {
    pub proof: ShareWriteProof,
    pub rollback: PreparedShareRollback,
}

impl PreparedShareChange {
    pub fn before_descriptor(&self) -> &[u8] {
        &self.pair.before
    }
    pub fn after_descriptor(&self) -> &[u8] {
        &self.pair.after
    }

    /// Exactly one local SetInfo attempt; a failed response is never retried.
    pub fn apply(self) -> ShareChangeAttempt {
        self.apply_with(&mut LocalBackend)
    }

    pub(crate) fn apply_before(self, deadline: Instant) -> ShareChangeAttempt {
        let proof = write_pair_timed(&mut LocalBackend, &self.pair, false, &|| {
            Instant::now() < deadline
        });
        ShareChangeAttempt {
            proof,
            rollback: PreparedShareRollback { pair: self.pair },
        }
    }

    fn apply_with(self, backend: &mut impl Backend) -> ShareChangeAttempt {
        let proof = write_pair(backend, &self.pair, false);
        ShareChangeAttempt {
            proof,
            rollback: PreparedShareRollback { pair: self.pair },
        }
    }
}

impl PreparedShareRollback {
    /// Restore only this derived pair after exact current hardened preimage match.
    pub fn rollback(self) -> ShareWriteProof {
        self.rollback_with(&mut LocalBackend)
    }

    pub(crate) fn rollback_before(self, deadline: Instant) -> ShareWriteProof {
        write_pair_timed(&mut LocalBackend, &self.pair, true, &|| {
            Instant::now() < deadline
        })
    }

    fn rollback_with(self, backend: &mut impl Backend) -> ShareWriteProof {
        write_pair(backend, &self.pair, true)
    }
}

fn write_pair(backend: &mut impl Backend, pair: &DerivedPair, restore: bool) -> ShareWriteProof {
    write_pair_timed(backend, pair, restore, &|| true)
}

fn write_pair_timed(
    backend: &mut impl Backend,
    pair: &DerivedPair,
    restore: bool,
    current: &dyn Fn() -> bool,
) -> ShareWriteProof {
    let (expected, desired) = if restore {
        (&pair.after, &pair.before)
    } else {
        (&pair.before, &pair.after)
    };
    if !current() {
        return ShareWriteProof {
            state: ShareWriteState::NotAttempted,
            write_attempted: false,
            set_status: None,
            readback: None,
            issue: Some("original_deadline_expired"),
        };
    }
    let Ok(before) = backend.observe(&pair.target) else {
        return ShareWriteProof {
            state: ShareWriteState::NotAttempted,
            write_attempted: false,
            set_status: None,
            readback: None,
            issue: Some("preimage_unavailable"),
        };
    };
    if before.metadata != pair.metadata || before.descriptor.bytes() != expected {
        return ShareWriteProof {
            state: ShareWriteState::NotAttempted,
            write_attempted: false,
            set_status: None,
            readback: Some(before.projection()),
            issue: Some("preimage_changed"),
        };
    }
    if !current() {
        return ShareWriteProof {
            state: ShareWriteState::NotAttempted,
            write_attempted: false,
            set_status: None,
            readback: Some(before.projection()),
            issue: Some("original_deadline_expired"),
        };
    }
    // The read/check/write interval is not a CAS. Exclusive writer admission is external.
    let status = backend.set_descriptor(&pair.target, desired);
    if !current() {
        return ShareWriteProof {
            state: ShareWriteState::Unknown,
            write_attempted: true,
            set_status: Some(status),
            readback: None,
            issue: Some("original_deadline_expired_after_write"),
        };
    }
    let observed = backend.observe(&pair.target).ok();
    let matched = observed
        .as_ref()
        .is_some_and(|row| row.metadata == pair.metadata && row.descriptor.bytes() == desired)
        && current();
    ShareWriteProof {
        state: if status == 0 && matched {
            ShareWriteState::ReadbackMatched
        } else {
            ShareWriteState::Unknown
        },
        write_attempted: true,
        set_status: Some(status),
        readback: observed.map(|row| row.projection()),
        issue: if status != 0 {
            Some("set_response_failed_state_unknown")
        } else if !matched {
            Some("exact_readback_unavailable")
        } else {
            None
        },
    }
}

pub fn observe_local(target: LocalShareTarget) -> Result<ShareObservation, String> {
    LocalBackend.observe(&target)
}

trait Backend {
    fn observe(&mut self, target: &LocalShareTarget) -> Result<ShareObservation, String>;
    fn set_descriptor(&mut self, target: &LocalShareTarget, descriptor: &[u8]) -> u32;
}

struct LocalBackend;

impl Backend for LocalBackend {
    fn observe(&mut self, target: &LocalShareTarget) -> Result<ShareObservation, String> {
        #[cfg(target_os = "windows")]
        return windows::observe(target);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = target;
            Err("native Windows local share observation is unavailable".into())
        }
    }

    fn set_descriptor(&mut self, target: &LocalShareTarget, descriptor: &[u8]) -> u32 {
        #[cfg(target_os = "windows")]
        return windows::set_descriptor(target, descriptor);
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (target, descriptor);
            50
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn validate_metadata(target: &LocalShareTarget, metadata: &ShareMetadata) -> Result<(), String> {
    if metadata.name != target.name
        || metadata.local_path != target.path
        || metadata.share_type != 0
        || metadata.flags & FORBIDDEN_FLAGS != 0
        || metadata.flags & !SUPPORTED_FLAGS != 0
        || metadata.client_cache_flags != metadata.flags & 0x30
        || metadata.encrypt_data_flag != (metadata.flags & 0x8000 != 0)
    {
        return Err("local share identity, type or flags differ from the finite target".into());
    }
    Ok(())
}

#[cfg(any(target_os = "windows", test))]
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
