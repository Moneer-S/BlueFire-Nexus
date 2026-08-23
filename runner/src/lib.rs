//! BlueFire Nexus's local execution authority.
//!
//! The Python control plane may select registered actions and submit typed
//! manifests, but this crate owns the final policy decision and every real
//! side effect.

pub mod actions;
pub mod contract;
pub mod process;
pub mod runner;
pub mod safety;

pub use actions::{inventory, ActionDescriptor};
pub use contract::{
    seal_manifest, seal_profile, utc_now, Approval, Capability, CleanupReport, EvidenceKind,
    EvidenceRecord, ExecutionLimits, ExecutionManifest, NetworkDestination, Platform, RunMode,
    RunnerProfile, SafetyTier, TargetScope, TaskResult, TaskStatus,
};
pub use runner::{execute_files, Runner, RunnerError, MAX_DOCUMENT_BYTES};
