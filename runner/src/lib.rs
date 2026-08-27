//! BlueFire Nexus's local execution authority.
//!
//! The Python control plane may select registered actions and submit typed
//! manifests, but this crate owns the final policy decision and every real
//! side effect.

pub mod actions;
pub mod contract;
mod process;
pub mod provider_action;
pub mod providers;
pub mod runner;
pub mod safety;

pub use actions::{inventory, ActionDescriptor, ACTION_SDK_SCHEMA_VERSION};
pub use contract::{
    seal_manifest, seal_profile, utc_now, Approval, Capability, CleanupReport, EvidenceKind,
    EvidenceRecord, ExecutionLimits, ExecutionManifest, NetworkDestination, Platform,
    ProviderActionLimits, ProviderArtifact, ProviderArtifactSpec, ProviderExecutionBinding,
    ProviderParameterSpec, ProviderParameterType, RunMode, RunnerProfile, SafetyTier, TargetScope,
    TaskResult, TaskStatus,
};
pub use providers::{provider_runtimes, ProviderRuntimeDescriptor};
pub use runner::{execute_files, Runner, RunnerError, MAX_DOCUMENT_BYTES};
pub use safety::RECEIPT_PROTOCOL_VERSION;
