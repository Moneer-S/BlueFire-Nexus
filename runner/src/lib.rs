//! BlueFire Nexus's local execution authority.
//!
//! The Python control plane may select registered actions and submit typed
//! manifests, but this crate owns the final policy decision and every real
//! side effect.

pub mod actions;
mod atomic_chmod;
mod atomic_gzip;
mod cancellation_witness;
mod canonical;
pub mod contract;
mod native_tool_inspection;
pub mod native_tool_installations;
mod native_tool_setup;
mod process;
pub mod provider_action;
pub mod providers;
mod receipt_store;
mod receiver_auth;
mod reviewed_chmod_builds;
pub mod runner;
pub mod safety;
pub mod service_operation_binding;

pub use actions::{inventory, ActionDescriptor, ACTION_SDK_SCHEMA_VERSION};
pub use cancellation_witness::{run_internal_cancellation_descendant, INTERNAL_DESCENDANT_VERB};
pub use contract::{
    seal_manifest, seal_profile, utc_now, Approval, Capability, CleanupReport, EvidenceKind,
    EvidenceRecord, ExecutionLimits, ExecutionManifest, NetworkDestination, Platform,
    ProviderActionLimits, ProviderArtifact, ProviderArtifactSpec, ProviderExecutionBinding,
    ProviderParameterSpec, ProviderParameterType, RunMode, RunnerProfile, SafetyTier, TargetScope,
    TaskResult, TaskStatus,
};
pub use native_tool_setup::inspect_candidate;
pub use native_tool_setup::inspect_installation;
pub use providers::{provider_runtimes, ProviderRuntimeDescriptor};
pub use runner::{execute_files, Runner, RunnerError, MAX_DOCUMENT_BYTES};
pub use safety::RECEIPT_PROTOCOL_VERSION;
