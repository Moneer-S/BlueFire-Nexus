//! Isolated WebAssembly execution for independently distributed action providers.
//!
//! Provider modules receive no imports. In particular, this module never links
//! WASI, filesystem, network, process, environment, clock, random, or shell
//! functions. The only host/guest interface is canonical JSON in one bounded
//! linear memory under the versioned ABI below.

use std::error::Error;
use std::fmt;

use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasmi::{
    CompilationMode, Config, EnforcedLimits, Engine, Linker, Module, Store, StoreLimits,
    StoreLimitsBuilder, TrapCode,
};

use crate::contract::canonical_json;

pub const PROVIDER_ABI_V1: &str = "bluefire.provider-abi.v1";
pub const PROVIDER_ENTRYPOINT_V1: &str = "bluefire_provider_run_v1";
pub const PROVIDER_MEMORY_EXPORT: &str = "memory";

const WASM_HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";
const WASM_PAGE_BYTES: u64 = 65_536;

pub const HARD_MAX_PROVIDER_MODULE_BYTES: usize = 2 * 1024 * 1024;
pub const HARD_MAX_PROVIDER_MEMORY_BYTES: usize = 16 * 1024 * 1024;
pub const HARD_MAX_PROVIDER_JSON_BYTES: usize = 1024 * 1024;
pub const HARD_MAX_PROVIDER_FUEL: u64 = 100_000_000;

/// Signed manifest fields required before a provider artifact may be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderArtifactContract {
    pub abi_version: String,
    pub artifact_sha256: String,
}

impl ProviderArtifactContract {
    pub fn new(abi_version: impl Into<String>, artifact_sha256: impl Into<String>) -> Self {
        Self {
            abi_version: abi_version.into(),
            artifact_sha256: artifact_sha256.into(),
        }
    }
}

/// Per-invocation limits, additionally capped by module-owned hard ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderLimits {
    pub max_module_bytes: usize,
    pub max_memory_bytes: usize,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub fuel: u64,
}

impl Default for ProviderLimits {
    fn default() -> Self {
        Self {
            max_module_bytes: 256 * 1024,
            max_memory_bytes: 2 * 1024 * 1024,
            max_input_bytes: 64 * 1024,
            max_output_bytes: 64 * 1024,
            fuel: 1_000_000,
        }
    }
}

/// A successful typed provider invocation and its auditable resource identity.
#[derive(Debug)]
pub struct ProviderExecution<T> {
    pub output: T,
    pub artifact_sha256: String,
    pub fuel_consumed: u64,
    pub memory_bytes: usize,
    pub output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    InvalidLimits(&'static str),
    InvalidArtifactDigest,
    ArtifactDigestMismatch,
    ArtifactTooLarge { size: usize, limit: usize },
    InvalidArtifact(String),
    UnsupportedAbi(String),
    ImportForbidden { module: String, name: String },
    InvalidExport(String),
    InputEncoding(String),
    InputTooLarge { size: usize, limit: usize },
    MemoryLimitExceeded,
    FuelExhausted,
    ExecutionTrap(String),
    OutputTooLarge { size: usize, limit: usize },
    OutputOutOfBounds,
    InvalidOutput(String),
    NonCanonicalOutput,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(field) => write!(formatter, "invalid provider limit: {field}"),
            Self::InvalidArtifactDigest => {
                formatter.write_str("provider artifact digest must be exact lowercase SHA-256")
            }
            Self::ArtifactDigestMismatch => {
                formatter.write_str("provider artifact does not match its signed SHA-256 digest")
            }
            Self::ArtifactTooLarge { size, limit } => {
                write!(
                    formatter,
                    "provider artifact is {size} bytes; limit is {limit}"
                )
            }
            Self::InvalidArtifact(message) => {
                write!(formatter, "provider artifact is invalid: {message}")
            }
            Self::UnsupportedAbi(abi) => write!(formatter, "unsupported provider ABI: {abi}"),
            Self::ImportForbidden { module, name } => write!(
                formatter,
                "provider import is forbidden: {module}/{name}; providers receive no host imports"
            ),
            Self::InvalidExport(message) => {
                write!(formatter, "provider ABI export is invalid: {message}")
            }
            Self::InputEncoding(message) => {
                write!(formatter, "provider input cannot be encoded: {message}")
            }
            Self::InputTooLarge { size, limit } => {
                write!(
                    formatter,
                    "provider input is {size} bytes; limit is {limit}"
                )
            }
            Self::MemoryLimitExceeded => {
                formatter.write_str("provider linear-memory limit was exceeded")
            }
            Self::FuelExhausted => formatter.write_str("provider execution exhausted its fuel"),
            Self::ExecutionTrap(message) => {
                write!(formatter, "provider execution trapped: {message}")
            }
            Self::OutputTooLarge { size, limit } => {
                write!(
                    formatter,
                    "provider output is {size} bytes; limit is {limit}"
                )
            }
            Self::OutputOutOfBounds => {
                formatter.write_str("provider output points outside its bounded linear memory")
            }
            Self::InvalidOutput(message) => {
                write!(
                    formatter,
                    "provider output is not valid typed JSON: {message}"
                )
            }
            Self::NonCanonicalOutput => {
                formatter.write_str("provider output must use canonical JSON encoding")
            }
        }
    }
}

impl Error for ProviderError {}

struct ProviderStore {
    limits: StoreLimits,
}

/// Return the lowercase content identity used by signed provider manifests.
pub fn provider_artifact_digest(artifact: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(artifact)))
}

/// Execute a no-import provider and decode its canonical JSON output as `O`.
///
/// ABI v1 exports exactly one memory named `memory` and one function named
/// `bluefire_provider_run_v1` with type `(i32, i32) -> i64`. The host writes
/// canonical input JSON at memory offset zero. The return value packs the
/// output pointer in its high 32 bits and output length in its low 32 bits.
pub fn execute_provider<I, O>(
    artifact: &[u8],
    contract: &ProviderArtifactContract,
    input: &I,
    limits: ProviderLimits,
) -> Result<ProviderExecution<O>, ProviderError>
where
    I: Serialize,
    O: DeserializeOwned,
{
    validate_limits(limits)?;
    if artifact.len() > limits.max_module_bytes {
        return Err(ProviderError::ArtifactTooLarge {
            size: artifact.len(),
            limit: limits.max_module_bytes,
        });
    }
    if !valid_digest(&contract.artifact_sha256) {
        return Err(ProviderError::InvalidArtifactDigest);
    }
    let actual_digest = provider_artifact_digest(artifact);
    if actual_digest != contract.artifact_sha256 {
        return Err(ProviderError::ArtifactDigestMismatch);
    }
    if contract.abi_version != PROVIDER_ABI_V1 {
        return Err(ProviderError::UnsupportedAbi(contract.abi_version.clone()));
    }
    if !artifact.starts_with(WASM_HEADER) {
        return Err(ProviderError::InvalidArtifact(
            "artifact is not a version-1 WebAssembly binary".to_string(),
        ));
    }

    let input_value = serde_json::to_value(input)
        .map_err(|error| ProviderError::InputEncoding(error.to_string()))?;
    let input_bytes = canonical_json(&input_value).into_bytes();
    if input_bytes.len() > limits.max_input_bytes {
        return Err(ProviderError::InputTooLarge {
            size: input_bytes.len(),
            limit: limits.max_input_bytes,
        });
    }

    let engine = provider_engine();
    let module = Module::new(&engine, artifact)
        .map_err(|error| ProviderError::InvalidArtifact(error.to_string()))?;
    validate_module_boundary(&module, limits.max_memory_bytes)?;

    let store_limits = StoreLimitsBuilder::new()
        .memory_size(limits.max_memory_bytes)
        .table_elements(0)
        .instances(1)
        .tables(0)
        .memories(1)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(
        &engine,
        ProviderStore {
            limits: store_limits,
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(limits.fuel)
        .map_err(|error| ProviderError::InvalidArtifact(error.to_string()))?;

    let linker = Linker::<ProviderStore>::new(&engine);
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(map_execution_error)?;
    let memory = instance
        .get_memory(&store, PROVIDER_MEMORY_EXPORT)
        .ok_or_else(|| ProviderError::InvalidExport("missing memory export".to_string()))?;
    if input_bytes.len() > memory.data_size(&store) {
        return Err(ProviderError::MemoryLimitExceeded);
    }
    memory
        .write(&mut store, 0, &input_bytes)
        .map_err(|_| ProviderError::MemoryLimitExceeded)?;

    let entrypoint = instance
        .get_typed_func::<(i32, i32), i64>(&store, PROVIDER_ENTRYPOINT_V1)
        .map_err(|_| {
            ProviderError::InvalidExport("entrypoint must have type (i32, i32) -> i64".to_string())
        })?;
    let packed = entrypoint
        .call(&mut store, (0, input_bytes.len() as i32))
        .map_err(map_execution_error)? as u64;
    let output_pointer = (packed >> 32) as u32 as usize;
    let output_length = packed as u32 as usize;
    if output_length > limits.max_output_bytes {
        return Err(ProviderError::OutputTooLarge {
            size: output_length,
            limit: limits.max_output_bytes,
        });
    }
    let output_end = output_pointer
        .checked_add(output_length)
        .ok_or(ProviderError::OutputOutOfBounds)?;
    if output_end > memory.data_size(&store) {
        return Err(ProviderError::OutputOutOfBounds);
    }

    let mut output_bytes = vec![0_u8; output_length];
    memory
        .read(&store, output_pointer, &mut output_bytes)
        .map_err(|_| ProviderError::OutputOutOfBounds)?;
    let output_value: serde_json::Value = serde_json::from_slice(&output_bytes)
        .map_err(|error| ProviderError::InvalidOutput(error.to_string()))?;
    if canonical_json(&output_value).as_bytes() != output_bytes {
        return Err(ProviderError::NonCanonicalOutput);
    }
    let output = serde_json::from_value(output_value)
        .map_err(|error| ProviderError::InvalidOutput(error.to_string()))?;
    let remaining_fuel = store
        .get_fuel()
        .map_err(|error| ProviderError::ExecutionTrap(error.to_string()))?;

    Ok(ProviderExecution {
        output,
        artifact_sha256: actual_digest,
        fuel_consumed: limits.fuel.saturating_sub(remaining_fuel),
        memory_bytes: memory.data_size(&store),
        output_bytes: output_length,
    })
}

fn provider_engine() -> Engine {
    let mut config = Config::default();
    config
        .consume_fuel(true)
        .compilation_mode(CompilationMode::Eager)
        .enforced_limits(EnforcedLimits::strict())
        .floats(false)
        .wasm_memory64(false)
        .wasm_multi_memory(false)
        .wasm_custom_page_sizes(false);
    Engine::new(&config)
}

fn validate_limits(limits: ProviderLimits) -> Result<(), ProviderError> {
    for (field, value, hard_limit) in [
        (
            "max_module_bytes",
            limits.max_module_bytes,
            HARD_MAX_PROVIDER_MODULE_BYTES,
        ),
        (
            "max_memory_bytes",
            limits.max_memory_bytes,
            HARD_MAX_PROVIDER_MEMORY_BYTES,
        ),
        (
            "max_input_bytes",
            limits.max_input_bytes,
            HARD_MAX_PROVIDER_JSON_BYTES,
        ),
        (
            "max_output_bytes",
            limits.max_output_bytes,
            HARD_MAX_PROVIDER_JSON_BYTES,
        ),
    ] {
        if value == 0 || value > hard_limit {
            return Err(ProviderError::InvalidLimits(field));
        }
    }
    if limits.max_memory_bytes < WASM_PAGE_BYTES as usize {
        return Err(ProviderError::InvalidLimits("max_memory_bytes"));
    }
    if limits.fuel == 0 || limits.fuel > HARD_MAX_PROVIDER_FUEL {
        return Err(ProviderError::InvalidLimits("fuel"));
    }
    Ok(())
}

fn validate_module_boundary(module: &Module, memory_limit: usize) -> Result<(), ProviderError> {
    if let Some(import) = module.imports().next() {
        return Err(ProviderError::ImportForbidden {
            module: import.module().to_string(),
            name: import.name().to_string(),
        });
    }

    let mut saw_memory = false;
    let mut saw_entrypoint = false;
    for export in module.exports() {
        match export.name() {
            PROVIDER_MEMORY_EXPORT if export.ty().memory().is_some() => {
                let memory = export.ty().memory().expect("checked memory export");
                if saw_memory || memory.is_64() {
                    return Err(ProviderError::InvalidExport(
                        "ABI requires one 32-bit linear memory".to_string(),
                    ));
                }
                let initial_bytes = memory
                    .minimum()
                    .checked_mul(WASM_PAGE_BYTES)
                    .ok_or(ProviderError::MemoryLimitExceeded)?;
                if initial_bytes > memory_limit as u64 {
                    return Err(ProviderError::MemoryLimitExceeded);
                }
                saw_memory = true;
            }
            PROVIDER_ENTRYPOINT_V1 if export.ty().func().is_some() => {
                if saw_entrypoint {
                    return Err(ProviderError::InvalidExport(
                        "entrypoint is exported more than once".to_string(),
                    ));
                }
                saw_entrypoint = true;
            }
            name => {
                return Err(ProviderError::InvalidExport(format!(
                    "unexpected export {name}"
                )))
            }
        }
    }
    if !saw_memory {
        return Err(ProviderError::InvalidExport(
            "missing 32-bit memory export".to_string(),
        ));
    }
    if !saw_entrypoint {
        return Err(ProviderError::InvalidExport(
            "missing versioned entrypoint export".to_string(),
        ));
    }
    Ok(())
}

fn map_execution_error(error: wasmi::Error) -> ProviderError {
    match error.as_trap_code() {
        Some(TrapCode::OutOfFuel) => ProviderError::FuelExhausted,
        Some(TrapCode::GrowthOperationLimited) => ProviderError::MemoryLimitExceeded,
        _ => ProviderError::ExecutionTrap(error.to_string()),
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    const OUTPUT_OFFSET: u64 = 4096;

    #[derive(Debug, Serialize)]
    struct TestInput {
        seed: u32,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct TestOutput {
        provider: String,
        value: u32,
    }

    fn contract(artifact: &[u8]) -> ProviderArtifactContract {
        ProviderArtifactContract::new(PROVIDER_ABI_V1, provider_artifact_digest(artifact))
    }

    fn bytes_literal(value: &[u8]) -> String {
        value.iter().map(|byte| format!("\\{byte:02x}")).collect()
    }

    fn returning_module(output: &[u8], initial_pages: u32, body: &str) -> Vec<u8> {
        let packed = (OUTPUT_OFFSET << 32) | output.len() as u64;
        wat::parse_str(format!(
            r#"(module
                (memory (export "{PROVIDER_MEMORY_EXPORT}") {initial_pages} 8)
                (data (i32.const {OUTPUT_OFFSET}) "{}")
                (func (export "{PROVIDER_ENTRYPOINT_V1}") (param i32 i32) (result i64)
                    {body}
                    (i64.const {packed})))"#,
            bytes_literal(output),
        ))
        .expect("test provider WAT must compile")
    }

    #[test]
    fn valid_independent_provider_executes_typed_canonical_json() {
        let output = br#"{"provider":"independent","value":7}"#;
        let artifact = returning_module(output, 1, "");
        let result: ProviderExecution<TestOutput> = execute_provider(
            &artifact,
            &contract(&artifact),
            &TestInput { seed: 42 },
            ProviderLimits::default(),
        )
        .expect("valid provider must execute");

        assert_eq!(
            result.output,
            TestOutput {
                provider: "independent".to_string(),
                value: 7,
            }
        );
        assert_eq!(result.artifact_sha256, provider_artifact_digest(&artifact));
        assert!(result.fuel_consumed > 0);
        assert_eq!(result.memory_bytes, WASM_PAGE_BYTES as usize);
        assert_eq!(result.output_bytes, output.len());
    }

    #[test]
    fn altered_artifact_is_refused_before_module_loading() {
        let artifact = returning_module(br#"{"provider":"independent","value":7}"#, 1, "");
        let signed_contract = contract(&artifact);
        let mut altered = artifact.clone();
        *altered.last_mut().expect("module is non-empty") ^= 0x01;

        let error = execute_provider::<_, TestOutput>(
            &altered,
            &signed_contract,
            &TestInput { seed: 1 },
            ProviderLimits::default(),
        )
        .expect_err("artifact substitution must fail");
        assert_eq!(error, ProviderError::ArtifactDigestMismatch);
    }

    #[test]
    fn every_host_import_including_wasi_is_refused() {
        for module_name in ["wasi_snapshot_preview1", "env"] {
            let artifact = wat::parse_str(format!(
                r#"(module
                    (import "{module_name}" "forbidden" (func))
                    (memory (export "{PROVIDER_MEMORY_EXPORT}") 1)
                    (func (export "{PROVIDER_ENTRYPOINT_V1}") (param i32 i32) (result i64)
                        (i64.const 0)))"#,
            ))
            .expect("test import module must compile");
            let error = execute_provider::<_, TestOutput>(
                &artifact,
                &contract(&artifact),
                &TestInput { seed: 1 },
                ProviderLimits::default(),
            )
            .expect_err("all imports must fail");
            assert_eq!(
                error,
                ProviderError::ImportForbidden {
                    module: module_name.to_string(),
                    name: "forbidden".to_string(),
                }
            );
        }
    }

    #[test]
    fn infinite_loop_is_stopped_by_fuel() {
        let artifact = returning_module(
            br#"{"provider":"independent","value":7}"#,
            1,
            "(loop $forever (br $forever))",
        );
        let limits = ProviderLimits {
            fuel: 10_000,
            ..ProviderLimits::default()
        };
        let error = execute_provider::<_, TestOutput>(
            &artifact,
            &contract(&artifact),
            &TestInput { seed: 1 },
            limits,
        )
        .expect_err("infinite provider must run out of fuel");
        assert_eq!(error, ProviderError::FuelExhausted);
    }

    #[test]
    fn initial_and_growing_memory_are_bounded() {
        let output = br#"{"provider":"independent","value":7}"#;
        let oversized = returning_module(output, 2, "");
        let one_page = ProviderLimits {
            max_memory_bytes: WASM_PAGE_BYTES as usize,
            ..ProviderLimits::default()
        };
        let error = execute_provider::<_, TestOutput>(
            &oversized,
            &contract(&oversized),
            &TestInput { seed: 1 },
            one_page,
        )
        .expect_err("oversized initial memory must fail");
        assert_eq!(error, ProviderError::MemoryLimitExceeded);

        let growing = returning_module(output, 1, "(drop (memory.grow (i32.const 1)))");
        let error = execute_provider::<_, TestOutput>(
            &growing,
            &contract(&growing),
            &TestInput { seed: 1 },
            one_page,
        )
        .expect_err("memory growth past the cap must trap");
        assert_eq!(error, ProviderError::MemoryLimitExceeded);
    }

    #[test]
    fn claimed_output_beyond_limit_is_refused_before_allocation() {
        let output_limit = 32;
        let claimed_length = output_limit + 1;
        let packed = (OUTPUT_OFFSET << 32) | claimed_length as u64;
        let artifact = wat::parse_str(format!(
            r#"(module
                (memory (export "{PROVIDER_MEMORY_EXPORT}") 1)
                (func (export "{PROVIDER_ENTRYPOINT_V1}") (param i32 i32) (result i64)
                    (i64.const {packed})))"#,
        ))
        .expect("test output-limit module must compile");
        let limits = ProviderLimits {
            max_output_bytes: output_limit,
            ..ProviderLimits::default()
        };
        let error = execute_provider::<_, TestOutput>(
            &artifact,
            &contract(&artifact),
            &TestInput { seed: 1 },
            limits,
        )
        .expect_err("oversized output claim must fail");
        assert_eq!(
            error,
            ProviderError::OutputTooLarge {
                size: claimed_length,
                limit: output_limit,
            }
        );
    }

    #[test]
    fn output_must_be_canonical_and_match_the_requested_type() {
        let noncanonical = returning_module(br#"{ "value": 7, "provider": "x" }"#, 1, "");
        let error = execute_provider::<_, TestOutput>(
            &noncanonical,
            &contract(&noncanonical),
            &TestInput { seed: 1 },
            ProviderLimits::default(),
        )
        .expect_err("non-canonical output must fail");
        assert_eq!(error, ProviderError::NonCanonicalOutput);

        let wrong_type = returning_module(br#"{"provider":"x","value":"seven"}"#, 1, "");
        let error = execute_provider::<_, TestOutput>(
            &wrong_type,
            &contract(&wrong_type),
            &TestInput { seed: 1 },
            ProviderLimits::default(),
        )
        .expect_err("typed output mismatch must fail");
        assert!(matches!(error, ProviderError::InvalidOutput(_)));
    }
}
