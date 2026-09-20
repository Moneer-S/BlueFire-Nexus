# Reviewed tool adapters

The Python `bluefire.tool_adapters` package validates review metadata and logical
inputs. The [GNU chmod permission method](ATOMIC_CHMOD.md) connects that contract
to protected installation setup, approval binding, a fixed Rust adapter, receipt
cleanup and permission observations. Its software validation is separate from
live lab proof. The existing [Atomic gzip method](ATOMIC_GZIP.md) remains its own
fixed Rust adapter.

## Decision

External utilities use reviewed native adapters, separate from declarative plugin
metadata and signed no-host-import WebAssembly providers. A run chooses a registered
method and typed inputs; the adapter owns executable content and invocation. The
WASM ABI gains no process, filesystem, interpreter, network, or host imports.

The first `bluefire.tool-adapter.v1` contract names exact adapter/action/implementation
versions, an upstream revision and content digest, supported platform/architecture,
prerequisites, closed logical parameters, supervision policy, resource ceilings,
cleanup action, result parser, artifact types and observation schema. Stable IDs
refer to reviewed code; they are not import strings or entrypoints to resolve dynamically.

Parsing validates structure, not source authenticity or licensing. A source URL is
an identity reference only, never a runtime download instruction. The canonical
snapshot is immutable and has a digest; reordering JSON keys leaves that digest
unchanged, while changed review data produces a different identity.

V1 supports reviewed string choices, bounded integers and booleans using the existing
catalog parameter vocabulary. Existing typed artifact bindings carry selected data;
they must still pass action-specific validation. No caller-supplied command, script,
executable, module, implementation URL, or argument array is accepted. An approved
installation path belongs to trusted setup configuration, not logical run parameters.

V1 declares a local owned endpoint, current-user privileges, network off, an
adapter-private working directory, an explicit environment allowlist, owned-process
tree cancellation, and read-only or receipt-owned filesystem effects. Elevated,
remote, and cloud methods need additional reviewed contracts before admission.
These initial limits are not a product-wide ban on those method families.

## Integration seams and required enforcement

Each concrete method must enforce these checks together before reporting readiness:

1. A tool-owned module provides its descriptor, fixed invocation, structured parser,
   prerequisites, source/license review, and simulation fixtures. Catalog and runner
   inventory bind the exact action/behavior/implementation identity.
2. Setup binds a protected installed tool's declared version, observed digest and location. Readiness
   distinguishes missing installation, unexpected identity, unsafe permissions,
   incompatible environment, and absent observers. Execution never installs code or
   searches an uncontrolled PATH.
3. The existing plan/profile/approval flow binds the descriptor digest, concrete tool
   identity, target, capabilities, inputs, effects, cleanup and effective limits.
   Descriptor maxima can only narrow those limits. Legacy approvals gain no new authority.
4. Rust rechecks that binding immediately before effects, pins the inspected tool,
   invokes only adapter-owned code, supervises its process tree and bounded I/O,
   and preserves partial effects for receipt-bound cleanup and restart recovery.
5. Result parsing applies the data policy before persistence. Execution status remains
   separate from independent observations and detector evaluations. Replay retains
   these identities and gaps; a new run requires its own valid authorization.

Do not wire a generic descriptor-to-command dispatcher into `runner_transport.py` or
`runner/src/actions.rs`. Share supervision through verified seams, while each tool
keeps explicit invocation and parsing code. Do not append per-tool persistence cases
to `product_store.py`; reuse durable artifact/evidence records.

The existing gzip adapter already pins a protected ELF inode, uses fixed arguments,
captures bounded output, and publishes receipt-owned artifacts. It records its
executable digest but does not bind a separately configured expected tool version and
digest; it also uses `/` as its working directory. It therefore is not advertised as
implementing this new contract. Migration must preserve its current negative tests
and receipt guarantees while adding the missing installation/supervision binding.

## Outcome and evidence contract

An adapter must preserve the difference between authorization refusal, dependency or
platform unavailability, target prevention supported by evidence, execution failure,
timeout/cancellation, missing telemetry, independently verified objective, and a
detector match. A zero exit status establishes none of the latter three by itself.
Unclassified output remains unknown. A process returning an error does not prove that
a target defense intervened. Existing runner result, observation and cleanup records
remain the durable sources; declarations of a parser or observer do not create evidence.

Resource fields cover elapsed time, input/output/diagnostic bytes, artifacts and their
bytes, processes and attempts. Positive v1 ceilings are schema constraints, not a
claim that this prerequisite alone enforces OS resource limits. Memory/CPU containment,
deadline propagation, child reaping, output redaction, interrupted cleanup and exact
installation checks must be proven by the concrete adapter before it is executable.

## Validation and rollback

`tests_platform/test_tool_adapter_contract.py` checks unknown-field rejection,
logical value bounds, canonical identity, mutation isolation and supervision limits.
These deterministic contract tests are not live execution or detection proof.
Existing catalog, runner, gzip and WASM-provider tests protect compatibility.

The first full journey must demonstrate actual execution, independent observation,
an evaluated detector revision, benign activity, a fresh variation, cleanup, saved
results and comparison through the installed UI. Keep absent lab/provider access
explicit; it blocks that proof rather than turning fixtures into success.

To disable the permission method, remove it and its installation binding from the
selected runner profile and review subsequent runs again. Keep historical evidence
and creation receipts for cleanup. Reverting the implementation must retain a runner
capable of cleaning up any outstanding receipt-owned files.
Later adapter admission must carry its own rollback and compatibility evidence.
