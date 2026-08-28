# Execution model

BlueFire Nexus has exactly two modes: **Simulate** and **Execute**. They share scenario and planning contracts but have different effect and evidence semantics.

## Mode invariants

| Property | Simulate | Execute |
|---|---|---|
| Default | Yes | No |
| Rust runner launched | Never | Only after preflight and policy |
| Action ID | May be shown as a possible action | Must be registered and profile-enabled |
| Profile | Simulate profile | Explicit Execute profile |
| Approval | Not an execution approval | Bound approval when the profile requires it |
| Primary provenance | synthetic | executed, control_blocked, or unknown on transport failure |
| Independent observation | Only if a separate observer runs | Only if a separate observer runs |
| Network | Modeled only | Literal allowlisted loopback only in the current runner |

AI autonomy (`off`, `assist`, or `auto`) is orthogonal to both modes. It never changes these invariants.

## Shared preflight

Before either mode, the control plane:

1. loads a versioned configuration without resolving environment values;
2. loads the versioned behavior and action catalogs;
3. parses the scenario with unknown-field rejection;
4. validates stable IDs, parameters, typed bindings, alternates, explicit edges, DAG shape, reachability, and artifact-source dominance;
5. compiles a deterministic plan;
6. records the scenario and plan digests.

Preview performs these checks without creating effects. Execute preview additionally resolves the selected profile, checks runner inventory compatibility, evaluates policy requirements, and reports approval and cleanup readiness.

## Simulate path

Simulate applies the behavior's registered simulation transition. It follows only declared outcome edges. A simulation result must retain synthetic provenance even when the modeled outcome is success.

If a blocked or failed step has a declared alternate edge, the planner follows that edge. If it models the success branch without a real alternate, the continuation is counterfactual. Counterfactual evidence remains labeled and cannot satisfy a requirement for executed or observed evidence.

Simulate must not:

- instantiate or invoke the Rust runner transport;
- write a runner manifest as if it were accepted;
- label evidence executed or observed;
- resolve a network destination for an effect;
- bypass metadata_only behavior restrictions.

## Execute prerequisites

Execute is unavailable unless every prerequisite succeeds:

- the requested mode is execute;
- an explicit Execute profile is selected;
- the operator supplied an explicit target scope contained by that profile;
- an explicit managed bootstrap has verified a compatible native artifact and created active local enrollment;
- the separately hosted runner is mutually authenticated and ready for the exact Execute profile;
- the managed or explicit operator sandbox is private, disposable, and passes exact readiness checks;
- runner inventory uses the supported schema and contains compatible descriptors;
- the scenario behavior exposes an action ID enabled by the profile;
- action, profile, and current host platforms intersect;
- action effect capabilities are contained by the profile capabilities;
- the requested safety tier is permitted;
- target scope is no broader than the profile;
- step, time, file, byte, and output budgets are positive and within profile maxima;
- cleanup is registered and permitted;
- policy allows the exact request;
- a live request-bound approval is present when required.

Failure of any prerequisite is a refusal, approval_required, or control_blocked outcome. It is not silently converted into simulated success.

## Logical contract to sealed executor contract

The behavior/action catalog and Rust inventory serve different purposes.

The logical catalog describes scenario-facing parameters and typed artifacts. It is stable across platforms and does not expose runner paths, process arguments, sockets, or receipt state.

The Rust inventory describes executor-facing, action-specific parameter objects and effect capabilities. Those objects may contain bounded relative paths, fixed template choices, reviewed booleans, literal loopback destinations, or receipt IDs after the control plane has resolved prior artifacts.

RunnerActionAdapter is the only bridge. For each known action ID it:

1. validates the logical parameters again;
2. resolves typed input bindings from prior normalized artifacts;
3. maps logical values to one fixed Rust parameter schema;
4. normalizes and checks portable relative paths;
5. rejects missing, ambiguous, or wrong-type artifacts;
6. rejects unknown fields and action IDs;
7. returns a sealed parameter mapping for manifest construction.

There is no reflective mapper, free-form fallback, or caller-supplied executable field.

## Policy and approval

Policy evaluation is deny by default. It considers:

- registered behavior and action identity;
- selected profile and mode;
- enabled and control-blocked action sets;
- semantic and effect capabilities;
- safety tier and platform;
- filesystem and network scope references;
- resource budgets and cleanup policy;
- approval threshold and approval state.

Approval uses a versioned record containing operator identity, issue and expiry times, action ID, runner-profile ID, target-scope digest, request hash, and nonce. It is valid only for the exact normalized request. Changing a parameter, artifact reference, action, profile, or scope requires a new approval.

The CLI approval option records an operator decision; it does not prove external authorization. Organizational authorization remains outside the software boundary.

## Manifest sealing

The sealed runner manifest includes request, run, step, behavior, action, runner, profile, and platform identity; timestamps; translated parameters; target scope; required effect capabilities; safety tier; limits; cleanup action; policy digest; approval; parent evidence references; and request hash.

The request hash is calculated over canonical JSON using the runner contract's normalization rules. The profile also has a canonical policy digest. These values detect mismatches between what was reviewed and what was received. They are not signatures.

The Rust runner rejects unknown fields and validates the profile and manifest independently. It also checks that the request has not expired and that the requested platform matches the actual host.

## Transport boundary

SubprocessRustRunner accepts only a configured absolute runner path and a configured work root. Its public calls are inventory and execute. Execute writes canonical manifest and profile JSON into a temporary request directory, then invokes a fixed argument vector with shell disabled.

The child receives null standard input, a minimal environment, a fixed working directory, a timeout, and bounded captured output. The transport rejects generic execution keys recursively before launch and verifies the returned schema, run ID, step ID, and action ID.

Transport failure is not action success. Invalid JSON, output overflow, timeout, nonzero exit, or identity mismatch is reported as an error/refusal according to the normalization layer and retains unknown or control-blocked provenance as appropriate.

## Rust action boundary

The current Rust registry contains eighteen IDs:

- sandbox.fixture.create.v1
- sandbox.fixture.transform.v1
- sandbox.discovery.list.v1
- sandbox.discovery.metadata.v1
- endpoint.discovery.system.v1
- endpoint.discovery.processes.v1
- sandbox.discovery.recursive.v1
- sandbox.archive.tar.v1
- sandbox.collection.stage.v1
- sandbox.network.loopback.v1
- sandbox.export.local.v1
- sandbox.execution.native-canary.v1
- sandbox.identity-material.seed.v1
- sandbox.identity-material.inspect.v1
- sandbox.peer.handoff.v1
- sandbox.observability.variant.v1
- sandbox.restricted.persistence-marker.v1
- sandbox.cleanup.v1

Their scope is deliberately narrow: create/transform deterministic fixtures; inspect one exact fixture's metadata plus bounded system, process, and recursive-file facts; create a deterministic archive; stage one fixture as one bundle; send one bounded artifact to a literal allowlisted loopback socket; create a temporary policy-labelled copy at a fixed runner-owned export path; run bounded in-process computation; seed and inspect one public fixed-path identity-material canary; authenticate one staged-bundle handoff to literal IPv4 loopback; create one fixed-path reversible observability representation; write one fixed non-executable restricted-tier canary marker; and clean receipt-bound objects. The canary never changes host persistence settings.

The native-canary, identity-seed, identity-inspection, and observability-variant representative descriptors are implementation version `1.0.0`; peer handoff is `2.0.0`. All report inventory readiness `ready`. Native canary accepts only `rounds` from 1 through 4096 and has no compiled effect capability beyond `NativeExecution`; it launches no process and has no filesystem or network effect. Identity seed has no logical parameter and writes the exact public synthetic document at `identity-material/public-canary.json`. Identity inspection accepts only the resulting typed artifact and returns byte count, field count, and SHA-256 digest without returning values. It is not credential access.

Peer handoff accepts only a port and exactly one typed `staged/bundle.json` or `staged/bundle.jsonl`. Its destination is hardcoded literal `127.0.0.1`; an authenticated challenge binds the approved task to one ephemeral receiver exchange, and the v2 receipt retains only an opaque task-capability handle plus bounded peer-process/lifecycle evidence. Execute requires the separate memory-only disposable receiver and the blocked-network profile lists the action as blocked. Observability variant accepts only `canonical` or `chunked_hex` and creates `observability/variant.bin`. The former is continuous lowercase hexadecimal; the latter uses 64-character lines without a trailing line feed. Both decode exactly to the source bundle. Output metadata names the representation, source and output identities, digests and sizes, and equivalence result. It is a transparent comparison action with no bypass, evasion, or control-impairment claim.

The shipped `scenario.operator.representative-validation.v1` orders native canary, public identity seed/inspection, fixture create/transform/metadata, staging, observability variant, peer handoff of the original staged bundle, and cleanup. All paths are fixed or artifact-derived, and the scenario's provenance and limitations distinguish simulated, executed, and independently observed evidence.

The fixture and staging contracts are exact rather than best-effort. Create writes 1..100 deterministic JSONL records to the adapter-derived `fixtures/input.jsonl`; every record has only `record_id`, `synthetic`, `template`, and `value`. Transform validates the full schema and generated values, canonicalizes the records, and uses a reviewed `redact_values` boolean. When enabled, it replaces every value with the public `synthetic-redacted` placeholder and reports the record and redaction counts.

List and metadata descriptors are version `2.0.0` and accept only the exact fixture `path`. Each returns one regular-file metadata entry for that path; neither enumerates siblings nor opens or hashes content. Collection `2.0.0` accepts exactly one bound fixture, validates the complete input and all limits before creating an effect, and emits one deterministic JSONL or JSON bundle. Its top-level result reports artifact, format, input/accept/reject counts, record count, digest, size, and completion; it does not return a nested `staged` object or leave a partial bundle after an input failure.

Export `2.0.0` derives `exports/ephemeral/bundle.bin` or `exports/review/bundle.bin` from the reviewed `retention_label`. Both are temporary, receipt-owned local copies. The label records policy classification only: `review` does not mean preserved or fallback-surviving, and normal scenario cleanup deletes both labels.

The runner has no generic command, shell, URL, hostname resolution, redirect, proxy, dynamic library, or Python plugin action. Its transforms/templates are compiled choices. Process discovery uses Windows native APIs or one fixed platform-selected absolute `ps` adapter; callers cannot select a program or arguments.

## AI proposal boundary

Off creates no provider. Assist/Auto request a strict v2 proposal only after a step produces an observed outcome. The request binds the exact registered edge for that outcome and correlated options for a compatible behavior, allowlisted primitive parameters, an exact-profile registered action, and one bounded retry. Assist persists the choice and pauses before mutation. Auto may apply a policy-valid choice only in Simulate. Execute mutations remain stopped until proposal review, fresh-workspace full replay from the scenario start, and a separate fresh exact approval.

Provider credentials are environment references. Requests are redacted/bounded; OpenAI-compatible structured responses use timeouts, retry limits, response/token bounds, exact schema validation, and deterministic fallback. The model cannot choose an edge for another outcome, cross-pair options, issue a command or path, create a capability, change profile/scope/tier/policy, approve itself, or exceed the retry budget.

These constraints describe the source contract. Execute readiness for a particular installation still requires a successful local build, inventory check, preflight, and applicable runner tests.

## Scope enforcement

Filesystem scope uses normalized relative paths beneath one existing sandbox root. Absolute, drive, UNC/device, alternate-separator traversal, dot-component, reserved-device, symbolic-link, and reparse-point escapes are refused.

Network scope uses literal IP address and port pairs. Both network actions accept loopback only; peer handoff further hardcodes `127.0.0.1`. The canonical profile allowlist contains only 127.0.0.1/32 and ::1/128. DNS names, redirects, proxies, and non-loopback destinations are outside the action contract.

## Results and evidence

The runner result echoes the request, action, behavior, runner, profile, platform, request hash, and policy digest. Runner statuses include success, failed, partial, refused, control_blocked, timed_out, and cleanup_failed. Normalization must preserve distinctions rather than folding them into success.

Runner evidence can claim executed after an action starts and control_blocked for a pre-effect policy refusal. It cannot claim observed. Independent observation belongs to SandboxObserver or another separately reviewed observer.

The control plane also supports synthetic, counterfactual, and unknown provenance. Each evidence record carries producer, parents, environment, hashes, confidence, limitations, and target-scope reference.

## Cleanup

Create-new runner actions issue receipts in runner-owned state. Cleanup `1.1.0` accepts receipt IDs, not caller-selected paths. It reloads each receipt, atomically moves an owned path without replacement into private runner-state quarantine, revalidates type, size, and digest there, and only then deletes it. If another object appears at the public path, that replacement is left untouched and the post-removal verification makes cleanup fail visibly. Changed objects, malformed receipt state, permission errors, and other unverifiable conditions are retained or reported rather than treated as absence. Successful receipts are consumed; reusing a consumed receipt is idempotent.

Cleanup holds the sandbox, source-parent, and staging directory chain while it moves, restores, removes, and verifies entries. Windows pins those names against rename and deletes the exact opened object by handle. Linux and macOS use descriptor-relative operations; their final quarantine unlink is basename-relative because POSIX has no portable unlink-by-open-file-descriptor primitive. Runner state is therefore enforced as effective-user-owned mode `0700`, identity mismatches fail closed, and the product does not claim protection from a hostile process running as the same OS user.

The control plane authenticates and records returned receipts immediately after runner identity checks, before evidence, event, or planner processing. A successful, partial, or timed-out mutating result counts as cleanup-owned only when the receipt has the exact schema and bounded owned paths, matches the request, action, profile, and canonical workspace, recomputes to its filename digest, and has a matching durable commit. Valid uncommitted intents remain recovery evidence for failed or cancelled dispatches but cannot justify a successful mutation. The control plane keeps outstanding receipts in creation order and submits them to cleanup in reverse order. If later control-plane processing raises unexpectedly, it makes an emergency cleanup attempt through the same registered Rust cleanup action and then preserves the original exception. Cleanup returns the same authoritative report in the result's `output` and `cleanup` fields. A claimed success is accepted only when verification ran, the report covers every requested receipt, its verified counters are internally consistent, and it lists no errors or retained paths.

Cleanup outcomes are first-class. partial and cleanup_failed remain visible in the step result, evidence, run bundle, and comparison view.

Profiles declare always, on_success, or manual cleanup policy. Any Execute plan containing a mutating action is refused unless the profile uses always, the cleanup action is enabled and unblocked, and the plan contains a cleanup step. Preview shows this readiness before Execute begins.

Before every mutating filesystem effect, the runner atomically publishes a durable intent record. After the effect it commits the corresponding receipt. On startup, the control plane reconciles only privately bound execution workspaces, discovers pending or committed records, and invokes the registered cleanup action in reverse creation order. A finalized run is never rewritten: recovery is recorded in a separately hashed, atomically published sub-bundle. Recovery is deferred rather than guessed if the original workspace, approval binding, runner WAL protocol, or receipt integrity cannot be proven. Host loss or destruction of the bound workspace remains outside what software recovery can repair.

## Replay and comparison

Replay never changes the source run. Exact replay retains the original scenario snapshot. Variant replay records the source digest and every declared change, including restart node, compatible behavior swap, profile, AI setting, or defense note.

Replaying executed evidence does not make the new run executed. Each new run produces its own provenance.

Comparison operates on normalized bundles. It reports differences; it does not infer that one changed setting caused an observed outcome.

## Operator checklist

For Simulate:

1. Validate the scenario.
2. Preview the plan and provenance.
3. Confirm the selected mode is simulate.
4. Run and validate the finalized bundle.

For Execute:

1. Confirm written authorization and sandbox ownership.
2. Install a compatible platform-native package, or build and test an explicit source-development runner override.
3. Set only any reviewed source-development binary or disposable-sandbox override; packaged bootstrap otherwise manages both beneath the private product root.
4. Run `bluefire runner bootstrap --profile PROFILE_ID` to verify the artifact and establish local enrollment.
5. Run `bluefire runner start --profile PROFILE_ID`, then require `bluefire runner status --profile PROFILE_ID` to report authenticated readiness.
6. Preview with mode execute and the exact profile.
7. Review actions, translated scope, capabilities, budgets, cleanup, and approval request hash.
8. Approve only the exact reviewed request.
9. Run, inspect refusal or result honestly, verify cleanup, and validate the bundle.
10. Stop the managed host before revocation, upgrade, or confirmed removal.

Never use a successful Simulate run, a preflight allow decision, or a bundle hash as proof that Execute occurred or that a defense observed it.
