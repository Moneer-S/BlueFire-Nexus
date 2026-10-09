# AI-first defense validation program

BlueFire's next program makes an objective, environment preparation, execution,
observations, defensive changes, and fresh retesting one saved operator workflow.
The delivery unit is a security question that a user can answer through normal
product controls. A scenario, adapter contract, or successful build alone does
not complete that unit.

## Scope and architecture

Keep the Python control plane, Rust execution boundary, React workspace, SQLite
product state, and immutable run evidence. Extend their existing contracts as
working operations need them. The [architecture](ARCHITECTURE.md),
[tool adapters](TOOL_ADAPTERS.md), [evidence model](EVIDENCE_MODEL.md), and
[replay and comparison](REPLAY_COMPARE.md) remain the starting points.

The finite initial scope is two distinct endpoint objectives, carried across the
declared endpoint environments, plus one AD and one AWS workflow:

| Objective | Proposed initial environment | Security question and intervention |
| --- | --- | --- |
| Controlled data handoff | Owned Ubuntu 24.04 x86_64 lab | Can generated records reach an authenticated destination, and does a redaction requirement block retained values while allowing legitimate redacted data? |
| Excess file access | Disposable Linux x86_64, Windows x86_64, then macOS arm64 endpoints | Can a dedicated test identity read or modify a generated application fixture through excessive permissions, and can a permission correction remove that access while preserving the intended application's access? |
| Excess domain access | Disposable Windows AD domain, an explicit member host and share, dedicated test identities | Does unnecessary group membership or an excessive share/file permission permit access to generated records, and does the selected correction remove the demonstrated access path while retaining authorized access? |
| Excess cloud access | Explicit AWS account, region, dedicated test roles, and one generated S3 data set | Does an excessive identity or resource policy permit access to the test objects, and does the selected policy correction block that route while preserving the intended role's access? |

The excess-file-access row now has a bounded Linux implementation with reviewed
software checks, not an installed or live cross-identity verification claim. Its
Windows and macOS paths, and the AD and AWS workflows, remain unverified
integration targets. See the [capability classification](RELEASE_CAPABILITIES.md).
Further method and library selection requires source, license, platform,
and environment review. These questions do not require credential extraction,
arbitrary command execution, production targets, or broad enterprise management.
Other cloud providers and additional technique families are later work.

Reusable resource and observation contracts must preserve environment, resource,
identity, provenance, time, and validity. Structural artifact compatibility alone
does not establish accessibility or current authority. Add these semantics first
for the selected operations; avoid a speculative environment ontology.

The existing [adaptive execution](ADAPTIVE_EXECUTION.md) policy binds exact
authored method alternatives. Runtime construction of new steps needs a distinct
versioned grant over a reviewed capability snapshot, objective, environment,
identities, effects, data, budgets, and lifetime. Existing exact-plan and adaptive
approvals keep their original meaning. Ordinary code validates each composition
and dispatch, reserves cumulative effects durably, and enforces expiry,
revocation, and recovery independently of the model.

## Delivery phases

Phases can overlap where their dependencies permit. Freeze each implementation
slice around its stated operator outcome. A phase closes with reviewed integrated
software and the required proof, or a prepared external dependency that identifies
exactly which proof remains unavailable. Missing access does not stop independent
implementation or other environment work.

### 1. A reliable starting point

**Outcome:** A user retains existing experiments and can resolve runner and method
readiness from the workspace without reconstructing a profile or losing work.

**Environment and prerequisites:** A matching packaged runner and an enrolled
local profile; the existing prepared Linux lab for installed execution checks.
Model connection remains optional for established manual operations.

**Implementation boundary:** Integrate the current setup and recovery work,
preserve saved graphs and evidence, and provide contextual repair actions.
Reconcile overlapping implementation before adding another execution family.
Use [native tool setup](NATIVE_TOOL_INSTALLATIONS.md),
[runner deployment](RUNNER_DEPLOYMENT.md), and the existing
[prepared lab](PREPARED_LINUX_LAB.md) lifecycle.

**Evidence and exclusions:** Verify installation, readiness repair, a saved and
reopened multi-stage experiment, actual execution, observation, cancellation,
cleanup, and recovery through visible controls. A working installed manual run
does not prove live AI, a defensive change, or fully automated lab provisioning.

### 2. One complete defensive workflow

**Outcome:** From the controlled-data objective, a user prepares the lab, executes
a chain, inspects independent observations, accepts a receiver control, retests
the original path, and checks that legitimate redacted data still passes.

**Environment and prerequisites:** The owned Linux lab, prepared runner and
receiver, generated records, and scoped loopback communication. Live model work
requires an explicitly configured provider and finite data and spending authority.

**Implementation boundary:** Build on the
[receiver control test](receiver-control-test.md), collection semantics,
Assistant, ordinary run/replay jobs, and comparison. Add guided objective and
environment selection with preparation progress in the experiment workspace.
Keep observations, rule work, and retests linked to that saved context from this
phase onward. Make a defensive change a
saved object with proposed, authorized, applied, externally reported, verified,
failed, reverted, or retained state. Keep observation distinct from a report that
a change was applied. Separate attack cleanup from accepted defense retention and
explicit rollback. Add the legitimate redacted-use check and a meaningful
compatible alternate where available. Connect an initial capability grant and
evidence-based composition to this operation, including changed prerequisites.

**Evidence and exclusions:** Require fresh baseline and protected execution,
authenticated receiver decisions, observed content, benign redacted-use results,
settled cleanup, retained change state, and comparison. A live configured model
must make a useful decision from evidence for live-AI proof. The existing fixed
baseline/protected/restored test is a reusable foundation; its runtime AI-Off
restriction, fixed route, and restoration semantics do not satisfy this outcome
by themselves. Loopback transfer remains a local control experiment.

### 3. Composition across different objectives

**Outcome:** The same workspace and capability system answer the excess file
access question as well as the handoff question. Users can inspect how observed
resources supply later steps and why a changed condition permits a new route.

**Environment and prerequisites:** Start with an owned Linux endpoint containing
generated application fixtures and deliberately provisioned test identities.
Identity creation and effective-access probes need explicit environment authority;
the current private workspace alone cannot demonstrate another user's access.

**Implementation boundary:** Add native permission observation, effective-access
testing under the selected test identity, reversible correction, and legitimate
application-use checks. Reuse versioned artifacts, method adapters, durable grant
accounting, evidence, changes, and comparison. Add freshness and invalidation for
the facts these methods consume. Support branching, joins, and controlled repeat
operations with visible limits, while recording attempted and unexecuted work
separately. Demonstrate adding one comparable reviewed method without a new
coordinator. Preserve direct graph editing of the same saved work.

**Evidence and exclusions:** Prove two materially different objectives, real
producer/consumer combinations, useful evidence-driven replanning, and refusal of
incompatible, stale, revoked, or excessive requests. Include restart and
interruption recovery without repeated effects. The existing
[chmod method](ATOMIC_CHMOD.md) establishes permission bits, not effective access;
it cannot substitute for this proof. Neither a reserved attempt nor an action's
exit status establishes the security objective.

### 4. Endpoint, AD, and cloud expansion

**Outcome:** The proposed Windows, macOS, AD, and AWS questions use the same
planning, readiness, evidence, defensive-change, and comparison workflow.

**Environment and prerequisites:** Disposable Windows x86_64 and macOS arm64
hosts; an explicit disposable domain and member host; an authorized AWS account,
region, test roles, resource names, network destinations, and audit collection.
Each environment needs selected tool identities, credentials supplied through
supported protected references, resource limits, and a cleanup or reconciliation
plan. Test access is a separate prerequisite from software implementation.

**Implementation boundary:** Use native ACL/access mechanisms on Windows and
macOS. For AD, compose scoped membership/permission observation, authenticated
access to generated share data, the selected permission or membership correction,
fresh authentication and retest, and an authorized-use control. For AWS, compose
identity/resource-policy observation, generated-object access, reviewed policy
correction, fresh retest, delayed audit correlation, and resource reconciliation.
Treat propagation delay and missing audit data explicitly. Keep implementations
in their tool-owned integration areas with shared supervision and typed results.

**Evidence and exclusions:** Every declared live environment needs actual native
execution, independent effect observation, a verified non-detection change, fresh
original-path retest, a permitted alternate where one exists, legitimate-use
checks, and cleanup or retained-hardening disposition. macOS compilation or
Windows API fixtures on Linux are structural evidence only. Existing deterministic
AWS identity/tagging work is useful prior integration work; it does not establish
an S3 policy intervention, cloud prevention, or live audit collection. No automatic
extension to other operating-system versions, architectures, domains, or accounts
is implied.

### 5. An integrated release candidate

**Outcome:** A fresh supported user can choose an objective, prepare or connect an
environment, connect an evaluated model, and reach a defensible result through a
consistent workspace. Expert editing, recovery, and export remain available when
inference fails.

**Environment and prerequisites:** The declared endpoint builds and authorized
test environments, reviewed distribution inputs, one high-capability model
configuration and one lower-cost configuration where access permits, plus one
selected real telemetry/detection integration.

**Implementation boundary:** Complete guided provisioning on supported paths;
bring setup, environment facts, graph, Assistant, observations, changes, rules,
and comparisons into one navigable experiment context. Integrate one real native
telemetry source with a supported detection backend, chosen after environment
review. Reuse [detection authoring](DETECTION_LAB.md) and evaluation lineage.
Evaluate model configurations on useful plans, compositions, decisions, recovery,
and measured cost. Update installation instructions, capability declarations,
screenshots, and recordings to match the delivered product.

**Evidence and exclusions:** Verify literal fresh-user installation, normal clicks
and keyboard interactions, reload/recovery, declared graph scale, accessibility,
and visual quality. Detection proof includes real source fields, actual supported
backend validation, observed activity, benign variation, misses, and revision
lineage. Distinguish local evaluation from deployed rules and actual alerts.
Require relevant candidate checks, scoped independent review, publication privacy
checks, and preserved-data upgrade checks. A release candidate is not a stable
release publication decision.

## Proof and external dependencies

Track each outcome and environment with separate evidence fields:

| Status | Meaning |
| --- | --- |
| Implemented | Code and focused software checks exist for the declared contract. |
| Integrated | The reviewed capability works with the main product interfaces. |
| Installed-verified | A matching installed build completed the normal operator journey. |
| Live-verified | Actual effects, independent observations, live-model decisions, or backend results were demonstrated in their explicitly named environment. |

Live model, native endpoint, domain, cloud, and deployed detection evidence are
separate categories. Historical results retain their original source/build and
environment identity. See the current
[capability classification](RELEASE_CAPABILITIES.md) for existing limitations;
this roadmap does not upgrade those claims.

Before an external-access decision, prepare the exact environment and identity
scope, selected methods and effects, data supplied or observed, network needs,
time/resource/cost limits, evidence to collect, and cleanup or retained-change
plan. List independently actionable implementation and validation separately.
Do not request secrets in a report or treat fixture success as missing live proof.

Program acceptance requires the complete declared outcomes: reusable substantial
chains across both endpoint objectives, live evidence-based composition within
enforced grants, retained non-detection improvements with fresh retests, real
detection work, truthful endpoint/AD/cloud coverage, evaluated model behavior,
and an installed workspace that supports the full journey. The first receiver
scenario is an early delivery, not program completion.
