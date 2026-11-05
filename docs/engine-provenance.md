# Strix engine candidate provenance

BlueFire prepares Strix as a separately attributed package-declared `1.7.0` modified-source
candidate, not an official Strix release. The candidate build is a
supply-chain step only. It does not run Strix, its TUI sidecar, a sandbox, a security tool, a
target, or a model, and it does not qualify runtime containment or effectiveness.

## Reviewed identities

The builder accepts only these source identities:

| Item | Reviewed identity |
| --- | --- |
| Repository | `https://github.com/usestrix/strix.git` |
| Source commit | `6b7ae2ebe4d47037a927aade23265ff4e4f27e84` |
| Git tree | `23c06e4a0e58bdf3b4979863d7623230e4091332` |
| Declared package version | `1.7.0` |
| Published `v1.7.0` release commit | `55bc07991aacb1c26a81b43e7ca53148730d2019` |
| Root declared source license | Apache-2.0; does not clear third-party components |
| Python requirement | `>=3.12` |

The reviewed source commit is not the published `v1.7.0` release commit. The candidate records
the declared package version, exact source commit, exact source tree, BlueFire workflow revision,
and resulting artifact hashes separately. It makes no release-equivalence claim.

The build also validates fixed Git blob identities for `pyproject.toml`, `uv.lock`, `LICENSE`, the
system prompt, `strix/interface/main.py`, the Hatch TUI build hook, and the Go module files. It refuses a dirty preimage,
unexpected remote, changed metadata, missing Apache-2.0 text, or drift in any reviewed blob.

## Engine selection and evidence record

Strix is the default external engine for this increment because the repository has already pinned
and reviewed its source, uses its supported headless CLI, and can integrate through its public
runtime-backend registry while preserving its report and agent-coordination behavior. BlueFire
places authorization, target and model routing, lifecycle control, evidence retention, and cleanup
outside that model-driven engine. Decepticon remains an alternative only if a concrete requirement
cannot be met through this controlled Strix profile. No Decepticon source version, dependency
closure, adapter, admission, or effectiveness proof is accepted by the current implementation, so
switching engines would require a separate source and runtime decision rather than an informal
fallback.

Every installed engine journey must retain one exact, reviewable record containing:

- BlueFire source revision; Strix source, package, prompt and startup overlay identities; the complete
  resolved dependency-lock digest; and the exact bootstrap, backend, policy-proxy,
  workspace-transfer, controlled-provider, SDK-closure, derived-image and runtime-profile digests;
- every candidate, installed runtime, image contract, base-image, Dockerfile, SBOM, provenance,
  attestation, image-qualification receipt-set and runtime-admission reference used;
- the exact preparation reference and acceptance record, binding and delegation digests, job,
  submission and intent identities, preflight revision and digest, execution-claim reference and
  runtime-resolution reference for the admitted attempt;
- provider and model identity, configuration, test-versus-live label, budgets, measured usage, and
  any usage or cost uncertainty;
- owned target, authorized scope, environment snapshot, versioned delegation, and controller-owned
  target and model relay identities;
- raw engine artifacts, engine-reported outcome and exit classification, independent observer
  identity and health, retained observations, and every evidence completeness gap;
- baseline mechanism and outcome, bounded defensive change, exact-mechanism retest, fresh adaptive
  attempt, legitimate-use check, and cleanup or retained-hardening disposition;
- cancellation and restart/reconciliation results, including pre-dispatch cancellation or
  absent-claim evidence where applicable; operator interventions, abandoned paths, reused
  findings, refreshed prerequisites, and unresolved uncertainty.

This record is an acceptance requirement, not evidence that such a journey has already run.

## Reviewed BlueFire modifications

The upstream system prompt contains blanket authorization and refusal-avoidance wording that is
not suitable as a BlueFire execution boundary. The candidate applies the reviewed correction
through `bluefire.strix_policy_overlay.apply_policy_overlay` to:

`strix/agents/prompts/system_prompt.jinja`

The pinned upstream CLI checks and may pull Docker before it selects the effective runtime backend.
The second reviewed correction is an exact old-to-new byte replacement through
`bluefire.strix_startup_overlay.apply_startup_overlay` in:

`strix/interface/main.py`

The replacement reads `load_settings().runtime.backend`, validates that name through the registered
`get_backend` hook before scan preflight, and performs the existing Docker check and image pull only
when the effective backend is `docker`. `validate_environment()` remains unconditional. The stock
Docker branch retains its check, pull, and environment validation order.

Both corrections require the exact upstream preimage and exact patched SHA-256. The startup
replacement bytes and the prompt correction are separately hash-pinned. The builder refuses any
modified tracked path beyond those two, checks both files in the wheel and its `RECORD`, and emits
separate prompt and startup receipts. The upstream commit and tree describe the clean preimage;
the source archive and wheel hashes identify the modified output. The manifest marks the result
as a modified upstream build. Authorization remains in BlueFire's reviewed controller and runtime
boundaries, not in the prompt or this startup branch.

## Controlled candidate build

The manual or reusable `Strix engine candidate` workflow uses:

- a standard `ubuntu-24.04` GitHub-hosted runner with a 30-minute job limit;
- Python 3.12.14, Go 1.24.10, and uv 0.13.6 from commit-pinned setup actions;
- the upstream frozen `uv.lock` and `uv export --frozen --no-dev --format cyclonedx1.5`;
- `uv build --wheel --frozen`, with a separately reviewed Hatchling 1.32.4 closure pinned to
  exact PyPI wheel URLs and SHA-256 hashes (and shared dependency versions cross-checked against
  `uv.lock`), plus Go modules restricted to the checksum-verified public proxy;
- an isolated HOME, temporary area, uv cache, and Go caches; and
- an upstream subprocess environment that inherits no GitHub, cloud, registry, Docker, model,
  proxy, user-home, or credential variables.

The manifest records exact tool versions and executable hashes, hosted runner identity, `uv.lock`,
`go.mod`, and `go.sum` hashes, source blobs, both overlay receipts, and artifact identities. Candidate output is
limited to 256 MiB. Destinations are exclusive, archives reject links and special files, and the
wheel is inspected as bounded ZIP data rather than installed or imported. A single build does not
establish byte-for-byte reproducibility; that remains an explicit qualification blocker until a
second clean build is compared.

Packaging necessarily executes the separately blob-pinned Hatch build hook, which issues a fixed
Go compile for the Bubble Tea sidecar. That build-time action is distinct from launching the Strix
engine or sidecar. No built executable, Strix import path, target operation, model request, or
sandbox image is run by this workflow.

Successful output contains:

- one platform wheel with the exact Apache license, reviewed prompt, reviewed startup, and a hashed, non-executed
  Linux x86-64 TUI sidecar;
- a deterministic source archive containing both reviewed modifications and upstream license;
- the exact upstream Apache-2.0 `LICENSE`;
- a CycloneDX 1.5 dependency SBOM;
- a canonical candidate manifest with SHA-256 and size for every payload; and
- `SHA256SUMS`, which covers the payloads and manifest but intentionally does not hash itself.

The workflow has read-only repository permission and does not retain checkout credentials. All
candidate payloads remain ephemeral under runner-temp; no Actions artifact, cache, package, or
release is published. Successful CI processing does not grant publication or redistribution rights.

The wheel is not a standalone installation artifact. Its broad upstream dependency metadata must
not be resolved later against a moving package index. Runtime installation remains refused until
an offline platform wheelhouse is produced from the same `uv.lock`, hashed, and bound to a
rehydration receipt. The CycloneDX file covers the Python lock export only; it does not inventory
the Go sidecar or OCI sandbox. Every component emitted in that SBOM is reconciled to a name and
version in `uv.lock`; independent proof that the export is the complete selected production closure
remains a qualification blocker. The reviewed tree has no upstream `NOTICE`, and the builder
checks that exact-tree absence. A future `NOTICE` addition fails closed until its distribution is
handled.

## Redistribution remains blocked

BlueFire remains MIT licensed. Strix's pinned
[`LICENSE`](https://github.com/usestrix/strix/blob/6b7ae2ebe4d47037a927aade23265ff4e4f27e84/LICENSE)
and [`pyproject.toml`](https://github.com/usestrix/strix/blob/6b7ae2ebe4d47037a927aade23265ff4e4f27e84/pyproject.toml)
declare Apache-2.0 for Strix source. Preserving that license and the BlueFire modification
notice does not establish redistribution readiness for the assembled candidate. The pinned
packaging metadata includes a compiled Go TUI and prebuilt viewer static assets in the wheel,
while excluding their source directories from that wheel. The candidate's Python lock export
does not inventory those bundled components or the OCI image.

Candidate, preparation, and CLI-startup admission manifests all carry
`qualification.redistribution_review`, schema `bluefire.strix-redistribution-review.v1`.
It fixes `redistribution_ready`, `license_review_complete`, `redistribution_authorized`, and
`root_license_is_component_clearance` to false. Four separate component reviews remain
incomplete: third-party Go TUI dependencies, bundled frontend/viewer assets, the complete
platform Python runtime wheel closure (including nested libraries and notices), and the OCI
image. Their license expressions, notice completeness, and confirmed redistribution rights
remain `null` (unknown), rather than inheriting either project's root license.

Public-repository Actions artifacts are retrievable by repository readers; short retention is
not access control. The candidate and preparation workflows therefore publish no artifact, including
raw manifests, SBOMs, source archives, wheels, wheelhouses, or OCI inventory. No reviewed sanitized
public evidence-receipt contract exists, so this change does not invent one. Admission is blocked
until a separately reviewed private cross-job transport can preserve the fresh-runner boundary
without publishing its input bundle. A threat-review ref does not clear redistribution. Strix
payloads remain excluded from normal BlueFire wheels and releases.

Downstream validation rejects an omitted or altered blocked review, including a root-license-only
claim. Existing receipts without this gate must be rebuilt; checksum consistency, an SBOM, and
a successful CLI-startup probe cannot supply the missing rights review. A separately reviewed
component inventory and applicable license texts, attribution, notices, and rights are required
before any future redistribution-ready claim. This increment neither completes that inventory
nor changes runtime or packaging scope.

Candidate metadata provides `sha256:`-prefixed canonical-source and package inputs for a later
`StrixBuildIdentity`, but deliberately leaves the protected installed CLI executable hash and
image-inventory hash unresolved. The separately hashed embedded TUI is not substituted for the
Strix CLI launch executable. Those missing identities must come from protected installation and
image-qualification receipts before a launch plan can be admitted.

## Sandbox identity and remaining qualification

The reviewed source names sandbox version 1.3.1. Tags are mutable, so candidate metadata pins the
external OCI index as:

`ghcr.io/usestrix/strix-sandbox@sha256:78df914f3029464c9d00580f531ec51025c251c422ec3b09c3f19c5fa6d80c30`

This digest is an external registry pointer, not a locally retrieved qualification result. The
candidate build does not pull, execute, bundle, or redistribute that image. Before runtime
qualification, the selected platform child manifest, config, and layer digests must be resolved
and recorded, and the image inventory and third-party notices must be reviewed. The manifest keeps
those fields unresolved and runtime qualification false. The image and its dependencies must not
be represented as wholly Apache-2.0 merely because the Strix source root uses that license.

That upstream sandbox identity is also not the image BlueFire proposes to execute. The separate
`bluefire.strix-derived-image.v1` declaration requires a digest-pinned controlled image and binds
its exact base image, Dockerfile, dependency lock, SBOM, provenance and attestation digests,
`linux/amd64` platform, fixed runtime profile, and component requirements: `strix-agent 1.7.0`,
`openai-agents 0.19.0`, `docker 7.1.0`, Caido `0.56.0`, and `caido-sdk-client 0.2.0`. A declaration
is not a build or qualification receipt. No production receipt-signing authority is configured,
and no current record proves that this derived image was built, admitted, executed, or cleared for
redistribution. A future installed journey must retain the actual contract and independently
verified receipt digests; the upstream OCI index cannot substitute for them.

Further runtime work must separately establish target binding, outer network containment,
lifecycle stop and cleanup, raw evidence collection, and controlled-provider mechanics. Live-model
quality is a different proof and requires its own authorization.

## Implemented BlueFire restricted runtime contracts

The reviewed source exposes a public downstream runtime-backend registry. BlueFire uses the exact
pinned upstream commit as its preimage and retains the official headless CLI with two reviewed
source corrections. Its implemented, separately hashed
`bluefire-controlled` bootstrap and backend contracts define an integration through that boundary.
The candidate's reviewed startup patch makes the registered backend reachable without the
upstream Docker check or pull when a downstream backend is selected. It does not normalize
unsafe Docker requests.

The stock Docker backend is not admissible for the first BlueFire workflow. At this pin it can pull
a missing image, adds `NET_ADMIN` and `NET_RAW`, requests
`host.docker.internal=host-gateway`, and lacks BlueFire's custody label. The controller policy
refuses those requests. The restricted contracts instead require the exact safe request shape for
a preloaded image, fixed internal network and relays, non-root user, bounded resources, required
upstream and BlueFire labels, no host mounts or host gateway, and no extra capabilities for the
initial HTTP authorization lab.

The current installed Strix adapter still selects `STRIX_RUNTIME_BACKEND=docker` and builds the
legacy Docker launch plan. The installed composition accepts an injected `InstalledAttemptFactory`,
but no maintained concrete factory yet selects and binds the controlled bootstrap, backend, relays,
and launch plan.

The bootstrap, controlled-backend implementation, policy proxy, relays, workspace transfer, SDK
closure, sandbox image, and runtime-profile digests are additional BlueFire artifacts. Their
contracts and fail-closed installed composition are implemented, but they are not covered by the
candidate's prompt or startup overlay digests and are not included in the candidate or startup admission.
Qualification and every later authority, admission, preparation, and launch record must bind them
before use. Durable execution consumption, independent-observation publication, concrete
attempt-factory wiring and positive installed qualification, and separate native or live-provider
proof remain incomplete. Until that exact profile passes session, cancellation, evidence, defense,
retest, legitimate-use, and cleanup
qualification, `production_runtime_admitted` remains false and no live Strix capability claim
follows from this document.

## Updating the pin

A source, package, prompt, startup, lock, build-hook, Go-module, sandbox, or toolchain change requires a new
source review. Update the exact identities, review the source and applicable licenses, regenerate
either overlay only after review of its changed preimage, extend regression tests, and build a new candidate. Never
move a tag, accept `latest`, loosen a hash assertion, or reuse an old manifest for a new source.
