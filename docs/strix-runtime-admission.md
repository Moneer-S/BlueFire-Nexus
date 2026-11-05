# Strix installed CLI startup qualification

The GitHub workflow currently fails closed before checkout, preparation, transfer, or execution.
Its former cross-job transfer was configured to publish an unreviewed candidate and dependency bundle through
public-repository Actions artifacts. Repository readers can retrieve those artifacts, and short
retention does not provide access control. The component redistribution review remains blocked;
no reviewed public sanitized-receipt contract or private cross-job transport is available.

The retained tooling below describes the requirements for a future reviewed private qualification
path. It can establish `runtime_qualified: true` for one exact Linux x86-64
installed CLI startup only. It does not qualify an assessment, sandbox, target, model,
containment, effectiveness, or
release. Its Strix input is a package-declared `1.7.0` modified-source candidate, not an official
Strix release. BlueFire remains MIT, and the pinned Strix source remains Apache-2.0 with the
reviewed modification notice; that attribution does not clear bundled third-party components.

The workflow is manual. Dispatch always fails while this transport boundary remains unresolved.
A threat-review ref, source pin, hash, successful probe, or operator variable cannot authorize
redistribution. Future restoration requires both a separately reviewed transport preserving the
fresh-runner isolation and the exact-candidate threat review; neither clearance is supplied here.

## Exact inputs

The retained qualification design requires two separate standard hosted jobs. The first prepares the
existing pinned inputs without executing Strix. The second starts on a fresh
hosted VM and performs the admission probe. Both jobs use the identical fixed
`$RUNNER_TEMP/bluefire-strix-preparation-stage` layout. This is required because
the interpreter receipt, launcher shebang, and hash-bound candidate-wheel URI
contain absolute paths; archive metadata and the fresh extraction fail closed if
that hosted layout differs. Before privileged parsing, job 2 seals the stage
parent as root-owned mode `0711`; the qualifier verifies that exact metadata so
uid/gid 65534 can traverse only to the explicitly opened read-only runtime and
private probe state, while sibling source, controller, and download directories
retain their private modes.

- the exact candidate manifest, checksums, wheel, source archive, and separate prompt and startup
  overlays produced from Strix commit
  `6b7ae2ebe4d47037a927aade23265ff4e4f27e84`;
- a fresh checkout of the pinned upstream commit, exact tree and reviewed
  blobs, with exactly the deterministic reviewed prompt and startup modifications;
- the exact offline wheel closure and installed-runtime receipt;
- the verified installed interpreter, `strix` entry point, package `RECORD`,
  patched prompt, and patched startup `main.py`;
- the pinned sandbox OCI index and resolved Linux AMD64 child/config/layer
  inventory; and
- the exact BlueFire commit, transfer bundle ref, recorded threat-review ref,
  and actual second-job probe-runner identity.

Those startup inputs inventory the upstream sandbox OCI and do not admit the controlled image for
an engine attempt. The separate `bluefire.strix-derived-image.v1` contract must bind the actual
derived image, base image, Dockerfile, dependency-lock, SBOM, provenance and attestation digests,
and admission must pair it with the full independently verified controller receipt set. It
requires `strix-agent 1.7.0`, `openai-agents 0.19.0`, `docker 7.1.0`, Caido `0.56.0`, and
`caido-sdk-client 0.2.0`; the complete
resolved lock closure and digest remain part of the retained build and journey evidence. The
upstream OCI index is not an executed-image identity and cannot substitute for this record.

Every preparation file is bound by `SHA256SUMS`. A deterministic bounded tar
contains the validated candidate and preparation artifacts, offline wheelhouse,
and exact pinned pip wheel. It deliberately does not contain job 1's installed
runtime or any symbolic link. The first job still builds and validates an
installed runtime to produce the comparison receipt. A future reviewed private
transport must bind the bundle's
inner SHA-256 to trusted controller state. Before receiving any bundle, the
fresh job must independently export hash-bound requirements from the reconstructed
exact `uv.lock` using the pinned uv version. The transferred requirements must
match those controller-held bytes exactly. The controller must verify the private
transport and inner bundle digests, manually extract the same open descriptor,
and repeat candidate, source, preparation, and OCI validation. It creates a new
virtual environment offline from the
revalidated wheel bytes and hash-required requirements. The new interpreter,
installed distribution metadata, entry point, package `RECORD`, patched prompt, patched startup,
and CLI must exactly match the first job's receipt before and after the probe.
The qualifier emits the exact
`StrixBuildIdentity` fields and a canonical manifest whose file SHA-256 is the
`runtime_qualification_ref` accepted by the product-side qualification loader.
The loader requires that separately retained, controller-owned expected ref;
it does not bless an arbitrary manifest merely because the file is internally
well formed.
The per-attempt resolver must still combine that immutable runtime identity with
current authorization, scope, target snapshot, network policy, process and
container custody, protected roots, and cleanup evidence.
It must obtain the expected manifest ref from trusted controller state and bind
the returned BlueFire source revision, rather than reading either value from the
manifest being admitted.

## Fixed probe boundary

The only upstream command is:

```text
strix --help
```

No target, target list, instruction, configuration path, model, API key,
container, sidecar, or tool server is supplied. The probe requires a successful
exit and bounded UTF-8 help output containing the supported usage and target
option. The output itself is not published in the manifest; only its byte count
and SHA-256 are retained.

The root `--help` path exits during argument parsing before the scan startup branch. A successful
help probe therefore does not show that the registered backend selection, Docker check/pull
condition, or `validate_environment()` branch ran. Those behaviors require separate qualification
before a controlled engine attempt.

The hosted controller starts the probe with:

- new network, IPC, UTS, PID, and mount namespaces;
- a private `/proc`;
- a private empty `/run`, hiding Docker, containerd, Podman, and other host
  management sockets;
- 8 MiB, inode-bounded, non-executable private mounts for `/tmp`, `/var/tmp`,
  and `/dev/shm`, a masked `/dev/mqueue`, and an independent 8 MiB private
  HOME/XDG tmpfs owned by the dropped identity;
- the exact runtime bind-mounted read-only;
- uid/gid `65534`, no supplementary groups or Linux capabilities, and
  `no_new_privs`;
- an empty environment reconstructed from an allowlist, a dedicated empty HOME,
  no inherited provider variables, no checkout credential, no OIDC permission,
  and no global model or MCP configuration;
- 10 CPU seconds, a 30-second wall limit, 2 GiB address space, 64 processes,
  128 file descriptors, no core dumps, and 1 MiB per output file; and
- a namespace init whose descendants are killed when the probe ends.

The mount namespace bounds and destroys the writable HOME and temporary files;
the controller removes their now-empty host mountpoints, verifies those exact
inspected runtime identities did not change, and refuses qualification if owned
probe work remains.
This is defense in depth for the compatibility probe. It is not the
external containment proof required for an actual engine attempt.
The probe controller runs on a fresh job VM after the producing job has ended.
The bundle is treated as untrusted until its controller-held ref, safe archive
shape, lock-derived dependency closure, and all inner identities validate. The
download directory must contain only the expected regular bundle. The
candidate, preparation, freshly built runtime, reconstructed source, bundle,
controller requirement export, download directory, and probe state are all
required to be absent after the probe. A cleanup or absence failure removes the
would-be admission output and fails the job. This compatibility receipt still
does not claim that GitHub's hosted-runner service itself is an adversarial
containment boundary.

## Claims and non-claims

The canonical admission manifest records:

- `runtime_qualified: true`;
- `production_runtime_admitted: false`;
- scope `exact-installed-cli-startup-only`;
- Strix imported and the fixed CLI help path executed; and
- container, target, model, sidecar, and network execution as false.

It also keeps all of these false:

- artifact reproducibility;
- attempt containment;
- lifecycle, cancellation, and cleanup effectiveness;
- target or model execution;
- offensive or defensive effectiveness;
- complete component-license review; and
- redistribution authorization.

`qualification.redistribution_review` separately fixes `redistribution_ready` to false and
retains incomplete reviews for third-party Go TUI dependencies, bundled frontend/viewer assets,
the complete Python runtime wheel closure, and OCI image notices/rights. Component license
expressions, notice completeness, and confirmed redistribution rights remain unknown (`null`).
The loader rejects an omitted or altered blocked review, including root-license-only clearance;
a passing startup probe cannot promote it. BlueFire remains MIT and Strix's root source
attribution remains Apache-2.0. See the
[redistribution gate](engine-provenance.md#redistribution-remains-blocked) and its pinned official
sources. This is separate from the limited `runtime_qualified: true` startup claim.

The probe does not establish that Strix can complete a scan, that its sandbox
can start, that a model makes a useful decision, that a defense works, or that
the image may be redistributed. Those claims require their own reviewed
evidence. The actual runtime bridge still refuses attempts lacking the exact
per-attempt external network, custody, protected-root, and process-containment
receipts.

## Current product boundary and persisted admission

The product now has a controller-only qualification resolver and private
append-only persistence for runtime authority and per-attempt admission. This
does not change the startup workflow's claim: its receipt alone cannot enable a
live engine attempt and still records `production_runtime_admitted: false`.

The committed state layers are deliberately separate:

| Store layer | Responsibility | What it cannot establish |
| --- | --- | --- |
| v18 tenant-generation journal | Exact generated-lab generation, transition, custody, and reconciliation history | Strix runtime authority or a launchable attempt |
| v19 tenant action material | Immutable server-derived preparation material, exact protected references, and atomic preparation/approval retention | A missing runtime admission, browser-supplied authority, or resource provisioning |
| v20 Strix runtime store | Append-only authority lineage, immutable attempt reservations and verified admission records, and admission lifecycle heads | Runtime allocation, credentials, process launch, or effectiveness |
| v21 Strix issuance evidence | Atomic append-only issuer records bind each runtime lifecycle event to the exact pre-admission profile, resource receipt set, reconciliation evidence, and retained admission document | Current resource custody, execution consumption, independent target observation, or effectiveness |

`ControllerQualifiedStrixAdmissionResolver` loads only an expected manifest ref
from a controller-private pinned artifact root, compares the installed BlueFire
revision, threat-review ref, and complete build identity, and reopens one exact
persisted admission. The authority and admission sources preserve the original
authority generation under which the record was admitted. A later revocation or
reactivation cannot relabel that historical record. Launch resolution requires
the exact active admitted authority and a `verified` admission lifecycle;
`unknown`, `revoked`, and `cleaned` records are reconciliation-only.

The runtime rereads the complete resolution after entering `RUNNING` and before
credential acquisition, then rereads it again after acquisition and before any
secret access or worker launch. Drift or revocation settles as a prelaunch
failure with no worker start. A failed credential revocation is retained as an
explicit limitation. Recovery may reopen historical custody without replaying
or recreating resources. These rereads do not claim an atomic lock against the
final operating-system launch instant.

The protected registries and controller-owned issuer now retain and independently
verify the complete protected resource set before a verified admission can be
retained. That set binds scope and gateway policy, network plan and verification,
custody plan, protected roots, containment, runtime installation, workspace,
executable and path environment, control and artifact roots, and source-root
custody. Cancellation and cleanup evidence belong to later runtime and
reconciliation lifecycle states, not the verified-issuance resource set. The
optional installed-service composition wires these owners to the shared product
store, job controller, prepared-action gate, and cancellation path. The default
service remains closed, and the composition refuses generic unprepared
controller work. Missing or changed material therefore still refuses before
credentials, target access, or worker launch.

This wiring is not positive installed qualification. Durable one-shot execution
consumption, controller-owned publication of independent target observations,
the installed attack-to-defense-to-retest journey, and native or live-provider
proof remain separate gates. No current record establishes that Strix executed,
that a target effect occurred, or that the model made a useful decision.

## Restricted runtime profile decision

The pinned Strix source remains the default engine, but its stock Docker backend
is not admissible for BlueFire's first controlled workflow. At the inspected pin
it requests a host-gateway mapping, adds `NET_ADMIN` and `NET_RAW`, may pull a
missing image, and does not add BlueFire's custody label. A policy proxy must
reject those requests; it must not silently rewrite them and make an unsafe
request appear qualified.

Strix exposes a public downstream-backend registry selected by
`STRIX_RUNTIME_BACKEND`. BlueFire now implements a separately hashed
`bluefire-controlled` bootstrap and backend contract designed to register through
that hook before the official headless CLI. The controlled contracts require an
exact preloaded image, internal target and model relays, a non-root owned
sandbox, bounded resources, no host gateway or host mounts, and an empty
capability set for the first HTTP authorization lab. They preserve Strix
reasoning, agent coordination, reports, exit semantics, and bounded commands
inside the owned sandbox. Raw-packet scanning, interface manipulation, VPN/TUN
devices, privileged mounts, host access, and unrelated network discovery remain
explicitly unavailable profile capabilities, not evidence of target prevention.

The current installed Strix adapter still selects the stock `docker` backend and
builds its legacy launch plan. `InstalledAttemptFactory` remains an injected
protocol; no maintained concrete factory yet selects the controlled bootstrap,
backend, relays, and launch plan for an installed attempt.

No production controller signing authority is configured for the derived-image
receipt set. The upstream sandbox index, a self-reported image hash, or a startup
receipt therefore cannot promote the controlled image into a launchable runtime.

The policy proxy, relay, workspace-transfer, controlled-provider, backend, and
composition contracts are implemented and fail closed, but they are not part of
an admitted release candidate or a live proof. Their exact bootstrap, backend,
policy, relay, SDK closure, image, and profile digests still must be present in
the build identity, runtime authority, admission, action material, and launch
intent used by a qualified run. `production_runtime_admitted` remains false
until a concrete controlled attempt factory is wired, durable execution
consumption is proven, and the complete installed session, cancellation,
artifact, independent-observation, defense, retest, legitimate-use, and cleanup
journey passes.

The exact per-journey identities and attack, defense, retest, legitimate-use,
lifecycle, and uncertainty record are listed in
[`engine-provenance.md`](engine-provenance.md#engine-selection-and-evidence-record).

## Workflow and outputs

`.github/workflows/strix-runtime-admission.yml` is manual and read-only. Its single bounded
`ubuntu-24.04` job reports the unresolved publication boundary and exits with status 2.
It has no checkout, setup, build, upload, download, cache, package, or release step, and
produces no admission receipt. Candidate and preparation CI may process their pinned inputs
only in ephemeral runner-temp and also publish no artifact. Strix payloads remain excluded
from normal BlueFire wheels and releases.

The admission tooling's potential output is limited to `strix-runtime-admission.json` and
`SHA256SUMS`; even those files have no reviewed public publication contract here. The fresh
runner design, safe archive validation, controller-held hashes, offline requirements,
descendant-killing preparation boundary, fixed namespace probe, and required cleanup remain
requirements for any future private admission process. Same-job execution is not substituted
for the fresh-runner isolation. Restoring the workflow requires a new reviewed implementation
and matching tests; repository variables or dispatch input cannot lift the current refusal.

No workflow has been dispatched by this implementation. No release, package publication,
container launch, target contact, or model call is part of this change.
