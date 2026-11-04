# Strix installed CLI startup qualification

This is a narrowly scoped follow-up to the non-executed
[runtime preparation](strix-runtime-qualification.md). It can establish
`runtime_qualified: true` for one exact Linux x86-64 installed CLI startup only.
It does not qualify a security assessment, sandbox container, target, model,
network path, containment control, lifecycle, evidence result, effectiveness, or
release asset.

The workflow is manual. Adding it to the repository does not dispatch it. A
refreshed threat-review clearance for the exact candidate is an owner-controlled
gate. Before dispatch, the owner must set repository variables
`STRIX_RUNTIME_ADMISSION_THREAT_REVIEW_REF` and
`STRIX_RUNTIME_ADMISSION_PREPARE_BACKENDS_REVIEW_REF` to the same approved
review SHA-256 ref, and set `STRIX_RUNTIME_ADMISSION_SOURCE_REVISION` to the
exact approved BlueFire commit. The job refuses an absent or different
variable, source revision, or dispatch input. The ref is retained in the
transfer and admission receipts. This establishes continuity with
owner-controlled workflow state; it does not cryptographically establish the
review document's authorship.

## Exact inputs

The workflow uses two separate standard hosted jobs. The first prepares the
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

- the exact candidate manifest, checksums, wheel, source archive, and policy
  overlay produced from Strix commit
  `6b7ae2ebe4d47037a927aade23265ff4e4f27e84`;
- a fresh checkout of the pinned upstream commit, exact tree and reviewed
  blobs, with only the deterministic reviewed prompt modification;
- the exact offline wheel closure and installed-runtime receipt;
- the verified installed interpreter, `strix` entry point, package `RECORD`,
  and patched prompt;
- the pinned sandbox OCI index and resolved Linux AMD64 child/config/layer
  inventory; and
- the exact BlueFire commit, transfer bundle ref, recorded threat-review ref,
  and actual second-job probe-runner identity.

Every preparation file is bound by `SHA256SUMS`. A deterministic bounded tar
contains the validated candidate and preparation artifacts, offline wheelhouse,
and exact pinned pip wheel. It deliberately does not contain job 1's installed
runtime or any symbolic link. The first job still builds and validates an
installed runtime to produce the comparison receipt. It exposes the bundle's
inner SHA-256 and immutable artifact ID. Before downloading that artifact, the
fresh job independently exports hash-bound requirements from the reconstructed
exact `uv.lock` using the pinned uv version. The transferred requirements must
match those controller-held bytes exactly. The job then uses the artifact
service's digest check, compares the service digest to the inner ref, manually
extracts the same open descriptor, and repeats candidate, source, preparation,
and OCI validation. It creates a new virtual environment offline from the
revalidated wheel bytes and hash-required requirements. The new interpreter,
installed distribution metadata, entry point, package `RECORD`, patched prompt,
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

The remaining production boundary is concrete rather than credential-blocked:
trusted protected registries and a controller-owned admission issuer must
allocate and independently verify the network, model gateway, process/container
custody, protected roots, containment, budgets, cancellation, source seal, and
cleanup evidence before retaining a verified v20 admission. The installed
service has not yet wired that issuer and composition. Missing material therefore
refuses before approval, credentials, target access, or worker launch.

## Restricted runtime profile decision

The pinned Strix source remains the default engine, but its stock Docker backend
is not admissible for BlueFire's first controlled workflow. At the inspected pin
it requests a host-gateway mapping, adds `NET_ADMIN` and `NET_RAW`, may pull a
missing image, and does not add BlueFire's custody label. A policy proxy must
reject those requests; it must not silently rewrite them and make an unsafe
request appear qualified.

Strix exposes a public downstream-backend registry selected by
`STRIX_RUNTIME_BACKEND`. The planned integration is a separately hashed
`bluefire-controlled` bootstrap and backend that register through that hook
before invoking the official headless CLI. The profile will use an exact
preloaded image, internal target and model relays, a non-root owned sandbox,
bounded resources, no host gateway or host mounts, and an empty capability set
for the first HTTP authorization lab. It preserves Strix reasoning, agent
coordination, reports, exit semantics, and bounded commands inside the owned
sandbox. Raw-packet scanning, interface manipulation, VPN/TUN devices,
privileged mounts, host access, and unrelated network discovery remain
explicitly unavailable profile capabilities, not evidence of target prevention.

This restricted backend is planned and under qualification; it is not part of
the admitted candidate or a live proof yet. Its bootstrap, backend, policy,
relay, SDK closure, image, and profile digests must be added to build identity,
runtime authority, v20 admission, action material, and launch intent before use.
`production_runtime_admitted` remains false until the complete session,
cancellation, artifact, independent-observation, and cleanup journey passes.

## Workflow and outputs

`.github/workflows/strix-runtime-admission.yml` is manual, exact-SHA, read-only,
and uses the standard `ubuntu-24.04` hosted image. The checkout and artifact
actions use their normal short-lived GitHub token, but checkout does not retain
it and the sanitized admission controller and probe receive no repository or
provider credential. OIDC is not granted.
Job 1 builds and validates the candidate, offline closure, installed runtime,
and non-executed OCI inventory, then uploads one immutable tar with three-day
retention. Its build, preparation, and packaging commands run as uid/gid 65534
inside one root-created PID and mount namespace. The checkout is bind-mounted
read-only as part of a read-only `/home`; `/opt` and the hosted tool cache are
also read-only. The host runner temporary tree, including GitHub file-command
paths, is read-only except for one fixed preparation stage owned by that dropped
identity. Host management sockets are masked, capabilities are dropped, and no
GitHub command-file path is passed inside. The namespace PID 1 cannot exit
without the kernel killing every remaining process in that namespace. Before
masking `/run`, the root controller validates and holds open the bounded,
root-owned resolver file, then recreates that exact content as a private
read-only file at the existing `/etc/resolv.conf` resolution path. This keeps
the shared-network fetch phase operational without exposing host `/run`.
After the namespace exits, trusted controller code
reopens the source tar and ref without following links, copies the exact bytes
into a new non-stage file, rehashes that copy, removes the entire stage, and only
then writes the verified ref to `GITHUB_OUTPUT`. The token-bearing upload action
can access only that immutable copy. The installed runtime is not transferred.
Job 2 checks out the same
BlueFire SHA, reconstructs the exact reviewed Strix source, and derives its
frozen requirements before downloading that tar. After download, controller and
probe work is forced into a fresh network namespace with no host interfaces. It
validates the artifact ID, service digest, inner
bundle ref, BlueFire revision, and all inner receipts, constructs a new
root-owned runtime from the validated offline wheels, runs the fixed probe, and
removes the bundle, download directory, controller requirements, reconstructed
source, extracted preparation, runtime, and probe state. Only the final
admission receipt is uploaded from job 2, also for three days.

The admission output contains only:

- `strix-runtime-admission.json`; and
- `SHA256SUMS` for that canonical manifest.

The workflow has not been dispatched by this implementation. No release,
package publication, container launch, target contact, or model call is part of
this qualification.

The process boundary prevents a daemonized build descendant from surviving into
the later artifact action. It is not a claim that the reviewed build code is
safe against kernel exploits, hosted-runner compromise, or every same-job
channel. The separately required
`STRIX_RUNTIME_ADMISSION_PREPARE_BACKENDS_REVIEW_REF` confirms that the refreshed
threat review covers the exact pinned PEP 517, Go, uv, pip, and package build
inputs as well as this process-custody boundary. If that review cannot make that
finding, the workflow remains fail-closed and must not be dispatched.
