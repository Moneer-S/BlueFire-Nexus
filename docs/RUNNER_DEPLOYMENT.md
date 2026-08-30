# Runner deployment

The Rust runner is BlueFire's execution authority. The current Windows x86_64 wheel includes one
manifest-bound runner artifact. Explicit `bluefire runner bootstrap` verifies its platform,
architecture, size, digest, and inventory before installing it in an owner-private per-user root
and creating local enrollment. `bluefire runner start` launches a separate unprivileged per-user
host process; it never installs an operating-system service or daemon. The control plane reaches
that host only over literal loopback with TLS 1.3 mutual authentication, enrollment-bound request
authentication, and a durable task ledger. Managed bootstrap never downloads executable content.

## Requirements

- A compatible platform-native wheel, or the pinned Rust toolchain from `rust-toolchain.toml` for source-development builds.
- An unprivileged local account.
- A dedicated existing sandbox root containing no personal or production data.
- A reviewed Execute runner profile.
- Explicit authorization for the lab.

Do not run the runner as administrator/root, install it as a system service, or point the sandbox at a home directory, repository root, system directory, network share, or cloud-synced personal folder.

## Packaged artifact layout

The checked-in release staging tree used by the Windows-hosted release workflow is deliberately
split by target:

```text
bluefire/native/
|-- runner-manifest.json
|-- bluefire-runner.exe
`-- linux-x86_64/
    |-- runner-manifest.json
    `-- bluefire-runner
```

The top-level pair is the Windows x86_64 wheel payload. The build hook verifies its executable
header, size, SHA-256 digest, product/runner versions, and platform tag and emits a non-pure
`py3-none-win_amd64` wheel. Release wheel inspection requires exactly that manifest/binary pair
and refuses a foreign native runner sibling.

The nested pair is a separately staged `x86_64-unknown-linux-musl` release artifact for the
cross-platform acceptance journey. It stays out of the Windows wheel. GATE-11 reads both Linux
files from the exact accepted Git commit and tree, verifies their blob identities, manifest,
ELF64 architecture, size, and digest, and only then stages them into a disposable Linux task
environment. This layout does not claim that the Windows wheel is Linux-compatible or that a
general Linux installer has been exercised.

## Build and verify from source

```bash
cargo fmt --manifest-path runner/Cargo.toml -- --check
cargo clippy --manifest-path runner/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path runner/Cargo.toml --all
python tools/build_native_runner.py
```

The release helper has a fixed Cargo argument list. It resolves the host home, workspace, checkout,
`CARGO_HOME`, `RUSTUP_HOME`, and `CARGO_TARGET_DIR` to absolute roots, supplies path remaps through
`CARGO_ENCODED_RUSTFLAGS`, disables incremental compilation, strips symbols, and scans the result
for unremapped UTF-8 or UTF-16 host paths. It replaces inherited `RUSTFLAGS` and encoded Rust flags.
Controlled build environments may set `CARGO` and the three root variables before invoking the
helper; relative roots are resolved beneath the checkout.

The helper also accepts the reviewed explicit targets
`x86_64-pc-windows-gnu` and `x86_64-unknown-linux-musl`. Those cross-target builds still require
the corresponding installed Rust target and linker; target support in the helper is not proof
that a produced binary ran on that operating system. Use `tools/stage_native_runner.py` to create
an atomic manifest/binary resource tree only after independently obtaining the compiled inventory.

## Cross-platform release validation

GATE-11 separates dynamic and structural claims:

- Windows proof builds the wheel from the exact committed source, verifies its `RECORD` and native
  resource, bootstraps that extracted resource, starts the managed runner, and executes the
  packaged Windows journey. Separate dynamic checks bind an authenticated one-shot receiver,
  interrupt and recover the managed host while preserving the authenticated task-ledger
  generation, and verify the fixed packaged cancellation-witness process tree is absent.
- Linux proof requires an existing WSL2 base distribution named
  `BlueFire-Gate11-Base-v1`, CPython 3.12, and the exact offline dependency wheelhouse named by
  `BLUEFIRE_GATE11_LINUX_WHEELHOUSE`. The harness stream-clones the base to a randomly named
  disposable WSL2 distribution, executes the commit-bound musl runner and canonical
  Linux/container path, verifies authenticated receiver success, POSIX watchdog containment,
  run-bundle integrity, and cleanup, then unregisters the clone and checks that its storage is
  gone.
- macOS validation checks package metadata, platform contracts, and the fixed process-adapter
  boundary when no macOS host is available. It is labeled structural and is never reported as
  dynamic execution.

The harness only probes the named WSL base; it does not install or modify that persistent base.
If WSL2, the exact distribution, CPython runtime, wheelhouse, or native dependency set is absent
or incompatible, the report carries a typed environment limitation and Linux dynamic proof does
not pass. A successful Linux run proves only the disposable WSL2 boundary and exact staged
artifact exercised by that acceptance run, not arbitrary distributions, containers, kernels, or
production hosts.

Read the compiled inventory on Linux/macOS:

```bash
./runner/target/release/bluefire-runner inventory --json
```

On Windows PowerShell:

```powershell
.\runner\target\release\bluefire-runner.exe inventory --json
```

Inventory schema is `bluefire.runner-inventory.v1`. Each action descriptor uses `bluefire.runner-action-sdk.v1` and declares its version, compatible behaviors, platforms, JSON parameter schema, capabilities, tier, target types, observation hints, cleanup relationship, limit classes, readiness, provenance, effects, and receipt behavior.

Packaged operators do not need a Rust toolchain. Bootstrap the verified native artifact, create local trust, and start the separately hosted runner explicitly:

```bash
bluefire --config config/bluefire.example.yaml runner bootstrap --profile sandbox-execute.v1
bluefire --config config/bluefire.example.yaml runner start --profile sandbox-execute.v1
bluefire --config config/bluefire.example.yaml runner status --profile sandbox-execute.v1
```

`runner status` is inert: it never installs or starts anything. A ready status includes only path-free authenticated health and inventory metadata. Stop the host before revocation; removal additionally requires the exact runner ID returned by status:

```bash
bluefire --config config/bluefire.example.yaml runner stop --profile sandbox-execute.v1
bluefire --config config/bluefire.example.yaml runner revoke
bluefire --config config/bluefire.example.yaml runner remove --confirm-runner-id RUNNER_ID
```

## Prepare a sandbox

Use a new disposable directory. The runner canonicalizes the root and refuses a symlink/reparse root. Action paths are normalized relative paths beneath it.

Linux/macOS:

```bash
mkdir -p .bluefire-sandbox
export BLUEFIRE_RUNNER_BINARY="$(pwd)/runner/target/release/bluefire-runner"
export BLUEFIRE_SANDBOX_ROOT="$(pwd)/.bluefire-sandbox"
```

Windows PowerShell:

```powershell
$env:BLUEFIRE_RUNNER_BINARY = (Resolve-Path .\runner\target\release\bluefire-runner.exe)
$env:BLUEFIRE_SANDBOX_ROOT = (New-Item -ItemType Directory -Force .\.bluefire-sandbox).FullName
```

The YAML contains only `{env: VARIABLE_NAME}` references. Values are resolved by the service at the boundary that needs them and are not serialized into config responses.

## Provision the loopback receiver

The canonical sandbox research chain sends its network artifact to literal loopback port `4317`.
Start the bounded built-in receiver in a separate unprivileged terminal before previewing and
approving that Execute path:

```bash
bluefire receiver --host 127.0.0.1 --port 4317 \
  --max-requests 1 --max-connections 16 \
  --max-body-bytes 5242880 --idle-timeout 300
```

The command exits after the accepted-artifact limit, total-connection limit, or idle timeout and
also closes cleanly on interruption. `--max-requests` counts only verified, accepted artifacts; a
malformed or refused request does not consume that success slot. `--max-connections` bounds all TCP
connections so repeated refusals still terminate the session; it must be at least twice
`--max-requests` to budget one challenge and one upload connection per possible success.
It loads the active enrollment from the fixed managed product root. The runner first obtains an
authenticated one-time `GET /bluefire/v1/challenge`, then sends only
`POST /bluefire/v1/artifact` with `Content-Length` and a matching lowercase
`X-BlueFire-SHA256`. The HMAC chain binds the exact transport task, ephemeral session, nonce,
listener host/port, digest, and length. The receiver never interprets, executes, redirects, or
forwards the body. Header lines,
aggregate headers, body size, request duration, idle duration, accepted artifacts, and total
connections are independently bounded. It produces no request-body or filesystem-path logs. The
runner accepts network success only when a bounded canonical 2xx JSON response reports schema
`bluefire.loopback-receiver-result.v2`, `accepted: true`, the exact task/session and received byte
count, the sent artifact digest, a boolean storage result, and a valid request-bound HMAC; an
arbitrary 2xx or 204 response fails the action. The bounded idle default is 300 seconds and remains
an explicit CLI override.

The default transiently buffers at most `--max-body-bytes` for digest verification and does not
persist the body. Persistent receipt of bytes is opt-in:

```bash
bluefire receiver --host 127.0.0.1 --port 4317 \
  --max-requests 1 --max-connections 16 \
  --storage-dir /tmp/bluefire-receiver-artifacts-SESSION
```

On first use the storage directory must be empty. The receiver marks it as receiver-owned and writes
only content-addressed names beneath that resolved root, without overwriting an existing artifact.
Do not use a personal, repository, shared, or production directory.

The Execute approval and runner manifest bind the literal destination host and port. The managed
runner adds an exact per-task capability and the receiver proves an ephemeral same-user session
before artifact transmission. This does not authorize a different host, port, task, or session and
does not turn the local receiver into remote transport or cross-user service authentication.

For `scenario.endpoint.deep-behavior-lab.v1`, start the one-shot peer variant instead:

```bash
bluefire receiver --host 127.0.0.1 --port 4317 --max-requests 1 --disposable-peer
```

This locks the receiver to memory-only storage, one accepted artifact, eight total connections, a
five-second per-connection deadline, and 240-second idle and absolute lifecycle caps. Clean protocol
use consumes one challenge plus one upload; the remaining bounded sockets tolerate incidental local
probes without making the receiver long-lived. The peer action requires challenge v2 and result v3,
then emits a v2 logical receipt with only an opaque approved-task capability handle. The receipt
authenticates the declared PID and terminal disposition, but release proof must observe the distinct
process and its exit independently.

## Check compatibility

```bash
bluefire --config config/bluefire.example.yaml runner status --profile sandbox-execute.v1
```

Confirm:

- the sandbox exists and is disposable;
- inventory and action SDK schema versions are supported;
- the runner exposes every enabled action used by the scenario;
- behavior IDs, platforms, capabilities, safety tiers, and cleanup IDs match;
- no unexpected action appears in the profile allowlist.

## Preview and execute

```bash
bluefire --config config/bluefire.example.yaml scenario preview \
  scenarios/sandbox_research_chain.yaml \
  --mode execute \
  --profile sandbox-execute.v1 \
  --scope-ref network.loopback \
  --scope-ref export.local
```

Only after review:

```bash
bluefire --config config/bluefire.example.yaml --runs-dir .bluefire-runs scenario run \
  scenarios/sandbox_research_chain.yaml \
  --mode execute \
  --profile sandbox-execute.v1 \
  --scope-ref network.loopback \
  --scope-ref export.local \
  --approve
```

The service builds an action-specific manifest. It never passes logical graph parameters directly to the executor. `RunnerActionAdapter` resolves typed artifacts and produces the sealed Rust parameter object for a known action ID.

## Process and network behavior

- System discovery uses compiled APIs.
- Windows process discovery uses Toolhelp snapshot APIs.
- Linux/macOS process discovery selects one compiled absolute `ps` path and fixed arguments. Callers cannot provide an executable or arguments.
- The current network action accepts a literal loopback IP and an allowlisted port. It does not accept DNS names, URLs, proxies, redirects, or non-loopback destinations.
- A monotonic deadline bounds connect, write, and response reading.

## Receipts and cleanup

Every create-new action uses the `bluefire.runner-receipt-wal.v2` protocol under the runner-reserved `.bluefire` state directory. It durably records an exact path/size/digest intent before effect, writes and syncs bytes in runner-owned staging, publishes without overwrite, verifies the result, and then records a commit. A crash between those phases leaves a discoverable intent and any staging/final effect attributable to that intent.

Cleanup accepts receipt IDs only. It:

1. reloads the runner-owned receipt;
2. rejects changed type, size, or content;
3. removes owned files before directories;
4. marks successful receipts consumed;
5. treats an already-consumed receipt as idempotent success;
6. retains changed objects and reports them.

The control plane collects receipts and submits them in reverse creation order. It also attempts emergency cleanup after certain control-plane failures. Cleanup can reconcile committed receipts and pending intents, removes safe partial staging, and retains any changed object for review instead of deleting it. Process interruption therefore does not make an exact runner-owned effect undiscoverable. Host or workspace loss can still remove the recovery journal or leave external effects; preserve the complete runner-owned sandbox until reconciliation is complete.

## Result and exit codes

The runner emits `bluefire.runner-result.v1` with correlated request/action/behavior/runner/profile/platform identities, request and policy digests, status, bounded output, evidence, receipts, cleanup, errors, and limitations.

| Exit | Meaning |
|---:|---|
| 0 | Action succeeded |
| 2 | CLI/input contract could not be read |
| 3 | Refused or control-blocked before effect |
| 4 | Failed, partial, timed out, or cleanup failed after attempt |

Runner evidence can be `executed` or `control_blocked`; it cannot be `observed`.

## Production hardening

- Pin and verify the built binary with your normal software-distribution controls.
- Restrict write access to the binary, profile source, sandbox, run store, and environment setup.
- Use a separate OS account and sandbox per lab where practical.
- Keep profiles in version control only after removing local paths and identifiers.
- Collect independent audit telemetry outside the runner process.
- Apply external disk quotas and retention to run/sandbox storage.
- Destroy disposable environments only after validating cleanup and exporting reviewed artifacts.

## Not implemented

The managed runner is local and same-user only. Cross-host transport or enrollment, a daemon/service installer, asymmetric signatures or non-repudiation for manifests/profiles/results, and general arbitrary execution are not provided. Do not republish the loopback host or wrap the runner with an ad hoc remote service.

See [Action SDK](ACTION_SDK.md), [Runner profiles](RUNNER_PROFILES.md), and [`runner/README.md`](../runner/README.md) for contract details.
