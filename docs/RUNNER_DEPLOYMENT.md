# Runner deployment

The Rust runner is BlueFire's execution authority. The Python package does not bundle, download, install, or start it as a service. Current transport is a local subprocess invoked with a fixed argument vector.

## Requirements

- A current stable Rust toolchain supported by `rust-toolchain.toml`.
- An unprivileged local account.
- A dedicated existing sandbox root containing no personal or production data.
- A reviewed Execute runner profile.
- Explicit authorization for the lab.

Do not run the runner as administrator/root, install it as a system service, or point the sandbox at a home directory, repository root, system directory, network share, or cloud-synced personal folder.

## Build and verify

```bash
cargo fmt --manifest-path runner/Cargo.toml -- --check
cargo clippy --manifest-path runner/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path runner/Cargo.toml --all
cargo build --release --manifest-path runner/Cargo.toml
```

Read the compiled inventory:

```bash
cargo run --release --manifest-path runner/Cargo.toml -- inventory --json
```

Inventory schema is `bluefire.runner-inventory.v1`. Each action descriptor uses `bluefire.runner-action-sdk.v1` and declares its version, compatible behaviors, platforms, JSON parameter schema, capabilities, tier, target types, observation hints, cleanup relationship, limit classes, readiness, provenance, effects, and receipt behavior.

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
  --max-body-bytes 5242880 --idle-timeout 120
```

The command exits after the accepted-artifact limit, total-connection limit, or idle timeout and
also closes cleanly on interruption. `--max-requests` counts only verified, accepted artifacts; a
malformed or refused request does not consume that success slot. `--max-connections` bounds all TCP
connections so repeated refusals still terminate the session.
It accepts only `POST /bluefire/v1/artifact`, requires `Content-Length` and a matching lowercase
`X-BlueFire-SHA256`, and never interprets, executes, redirects, or forwards the body. Header lines,
aggregate headers, body size, request duration, idle duration, accepted artifacts, and total
connections are independently bounded. It produces no request-body or filesystem-path logs. The
runner accepts network success only when a bounded 2xx JSON response reports schema
`bluefire.loopback-receiver-result.v1`, `accepted: true`, the exact received byte count, the sent
artifact digest, and a boolean storage result; an arbitrary 2xx or 204 response fails the action.

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

The Execute approval and runner manifest bind the literal destination host and port. They do not
authenticate the receiver process identity or establish a receiver session. Consequently, even a
valid digest-bound acknowledgement proves neither remote transport nor authenticated/mutually
authenticated service identity. This local receiver is a controlled lab fixture, not a remote
transport or authentication mechanism.

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

The current runner does not provide remote transport, TLS, mutual authentication, enrollment, revocation, a daemon/service installer, signed manifests/profiles/results, or a persistent task replay cache. Do not expose the local binary through an ad hoc network wrapper.

See [Action SDK](ACTION_SDK.md), [Runner profiles](RUNNER_PROFILES.md), and [`runner/README.md`](../runner/README.md) for contract details.
