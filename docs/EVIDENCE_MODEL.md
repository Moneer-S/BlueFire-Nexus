# Evidence model

BlueFire preserves a graph of attributable claims. Provenance answers **how this record was produced**, not whether the content is universally true.

## Provenance classes

| Provenance | Producer and meaning | It does not prove |
|---|---|---|
| `synthetic` | Deterministic simulation or declared fixture model | That an action ran or a defense observed it |
| `executed` | Rust runner reports an action started/resulted | Independent observation or defensive detection |
| `observed` | A separate declared collector read an observable | Causality without parent/context analysis |
| `control_blocked` | Policy or a declared control prevented dispatch/effect | That the requested action succeeded |
| `counterfactual` | Planner modeled continuation after a real path stopped | That the continuation occurred |
| `unknown` | Observation was unavailable, invalid, timed out, or otherwise unestablished | Absence of the underlying activity |

Never relabel between these classes to make a run appear complete.

## Record contract

A `bluefire.evidence.v1` record contains:

- generated evidence ID;
- run, step, behavior, optional action, and optional runner-profile identity;
- producer and timestamp;
- environment description and target-scope reference;
- same-run parent evidence IDs;
- structured content and content hash;
- whole-record hash;
- confidence from 0 to 1;
- explicit limitations.

The evidence graph requires parents to exist before a child is added and refuses cross-run parent edges. Replay creates new evidence; it does not graft source-run records into the new run's evidence graph.

Content and record hashes are deterministic integrity identifiers. They are not signatures or proof of producer identity.

## Proposal, execution, and observation

```mermaid
flowchart LR
    P[Planner/model proposal] --> A[Policy decision]
    A -->|allowed| R[Runner dispatch]
    A -->|refused/blocked| B[control_blocked evidence]
    R --> X[executed evidence]
    X --> C[Independent collector]
    C --> O[observed evidence]
    C -->|unavailable/error| U[unknown evidence gap]
```

A policy allow is not execution. An execution receipt is not observation. Observation is not automatically a detection match.

## Built-in observation

### Sandbox filesystem observer

`SandboxObserver` reads one declared normalized relative file under an existing sandbox root. It:

- refuses absolute/traversal/link paths and files outside the root;
- enforces configured byte and read-time limits;
- records size, SHA-256, modification time, and relative path;
- detects a size/mtime change during collection;
- describes itself as filesystem-only.

### Native process/system discovery

`endpoint.discovery.system.v1` and `endpoint.discovery.processes.v1` are compiled runner actions.
Their results are `executed` evidence: they do not become independent observation merely because
they use platform APIs.

`collector.process.native.v1` is a separate read-only observer for one exact
control-plane-authorized child process. At authorization it pins the PID, expected parent, and
creation identity, then verifies that identity again during collection. Windows uses
`CreateToolhelp32Snapshot`, `GetProcessTimes`, and a fixed image-name query; Linux uses bounded
reads from `/proc/<pid>/stat` plus `/proc/<pid>/exe`. The record contains process, parent,
executable, platform, and creation-identity fields. It is not a host-wide process inventory,
system telemetry feed, macOS collector, or proof that a runner-reported discovery result was
correct.

### Authenticated loopback and disposable-peer observation

`collector.network.loopback-receiver.v1` reads the path-free accepted-artifact bindings owned by
one live managed loopback receiver. Its source authority pins literal loopback host, port,
receiver PID, and ephemeral session ID. Collection is bound to the executed runner task and emits
only the accepted task ID, SHA-256 digest, byte count, receiver PID, and receiver session ID. A
missing or mismatched task becomes an explicit `unknown` gap.

This proves that the authenticated receiver accepted the task-bound bytes; it is not packet
capture, payload retention, remote-host observation, or cross-user authorization. In the
disposable-peer journey, the receiver is a distinct one-shot process and the acceptance workflow
also verifies its PID and terminal exit independently. A peer receipt by itself remains runner
self-report and cannot substitute for those checks.

### Collector registry

| Collector | Readiness | Evidence |
|---|---|---|
| `collector.filesystem.sandbox.v1` | Ready when its root is readable | Observed file metadata/hash or explicit unknown gap |
| `collector.process.native.v1` | Ready for a pinned, caller-authorized child PID on Windows or Linux | PID, parent, executable, platform, and creation identity, or an explicit unknown gap |
| `collector.network.loopback-receiver.v1` | Ready only while attached to a pinned managed receiver session | Authenticated task/digest/byte-count binding and receiver identity, or an explicit unknown gap |
| `collector.fixture-jsonl.v1` | Ready for configured disposable JSONL fixtures | One observed record per bounded JSON object or unknown gap |
| `collector.sysmon-eventlog.v1` | Descriptor only | Unavailable until a real adapter/channels/access are configured |
| `collector.auditd.v1` | Descriptor only | Unavailable until a real adapter/audit access are configured |
| `collector.pcap-disposable.v1` | Descriptor only | Unavailable until a disposable CIDR/capture adapter is configured |
| `collector.cloud-identity-audit.v1` | Descriptor only | Unavailable until an account/tenant allowlist and read-only credential reference are configured |
| `collector.edr-query.v1` | Descriptor only | Unavailable until a read-only provider and registered query templates are configured |
| `collector.siem-query.v1` | Descriptor only | Unavailable until a read-only provider adapter is configured |

Collector readiness is `ready`, `degraded`, or `unavailable`. A failed requested collection emits an `unknown` evidence-gap record with zero confidence rather than disappearing.

Execute preflight binds the per-run collector selection and the exact built-in implementation/source
authority into the reviewed approval context. The ordinary product composition defaults to
`collector.filesystem.sandbox.v1` and observes only declared sandbox artifact paths after runner
execution. Specialized managed journeys can attach the native-process and loopback-receiver
collectors only with their live, pinned source authorities. Runner output remains `executed`, never
`observed`. Optional host-audit, cloud-audit, packet-capture, EDR, and SIEM descriptors remain
unavailable until real adapters, access, and target scopes are configured.

Collector sessions retain health, hashes, parent evidence lineage, enabled settings, and
predicted-versus-observed reconciliation. Reconciliation reports missing fields, unexpected
fields, value mismatches, missing observations, unexpected observations, and duplicate attempts;
it does not infer causality.

## Run bundle

Each run directory contains fixed-name records:

- `scenario.json`
- `plan.json`
- `policy.json`
- `profile.json`
- `result.json`
- `evidence.json`
- `detections.json`
- `events.jsonl`
- `manifest.json` after finalization

JSON snapshots are written by same-directory atomic replacement. Events have contiguous sequence numbers, previous-event hashes, and per-row hashes. Finalization records file SHA-256 values and sizes, then hashes that file table.

Validate a bundle:

```bash
bluefire --runs-dir .bluefire-runs bundle validate RUN_ID
```

Validation detects missing or modified covered files. A user able to rewrite the entire bundle can recompute hashes; use OS access control or external signing for stronger assurance.

## Retention and sharing

Run bundles may include scenario parameters, environment descriptors, relative filenames, telemetry summaries, model metadata, and defensive observations. Before sharing:

1. validate the original bundle;
2. make a separate sanitized export rather than editing the original;
3. remove secrets, personal identifiers, real internal targets, and private telemetry;
4. preserve provenance/limitations and state that the export is sanitized;
5. apply the appropriate license/authorization policy.

Browser-side retention settings are not a server-side deletion policy in 0.1.x. Apply retention and disk quotas through protected local storage controls.
