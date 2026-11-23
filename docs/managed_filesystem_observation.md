# Managed filesystem observation after each producer

Managed Execute requests can observe a bounded list of files immediately after
the reviewed action that produces each file. This supports conditional branches,
including local export after blocked transport, without scheduling a read of an
unreached branch.

```json
{
  "schema_version": "bluefire.collector-runtime-settings.v1",
  "collectors": {
    "collector.filesystem.sandbox.v1": {
      "enabled": true,
      "settings": {
        "schedule": "after_each_producer",
        "paths": [
          "fixtures/input.jsonl",
          "fixtures/transformed.jsonl",
          "staged/bundle.jsonl",
          "exports/ephemeral/bundle.bin"
        ]
      }
    }
  }
}
```

Supply this object as `collector_runtime` through the existing managed run API or
CLI. The mode is explicit and mutually exclusive with `collect_after_step` for
that filesystem collector. Simulate does not read files. Preflight validates the
same unique relative-path bounds as scheduled filesystem collection, verifies
the managed backend, and binds the exact mode and paths into approval. Exact
replay retains them; a controlled settings change requires a fresh approval.
This mode supports full replay. Replay from a checkpoint is refused before
runner preparation because checkpoint-prefix reconstruction has a separate
observation phase that is not yet represented in this managed collection session.
Existing fixed scheduled collection keeps its existing replay behavior.

The path list is an eligibility allowlist. At each successful or partial producer
episode, the orchestrator intersects it with observable paths declared by the
reviewed action adapter. Runner output, file contents, and caller-supplied
evidence cannot add paths. The existing filesystem collector independently reads
only that intersection, preserving contained no-follow file handles, identity,
size, digest, byte limits, and execution deadlines. Each observation names the
producing step and its exact execution evidence parent.

Actual per-step results are retained together in the normal hashed
`CollectionSession`, under the original approved settings. An eligible export
that is never reached creates no file obligation. A reached producer whose file
is missing, unreadable, changed, or mismatched remains insufficient evidence;
successful action output cannot substitute for observation. Repeated writes to
the same path have separate observation obligations. The final produced file
effect remains required even if its path was omitted from the allowlist.

If no eligible producer runs, the filesystem result contains zero observations
and reports `schedule_state: not_triggered`; backend readiness describes its
availability, not an observed effect. A paused run can likewise retain explicitly
untriggered scheduled backends without inventing evidence. Existing run and
objective state still governs whether the experiment is complete.

Other managed collectors continue to use one explicit `collect_after_step`
shared by the scheduled phase. Its existing reachability and all-path coverage
checks remain in force. The Windows collector acceptance journey uses the
per-producer filesystem mode for fixture creation, transformation, staging, and
conditional export, while its process and authenticated receiver observations
remain at the transport step. This scheduling change makes no claim about host
audit telemetry or whether a detector fired.
