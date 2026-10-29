# Retained results and objective continuation

The experimental receiver composition pack v2 can retain one generated JSONL
result per attempt and use it in a later attempt of the same saved objective.
This is an explicit choice when reviewing a new objective. Existing objectives
and approvals keep their original meaning.

The reviewed scope permits at most 256 KiB of generated JSONL per attempt,
within the grant's cumulative attempt and storage limits. It does not permit
arbitrary file collection. The review describes retained source data and the
copies held by execution records. Workspace cleanup removes temporary files;
the retained source remains with its original run until that run bundle is
deleted. A metadata-only export excludes the private payload and states that
omission. Exporting a record does not establish executable custody of its data.

## Reusing a result

A plan can select an available retained source by its exact reference. Ordinary
code checks the original attempt, compiled producer, execution and observation
records, trusted capture record, saved objective, environment, digest and byte
bounds. Sharing an environment or a resource-budget lineage does not authorize
reuse across separate saved objectives.

The materialization method publishes the exact retained bytes into a fresh
workspace with a new cleanup receipt. It does not rerun the original producer or
reuse its receipt. Its workspace output feeds the existing transformation,
inspection, staging and receiver methods through normal typed dependencies.
The new attempt records both the original source and what actually executed.

For example, a receiver can refuse nonredacted generated records after staging
has succeeded. A later plan can reuse that staged result, change the earlier
redaction choice, and execute the transformation and handoff against the same
receiver policy. The earlier refusal remains evidence; a successful later
attempt does not rewrite it. This mechanism is a bounded reuse capability, not
proof of general investigation quality or live-model decision making.

## History and current availability

Sealed historical metadata and private payload availability are separate. If the
payload is missing or no longer matches its digest, it cannot be imported.
Historical records remain inspectable when their own integrity is valid. The
operator can explicitly propose fresh work within the same objective and grant;
BlueFire does not silently recreate the missing source or replay the old prefix.
Corrupt historical evidence and unresolved effects still require reconciliation.

Retained bytes establish the content of that captured result, not current access
to the original mutable resource. A new permission, identity or environment
change requires the relevant fresh checks. A prior read is not evidence that a
new read would succeed.

## Assistant and execution boundaries

Retained-result proposals require the separate
`bluefire_receiver_retained_composition_proposal` model purpose. The model sees
bounded source summaries and references, never retained payload bytes. Captured
reasoning remains inspectable after navigation; source availability and
authority are rechecked before a proposed continuation can execute.

Native use requires a compatible Linux runner with the reviewed materialization
method and matching implementation identity. Source-level and controlled-provider
tests do not establish installed native execution or live inference. Other
platforms, arbitrary artifact types, cross-objective imports and representative
endpoint investigations are outside this pack's scope.
