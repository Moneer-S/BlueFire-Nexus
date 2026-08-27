# Source intake workflow

BlueFire can learn from mature public security projects without blindly copying, vendoring, or executing them. Every external source record must be pinned, license-reviewed, attributed, and classified before it expands a behavior, action, collector, detection, or tool-adapter workflow.

## Use classifications

| Classification | Meaning | Allowed handling |
|---|---|---|
| `reference_only` | Study behavior, telemetry, architecture, or documentation. | Copy no source, rules, payloads, fixtures, or generated outputs. |
| `metadata_import` | Import or transform compatible declarative metadata. | Record source, exact ref, license, attribution, imported paths, and transformation history. |
| `clean_reimplementation` | Implement independently from public specifications and observed semantics. | Copy no source; record inspirations and specification references. |
| `external_adapter` | Invoke a separately installed tool through a strict typed adapter. | Verify version, integrity, capability, safety tier, license, availability, structured output, and cleanup. Do not bundle or silently install it. |
| `compatible_code_adaptation` | Copy or adapt code only after file-level compatibility review. | Preserve notices and attribution, record modifications, and keep copied code isolated and identifiable. |
| `incompatible_or_restricted` | Do not copy into core or official packs. | Permit reference-only research or optional separate adapter only when legally and technically appropriate. |

## Required record fields

`bluefire.research-source.v1` records include project/repository, exact ref, retrieval and verification dates, license, file-level license review, trademark considerations, use classification, imported/adapted paths, attribution, security review, transformation history, update status, and ordinary registry use.

The registry rejects mutable pins such as `latest`, `main`, `master`, and `HEAD`; credentialed URLs; unsupported classifications; reference-only records with imported paths; code adaptation without explicit imported/adapted paths and reviewed license status; and external adapters that do not remain external executable content.

## Operator rule

Never execute external install scripts, payloads, containers, binaries, or upstream test harnesses during source intake. Intake records are provenance and decision records; execution requires a reviewed action, collector, detection backend, or tool adapter with its own typed contract.
