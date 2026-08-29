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

## Reviewed MITRE ATT&CK® metadata import

Gate 09 includes one vendored public declarative record: MITRE ATT&CK® Enterprise T1082,
System Information Discovery, release `ATT&CK-v19.2`. The source is pinned to
`mitre/cti` commit `8543c5b05bd9bbcace9fc37f30bba96b675b6f33`, reached by the
signed annotated tag object `8378689cbd8cf6ad7d566d3924c3c9755417cf43`.

- `bluefire/data/mitre_attack_t1082_v19_2.json` is the unchanged 6,617-byte Git blob
  `456248b9947555603bfe2981ae8d931cb2ba88a7`, with SHA-256
  `dd2e50ceef844302a690a1debac8336864e93ebd19da526eefac3072f5ee9a02`.
- `bluefire/data/mitre_attack_v19_2_LICENSE.txt` is the complete unchanged 2,311-byte
  license blob `ecac4fdc83b412256b233fc25d5f3502f2eaa07a`, with SHA-256
  `4de9222b0d5bc69b758f9cf0afdaea48fdcbfe7d33c7481973a6aa07d6cbea9d`.
- The custom license identifier is `LicenseRef-MITRE-ATTACK-2026`. The required notice is:
  “© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission
  of The MITRE Corporation.”

The deterministic transformer validates the exact source digest and projects only neutral
identity, name, version, status, timestamp, and primary-reference fields. It explicitly discards
the upstream description, citations, procedure material, command examples, and unrelated
references. Its envelope and any signed action package are content-addressed in
acceptance/runtime state rather than checked into the repository.

The metadata maps to BlueFire's independently authored, Windows-only compiled
`endpoint.discovery.windows-version.v1` operation. The fixed `RtlGetVersion` boundary accepts no
parameters and returns only operating-system, major-version, minor-version, and build-number
fields. The primitive has no built-in behavior; the reviewed package contributes the behavior,
typed output, T1082 mapping, and source-intake provenance that make it usable. The upstream record
contributes no command, program, payload, or execution implementation. No upstream code, install
script, payload, binary, container, or test harness is run during intake. MITRE and ATT&CK are
attribution references only; no affiliation, sponsorship, or endorsement is implied.

## Product workflow

The Research Sources screen exposes the fixed reviewed intake with a new destination ID, a
compatible Windows Execute profile, and a local operator ID. The same operation is available as
`POST /api/v1/research-intakes/mitre-attack-t1082-v19-2` and as `bluefire research intake-t1082`.
It verifies the packaged source and license, persists a content-addressed envelope beneath the
configured product-state root, locally signs and installs the fixed package, validates the
authenticated runner inventory, and activates the new behavior. An interrupted destination resumes
only after its exact artifact and package state are revalidated; retrying a completed destination
replays its immutable receipt without another activation. A separate review uses a new destination
and revalidates the already-active package without duplicating catalog entries.

The browser and API return only relative product-state references and public digests. They do not
return host paths, the generated private signing key, runner credentials, or upstream content.
Activating the package does not execute the action; an ordinary reviewed Execute run is still
required.

## Operator rule

Never execute external install scripts, payloads, containers, binaries, or upstream test harnesses during source intake. Intake records are provenance and decision records; execution requires a reviewed action, collector, detection backend, or tool adapter with its own typed contract.
