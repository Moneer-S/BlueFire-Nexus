# Compatible collection experiment

`scenario.endpoint.lab-collection-methods.v1` retains generated public lab
values. `scenario.endpoint.lab-benign-collection.v1` performs the same discovery,
transformation, collection, and cleanup with the values redacted first. These are
bounded synthetic materials, not personal files or credentials. System/process
discovery and canary inspection report executed activity; independent collection
observations establish the staged file's bytes and aggregate semantics.

Both scenarios use `sandbox-execute.v1`. The fresh collection behaviors share the
same parameters and `artifact.sandbox.collection.v1` output contract:

| Method | Operation on the same exact input | Output |
| --- | --- | --- |
| `sandbox.collection.records.v1` | Parse reviewed records and serialize canonical JSONL | `staged/collection/bundle.jsonl` |
| `sandbox.collection.archive.v1` | Preserve the exact transformed file in one deterministic USTAR member | `staged/collection/bundle.tar` |

Each consumes exactly one typed discovery artifact for
`fixtures/transformed.jsonl`. Native execution checks its SHA-256 against the
same bounded bytes it then processes. A changed source fails before staging.
Inputs and outputs are capped at 1 MiB. The `stage_variant: heldout` parameter
uses `staged/variation` instead. Neither method accepts an arbitrary path or
command. Existing collection and archive identities retain their old contracts.
Every written file remains subject to receipt-bound cleanup.

Select the collection semantics observer explicitly. Its scheduled output path
must match the chosen method and variant. The [observer contract](collection_semantics_observer.md)
defines independent same-handle hashing and parsing, exact generated templates,
and aggregate counts without exporting record values. Malformed, missing,
changed, oversized, or unsupported bytes remain insufficient evidence. Simulate
produces synthetic artifacts only.

## Detector experiment

The question is whether a detector recognizes retained lab values across both
collection methods while avoiding redacted benign staging. Use the real SQLite
backend and immutable [run evaluation](detection_run_evaluations.md) reports.
Case roles document the experiment; they do not supply expected answers.

A deliberately incomplete baseline can inspect only the archive container:

```sql
SELECT fixture_id FROM logs
WHERE artifact_type = 'collector_observation'
  AND observation_kind = 'collection_semantics'
  AND container = 'ustar'
```

This baseline misses record collection and can match a redacted benign archive.
Those are deliberate weaknesses to measure, not claims about an existing
production rule. Create a new immutable revision that inspects retained material
independently of container and path:

```sql
SELECT fixture_id FROM logs
WHERE artifact_type = 'collector_observation'
  AND observation_kind = 'collection_semantics'
  AND retained_record_count > 0
```

Evaluate each revision against completed attack and benign Execute runs. Replay
the attack with the compatible alternate, then execute a heldout path variation.
Evaluate the resulting immutable runs as `replay` and `heldout`; inspect actual
match counts and evidence identities in each report. A missing observation is
not a detector miss. A detector match does not prevent the collection action or
prove malicious intent. The changed defense here is a real query revision, not
the profile action allowlist.

## Implementation provenance

The record serializer, deterministic USTAR writer, strict observer, and scenario
definitions are BlueFire-authored MIT code in this repository. The archive
representation uses the POSIX USTAR header layout; it contains exactly one
ordinary file named `fixtures/transformed.jsonl`, with no compression, extensions,
links, or extraction. No external archive implementation was copied. This
experiment uses the existing Python standard-library SQLite backend and does
not require pySigma or YARA. Optional Sigma evaluation reports its actual
installed backend separately under the existing detection backend contract.
