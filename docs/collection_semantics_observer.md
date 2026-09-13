# Collection semantics observer

`collector.collection-semantics.sandbox.v1` independently observes aggregate facts
about reviewed synthetic collection artifacts. In Runs, choose **Collection
contents (bounded synthetic records)** for the compatible collection scenarios.
Switching those scenarios to Execute selects this observer and shows its path.
The API/CLI accepts its ID in the existing per-run `collectors` list. The server
schedules it only after `sandbox.collection.records.v1` or
`sandbox.collection.archive.v1`, using the exact output declared by the approved
method and parameters. Replay binds its own approved method/path. The selection
is part of preflight and one-time approval; missing contents observation leaves
these new methods' objective incomplete even when filesystem hashes exist.

Other reviewed uses can enable it through versioned `collector_runtime` settings
with explicit `paths` and a `collect_after_step`:

```json
{
  "schema_version": "bluefire.collector-runtime-settings.v1",
  "collectors": {
    "collector.collection-semantics.sandbox.v1": {
      "enabled": true,
      "settings": {
        "paths": ["staged/collection/bundle.jsonl"],
        "collect_after_step": "stage_records"
      }
    }
  }
}
```

Use the actual producing step ID and final artifact path from the selected
scenario. Collection requires managed Execute authorization. Simulate does not
read files or accept collector runtime settings. No directory discovery or
implicit file reads are performed by this collector.

The observer reads at most 16 declared files, each at most 1 MiB, under the pinned
sandbox root. It hashes and parses the same bytes from one independently opened
file handle. Existing root identity, no-follow path traversal, stable-file,
deadline, and byte limits remain in effect. The reader accepts JSONL or the
reviewed deterministic USTAR representation with exactly one regular member,
`fixtures/transformed.jsonl`. It does not extract archives or follow archive
links, and rejects compressed, multiple-member, extended-header, truncated, or
otherwise unsupported representations.

A valid stream contains 1–100 sequential records with exactly `record_id`,
`synthetic`, `template`, and `value`. IDs start at `synthetic-001`, `synthetic`
must be true, and values must match the reviewed `telemetry-seed`,
`harmless-document`, or `empty` template for their ordinal, or the exact
`synthetic-redacted` placeholder. Mixed reviewed templates are allowed. Duplicate
keys, extra fields, unsupported values, and nonfinite JSON constants are invalid.

An OBSERVED record has `artifact_type: collector_observation`,
`observation_kind: collection_semantics`, and the following top-level fields,
also retained under `observed_fields`:

| Field | Meaning |
| --- | --- |
| `path`, `sha256`, `size_bytes` | Exact independently read file identity |
| `container` | `jsonl` or `ustar` |
| `record_count` | Total valid records |
| `retained_record_count` | Original nonempty generated values |
| `redacted_record_count` | Exact reviewed redaction placeholders |
| `empty_record_count` | Original empty-template values |

The three categories sum to `record_count`. Record values are never included in
the observation. Missing, malformed, unsupported, changed, or unreadable files
produce UNKNOWN evidence gaps; they do not become zero-count observations or
negative detection results. Existing observation integrity checks bind this
collector's digest and size to the producing action within the same write
episode, run, profile, and scope.

SQLite detection candidates can use the top-level fields directly. For example,
this condition detects retained synthetic values in either supported container:

```sql
SELECT fixture_id FROM logs
WHERE artifact_type = 'collector_observation'
  AND observation_kind = 'collection_semantics'
  AND retained_record_count > 0
```

The existing evidence selection and provenance rules still apply. A rule exercise
must select the independent observation, and an unavailable observation remains a
gap requiring investigation.
