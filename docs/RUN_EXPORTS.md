# Saved run exports

Run review offers two downloads after finalization:

- **Download report** saves a readable Markdown summary of the displayed saved run. It uses the same objective, step outcome, authorized target scope and cleanup labels as the review. Simulation, absent evidence and unknown cleanup remain explicit. It is a summary, not an evidence archive.
- **Download run bundle** validates a fresh read-only snapshot and saves a ZIP containing one canonical run directory. Original manifest and artifact bytes, the complete `events.jsonl` and published recovery records with their independent manifests are preserved. It does not export the paginated run-detail JSON.

Detection candidates recorded during the run are included in its original files. Later detector revisions and Detection Lab evaluations are separate product-store records and are not included. A sanitized demo supports the report only.

The local API is `GET /api/v1/runs/{run_id}/bundle`. It accepts a canonical run ID, no query parameters, no paths, and requires the normal browser session. Responses are attachments with `application/zip` and `Cache-Control: no-store`. Other methods do not create an export or a job.

Exports use the existing cloud run-bundle read bounds: at most 32 files, 4 MiB per file and 16 MiB total uncompressed, including manifests and recovery records. Oversized or incomplete bundles are refused, never truncated. All directory entries must belong to the original manifest or a complete canonical recovery directory; unlisted files and temporary staging, links, reparse points and multiply linked files refuse the snapshot. The adapter validates hashes and sizes against the actual captured bytes, validates the complete event chain and recovery source digests, and rejects identity or inventory changes during capture. If recovery is being published concurrently, retry after it settles.

Downloads start only from an operator click. A bundle request has a 30-second browser bound and is aborted when its review unmounts or changes run. A late response cannot download a previous run after navigation. No preflight, approval, replay, model request or target effect is involved.
