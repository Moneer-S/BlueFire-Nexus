# Immutable detector results for observed runs

Detection Lab's **Run evaluations** tab evaluates a parsed SQLite or Sigma candidate against the complete observed evidence in a finalized run. The same service is available through `POST /api/v1/detections/{candidate_id}/evaluate-run` and `bluefire detections evaluate-run CANDIDATE_ID request.json`.

The request contains exactly:

```json
{
  "run_id": "run-20260906T120000Z-0123456789abcdef",
  "question": "Does this detector identify collection staging without matching observed benign activity?",
  "case_role": "attack"
}
```

Replace the example run ID with a real retained run. Case roles are `attack`, `benign`, `replay`, and `heldout`. They are operator-assigned context. They neither prove intent nor specify an expected match. A match in a declared benign case remains a measured match and is shown as a potential false positive.

The service verifies the immutable run manifest and every evidence identity before selecting all `observed` records. Callers cannot supply raw evidence, a subset of evidence IDs, or expected results. Synthetic, executed, and counterfactual records cannot supply missing observations. Unknown evidence, failed file postconditions, missing query fields, or an input beyond the existing 128-record executor limit produce `insufficient_evidence` with no supported match count. A refused backend execution produces `backend_error`.

SQLite queries run in the existing bounded in-memory executor. Sigma uses the installed, pinned pySigma SQLite adapter and that same executor. Reports preserve actual backend version, limits, query digest, evidence IDs, field names, and sanitized diagnostics. They do not copy the raw evidence rows, deploy a detector, or establish prevention on a host. Internal matcher and YARA metadata candidates are not supported by this query-evaluation path.

Each report has a content-derived ID and binds the detector definition/query, source manifest/evidence, experiment question, and case role. Storage is append-only. `GET /api/v1/detections/{candidate_id}/evaluations` and `bluefire detections evaluations CANDIDATE_ID` revalidate those bindings. Lifecycle promotion, tuning, and run replay remain separate operations. Related-revision reports can be viewed together in the UI without changing either revision.

For a detector-revision experiment, first evaluate the baseline against the actual attack run. Create and parse a new immutable revision, then evaluate it against that same run, relevant observed benign activity, the actual replay, and a held-out variation. A deliberately archive-only baseline may miss JSONL staging; broadening its path predicate may recover that case but also match benign staging. Report both measured effects. A path-only rule cannot establish whether collected material was retained or redacted; that requires independent semantic observations of the staged bytes.

To revise SQLite or Sigma directly, edit the **Rule** tab, enter a reason, and choose **Validate and save new revision**. The parent and its evaluation reports remain unchanged. **Evaluate actual runs** opens the current run selection; synthetic fixture exercise is optional for this per-run path. Structured selection and log-source JSON remain available under **Revisions** for the existing internal matcher and advanced metadata workflows. Those fields do not need to change when editing SQL or Sigma source.

The same operation is `POST /api/v1/detections/{candidate_id}/revise-source` or `bluefire detections revise-source CANDIDATE_ID request.json`:

```json
{
  "source": "SELECT fixture_id FROM logs WHERE observation_kind = 'collection_semantics'",
  "reason": "Examine independent collection contents observations"
}
```

An optional `title` names the new revision. The service accepts no caller-supplied compiled query, backend identity, evidence, or expected result. It validates at most 256 KiB of source through the installed reviewed parser/converter and the existing bounded SQLite dry run, then atomically saves one **parsed** child. Invalid source, an unavailable backend, or an interrupted transaction creates no child and consumes no revision ordinal. Parsing is not an observation or detector-match claim.

`revision_kind: source` is an additive extension of `bluefire.detection.v2`. For this kind, the definition digest includes the SHA-256 of the exact UTF-8 `rule_source` bytes. Candidate identity still binds the definition, parent, root and revision ordinal. Legacy origin, clone and tune identities retain their original digest calculation and remain readable. Source and converted-query digests are distinct: identical source is refused, while a textual edit that compiles to the same query is a valid textual revision and makes no improvement claim. Before run evaluation, the existing engine independently reconstructs and verifies the query from the stored source.

Clone retains structured metadata as an unparsed hypothesis; it does not copy compiled source or earned results. Tune still requires a structured selection or log-source change. These existing API and CLI operations remain supported.
