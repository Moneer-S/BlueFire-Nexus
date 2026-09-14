# Immutable detector results for observed runs

Detection Lab's **Run evaluations** tab evaluates a parsed SQLite or Sigma candidate against the complete observed evidence in a finalized run. The same service is available through `POST /api/v1/detections/{candidate_id}/evaluate-run` and `bluefire detections evaluate-run CANDIDATE_ID request.json`.

The API requires `run_id`, `question` and the compatibility field `case_role`; it also accepts `activity_label` and `evaluation_use`. For example:

```json
{
  "run_id": "run-20260906T120000Z-0123456789abcdef",
  "question": "Does this detector identify collection staging without matching observed benign activity?",
  "case_role": "attack",
  "activity_label": "attack",
  "evaluation_use": "development"
}
```

Replace the example run ID with a real retained run. In **Run evaluations**, choose **Evaluation source run**, optionally enter an **Experiment question**, then set **Activity label** and **Use of this data** independently before choosing **Evaluate full observed run**. An empty question uses the selected rule's default question.

Activity labels are `attack`, `benign` or `unknown`; they describe operator-assigned context, not observed intent or an expected match. Data use is `development`, `independent` or `unspecified`. The compatibility `case_role` still accepts `attack`, `benign`, `replay`, `heldout` and `unknown`; only attack/benign provide a default activity label, and neither replay nor heldout implies independent data use.

The report's `classification` records these dimensions separately. Replay lineage comes from the verified immutable run. Recorded development use in the candidate or its inspected ancestors overrides a later independent label, including known development source use for a replay. Incomplete development history prevents a claim of independent use from being retained as such. `independence_verified` remains false: an operator label is not proof that the data was unseen. Historical reports without these fields remain unchanged and do not gain an independence guarantee.

The service verifies the immutable run manifest and every evidence identity before selecting all `observed` records. Callers cannot supply raw evidence, a subset of evidence IDs, or expected results. Synthetic, executed, and counterfactual records cannot supply missing observations. Unknown evidence, failed file postconditions or missing query fields produce `insufficient_evidence` with no supported match count. A source collection above 10,000 total evidence records is refused before evaluation. Backend or execution-budget refusal produces `backend_error`, without a partial match result.

SQLite queries run in the existing bounded in-memory executor. Sigma uses the installed, pinned pySigma SQLite adapter and that same executor. Reports preserve actual backend version, limits, query digest, evidence IDs, field names, and sanitized diagnostics. They do not copy the raw evidence rows, deploy a detector, or establish prevention on a host. Internal matcher and YARA metadata candidates are not supported by this query-evaluation path.

Full-run evaluation uses the complete observed dataset within the limits in [the query budget](../bluefire/detection_query_limits.py): up to 10,000 input records and 16 MiB of normalized input, 32 KiB of query text, 10,000 result rows, 64 result fields, 16 MiB of results, 5,000,000 SQLite VM steps and a 2,000 ms execution deadline. It executes one query over the dataset, not separate per-batch queries that could change aggregate semantics. All limits apply; the record ceiling alone does not guarantee execution. Gap detail display is capped at 128 IDs, but every gap still prevents a supported evaluation. The separate 128-observation model-context cap remains unchanged and does not truncate this detector query.

Each new report has a content-derived ID and binds the detector definition/query, source manifest/evidence, experiment question, compatibility case role and classification. Storage is append-only. `GET /api/v1/detections/{candidate_id}/evaluations` and `bluefire detections evaluations CANDIDATE_ID` revalidate those bindings. Lifecycle promotion, tuning, and run replay remain separate operations. Related-revision reports can be viewed together in the UI without changing either revision.

For a detector-revision experiment, first evaluate the baseline against the actual attack run. Create and parse a new immutable revision, then evaluate it against that same run, relevant observed benign activity, the actual replay, and a separately prepared variation not used to develop the rule. Record its actual data use; a heldout label alone is insufficient. A deliberately archive-only baseline may miss JSONL staging; broadening its path predicate may recover that case but also match benign staging. Report both measured effects. A path-only rule cannot establish whether collected material was retained or redacted; that requires independent semantic observations of the staged bytes.

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

## Reviewed AI source revisions

`POST /api/v1/detections/{candidate_id}/ai-revision-jobs` requests one concrete SQLite or Sigma source change from the selected configured provider. The body contains `submission_id` (canonical UUID), `run_id`, `parent_resource_digest`, `question`, `case_role`, `provider_id`, and optional `autonomy: "assist"`. Persist that exact request before sending it; retry uncertain publication with the same UUID and body. The response contains `job`. Read its durable state through `GET /api/v1/jobs/{job_id}`.

A completed `detection.ai.propose` job means a parsed suggestion is available in `progress.proposal`; it does not mean a detection revision was applied. The suggestion binds the parent source/resource/definition, immutable run and observed record digests, model/provider, and exact supplied evidence references. Observations are untrusted input. Default provider redaction sends field names/types and reference IDs, not observed values. If evidence content is enabled, only bounded allowlisted metadata is supplied; raw logs, bodies and commands are still excluded. No deterministic substitute is presented as a model-generated revision. Off makes no provider request. This operation currently supports Assist review; autonomous detector acceptance is not implemented.

Semantic admission failures, including a stale parent or unavailable source, are retained as failed proposal jobs with `progress.operation_error`. A repeated UUID never starts another provider request. A queue-capacity failure can occur before publication: retain the request and retry the same UUID when capacity is available. Invalid field shapes and UUIDs are rejected before admission.

After reviewing the before/after source and exact parent/run binding, submit `POST /api/v1/jobs/{proposal_job_id}/detection-revision-decisions` with `proposal_digest`, `parent_resource_digest`, `decision` (`accept` or `reject`), and `reviewed_by`. The first decision is durable; exact retries recover it. Acceptance returns an `application_job`, while rejection returns null. This is a local detection review, not an Execute approval and not a runner capability.

A completed `detection.ai.apply` job points to the child candidate in `result_ref`. Both jobs retain `progress.application` with the child `candidate_id`, immutable `evaluation_id`, and `development_case: true`. The existing source revision parser and bounded run evaluator create the child, report and both job links in one SQLite transaction. Stale parent checks, parser refusal, cancellation before commit, and precommit faults leave no partial child/report. A retry after commit returns the same receipt. Existing lineage and evidence rules remain in force, and the parent is unchanged.

The selected source run was used to propose the source, so its evaluation is explicitly a **development case**, even if its operator-declared case role is `heldout`. It does not establish independent held-out validation, deployment or prevention. Evaluate separate run evidence through the existing run evaluation endpoint to obtain independent cases.

Completed proposals and decisions survive reconnects. Running jobs interrupted by a process exit use the existing `POST /api/v1/jobs/{job_id}/retry` operation, which requires an empty JSON body. A retry gets its own durable attempt ID and records `retry_of_job_id`; repeating the same retry returns that attempt. Application attempts share the original proposal's atomic receipt and cannot create duplicate children or reports. Cancelled and failed jobs are not automatically resumed. The ordinary job cancellation endpoint also applies to detection jobs.


## Download retained evaluation results

In **Related revision reports**, choose a revision to include its loaded results alongside the selected detector. **Download evaluation report** saves readable Markdown with source run names and creation times, recorded detector revisions, matched and evaluated counts, actual query status, comparison results, and evidence limits. Its Details appendix preserves the exact retained report records, immutable IDs and digests, and backend identity.

If either selected history is still loading or unavailable, **Download available reports** exports only successfully loaded records and marks the report partial. Insufficient evidence and backend errors never become zero-match conclusions. Development data and operator-declared independence remain explicit. The export describes the reports loaded at download time; it does not imply that every run or revision was evaluated.

**Export evaluation inputs** remains a separate download of the browser's question and source choices. Those inputs are not evaluation results. Downloading either file does not evaluate a run, call a model, or execute an experiment.
