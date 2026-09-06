# Connected method comparison

The native Compare operation selects a compatible registered alternative for one
step, reviews a full replay, and evaluates the same saved SQLite/Sigma detector on
the finalized source and child. The packaged collection-method and benign
collection scenarios support record collection versus whole-file archive of the
same transformed input. These are actual registered replay variants.

`GET /api/v1/runs/{run}/method-comparison-context` returns the authoritative source
digest and eligible named methods. `POST /api/v1/runs/{run}/ai-method-comparison-jobs`
accepts a canonical `submission_id`, `source_binding_digest`, `selected_step_id`,
`candidate_id`, `candidate_resource_digest`, `question`, `source_case_role`,
`provider_id`, and optional per-operation `autonomy`. Exact repeats resolve the
same durable `replay.ai.propose` job. Off sends no provider request. Semantic
admission refusals are retained failed jobs; malformed submissions are rejected.

The injected provider access supports both Responses and Chat Completions,
including isolated broker enrollment for the exact `bluefire_method_comparison`
schema. The model chooses only an eligible option and bounded rationale,
limitations and observed evidence references. It cannot select scope, profile,
collector settings, query source, approval or job identity. Source, detector,
provider and prepared replay bindings are revalidated. Model context uses bounded
observed field metadata and configured redaction; raw collected values are not
transmitted by this operation.

A completed proposal job means a proposal is available, not that the replay or
comparison completed. `POST /api/v1/jobs/{job}/method-comparison-decisions` accepts
`proposal_digest`, `decision` (`accept` or `reject`) and `reviewed_by`, returning
`proposal_job`, `replay_job` and the durable `decision`. Assist requires this
review. Auto retains a bounded policy decision and continues the same fixed
sequence. Execute always waits for a fresh ordinary Execute approval. The replay
planner is Off to prevent additional unreviewed adaptations; that setting and any
change from the source are shown explicitly. Scope, profile, catalog and collector
authority must be reconstructable without widening.

One reserved replay UUID is published through existing replay admission. Parent
Stop and child publication serialize in the same jobs-table transaction. The
normal replay callback validates the accepted operation before running and links
the known finalized run before analysis. Two immutable evaluation reports, the
existing comparison resource and both job receipts commit in one transaction.
The final receipt contains source/child run IDs, the unchanged detector identity,
both evaluation IDs, the comparison ID and its digest. A receipt is revalidated
against its owner, runs, detector and stored reports before recovery claims it.

If analysis fails or is interrupted, ordinary job Retry creates an idempotent
`replay.comparison.recover` job. It validates the exact known run, its lineage and
settled cleanup, then performs analysis only. It never enters generic replay
retry. An unknown run or unsettled cleanup refuses recovery rather than assuming
no effects happened. A crash before result-link persistence can recover the exact
run ID already retained by the ordinary run checkpoint. Parent progress retains
`replay_result`, `comparison_recovery_job_id` and `comparison` for reconnect.
Retry returns the standard `bluefire.job-retry.v1` envelope; analysis replacements
also report `operation_kind: comparison_only`. Stop cancels both the replay and
current analysis job. A later explicit analysis retry binds the current persisted
stop generation; another Stop invalidates it. This never clears the permanent
replay-publication stop flag, and a committed comparison receipt is preserved.

Matches describe the bounded query over independently observed metadata; missing
observations remain insufficient evidence. The source informed method selection,
so the resulting exploratory comparison does not establish independent held-out
validation, deployed detection or prevention. Manual detector or replay edits
stale an unaccepted proposal; accepted identities cannot be retargeted.
