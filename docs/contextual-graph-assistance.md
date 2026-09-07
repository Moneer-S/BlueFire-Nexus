# Contextual graph proposals

The contextual Assistant can select `graph.propose_and_validate` from an authoritative graph context. The existing callback controller creates one durable `graph.ai.propose` child. The existing strict graph schema, registered behavior catalog, parameter validation, artifact binding normalizer and graph validator produce a separate proposed graph. No runner, execution approval, scenario run or detector result is created.

Off makes no model request. Assist and the explicitly advertised bounded Auto capability generate, validate and retain proposals only. Both require explicit native Builder review before saving. The selected model provider is retained by content digest; provider failure never falls back to offline drafting on this path. The older synchronous drafting API retains its existing behavior.

## Selected context and submission

`GET /api/v1/assistance/graph-context` selects a new graph with no reference. An optional exact saved reference requires all three query parameters `scenario_id`, `version` and `digest`. The reference must match its current saved head. The response preserves the existing context envelope with:

```json
{
  "selected": {"kind": "graph", "base_scenario": null},
  "bounds": {"max_nodes": 8, "max_edges": 16},
  "reference_summary": null,
  "catalog_digest": "sha256:<full registered descriptor digest>",
  "context_digest": "sha256:<context digest>"
}
```

The complete draftable descriptors and registered behavior definitions are hashed, and the current authoritative catalog generation/digests are bound. Each freshness boundary reads the existing catalog snapshot rather than holding a stale registry object. An optional reference contributes its exact immutable version digest plus a bounded summary of the saved title, purpose and up to eight behavior IDs. The summary marks truncation and is treated as untrusted model input. This supplies reference context; it does not promise an exact edit, copy or preservation of the reference graph.

Submit to the existing `POST /api/v1/assistance/turns` with `submission_id`, `selection`, `context_digest`, `message`, `autonomy` and an explicit `provider_id` for Assist/Auto. Graph selection is `{kind:"graph",base_scenario:null|{scenario_id,version,digest}}`. A graph-only plan has one capability with symbolic `detector_ref:"none"`; no fake detector or run IDs are introduced. The original flat detection submission remains accepted. Additive detection selection is `{kind:"detection",run_id,candidate_id,candidate_resource_digest,case_role}` with the common fields outside it. The exact submitted request is retained unchanged for uncertain-request recovery. Messages accept ordinary CR/LF line breaks and tabs within the 1000-character bound; other controls are refused. Derived detection/method child questions collapse whitespace to preserve those existing single-line native contracts.

## Native review and atomic save

The child link is `/builder?graph_job=<job_id>`. `GET /api/v1/ai/graph-jobs/<job_id>` returns `{job,proposal,application,review_ready}`. The authoritative review flag also permits a valid published proposal retained across process loss before its terminal callback update; failed, cancelled, in-flight, declined or parent-stopped proposals cannot be newly saved. Reopening and reviewing such an interrupted proposal never repeat its model request. The retained proposal includes its content digest, exact parent context/catalog/reference binding, normalized scenario, registered validation, provider metadata, rationale, assumptions and limitations. Reopening only reads these records.

`POST /api/v1/ai/graph-jobs/<job_id>/validate` accepts `{proposal_digest,scenario}` and returns `{proposal_digest,reviewed_digest,scenario,validation:{valid:true}}`. This read-only operation validates the frozen edit and supplies the server's canonical digest. It makes no model request or save. Invalid native graphs receive a safe `graph_validation_refused` response. Clients must inspect changed normalized content rather than silently accepting it, and must exclude local editor layout from the canonical graph document.

Explicit acceptance uses `{decision:"accept",proposal_digest,reviewed_digest,scenario}`. Rejection uses `{decision:"reject",proposal_digest}`. The exact decision is retained in `job.progress.decision`. Accept validates the separate proposal identity, registered graph and bounds, then rechecks the source/catalog/provider and active parent lineage. Scenario saving and its application receipt share the existing database transaction. Stop and review serialize through that transaction: Stop winning prevents the save; a committed save remains recoverable. An exact retry returns the already committed receipt even after later provider/configuration changes; a different review body is refused. No repeat provider request occurs.

The immutable application is `{proposal_job_id,proposal_digest,reviewed_digest,operator_modified,scenario_id,version,digest}`. The original proposal stays unchanged; edited saves are explicitly attributed to the operator. Fetch the reviewed saved document at `GET /api/v1/scenario-versions/<scenario_id>/versions/<version>` and verify its digest. The normal Builder must preserve its current unsaved working copy before explicitly opening that saved graph.

The Assistant result has `kind:"graph_saved"`, the application fields, its `step_id`, the retained Builder link and `execution_state:"not_run"`. Proposal retention is not graph acceptance; graph acceptance is not a successful experiment. Ordinary Runs setup, preflight, scope, budgets and fresh Execute approval remain separate.

## Verification limits

Portable tests exercise both provider dialects and actual framed broker enrollment, zero-call Off, strict no-fallback behavior, stale catalog/provider/reference refusal, edited saves, transactional rollback, cancellation during generation and held native acceptance, exact retries after reopening, native HTTP validation failures, and compatibility with existing detector/method turns. These tests do not claim an installed UI journey, provider quality, Execute effects or broader autonomous experimentation. Those remain separately verified product work.
