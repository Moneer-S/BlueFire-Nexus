# Detection Lab

BlueFire's detection model is evidence-driven. A rendered rule is a hypothesis until an appropriate parser/compiler and explicit fixtures or observations support a stronger state.

## Revise a rule with observed evidence

Open a completed run and choose **Open Detection Lab**. Select a saved, validated SQLite or Sigma rule and keep the source run selected. In the rule workspace, open **Improve this rule with AI**, select **Assist** and a configured model provider, and describe the miss or false positive to investigate. **Off** sends no model requests. Save or restore any manual source edits before requesting or accepting an AI change.

The service verifies the saved rule and finalized run before sending a bounded context. Only independently observed records qualify; synthetic and runner-reported records cannot substitute. Provider configuration determines whether the request includes field metadata or a bounded, redacted projection of permitted content. More than 128 observations is refused instead of silently truncating the case. An unavailable provider, unsupported source, parser error or stale rule remains a visible failed job.

Review the original and proposed source together, the model's explanation, referenced observations and limitations. **Accept, save and evaluate** records your decision, creates an immutable child revision and runs the installed query backend on this source run. The child, evaluation and job receipts are persisted together. **Reject proposed change** preserves the review without applying the source. This operation does not deploy a detector or change an execution target.

A ready proposal is not an applied revision. The workspace reports saving, cancellation, interruption and failure separately, and links to the child only when a persisted application receipt is available. Reload restores the job from its link. An uncertain submission retains its original request for retry; interrupted work uses an explicit retry and follows its recorded successor. Changing the selected run or editing a rule keeps the proposal reachable while preventing acceptance against stale context.

The source evaluation is **development evidence** because the model used it to propose the change, even if the run was previously withheld. Evaluate the saved revision on separate attack, benign and withheld cases, then on a replay. Use **Run evaluations** and **Compare** to inspect measured matches, missing telemetry and backend limitations. A match on the development case alone does not establish an improvement.

Detection assistance currently supports reviewed source revision and evaluation in Assist. Automatic multi-operation experiment orchestration is not provided by this operation. The configured Responses or Chat Completions adapter is used as selected; no offline draft or alternate model is silently substituted.

The API uses the same services: `POST /api/v1/detections/{candidate_id}/ai-revision-jobs` accepts a UUID `submission_id`, `run_id`, `parent_resource_digest`, `question`, operator-assigned `case_role`, `provider_id`, and optional `autonomy: "assist"`. Read its durable job through `GET /api/v1/jobs/{job_id}`. Submit review through `POST /api/v1/jobs/{job_id}/detection-revision-decisions` with `proposal_digest`, `parent_resource_digest`, `decision` (`accept` or `reject`), and `reviewed_by`. Repeated matching submissions and decisions recover the same operation; they do not allocate another revision. A conflicting decision is refused.

### Unsent revision requests

The revision panel keeps an unsent question and development-case choice in this browser tab for the exact saved rule revision and source run. Returning to that selection restores those inputs; a different revision or run has its own draft. Reopening the page keeps AI Off and never submits the draft. Model/provider selection and reviewer identity are not restored from this draft.

**Discard request draft** asks before clearing these unsent inputs. It does not clear a submitted request, job, decision or saved rule. If browser storage fails, the panel reports that limitation and keeps edits in the open session. Copy the question before closing or reloading in that case.

## Candidate contract

A newly created `bluefire.detection.v2` candidate records (`v1` is accepted only when reading legacy origins):

- behavior ID, title, target language, and log source;
- structured selection and optional rule source;
- parser/backend identity and validation details;
- malicious, observed, and benign fixture/evidence IDs;
- public baseline references;
- predicted fields, observed fields, and field drift;
- match counts, known misses, false-positive notes, tuning decisions, and limitations;
- bounded malicious/benign fixture documents and provenance;
- lifecycle state and an ordered, input-digested transition history.
- immutable revision number, lineage root/parent IDs, revision kind, and definition digest.

Executable target language labels are `internal`, `sigma`, `sqlite`, and `yara`; `spl` is structural-only. Legacy `yara-l` candidates remain readable but unavailable because YARA-L is not YARA and has no authoritative local evaluator in this release.

## Lifecycle

| State | What it proves |
|---|---|
| `hypothesis` | A behavior-linked idea exists; syntax and matches are unproven |
| `parsed` | An authoritative maintained parser/compiler accepted the source |
| `fixture_exercised` | The parsed candidate was run against declared malicious fixtures and matched at least one where required |
| `observed_exercised` | The candidate matched independently attributable `observed` evidence |
| `benign_evaluated` | Declared benign fixtures were evaluated and match counts/notes retained |
| `rejected` | Parsing, compilation, fixture expectations, or review rejected the candidate |

The lifecycle prevents unsupported jumps. An external-language candidate cannot use the built-in structured matcher to claim parsing. `observed_exercised` includes only evidence IDs that actually matched, not every record evaluated.

The persisted API is the lifecycle authority. Hypotheses are created through `POST /api/v1/detections`; parse, malicious-fixture, observed-evidence, benign, and rejection operations use the named candidate action routes documented in [Local API](API.md). Generic detection resource writes are refused so a client cannot assert an advanced status or erase history. An origin ID is derived from behavior, language, logsource, and selection. Clone/tune IDs also bind the definition digest, atomically allocated revision, lineage root, parent, and revision kind. Definitions never update in place; an exact origin create is idempotent and any change requires an explicit clone or tune. The stored resource status must exactly equal the candidate state.

Each accepted action appends an ordered history record with the previous/current state, honest outcome, timestamp, and a digest of the bounded input. Observed exercise also records the source run ID. The service rehydrates every stored candidate through the strict contract and verifies the resource digest, ID, and status before a subsequent action.

## Immutable revisions

Clone retains the source rule semantics and requires a research reason; optional title, provenance,
known-miss, public-baseline, and predicted-field changes create a new revision. Tune additionally
requires a changed `selection` or `logsource`. Both operations allocate the next revision atomically,
retain the selected parent, and start a new hypothesis without changing the parent lifecycle.

Revision comparison accepts one candidate ID and requires both candidates to share the same lineage
root:

```json
{"candidate_id": "detection-child-id"}
```

The response identity and digest cover the complete comparison snapshot, including lifecycle state;
comparison does not mutate either revision.

## Backend status

`ExternalDetectionValidator.health()` reports actual local readiness and version:

- **pySigma plus SQLite backend**: parses exactly one Sigma rule, converts it through the exact pinned 1.2.2 backend, retains both versions and the converted-query digest, and refuses unsupported query fields.
- **bounded SQLite executor**: executes converted Sigma or native SQLite `SELECT` candidates against a fresh fixed `logs` table. It permits no attachment, extension loading, schema mutation, data mutation, multiple statement, alias/join, or unbounded result path; a query-only connection, authorizer, VM/deadline limits, and row/field/byte caps are independently recorded.
- **YARA-Python**: compiles with includes disabled and warnings as errors; fixture data is bounded and matching uses a timeout.
- **SPL structural checker**: checks bounded source, quotes, delimiters, and control characters. It is not an authoritative Splunk parser, so a successful structural check remains `hypothesis`.

Install the pinned optional adapters into the project virtual environment:

```bash
python -m pip install "pysigma==1.5.0" "pysigma-backend-sqlite==1.2.2" "yara-python==4.5.4"
python -m pytest tests_platform/test_detections.py
```

The installable YARA adapter and its reviewed upstream research-source record are both pinned to 4.5.4.

The SQLite backend record pins upstream tag `v1.2.2` at commit
`cfc0a2dd75470f73e2e375c3e58aecc21a33fbc6`, records PyPI's attested wheel and source
distribution hashes, and identifies the LGPL-3.0-only license. The upstream plugin directory marks
the backend `testing`; keep the exact pin and require focused local conversion and execution tests.
See [Third-party notices](../THIRD_PARTY_NOTICES.md). The intake record alone does not claim that an
artifact was installed or that generated SQL ran; only a persisted lifecycle execution result does.

If an optional package is absent, the candidate remains a hypothesis. Do not catch that condition and mark it parsed.

## Sigma workflow

1. Create a `target_language="sigma"` hypothesis.
2. Render or author one reviewed Sigma YAML rule.
3. Call `parse_sigma`; retain the pySigma/backend versions, source and converted-query digests, fixed table, mapping, and all rule/collection errors.
4. Exercise deterministic malicious fixtures through the bounded SQLite executor.
5. Link independent observed evidence only after mapping actual telemetry fields.
6. Evaluate benign fixtures and document false-positive tradeoffs.

Parsing and conversion record `source_rule_executed: false`. Before each fixture or observed-evidence action, BlueFire reconverts the persisted Sigma source and verifies its source digest, query digest, parser version, conversion backend, and conversion version. Only a successful bounded evaluation records `source_rule_executed: true`, evaluated/matched IDs, mapped and unsupported fixture fields, result fields, and executor limits. This is local rule evaluation, not a claim that a SIEM deployed or executed the rule.

## Native SQLite workflow

Create a `target_language="sqlite"` hypothesis and submit exactly one bounded `SELECT` from the fixed `logs` table. The query must return `fixture_id` exactly once so results remain attributable. Only declared schema fields are available; extra fixture fields are reported but never become identifiers or schema changes. Native queries use the same malicious, immutable observed-evidence, and benign lifecycle actions and the same execution caps as converted Sigma.

## YARA workflow

1. Create a `target_language="yara"` hypothesis.
2. Compile with `compile_yara`.
3. Exercise bounded malicious fixture bytes with `exercise_yara_fixtures`.
4. Record every evaluated fixture ID and only the matched IDs.
5. Evaluate benign fixtures with the same compiled source before production use.

Includes are disabled to avoid unexpected filesystem access. The fixture collection is limited to 1 MiB in total and the source to 256 KiB. BlueFire does not import or vendor a public YARA corpus.

## Internal matcher

The orchestrator currently creates one built-in internal staging candidate for `sandbox.collection.stage.v1`. It parses with `bluefire-structured-matcher`, exercises a positive staging-path fixture, compares applicable observed file evidence, and evaluates a benign source-path fixture.

This internal matcher validates its own structured predicate only. It is not a replacement for Sigma, YARA, SPL, EDR, or SIEM syntax.

## Predicted versus observed fields

Field drift reports:

- `predicted_only`: required/expected fields absent from the observation;
- `observed_only`: available fields not anticipated by the candidate;
- `intersection`: fields present in both sets.

Treat predicted-only fields as a telemetry dependency or mapping problem before weakening a detection. An absent field is not evidence that an action did not occur.

## Public baselines

Public rules are research references, not automatic evasion targets. New Detection Lab pins use the enriched `bluefire.public-baseline.v2` contract and preserve the research-source ID, source digest, version, exact commit/tag/ref, retrieval and verification dates, license review, file-level license and trademark notes, relationship, source-use classification, attribution, security review, and update status. Legacy `bluefire.public-baseline.v1` pins remain readable for existing candidates but should not be used for new source attachments.

The current revision comparison reports changes to registered public-baseline metadata alongside the two candidates' own malicious/benign fixture, observed-evidence, field, rule, and lifecycle deltas. It does not fetch a public corpus, execute a public rule, or compute candidate-only/baseline-only public-rule hit sets.

BlueFire's built-in research registry references MITRE ATT&CK, Sigma specification, pySigma, the pinned pySigma SQLite backend, and yara-python. It does not synchronize SigmaHQ, Elastic, Splunk, or commercial rule corpora.

## UI behavior

The selected rule is the main workspace. Open **New rule** to create a draft; **Detection backends** and **Validation stages** contain setup and lifecycle details. An empty SQLite draft offers an editable staged-file query for the `logs` table. Inserting it performs no validation or evaluation. Choose evidence fields appropriate to the source run, validate the rule, and measure actual matches. Changing the source run keeps a selected registry rule and its current source edits in place.

Detection Lab clients can inspect persisted candidates, create local hypotheses, show lifecycle counts, and organize candidate/fixture/field/baseline views. Local draft source and disabled backend buttons do not indicate that a parser ran. Trust only the service response's backend metadata, resource status, lifecycle state, and ordered history.

Observed evidence cannot be supplied by a client. The service reads a finalized run bundle, validates its manifest and every evidence hash/identity, and then admits only `observed` provenance. Unfinalized, corrupted, synthetic, executed, or caller-invented evidence cannot advance the observed state.

## Quality checklist

- Is the candidate linked to a registered behavior?
- Did an authoritative parser/compiler produce the claimed state?
- Are parser/backend names and versions retained?
- If Sigma was converted, is the exact converted-query identity retained and is execution distinguished from conversion?
- Are malicious and benign fixtures deterministic, sanitized, and attributed?
- Does observed exercise use only `observed` evidence and only actual matches?
- Are predicted/observed field mappings explicit?
- Are known misses and telemetry dependencies recorded?
- Are false-positive notes and benign match counts present?
- Are public baselines licensed and pinned?
- Do public baselines include exact source-use classification, attribution, security review, and verification metadata?
- Is every tuning decision retained rather than overwriting history?
- Does the documentation avoid the word “validated” when only rendered, parsed, or structurally checked?
