# Detection Lab

BlueFire's detection model is evidence-driven. A rendered rule is a hypothesis until an appropriate parser/compiler and explicit fixtures or observations support a stronger state.

## Candidate contract

A `bluefire.detection.v1` candidate records:

- behavior ID, title, target language, and log source;
- structured selection and optional rule source;
- parser/backend identity and validation details;
- malicious, observed, and benign fixture/evidence IDs;
- public baseline references;
- predicted fields, observed fields, and field drift;
- match counts, known misses, false-positive notes, tuning decisions, and limitations;
- bounded malicious/benign fixture documents and provenance;
- lifecycle state and an ordered, input-digested transition history.

Supported target language labels are `internal`, `sigma`, `yara`/`yara-l`, and `spl`.

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

The persisted API is the lifecycle authority. Hypotheses are created through `POST /api/v1/detections`; parse, malicious-fixture, observed-evidence, benign, and rejection operations use the named candidate action routes documented in [Local API](API.md). Generic detection resource writes are refused so a client cannot assert an advanced status or erase history. Candidate IDs are derived from behavior, language, logsource, and selection, while the stored resource status must exactly equal the candidate state.

Each accepted action appends an ordered history record with the previous/current state, honest outcome, timestamp, and a digest of the bounded input. Observed exercise also records the source run ID. The service rehydrates every stored candidate through the strict contract and verifies the resource digest, ID, and status before a subsequent action.

## Backend status

`ExternalDetectionValidator.health()` reports actual local readiness and version:

- **pySigma**: parses exactly one Sigma rule and retains parser errors/version.
- **YARA-Python**: compiles with includes disabled and warnings as errors; fixture data is bounded and matching uses a timeout.
- **SPL structural checker**: checks bounded source, quotes, delimiters, and control characters. It is not an authoritative Splunk parser, so a successful structural check remains `hypothesis`.

Install the pinned optional adapters into the project virtual environment:

```bash
python -m pip install "pysigma==1.4.0" "yara-python==4.5.4"
python -m pytest tests_platform/test_detections.py
```

If an optional package is absent, the candidate remains a hypothesis. Do not catch that condition and mark it parsed.

## Sigma workflow

1. Create a `target_language="sigma"` hypothesis.
2. Render or author one reviewed Sigma YAML rule.
3. Call `parse_sigma`; retain pySigma version and all rule/collection errors.
4. Exercise deterministic malicious fixtures using a backend or field-normalized harness appropriate to the rule.
5. Link independent observed evidence only after mapping actual telemetry fields.
6. Evaluate benign fixtures and document false-positive tradeoffs.

BlueFire currently parses Sigma source but does not ship backend-specific Sigma conversion or a SIEM deployment connector.

The local fixture and observed-evidence actions can evaluate the candidate's explicitly declared normalized selection after pySigma accepts the source. They record `source_rule_executed: false`; this is not a claim that a SIEM executed the Sigma rule.

## YARA workflow

1. Create a `target_language="yara"` hypothesis.
2. Compile with `compile_yara`.
3. Exercise bounded malicious fixture bytes with `exercise_yara_fixtures`.
4. Record every evaluated fixture ID and only the matched IDs.
5. Evaluate benign fixtures with the same compiled source before production use.

Includes are disabled to avoid unexpected filesystem access. Each fixture is limited to 1 MiB and the source to 256 KiB. BlueFire does not import or vendor a public YARA corpus.

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

Public rules are research references, not automatic evasion targets. Preserve source, version/commit, retrieval date, license, and the candidate relationship. Baseline comparison reports candidate-only, baseline-only, overlap, and incremental candidate matches over the same named fixtures.

BlueFire's built-in research registry references MITRE ATT&CK, Sigma specification, pySigma, and yara-python. It does not synchronize SigmaHQ, Elastic, Splunk, or commercial rule corpora.

## UI behavior

Detection Lab clients can inspect persisted candidates, create local hypotheses, show lifecycle counts, and organize candidate/fixture/field/baseline views. Local draft source and disabled backend buttons do not indicate that a parser ran. Trust only the service response's backend metadata, resource status, lifecycle state, and ordered history.

Observed evidence cannot be supplied by a client. The service reads a finalized run bundle, validates its manifest and every evidence hash/identity, and then admits only `observed` provenance. Unfinalized, corrupted, synthetic, executed, or caller-invented evidence cannot advance the observed state.

## Quality checklist

- Is the candidate linked to a registered behavior?
- Did an authoritative parser/compiler produce the claimed state?
- Are parser/backend names and versions retained?
- Are malicious and benign fixtures deterministic, sanitized, and attributed?
- Does observed exercise use only `observed` evidence and only actual matches?
- Are predicted/observed field mappings explicit?
- Are known misses and telemetry dependencies recorded?
- Are false-positive notes and benign match counts present?
- Are public baselines licensed and pinned?
- Is every tuning decision retained rather than overwriting history?
- Does the documentation avoid the word “validated” when only rendered, parsed, or structurally checked?
