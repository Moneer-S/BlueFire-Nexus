# AI Planner

BlueFire treats model output as an untrusted proposal. The model operates inside a small allowlist derived from the deterministic graph; it is never an execution or policy authority.

## Autonomy levels

Autonomy is independent from Simulate/Execute.

| Level | Provider call | Current runtime behavior |
|---|---|---|
| `off` | No | Deterministic planner only; no AI proposal record |
| `assist` | Yes, at a bounded runtime decision point | Record default-preserving advice; pause every actual registered mutation for durable accept/reject review |
| `auto` | Yes, at a bounded runtime decision point | In Simulate only, may apply a policy-permitted registered behavior, typed parameter, action-independent edge, or one-retry proposal; review-required proposals still pause |

Execute never applies a runtime mutation directly, including under Auto. It pauses before the mutation, persists the proposal for review, and requires a fresh exact one-time execution approval after acceptance. Runtime AI cannot create or reorder nodes, invent an outcome edge, select an unregistered behavior or action, change a profile/scope/tier/budget, or introduce commands, paths, plugins, providers, or executable content.

## Runtime decision loop

After a step completes:

1. the deterministic planner selects the registered edge for the observed outcome and records a state digest;
2. if autonomy is not Off, BlueFire builds a bounded `bluefire.ai-request.v2`;
3. the request correlates each permitted next or retry node with its registered behaviors, safe primitive parameter schemas, exact edge, and behavior-owned actions enabled by the exact Execute profile;
4. action IDs are omitted in Simulate, and only the current eligible node is exposed for retry;
5. the provider returns strict `bluefire.ai-proposal.v2` JSON;
6. BlueFire checks provider identity, schema, forbidden fields, request allowlists, registered ownership, exact profile enablement, parameter contracts, retry bounds, and autonomy semantics;
7. policy-permitted Auto mutations apply only in Simulate; actual Assist mutations and every Execute mutation stop at a durable operator gate;
8. acceptance revalidates the immutable run bundle, proposal, registered options, and state/plan/proposal/policy digests, then reconstructs only the accepted registered change;
9. preflight is rerun against the exact scenario, profile, scope, policy, and resolved action plan;
10. Execute acceptance creates a fresh exact one-time approval and performs a fresh-workspace replay from scenario start so prerequisite effects are recreated; the original approval can never be reused;
11. the approved resolution is consumed only at its recorded source-step boundary, while normal graph, policy, adapter, budget, and runner checks remain authoritative;
12. proposal and decision records retain the source digests, policy evaluation, evidence, limits, resolved plan, and continuation lineage.

Application states include `recorded_for_review`, `awaiting_operator_approval`, `accepted_registered_default`, `accepted_registered_next_node`, `applied_registered_alternate`, `applied_typed_parameters`, `applied_registered_action`, `applied_registered_retry`, and explicit rejection/not-applied reasons. Durable reviews have one-time `pending`, `accepted`, or `rejected` states with operator/time metadata.

## Proposal schema

A v2 proposal contains only:

- schema/proposal identity and a closed type: `no_change`, `select_registered`, `select_next_node`, `change_parameters`, `select_registered_action`, `retry_registered`, `request_approval`, or `stop`;
- selected step and behavior IDs constrained by the correlated registered option;
- an optional exact registered edge, optional behavior-owned action ID, or at most 16 named primitive parameter changes, as required by that type;
- rationale, alternatives, confidence, and review requirement.

Recursive forbidden-field checks reject executable concepts such as commands, scripts, payloads, shells, interpreters, binaries, entry points, and arbitrary paths. Parameter changes are limited to booleans, bounded finite numbers/integers, and strings with a closed registered enum; nested values, free-form strings, and list parameters are not exposed. The merged parameters must still validate against the registered behavior contract. Assist proposals must set `requires_operator_review`.

`select_next_node` can select only the exact edge registered for the outcome that actually occurred. The current scenario contract allows at most one edge for each `(from_step, outcome)` pair, so this records and verifies the registered transition; it does not let a model choose across outcomes or invent a branch.

`select_registered_action` is exposed only in Execute and only for actions owned by the selected behavior and enabled, but not blocked, by the exact immutable runner profile. It changes metadata used for deterministic compilation; it does not load code dynamically. `retry_registered` is limited to the current non-cleanup node after `partial`, `blocked`, or `failed`, consumes normal step/time limits, and is capped at one adaptive retry for the entire lineage. Retry attempts keep separate result and evidence records.

## Providers

### Deterministic offline

`deterministic-offline.v1` is the default and test provider. It makes no network call and chooses only from request allowlists. It lets demos/tests exercise proposal records and autonomy semantics without credentials.

### Configured Responses HTTP provider

`openai-responses.v1` is the provider ID in the shipped example configuration. Its implementation sends bounded HTTPS requests (or loopback HTTP) using the OpenAI Responses request/response shape and strict Structured Outputs. It:

- sends no tools and sets tool choice to none;
- disables parallel tool calls;
- requests a strict JSON schema with no additional properties;
- enforces endpoint syntax and forbids embedded credentials/query strings;
- uses a configured timeout and bounded retry count;
- retries only transport/rate-limit/server failures;
- caps response bytes and output tokens;
- rejects incomplete, malformed, over-budget, or schema-invalid output;
- falls back deterministically.

Provider-neutral behavior is defined by the `AIProvider` protocol, but the shipped network implementation is specifically the Responses implementation above. A configurable endpoint does not imply compatibility with arbitrary providers: the endpoint must accept this exact request and return the expected Responses envelope. Offline CI uses an injected deterministic fake transport and does not certify a third-party endpoint.

## Configuration

```yaml
ai:
  autonomy: off
  active_provider: deterministic-offline.v1
  fallback_provider: deterministic-offline.v1
  providers:
    - id: deterministic-offline.v1
      kind: deterministic
      model: deterministic-planner.v1
      timeout_seconds: 1
      max_retries: 0
      max_output_tokens: 800
      redaction:
        enabled: true
        redact_keys: [api_key, authorization, cookie, credential, password, secret, token]
        max_string_chars: 4000
        include_evidence_content: false

    - id: openai-responses.v1
      kind: openai_responses
      model: gpt-4o-mini
      endpoint: https://api.openai.com/v1/responses
      api_key: {env: OPENAI_API_KEY}
      timeout_seconds: 30
      max_retries: 2
      max_output_tokens: 800
      redaction:
        enabled: true
        redact_keys: [api_key, authorization, cookie, credential, password, secret, token]
        max_string_chars: 4000
        include_evidence_content: false
```

The API key value is read from the named environment variable at runtime for readiness checks and request authentication; it is not written to YAML, SQLite, catalog responses, or run bundles. Configuration and the local product-store resource retain the endpoint, model, bounds, redaction policy, and environment-variable reference. Bundle-safe runtime metadata deliberately omits the endpoint and redaction configuration; it exposes provider ID/kind, model, timeout/retry/token bounds, the credential-reference name, readiness/fallback status, proposal-application mode, and trust-boundary label.

Set the secret locally:

```bash
export OPENAI_API_KEY="..."          # Linux/macOS
# Windows PowerShell: $env:OPENAI_API_KEY = "..."
```

Then select autonomy/provider:

```bash
bluefire scenario preview scenarios/ai_adaptive_safe_chain.yaml \
  --autonomy assist \
  --ai-provider openai-responses.v1
```

Use Auto only after the same scenario/provider has been reviewed in Assist and the runner profile is appropriately narrow.

## Redaction and data controls

Redaction replaces values whose keys match configured secret terms, truncates strings, and excludes evidence content by default. The current runtime proposal context contains mode, current step/outcome, completed step IDs/behaviors/statuses, and the deterministic decision—not raw evidence bodies.

If evidence forwarding is enabled in future integrations, classify the data and provider terms before sending it. A redaction list reduces accidental disclosure; it is not a complete data-loss-prevention system.

## Failure and fallback

Credential unavailable, transport failure, timeout, retry exhaustion, invalid content type/JSON, incomplete response, schema mismatch, unregistered selection, or token-budget excess produces a deterministic fallback or explicit rejected proposal record. BlueFire does not silently apply partially parsed model text.

Provider health checks only whether the configured credential reference currently resolves; it does not contact the endpoint or measure model quality. Service startup persists secret-safe provider configuration plus that readiness snapshot in the local product store. The catalog returns bundle-safe runtime metadata and a freshly computed readiness view, without returning the configured endpoint.

## Objective-to-graph drafting

`POST /api/v1/ai/drafts` provides a backend objective-to-graph boundary separate
from the runtime decision loop. It accepts a natural-language objective, an
optional configured provider ID, and caller-selected bounds of at most 16 nodes
and 32 edges. The response is an audit-rich, normalized
`bluefire.scenario.v1` document marked `saved: false`; drafting does not write a
scenario version, create a job, run an action, or grant authority.

The model-facing catalog contains only registered non-metadata behavior IDs,
descriptions, artifact contracts, and safe primitive parameter schemas. It
contains no action IDs, implementation details, capabilities, runner profiles,
scope, approvals, policy, or execution mode. The request-specific strict output
schema lets a provider select only those behavior IDs and exact typed parameter
fields. Recursive checks reject executable fields, authority fields, nested
parameter payloads, and path-like string values.

BlueFire treats the returned graph as an untrusted sketch. It enforces node and
edge bounds, validates references and acyclicity, topologically normalizes the
steps, derives deterministic artifact bindings from registered contracts, and
adds identity, provenance, and limitations outside the provider boundary. The
result must parse through `ScenarioDefinition` and pass the same registry graph
validation as an operator-authored scenario before it is returned.

The deterministic offline provider performs this drafting locally and is the
fallback for unavailable credentials, bounded transport failures, incomplete
responses, or invalid model output. The OpenAI Responses implementation uses
the configured provider endpoint/model and credential environment reference,
requests strict Structured Outputs, disables storage and tools, caps request,
response, and output-token sizes, and never includes the credential in the
result. Offline tests use an injected fake transport; they do not make a real
credential or network call.

## Audit and comparison

Each proposal record retains run/current-step/outcome, autonomy, exact state/plan/proposal/policy digests, deterministic decision ID, correlated registered options, exact allowlists and limits, provider/result metadata, proposal content, policy evaluation, application state/reason, and a registered step when applicable. Durable decision records add job/source identity, operator, timestamp, resolution, fresh Execute approval reference when required, and deterministic continuation lineage. Execute continuation lineage also records the fresh preflight, target-scope, retry-count, full-replay, and resolved-action context used by the new exact approval. Comparison reports provider/autonomy changes, proposal counts, and application-state counts.

## Current limitations

- Runtime behavior, parameter, and action changes are limited to the deterministic successor; a retry is limited to the eligible current node.
- Registered next-node selection cannot choose across outcome branches because `bluefire.scenario.v1` permits only one edge for each source-node/outcome pair.
- Runtime action choice is meaningful only when a behavior has more than one contract-compatible registered action enabled by the exact Execute profile. It never grants new runner authority or loads executable code.
- Adaptive retry is a single lineage-wide retry, not a configurable recovery workflow.
- Runtime AI cannot propose detections or arbitrary replay edits. Objective drafting remains an unsaved, separately validated contract.
- No monetary cost calculation/budget is implemented; output tokens, attempts, response bytes, and time are bounded.
- The Responses HTTP path is tested with deterministic fake transport; a real account/network call requires operator credentials and infrastructure and is not part of offline tests.

These limits keep product claims aligned with the current implementation while preserving a safe path for future expansion.
