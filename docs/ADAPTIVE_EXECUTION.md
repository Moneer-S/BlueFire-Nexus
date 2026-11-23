# Reviewed adaptive execution contract

An experiment may explicitly declare a finite set of compatible methods. The
declaration is part of the saved scenario; it is not an approval or executable
model output. Omitting it preserves legacy exact-plan approval semantics and
serialization. Explicit `null`, unknown fields, and expanded limits are rejected.

The legacy contract is `bluefire.adaptive-execution.v1`:

```json
{
  "schema_version": "bluefire.adaptive-execution.v1",
  "steps": [{
    "step_id": "discover_records",
    "methods": [
      {"behavior_id": "sandbox.discovery.list.v1", "action_id": "sandbox.discovery.list.v1"},
      {"behavior_id": "sandbox.discovery.metadata.v1", "action_id": "sandbox.discovery.metadata.v1"}
    ]
  }],
  "eligible_outcomes": ["blocked", "failed", "partial"],
  "max_retries": 1,
  "on_provider_failure": "stop"
}
```

Each of 1–64 designated steps has 2–4 distinct exact behavior/action pairs. A
behavior must be that step's primary or an authored compatible alternate; the
action must belong to that behavior and be enabled for the exact profile and
platform. The saved primary method must appear explicitly. No other catalog
method becomes permitted merely because it is available. Outcomes are a
nonempty subset of `blocked`, `failed`, and `partial`. One retry is the maximum
for the run lineage, not one retry per method. `deterministic` is the only other
provider-failure policy and must be labeled as fallback, not live-model success.

An operator may explicitly opt into `bluefire.adaptive-execution.v2` when
authoring or editing a scenario. It retains the same fields and exact method
choices, adds `max_retries` to each selected step, and uses the root
`max_retries` for the experiment-wide lineage cap. The root cap is 1–8; every
step cap is 1–3 and cannot exceed the number of distinct alternatives after its
initial method; the root cap cannot exceed the sum of the step caps. A retry is
one additional method after the initial method. Existing v1 documents keep
their v1 serialization and one-retry semantics until an operator explicitly
chooses the v2 budget option. `bluefire.adaptive-authorization.v2` binds the
same reviewed operation details as v1 together with the explicit v2 policy.

For example, a two-retry experiment can allocate both retries to one step with
three distinct methods:

```json
{
  "schema_version": "bluefire.adaptive-execution.v2",
  "steps": [{
    "step_id": "stage",
    "methods": [
      {"behavior_id": "sandbox.collection.atomic-gzip.v1", "action_id": "sandbox.collection.atomic-gzip.v1"},
      {"behavior_id": "sandbox.collection.records.v1", "action_id": "sandbox.collection.records.v1"},
      {"behavior_id": "sandbox.collection.archive.v1", "action_id": "sandbox.collection.archive.v1"}
    ],
    "max_retries": 2
  }],
  "eligible_outcomes": ["blocked", "failed", "partial"],
  "max_retries": 2,
  "on_provider_failure": "stop"
}
```

The step cap cannot exceed its two alternatives; the experiment cap cannot
exceed the sum of all designated step caps.
For v2, a finite-method proposal is available only at an authored adaptive step
after an eligible outcome. Other steps and noneligible outcomes continue along
the deterministic graph without calling the generic legacy Execute proposal
path. V1 and Simulate retain their existing decision behavior.

`compile_adaptive_authorization` resolves these pairs using the current registry
and planner. Its `bluefire.adaptive-authorization.v1` or
`bluefire.adaptive-authorization.v2` result follows the selected policy version
and retains the declared objective, scenario and plan digests, profile, platform,
target scope, catalog identity, exact parameter policy, resource limits, cleanup
policy, and method choices. Mutating methods require enabled cleanup and the
`always` policy.

Each `steps[*].methods[*]` contains:

- `plan_step`: a complete `PlanStep.to_dict()` with exact resolved parameters,
  artifact input bindings, expected outputs, action and execution binding;
- `plan_step_digest`, `behavior_contract_digest`, `action_contract_digest`, and
  `execution_binding_digest`;
- the capability union, mutation flag, cleanup action and cleanup contract digest.

The whole document's `authorization_digest` is bound into the one-time Execute
approval by `execution_approval_binding(adaptive_authorization=...)`. An opted-in
scenario without this resolved review document cannot obtain that binding.
Legacy scenarios cannot be given an adaptive document to acquire new authority.

`validate_selected_method` requires the trusted approval-bound digest, checks the
current profile/target/platform/catalog/contracts, remaining resources and
approval expiry, and returns an exactly matching reviewed choice. A changed
parameter, input, method or execution binding is not a match. Set `is_retry=True`
when admitting a new retry using counts before reservation; rechecks after
reservation use `False`. The coordinator must durably reserve v2 attempts and
enforce eligible outcomes before dispatch. A reservation consumes both the
lineage and step allowance before effects. Its
`bluefire.adaptive-retry-budget.v2` ledger carries the policy digest, per-step
counts, reservations and attempted method identities into approved Assist
continuations and replay. A method already attempted or reserved in that
lineage is excluded. A new independently saved experiment starts with a fresh
ledger. Reservations are not runner results: only a matching recorded step can
establish that an operation was attempted, and neither a reservation nor a
runner result establishes objective success. A digest supplied by the candidate
document or model is not the trusted expected digest.

These helpers do not grant authority, execute, choose routes, or resume effects.
Runtime integration must keep normal policy, adapter, runner, expiry and cleanup
checks; it must persist proposal, decision and attempted operation separately.
Parameter mutation remains outside this version's adaptive authority. Cancellation
and interruption recovery cannot turn the review document into a new approval.
