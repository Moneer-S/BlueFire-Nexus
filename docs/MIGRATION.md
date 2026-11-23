# Migration from historical Python modules

The maintained product is the bluefire package plus the separately built runner crate. Superseded Python modules, identity-oriented scenarios, compatibility configuration, and generated reports are retired from the working tree and remain available only through Git history.

This is an architectural migration, not an import-path rename.

## Concept mapping

| Historical concept | Maintained replacement |
|---|---|
| Tactic-level Python module with execute method | Neutral BehaviorDefinition plus optional simulation ID and reviewed action IDs |
| Advisory module input/output metadata | Enforced ArtifactSpec and ArtifactBinding contracts |
| Sequential scenario steps | Validated DAG with explicit outcome edges |
| dry_run, emulate, live-lab, and pack toggles | Exactly Simulate or Execute plus an explicit RunnerProfile |
| Python subprocess/network/filesystem behavior | Fixed Rust action selected by stable action ID |
| Actor pack or actor-named wrapper | Neutral technique metadata or no migration |
| Implicit Python entry-point plugin | Declarative PluginManifest inventory |
| Free-form AI plan text | Strict AIProposal allowlisted by the deterministic planner |
| Synthetic telemetry reported as success | EvidenceRecord with explicit synthetic provenance |
| Generated detection files counted as validation | DetectionCandidate lifecycle with distinct exercise states |
| Mutable output directory | Contained RunStore bundle plus migrated SQLite ProductStore metadata/index |

## What may be migrated

Useful source material can be transcribed into neutral, reviewed contracts:

- technique mappings and purpose statements;
- typed parameters with bounded enums and ranges;
- platform prerequisites;
- typed inputs and outputs;
- expected observables and detection hypotheses;
- cleanup requirements and known limitations;
- public source and license provenance;
- deterministic tests and parsers that do not perform effects.

Record derivation honestly in SourceProvenance. Do not describe inherited metadata as newly observed or independently validated.

## What must not be restored into Python

Do not copy or re-enable:

- subprocess, shell, script, payload, interpreter, or arbitrary command interfaces;
- direct network, persistence, credential, lateral-movement, evasion, or destructive handlers;
- actor branding used as a behavior identity;
- random or unconditional success results;
- default targets, credentials, host paths, or external endpoints;
- implicit dynamic imports or Python entry-point execution;
- compatibility aliases that recreate a third mode;
- status normalization that converts refusal, partial, timeout, or cleanup failure into success.

If a real effect remains useful, design a new narrow Rust action. Give it a stable versioned ID, strict executor schema, capabilities, tier, scope, budgets, cleanup semantics, evidence contract, and boundary tests. Add a hard-coded RunnerActionAdapter translation only after both logical and executor contracts are reviewed.

## Scenario migration

For each scenario:

1. replace actor or campaign identity with a neutral research objective;
2. select registered behaviors only;
3. define every typed artifact binding;
4. add explicit success, partial, blocked, and failed routes where continuation is meaningful;
5. ensure every input producer dominates its consumer;
6. mark compatible alternates explicitly;
7. add cleanup to every branch that can create runner-owned artifacts;
8. record provenance and limitations;
9. validate in Simulate before considering an Execute profile.

An old scenario filename or successful historical dry run is not evidence that the migrated graph is safe or executable.

## Configuration migration

Start from config/bluefire.example.yaml rather than translating old keys automatically.

- Choose Simulate unless Execute is specifically required.
- Choose AI autonomy independently from mode: `off`, `assist`, or `auto`; configure a deterministic fallback and secret-safe provider references.
- Store runner binary, sandbox root, and secret names as environment references.
- Do not add a network unless the new action and authorization require it. The canonical example is loopback only.
- Define enabled and blocked actions explicitly.
- Grant only required capabilities and safety tiers.
- Set positive budgets and a cleanup policy.
- Require approval for Execute.

There is intentionally no compatibility resolver for dry_run, emulate, live-lab, actor packs, or global legacy toggles.

The legacy `ai_enabled` request alias is accepted only for v1 callers: false maps to Off and true maps to Assist, never Auto. Do not persist it in new configuration or send it together with `autonomy`.

## Completion criteria

A migrated capability is complete only when:

- schema parsing rejects unknown fields;
- catalog, adapter, and runner inventory agree on action identity and capability semantics;
- logical and executor parameter interfaces are linked by one explicit adapter;
- scenario graph and typed propagation validate;
- Simulate provenance is honest;
- Execute refusal paths, approval binding, scope, budgets, and cleanup are tested;
- runner result normalization preserves every non-success status;
- observed evidence, when claimed, comes from an independent observer;
- detection maturity is reported by lifecycle state;
- the built wheel contains no historical package.
