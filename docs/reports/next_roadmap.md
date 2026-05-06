# BlueFire Nexus roadmap

Public roadmap for the framework. Companion to
[capability_inventory.md](capability_inventory.md). Each item names a
goal and the suggested approach. Priorities are kept stable so that
contributors can pick up a focused workstream without coordination.

The lens is high-fidelity adversary emulation paired with local
defensive validation: realistic adversary chains, actor-inspired packs,
C2/protocol research, stealth/evasion modeling, exfiltration, AI-assisted
planning, local telemetry/detections/reports, and gated lab behaviour.
Recommendations preserve offensive realism — the common pattern is
"wire dormant offensive-research code into the standard module layer
under the same safety gates that already work for the legacy capability
adapters."

## Done

The following gaps have been closed and are kept here for context.

- **Missing ATT&CK tactic modules.** Standard modules now exist for
  `credential_access`, `lateral_movement`, `privilege_escalation`,
  `impact`, and `collection`. Each uses a per-input profile catalog
  mapping operator-facing values to MITRE sub-techniques, logsources,
  and detection-selection fields. Combined: 46 distinct techniques
  mapped to MITRE.
- **Per-input fan-out for placeholder modules.** `command_control`,
  `persistence`, `defense_evasion`, `network_obfuscator`,
  `intelligence`, `reconnaissance`, and `resource_development` now
  fan out telemetry, ATT&CK techniques, logsources, and detection
  selections per input. Backwards-compat preserved for default inputs.
- **Mutation engine reachable from CLI.** `python -m src.run_scenario --mutate <strategy>`
  is wired and recorded in the run summary. Strategies: `low_noise`,
  `evasion-lite`, `protocol_shift`, `protocol-shift`.
- **ExecutionModule logsource is platform-aware.** The `ExecutionModule`
  switches its detection-hint logsource on `platform.system()` and the
  optional `target_os` param. Linux runs no longer produce
  Windows-shaped Sigma rules.
- **Run report / risk summary per-step mode badges.** `report.md`,
  `report.json`, and `risk_summary.json` now surface a per-step
  `mode` badge (simulate / emulate / dry-run / real-execution),
  destructive-acknowledgment state, network_touch state, and an
  explicit "Blocked Steps" section.
- **Scenario ↔ ATT&CK alignment cross-check.**
  `tests/test_scenario_attack_coverage.py` enforces two CI-grade gates
  on every scenario: (1) declared `attack_coverage` is a subset of the
  union of `attack_techniques` exposed by the modules each step
  invokes; (2) declared coverage is satisfied by techniques actually
  emitted at runtime (parent-of-subtechnique still satisfies the
  parent). Includes a registry-presence check.
- **Per-actor APT adapters.** `legacy_apt28_research`,
  `legacy_apt32_research`, `legacy_apt38_research`, and
  `legacy_apt41_research` are now concrete subclasses of the generic
  adapter. Each emits an actor-specific `attack_techniques` surface,
  refined `tactic -> MITRE` mapping (e.g. APT32 execution -> T1059.005,
  APT28 -> T1059.001), a stable `actor_signature`, an `aka` (alias)
  list, and a tactic-aware Sigma logsource so generated detection
  drafts carry per-actor correlation fields. APT29 keeps its existing
  per-technique branches and now also surfaces `actor_signature` and
  `aka` in selection.
- **Per-step ATT&CK coverage map in run reports.** `report.md` now
  renders a `## ATT&CK Technique Coverage` section that maps each
  emitted technique to the `module:step_id` results that produced it,
  so defenders can read the coverage without parsing `report.json`.
- **Scenario field in `risk_summary.json`.** When the runner passes a
  scenario name, `risk_summary.json` includes a `scenario` field so
  downstream consumers can identify the scenario without reading the
  `run_id` directory layout.
- **Tactic-pack legacy adapters.** The preserved per-tactic legacy
  classes under `src/core/credential/`, `src/core/movement/`,
  `src/core/privilege/`, `src/core/impact/`, and `src/core/collection/`
  are now reachable through five explicit, gated adapter modules:
  `legacy_credential_access`, `legacy_lateral_movement`,
  `legacy_privilege_escalation`, `legacy_impact`, and
  `legacy_collection`. Each sits behind a new `tactic_pack` /
  `<tactic>` capability and uses the same `evaluate_legacy_capability`
  + `_ensure_allowed` + `safe_call` pattern the actor / C2 / stealth
  adapters already use. Standard tactic modules remain simulate-only
  and unchanged in their safety/mode model. Scenarios that want the
  legacy behaviour must explicitly say `module: legacy_<tactic>` —
  there is no implicit routing or `emulate_via_legacy` flag.
- **Direct `_handle_*` dispatch in tactic_pack helpers.** Earlier
  versions of the `run_<tactic>(...)` helpers fed payloads through the
  legacy class's staged-pipeline entrypoint, which silently dropped
  techniques meant for the second or third dispatch stage and let
  `service_creation` / `token_creation` collide on the same data key.
  Helpers now dispatch directly to `_handle_<method>` so every
  advertised technique returns rich, technique-specific details and
  the token/service collision is resolved.
- **Cross-adapter consistency tests + lateral_movement MITRE
  normalisation.** A new test set pins five structural invariants
  across the entire `tactic_pack` family (every dispatch entry has a
  handler, every emitted MITRE id is advertised, every advertised
  MITRE id is reachable, every dispatch entry has tradecraft notes,
  no orphan notes). `legacy_lateral_movement` now emits T1570
  (Lateral Tool Transfer) for FTP/SCP transfers — matching the
  standard module's MITRE convention — instead of the legacy class's
  internal T1105. A new `ssh` dispatch entry advertises T1021.004.
  The deprecated T1145 emitted by the SSH-keys handler is normalised
  to the modern T1552.004 in adapter output, with the legacy id
  preserved under `legacy_mitre_technique_id` for traceability.
- **Step-to-step artifact propagation.** The runtime now threads a
  read-only `previous_step_results` mapping into every step's
  context. Built incrementally as the scenario runs; carries
  `{step_id: {status, module, techniques, artifacts}}` for upstream
  steps (errored steps included). Modules opt in by reading
  `context["previous_step_results"]` — the runtime never auto-injects
  values into params. No new artifact-path surface, no safety/mode
  model change.
- **Enterprise intrusion kill-chain scenario.** A new shipped
  scenario (`scenarios/enterprise_intrusion_chain.yaml`) chains 12
  standard modules end-to-end (`resource_development` →
  `reconnaissance` → `initial_access` → `execution` →
  `defense_evasion` → `discovery` → `credential_access` →
  `lateral_movement` → `collection` → `command_control` →
  `exfiltration` → `impact`) with explicit tradecraft expectations
  and blue-team guidance. Realistic purple-team validation harness;
  all steps simulate-only.
- **Test isolation + artifact-path performance.** The runtime output
  root is now resolved through a three-layer precedence
  (config / env var / default `output`), so tests automatically
  scope nexus runs to a session tmp dir. The artifact-path test
  was restructured to a session-scope canary plus per-test artifact-
  string validation, dropping wallclock from ~12 min to ~13s while
  preserving the discipline.

## Open items

### 1. AI provider end-to-end implementation
`OpenAICompatibleProvider` is wired to `ProviderFactory` and recognizes
the major provider names, but the current implementation produces a
structured stub response rather than calling out.

**Approach:** Pick one provider (Ollama is the obvious offline-first
choice; OpenAI-compatible is the obvious BYOK choice) and implement
`complete()` end-to-end. Cover with tests including the offline
fallback path. Avoid multi-provider sprawl until at least one real
backend is solid.

### 2. Future remote-observability story
Out of scope for the local-first baseline. If/when added, would belong
in a separate optional module behind explicit configuration. No remote
SIEM exporters or external collectors today.
