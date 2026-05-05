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

## Open items

### 1. Emulate-mode bridges for the new tactic modules
The five recently-added standard modules (`credential_access`,
`lateral_movement`, `privilege_escalation`, `impact`, `collection`) are
simulate-only. Each has a substantial legacy implementation under
`src/core/<tactic>/*.py` (~5,400 lines combined) that is preserved but
not yet invoked.

**Approach:** For each tactic, add an emulate-mode path that calls the
legacy class through the same `safe_call` + `_ensure_allowed` pattern
the existing legacy adapters use. Gate behind explicit
`lab_confirmation`. One focused PR per tactic.

### 2. AI provider end-to-end implementation
`OpenAICompatibleProvider` is wired to `ProviderFactory` and recognizes
the major provider names, but the current implementation produces a
structured stub response rather than calling out.

**Approach:** Pick one provider (Ollama is the obvious offline-first
choice; OpenAI-compatible is the obvious BYOK choice) and implement
`complete()` end-to-end. Cover with tests including the offline
fallback path. Avoid multi-provider sprawl until at least one real
backend is solid.

### 3. Step-to-step artifact propagation
Scenario steps cannot read artifacts from earlier steps in the same
chain. This is the deepest reason scenarios feel like disconnected
calls rather than coherent adversary chains.

**Approach:** Add a `previous_step_results` mapping to the context
dict, passed to each step's `execute()`. Modules can opt in to read
prior step outputs (e.g. `discovery` results feeding `credential_access`
target selection).

### 4. Future remote-observability story
Out of scope for the local-first baseline. If/when added, would belong
in a separate optional module behind explicit configuration. No remote
SIEM exporters or external collectors today.
