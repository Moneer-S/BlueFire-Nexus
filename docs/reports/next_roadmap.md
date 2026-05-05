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

### 2. Per-actor APT adapters
APT28, APT32, APT38, and APT41 currently share a generic actor adapter.
Their hint shapes are identical regardless of which actor or technique
is requested.

**Approach:** Replace the generic adapter with per-actor adapters that
mirror the existing per-technique branching pattern in
`legacy_apt29_research`. Each actor adapter wires actor-specific
tradecraft notes and detection-relevant fields into hints.

### 3. AI provider end-to-end implementation
`OpenAICompatibleProvider` is wired to `ProviderFactory` and recognizes
the major provider names, but the current implementation produces a
structured stub response rather than calling out.

**Approach:** Pick one provider (Ollama is the obvious offline-first
choice; OpenAI-compatible is the obvious BYOK choice) and implement
`complete()` end-to-end. Cover with tests including the offline
fallback path. Avoid multi-provider sprawl until at least one real
backend is solid.

### 4. ExecutionModule logsource
`ExecutionModule` emits a hardcoded `windows` logsource for its
detection hints regardless of host OS. This produces Windows-shaped
Sigma rules even on Linux runs.

**Approach:** Switch logsource on `platform.system()` (or on a
`target_os` param). Backwards-compatible.

### 5. Run reports / risk summary mode badges
`report.md`, `report.json`, and `risk_summary.json` capture per-step
status but do not surface mode/safety state per step. A defender
reading the report has to cross-reference telemetry to see which steps
ran in `simulate` vs `emulate`, which were blocked, and which had
network_touch enabled.

**Approach:** Extend `run_reports.py` to render a per-step "mode badge"
(simulate / emulate / blocked), surface destructive-acknowledgment
state when relevant, and add a "blocked steps" section.

### 6. Scenario ↔ ATT&CK alignment cross-check
A scenario's declared `attack_coverage` is sometimes wider than what
its registered modules actually emit. A small CI gate that compares
declared coverage to emitted MITRE technique IDs would catch drift.

**Approach:** Add a `tests/test_scenario_attack_coverage.py` that loads
each scenario, runs it in dry-run, collects emitted techniques, and
asserts the declared `attack_coverage` is a subset.

### 7. Step-to-step artifact propagation
Scenario steps cannot read artifacts from earlier steps in the same
chain. This is the deepest reason scenarios feel like disconnected
calls rather than coherent adversary chains.

**Approach:** Add a `previous_step_results` mapping to the context
dict, passed to each step's `execute()`. Modules can opt in to read
prior step outputs (e.g. `discovery` results feeding `credential_access`
target selection).

### 8. Future remote-observability story
Out of scope for the local-first baseline. If/when added, would belong
in a separate optional module behind explicit configuration. No remote
SIEM exporters or external collectors today.
