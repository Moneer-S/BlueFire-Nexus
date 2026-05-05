# BlueFire-Nexus next roadmap

Companion to [capability_inventory.md](capability_inventory.md). Identifies the
top functionality gaps preventing the framework from feeling like a coherent
high-fidelity adversary-emulation platform, and ranks them by impact.

The lens is the user's stated value prop: realistic adversary chains, actor-
inspired packs, C2/protocol research, stealth/evasion, exfil, AI-assisted
planning, local telemetry/detections/reports, gated lab behaviour. NOT a
generic BAS simulator. Recommendations preserve offensive realism — the
common pattern is "wire dormant legacy code into the standard registry under
the same safety gates that already work for `legacy_protocol_research` and
`legacy_stealth_research`."

## Top 10 functionality gaps (ranked)

### 1. Five ATT&CK tactics have no registered standard module
**Missing:** `credential_access`, `lateral_movement`, `privilege_escalation`, `impact`, `collection`. All five have substantial legacy implementations (~5,400 lines combined) but no registry entry, so scenarios cannot reference them.

**Why it matters most:** The single biggest gap between BlueFire's positioning ("high-fidelity adversary emulation") and what its scenarios can actually express. `apt29_credential_access` is named for credential access but routes its third step through `anti_detection` because no `credential_access` module exists.

**Suggested approach:** Add 5 new standard modules of similar shape to the existing toys, then wire them as thin adapters around the legacy implementations behind the same `simulate` / `emulate` gating that legacy_protocol_research and legacy_stealth_research already use. One focused PR per module.

### 2. Standard modules are mostly placeholders despite rich legacy code existing
**Examples:** `discovery` returns `[{"target": ..., "status": "simulated_up"}]` but `src/core/discovery/discovery.py` (~1,100 lines) has real Nmap-backed host/port/service scan, system/process/service info, user/group/privilege enumeration with proper psutil + pwd/grp handling. Same pattern for `execution`, `persistence`, `defense_evasion`, `network_obfuscator`, `command_control`, `exfiltration`, `intelligence`, `reconnaissance`, `resource_development`.

**Why it matters:** When a user runs `apt29_credential_access`, the run produces telemetry that doesn't reflect any of the rich detection-relevant data the legacy implementations could produce.

**Suggested approach:** For each "low-fidelity placeholder" module, add a simulate-mode bridge that synthesises telemetry from the legacy class WITHOUT invoking real side effects, plus an emulate-mode path that calls the legacy class through the same `safe_call` + `_ensure_allowed` pattern legacy adapters already use. Big payoff per PR; do not do all 10 in one PR.

### 3. Detection hint shape doesn't fan out by input
Most standard modules emit a single hardcoded detection hint regardless of the input parameters. `command_control` emits the same hint whether channel is `http`, `dns`, `quic`, or `solana_rpc`. `persistence` emits the same hint for `scheduled_task` vs `registry_run_key` vs `service`. `defense_evasion` emits the same hint regardless of `technique` value.

**Why it matters:** Detection drafts are one of BlueFire's three local artifact pillars (telemetry, reports, detections). Hardcoded hints produce hardcoded detections.

**Suggested approach:** Per module, add a small mapping `input_value → {logsource, selection, mitre_technique}` and switch the hint accordingly. The pattern already works in `legacy_protocol_research` and `legacy_stealth_research` — copy that style. No new architecture needed.

### 4. APT actor packs (apt28, apt32, apt38, apt41) share one generic adapter
All four are dynamically generated `type(...)` of `LegacyGenericActorTechniqueModule`. They emit identical hint shapes (`logsource: threat_intelligence/generic`) regardless of which actor or technique is requested. APT41's supply-chain tradecraft and APT28's spearphishing should produce visibly different hints; today they don't.

**Why it matters:** Actor flavor is core to the value prop. If the only difference between "APT28 powershell" and "APT41 c2" is a string label in the artifact, the actor packs are theatre.

**Suggested approach:** Replace the generic adapter with per-actor adapters that mirror the `LegacyApt29ResearchModule` per-technique branching pattern. Each actor adapter wires actor-specific tradecraft notes and detection-relevant fields into hints. The dynamically-generated modules also report `__module__ == 'abc'`, which is a small ergonomic issue.

### 5. AI copilot is fully scaffolded but provider implementation is intentionally inert
`AICopilot.plan/narrate/suggest_detections` are wired and write artifacts to the run directory. The `OpenAICompatibleProvider.complete()` method explicitly returns a stub message and does not call any provider — even when an API key is configured. The fallback `TemplateProvider` returns a deterministic string. So the AI artifacts (`copilot_plan.txt`, `copilot_narrative.md`, `copilot_detections.md`) are produced for every run, but they contain no model-generated content even when a provider is named in `config.modules.ai`.

**Why it matters:** Either the AI layer is part of the value prop or it isn't. As shipped, it is overhead with no payoff.

**Suggested approach:** Two non-mutually-exclusive options. (a) **Make AI optional and silent.** When provider is `template`/`none` or there's no API key, skip writing copilot artifacts entirely so the run is genuinely AI-free. (b) **Implement a single real provider end-to-end** (Ollama is the obvious offline-first choice; OpenAI-compatible is the obvious BYOK choice). Cover with small tests including the offline fallback path. Do NOT add multi-provider complexity until at least one real path actually works.

### 6. ExecutionModule logsource is hardcoded `windows`
`logsource = {"category": "process_creation", "product": "windows"}` regardless of host OS. On Linux runs, this generates Windows-shaped Sigma rules.

**Why it matters:** Detection drafts that don't match the OS the operator is emulating against are misleading.

**Suggested approach:** Switch logsource on `platform.system()` (or on a `target_os` param). Easy fix; could ride with the next ExecutionModule pass.

### 7. Scenarios use undeclared parameters silently
- `insider_exfil_dns` step `discovery` passes `discovery_type: files` and `network_touch: true` — `DiscoveryModule.execute()` ignores both.
- `apt29_credential_access` exfil step passes `targets: [10.0.0.15]` — `ExfiltrationModule.execute()` ignores it (it reads `method` only).
- Most scenarios pass `network_touch` to multiple steps — no module reads it.

**Why it matters:** Scenario authors get the impression they're configuring behaviour when they aren't. Silent ignore = misleading docs.

**Suggested approach:** Either consume the parameters and shape telemetry/hints around them, or have `BaseModule.validate()` warn (not fail) on unknown keys. Probably both: standardize a tiny set of universally-honored params (`network_touch`, `target_os`, `target_user`) and update each module to read them.

### 8. Several scenarios have weak ATT&CK ↔ module alignment
- `apt29_credential_access` declares T1555 in `attack_coverage` but no module emits T1555 telemetry (no credential_access module exists).
- `healthcare_ransomware` declares T1486 (data encrypted for impact) implicitly via "ransomware" in the name but uses no impact module (no impact module exists either).
- `legacy_actor_apt29` declares ATT&CK coverage that's actually only met by the techniques the apt29 adapter knows about (4 techniques).

**Why it matters:** ATT&CK coverage tags should match what the run actually emits.

**Suggested approach:** After (1) lands (5 missing modules), refresh scenarios to use the new modules. For now, add a scenario-validation report sub-step that compares declared `attack_coverage` to telemetry MITRE techniques and flags mismatches.

### 9. Run reports / risk summary don't surface mode/safety state per step
The artifacts produced today (`report.md`, `report.json`, `risk_summary.json`) capture per-step status but don't prominently surface "this step ran in `simulate` mode," "this step would have been blocked but lab confirmation was given," or "no detection hints were emitted for this step." A purple-team operator reading the report has to cross-reference telemetry to figure out what was real vs synthesised.

**Why it matters:** Reports are the primary deliverable to a defender consumer. They should be self-explanatory.

**Suggested approach:** Extend `run_reports.py` to render a per-step "mode badge" and a "real side-effects" indicator. Add a "blocked steps" section. Cheap; no behaviour change required.

### 10. AI mutation engine is decoupled from scenario runs
`mutate_step_params`, `mutate_steps`, `mutate_technique` exist (`src/core/ai/mutation.py`) and are tested (`tests/test_mutation.py`) but they aren't called from `run_scenario` or any standard CLI command. There's a `--legacy-guided` and `--legacy-preset` on `run_scenario`, but no `--mutate` or `--variant`.

**Why it matters:** Mutation/variant generation is in the value prop. If it isn't reachable from the operator path, it doesn't count.

**Suggested approach:** Add `--mutate <strategy>` to `run_scenario` that applies `mutate_step_params` to each step's params before dispatch. Gate behind explicit opt-in (mutation already requires `allowed=True`). Cover with a test.

## Workstream sequencing recommendation

If the goal is "highest impact per focused PR," the order I'd run:

1. **Discovery quality pass** (this cycle, see Priority 6 below). Establishes the per-input-fan-out pattern + telemetry-from-legacy bridge approach for one module, with tests, in a contained PR. This is the template.
2. **Add `credential_access` standard module** wired to the legacy class through the simulate/emulate pattern. Update `apt29_credential_access` scenario to use it.
3. **Add `lateral_movement` standard module** with the same pattern. Update relevant scenarios.
4. Repeat for `privilege_escalation`, `collection`, `impact` (one PR each).
5. **Per-actor APT adapters** to replace the generic dynamic adapter.
6. **Detection-hint fan-out pass** across all standard modules.
7. **AI copilot decision**: implement Ollama path or make copilot opt-in.
8. **Reports/risk summary mode-badge enhancement.**
9. **Mutation engine wiring into `run_scenario --mutate`.**

Each item is one focused PR. The first ~6 should land within a week of focused work; the last ~3 are larger and need their own scoping.
