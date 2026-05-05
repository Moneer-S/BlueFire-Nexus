# BlueFire-Nexus capability inventory

Snapshot taken at `main` = `c0b0669` (post Phase-9 squash + post-PR-#4 hardening).
21 modules registered via `build_runtime_modules()`: 12 standard + 9 legacy adapters.

## Conventions

- **Mode behaviour** — `dry_run` (no real side effects, telemetry synthesised), `simulate` (legacy adapter local synth path), `emulate` (legacy adapter live runtime via `safe_call(...)`, gated by lab confirmation).
- **Side-effect gates** — what must be true before any real side-effect path runs.
- **Artifacts** — keys present in `ModuleResult.artifacts`.
- **Telemetry** — events emitted in `ModuleResult.telemetry`.
- **Detection hints** — keys present in `ModuleResult.detection_hints`.
- **Tests** — files in `tests/` covering this module (not counting registry-wide contract/safety/artifact tests, which cover all 21 by construction).

## 12 Standard modules

### `initial_access` (T1566)
- **Source:** [src/core/modules/impl/standard_modules.py:37](src/core/modules/impl/standard_modules.py:37) (`InitialAccessModule`)
- **Mode behaviour:** simulate-only — emits telemetry shape with `vector` + `target` regardless of `dry_run`.
- **Side-effect gates:** none required (no real side effects in code path).
- **Artifacts:** `{target, vector}`
- **Telemetry:** `initial_access_simulated`
- **Detection hints:** `title, logsource(email/generic), detection.selection, condition, mitre_technique`
- **Scenarios:** `apt29_credential_access`, `fin7_initial_access_to_c2`, `healthcare_ransomware`
- **Tests:** registry-wide only. No module-specific test.
- **Gaps:** no per-vector fan-out (phishing_email vs spearphishing_attachment vs drive-by). No artifact paths written. Doesn't enrich from a vector → tactic catalog.

### `execution` (T1059)
- **Source:** [src/core/modules/impl/standard_modules.py:69](src/core/modules/impl/standard_modules.py:69) (`ExecutionModule`)
- **Mode behaviour:** real `subprocess.run` ONLY when `dry_run=False` AND `allow_real_execution=True`. Otherwise emits dry-run telemetry shape.
- **Side-effect gates:** `context["dry_run"]` AND `module.config["allow_real_execution"]`.
- **Artifacts:** `{command, stdout, return_code}`
- **Telemetry:** `execution` event with `command, return_code, timestamp`
- **Detection hints:** title, logsource(process_creation/windows), detection, condition, mitre_technique, process_command_line.
- **Scenarios:** `apt29_credential_access`, `fin7_initial_access_to_c2`, `healthcare_ransomware`
- **Tests:** registry-wide. The legacy `linux_execution.py`/`windows_execution.py` per-OS adapters are referenced from `Execution` class in `src/core/execution/execution.py` but **not wired into the standard `ExecutionModule`** — so the rich per-OS handlers, lab-staging, and shell management code is dormant from the orchestrator's perspective.
- **Gaps:** stdout truncated at 4096 bytes silently. Logsource hardcoded to `windows` even on Linux runs. No timeout escalation strategy. Per-OS adapters not wired up.

### `persistence` (T1053)
- **Source:** [src/core/modules/impl/standard_modules.py:136](src/core/modules/impl/standard_modules.py:136) (`PersistenceModule`)
- **Mode behaviour:** simulate only.
- **Side-effect gates:** none.
- **Artifacts:** `{technique}`
- **Telemetry:** `persistence_simulated`
- **Detection hints:** title, logsource(process_creation/windows), detection, condition, mitre_technique=T1053.
- **Scenarios:** `healthcare_ransomware`
- **Tests:** registry-wide.
- **Gaps:** Hardcoded MITRE T1053; doesn't switch hint by technique (e.g., `registry_key` vs `scheduled_task` vs `service` vs `wmi`). The rich `src/core/persistence/{linux,macos,windows}_persistence.py` legacy code is **not wired in**. No scenario coverage for non-`scheduled_task` techniques.

### `defense_evasion` (T1036, T1070.006)
- **Source:** [src/core/modules/impl/standard_modules.py:167](src/core/modules/impl/standard_modules.py:167) (`DefenseEvasionModule`)
- **Mode behaviour:** simulate only.
- **Artifacts:** `{technique}`
- **Telemetry:** `defense_evasion_simulated`
- **Detection hints:** title, logsource(process_creation/linux), detection, mitre=T1036 (only — second declared technique T1070.006 not used in hints).
- **Scenarios:** none directly; legacy variants exercised via `legacy_apt29_research`, `legacy_stealth_research`.
- **Tests:** registry-wide.
- **Gaps:** Hint MITRE id hardcoded to T1036; ignores `attack_techniques` class attribute. No fan-out across technique values. Rich `src/core/defense_evasion/*` per-OS legacy code not wired in.

### `discovery` (T1046)
- **Source:** [src/core/modules/impl/standard_modules.py:195](src/core/modules/impl/standard_modules.py:195) (`DiscoveryModule`)
- **Mode behaviour:** simulate only.
- **Artifacts:** `{targets, discovered:[{target,status:'simulated_up'}, ...]}`
- **Telemetry:** `discovery` event with `targets, discovered_count`
- **Detection hints:** title, logsource(network_connection/linux), detection, mitre=T1046, network_targets.
- **Scenarios:** `insider_exfil_dns`
- **Tests:** registry-wide. Legacy `src/core/discovery/discovery.py` (~1100 lines) has its own contract test (`test_execution_coherence.py`) and now imports cleanly on Windows via the Phase 6 `grp` guard.
- **Gaps:** Standard `DiscoveryModule` does not invoke the legacy `Discovery` class. Targets fall back to `context["allowed_subnets"]` which is fine but undocumented. No discovery-type fan-out (`files`, `processes`, `services`, `network_scan`) — the scenario `insider_exfil_dns` passes `discovery_type: files` but it is silently ignored.

### `command_control` (T1071.001)
- **Source:** [src/core/modules/impl/standard_modules.py:265](src/core/modules/impl/standard_modules.py:265) (`CommandControlModule`)
- **Mode behaviour:** simulate only.
- **Artifacts:** `{channel, c2_url}`
- **Telemetry:** `c2_beacon_simulated`
- **Detection hints:** title, logsource(network_connection/windows), detection (network.url|contains), mitre=T1071.001, network_url.
- **Scenarios:** `fin7_initial_access_to_c2`
- **Tests:** registry-wide + `test_command_control_adapter.py`
- **Gaps:** Doesn't validate `c2_url` against allowed lab domains. The rich `src/core/command_control/command_control.py` legacy module (520 lines, real Flask mock C2 server) is **not wired in**. Channel value (`http`, `dns`, `quic`, etc.) doesn't change hint/telemetry shape.

### `anti_detection` (T1027)
- **Source:** [src/core/modules/impl/standard_modules.py:295](src/core/modules/impl/standard_modules.py:295) (`AntiDetectionModule`)
- **Mode behaviour:** simulate only.
- **Artifacts:** `{method}`
- **Telemetry:** `anti_detection_simulated`
- **Detection hints:** title, logsource(process_creation/linux), detection, mitre=T1027.
- **Scenarios:** `apt29_credential_access`
- **Tests:** registry-wide.
- **Gaps:** Single shape regardless of `method`. The legacy `src/core/anti_detection/manager_impl.py` (now lazy via Phase-7) is invoked only by the legacy stealth adapter, not the standard module.

### `intelligence` (T1595)
- **Source:** [src/core/modules/impl/standard_modules.py:323](src/core/modules/impl/standard_modules.py:323) (`IntelligenceModule`)
- **Mode behaviour:** simulate only.
- **Artifacts:** `{focus, confidence:'medium'}` (confidence is hardcoded)
- **Telemetry:** `intelligence_collection_simulated`
- **Detection hints:** title, logsource(threat_intelligence/generic), detection, condition, mitre=T1595 (added in Phase 8).
- **Scenarios:** none currently.
- **Tests:** registry-wide.
- **Gaps:** No real intel input. Confidence hardcoded. No relationship to actor packs. The rich `src/core/intelligence/{apt28_intelligence,apt_intelligence}.py` files are **not wired in**.

### `network_obfuscator` (T1572)
- **Source:** [src/core/modules/impl/standard_modules.py:351](src/core/modules/impl/standard_modules.py:351) (`NetworkObfuscatorModule`)
- **Mode behaviour:** simulate only.
- **Artifacts:** `{protocol}`
- **Telemetry:** `network_obfuscation_simulated`
- **Detection hints:** title, logsource, detection, mitre=T1572, network_protocol (Phase 8 normalization).
- **Scenarios:** `insider_exfil_dns`
- **Tests:** registry-wide.
- **Gaps:** No protocol-specific shape. The legacy `src/core/network/network_obfuscator.py` (~600 lines) is **not wired in**.

### `resource_development` (T1583)
- **Source:** [src/core/modules/impl/standard_modules.py:373](src/core/modules/impl/standard_modules.py:373) (`ResourceDevelopmentModule`)
- **Mode behaviour:** simulate only.
- **Artifacts:** `{resource_type}`
- **Telemetry:** `resource_development_simulated`
- **Detection hints:** title, logsource(infrastructure_provisioning), detection, mitre=T1583 (Phase 8).
- **Scenarios:** none.
- **Tests:** registry-wide.
- **Gaps:** Single shape; no fan-out (domain registration vs infra provisioning vs cert acquisition). Legacy `src/core/resource/resource_development.py` not wired in.

### `reconnaissance` (T1592)
- **Source:** [src/core/modules/impl/standard_modules.py:417](src/core/modules/impl/standard_modules.py:417) (`ReconnaissanceModule`)
- **Mode behaviour:** simulate only.
- **Artifacts:** `{source}`
- **Telemetry:** `reconnaissance_simulated`
- **Detection hints:** title, logsource, detection, mitre=T1592 (Phase 8).
- **Scenarios:** none.
- **Tests:** registry-wide.
- **Gaps:** No source taxonomy (osint vs scanning vs whois vs dns). Legacy `src/core/reconnaissance/reconnaissance.py` not wired in.

### `exfiltration` (T1041)
- **Source:** [src/core/modules/impl/standard_modules.py:227](src/core/modules/impl/standard_modules.py:227) (`ExfiltrationModule`)
- **Mode behaviour:** simulate only. Real destructive path **gated** by `params["destructive"] AND params["i_understand_this_is_a_lab"]`; without both, returns `failure` with `error="missing_lab_acknowledgment"`.
- **Side-effect gates:** explicit lab acknowledgement param.
- **Artifacts:** `{method, artifact_name}` (artifact_name uses `run_id` but file is not actually written under output_dir)
- **Telemetry:** `exfiltration_simulated`
- **Detection hints:** title, logsource(network_connection/windows), detection (exfil.method), condition, mitre=T1041, network_method.
- **Scenarios:** `apt29_credential_access`, `healthcare_ransomware`, `insider_exfil_dns`
- **Tests:** registry-wide.
- **Gaps:** `artifact_name` is a string but no file is created — misleading. Method values from scenarios (`via_c2`, `dns_tunnel`) don't change hint shape. The rich `src/core/exfiltration/{data_exfiltration,exfiltration}.py` (~1500 lines) is **not wired in**.

## 9 Legacy adapters

### `legacy_capability_summary`
- **Source:** [src/core/modules/impl/legacy_packs.py:56](src/core/modules/impl/legacy_packs.py:56) (`LegacyPackSummaryModule`)
- **Mode behaviour:** stateless — returns the active legacy enablement summary.
- **Artifacts:** `{legacy_summary, requested}`
- **Telemetry:** `legacy_capability_summary`
- **Hints:** none (no `mitre_technique` either).
- **Scenarios:** all 5 legacy scenarios use it as a first step.
- **Tests:** `test_legacy_controls.py`, `test_legacy_config_aliases.py`, `test_legacy_guided_mapping.py`.
- **Gaps:** Should expose recommended-preset hint and known unsafe-overrides count.

### `legacy_actor_profile` (T1589, T1591)
- **Source:** [src/core/modules/impl/legacy_packs.py:78](src/core/modules/impl/legacy_packs.py:78) (`LegacyActorProfileModule`)
- **Mode behaviour:** Always emits actor-profile telemetry. In `emulate` mode, additionally instantiates the actor class from `src.core.actors.<actor>` via `safe_call(instantiate_apt_actor, ...)`. Currently only loads class for introspection — does not call `execute_technique`.
- **Side-effect gates:** `_ensure_allowed` raises `RuntimeError` if pack disabled or emulate without lab_confirmation.
- **Artifacts:** `{legacy:{summary, pack, capability, mode, payload}, actor_profile, tactics}`
- **Telemetry:** `legacy_actor_profile`
- **Hints:** title, logsource(threat_intelligence), detection, mitre=T1589.
- **Scenarios:** `legacy_actor_apt29`, `legacy_actor_family_full`, `legacy_flagship_blended`.
- **Tests:** `test_legacy_runtime_integration.py`.
- **Gaps:** `runtime_class` is just the class name — adds little value over `simulate` mode. No actor metadata exposed (aliases, focus). The static `_PROFILE_MAP` duplicates info already on the actor classes.

### `legacy_apt29_research` (T1566, T1059, T1036, T1071.004)
- **Source:** [src/core/modules/impl/legacy_packs.py:161](src/core/modules/impl/legacy_packs.py:161) (`LegacyApt29ResearchModule`)
- **Mode behaviour:** Per-technique branching (`phishing`, `powershell`, `process_hollowing`, default DNS C2). `emulate` mode invokes `run_actor_technique('apt29', tactic, technique, params)`.
- **Side-effect gates:** `_ensure_allowed`. Live actor runtime gated by emulate mode.
- **Artifacts:** `{legacy:{...}, runtime_outcome, runtime_indicators?, runtime_warning?}`
- **Telemetry:** `legacy_apt29_research`
- **Hints:** technique-specific title/logsource/detection, mitre per branch.
- **Scenarios:** `legacy_actor_apt29`, `legacy_actor_family_full`, `legacy_flagship_blended`.
- **Tests:** `test_legacy_runtime_integration.py`.
- **Gaps:** Only 4 hardcoded techniques. Hardcoded encoded PowerShell payload is dummy (no clear connection to actual APT29 TTPs in source).

### `legacy_apt28_research`, `legacy_apt32_research`, `legacy_apt38_research`, `legacy_apt41_research`
- **Source:** dynamically generated via `type(...)` from `LegacyGenericActorTechniqueModule` ([src/core/modules/impl/legacy_packs.py:338](src/core/modules/impl/legacy_packs.py:338)).
- **Mode behaviour:** All four take `tactic` + `technique` + `target` params. Emulate runs `run_actor_technique(actor_key, tactic, technique, params)`.
- **Hints:** generic shape per actor; logsource is always `threat_intelligence/generic` (no per-actor variation).
- **Scenarios:** `legacy_actor_family_full` covers all four.
- **Tests:** registry-wide only.
- **Gaps:** All four share identical implementation. No actor-specific tradecraft fingerprint in hints (e.g., APT41 supply-chain detection would differ from APT28 phishing detection). The `__module__` attribute reads `abc` because they are dynamically generated — slightly noisy in tracebacks.

### `legacy_protocol_research` (T1071.004, T1572, T1090)
- **Source:** [src/core/modules/impl/legacy_packs.py:441](src/core/modules/impl/legacy_packs.py:441) (`LegacyProtocolResearchModule`)
- **Mode behaviour:** Per-protocol branching (`dns_tunneling`, `tls_fast_flux`, `websocket_quic`, `solana_rpc`, `network_obfuscator_legacy`). Domain allowlist enforcement via `_domain_allowed`. Emulate mode invokes the matching `run_*` runtime helper.
- **Side-effect gates:** `_ensure_allowed`, `_domain_allowed` (allowlist of `.example.lab`, `localhost`, `*.invalid`, `*.test`).
- **Artifacts:** `{legacy:{...}, protocol-specific details}`
- **Telemetry:** `legacy_protocol_research`
- **Hints:** rich per-protocol detection drafts (DNS query patterns, TLS JA3, QUIC port/ALPN, Solana RPC method).
- **Scenarios:** `legacy_c2_protocols`, `legacy_flagship_blended`.
- **Tests:** `test_command_control_adapter.py`, registry-wide.
- **Gaps:** This is the **best-modeled** legacy adapter. Cadence, ja3, alpn, etc. are all surfaced. The lone weakness: `network_obfuscator_legacy` is not allowlist-checked (intentional? bypasses domain check).

### `legacy_stealth_research` (T1497, T1562, T1070)
- **Source:** [src/core/modules/impl/legacy_packs.py:656](src/core/modules/impl/legacy_packs.py:656) (`LegacyStealthResearchModule`)
- **Mode behaviour:** Per-capability branching (`anti_forensic`, `anti_detection_legacy`, `anti_sandbox`, `dynamic_api`). Emulate runs `run_stealth_capability` against the live legacy classes.
- **Side-effect gates:** `_ensure_allowed`. Live class instantiation gated by emulate.
- **Artifacts:** capability-specific `cleanup_targets` / `checks` / `signals`.
- **Telemetry:** `legacy_stealth_research`
- **Hints:** rich per-capability shape.
- **Scenarios:** `legacy_stealth_research`, `legacy_flagship_blended`.
- **Tests:** registry-wide + `test_legacy_runtime_integration.py`.
- **Gaps:** API hash example (`0xA3D82B19`) is hardcoded fake.

## Unwired legacy capability code (preserved but not in registry)

These files survived stabilization and contain substantial offensive-research code. They are NOT currently dispatched by any registered module:

| File | Lines | Status |
|---|---|---|
| `src/core/credential/credential_access.py` | 1336 | Not wired. **No `credential_access` module exists**. |
| `src/core/movement/lateral_movement.py` | 1397 | Not wired. **No `lateral_movement` module exists**. |
| `src/core/privilege/privilege_escalation.py` | 899 | Not wired. **No `privilege_escalation` module exists**. |
| `src/core/impact/impact.py` | 924 | Not wired. **No `impact` module exists**. |
| `src/core/collection/collection.py` | 807 | Not wired. **No `collection` module exists**. |
| `src/core/discovery/discovery.py` | ~1100 | Not wired into `DiscoveryModule`. |
| `src/core/execution/{linux,windows,macos}_execution.py` | per-OS | Not wired into `ExecutionModule`. |
| `src/core/persistence/{linux,windows,macos}_persistence.py` | per-OS | Not wired into `PersistenceModule`. |
| `src/core/exfiltration/{data_exfiltration,exfiltration}.py` | 1500+ | Not wired into `ExfiltrationModule`. |
| `src/core/network/network_obfuscator.py` | 600 | Wired only via the legacy protocol adapter `network_obfuscator_legacy` capability. Not into `NetworkObfuscatorModule`. |
| `src/core/anti_forensic.py` | 482 | Wired only via `legacy_stealth_research` emulate mode. |
| `src/core/anti_detection/manager_impl.py` | 750+ | Wired only via `legacy_stealth_research`. |
| `src/core/intelligence/{apt28,apt}_intelligence.py` | combined | Not wired anywhere. |
| `src/core/reporting/{apt28,apt29,apt}_reporting.py` | combined | Not wired into the run reporter. |

## Standard-module / legacy-module overlap matrix

| Tactic | Standard module | Legacy code | Overlap state |
|---|---|---|---|
| Initial access | `initial_access` (toy) | `src/core/initial_access/initial_access.py` | not wired |
| Execution | `execution` (real subprocess gated) | `src/core/execution/{linux,windows,macos}_*.py` | not wired |
| Persistence | `persistence` (toy) | `src/core/persistence/{linux,windows,macos}_*.py` | not wired |
| Defense evasion | `defense_evasion` (toy) | `src/core/defense_evasion/{linux,windows,macos}_*.py` | not wired |
| Discovery | `discovery` (toy) | `src/core/discovery/discovery.py` | not wired |
| Command and control | `command_control` (toy) | `src/core/command_control/command_control.py` (Flask mock C2) | not wired into standard; partially via `legacy_protocol_research` |
| Exfiltration | `exfiltration` (toy + lab gate) | `src/core/exfiltration/{data_,}exfiltration.py` | not wired |
| Anti-detection | `anti_detection` (toy) | `src/core/anti_detection/manager_impl.py` | not wired into standard; via `legacy_stealth_research` only |
| Network obfuscation | `network_obfuscator` (toy) | `src/core/network/network_obfuscator.py` | not wired into standard; via `legacy_protocol_research` only |
| Intelligence | `intelligence` (toy) | `src/core/intelligence/*` | not wired |
| Resource dev | `resource_development` (toy) | `src/core/resource/resource_development.py` | not wired |
| Reconnaissance | `reconnaissance` (toy) | `src/core/reconnaissance/reconnaissance.py` | not wired |
| **Credential access** | **MISSING** | `src/core/credential/credential_access.py` | not wired |
| **Lateral movement** | **MISSING** | `src/core/movement/lateral_movement.py` | not wired |
| **Privilege escalation** | **MISSING** | `src/core/privilege/privilege_escalation.py` | not wired |
| **Impact** | **MISSING** | `src/core/impact/impact.py` | not wired |
| **Collection** | **MISSING** | `src/core/collection/collection.py` | not wired |

The first 12 standard modules cover most ATT&CK tactics with thin synthesisers; the bottom 5 tactics have legacy implementations but **no registered standard module to expose them**.

## Capability strength assessment (subjective)

| Strength | Modules |
|---|---|
| **High fidelity** (rich per-input shape, real lab gates) | `legacy_protocol_research`, `legacy_stealth_research`, `exfiltration` (gate only) |
| **Medium fidelity** (real shape but limited fan-out) | `legacy_apt29_research`, `legacy_actor_profile`, `legacy_capability_summary`, `execution` (real subprocess path) |
| **Low fidelity / placeholder** | `initial_access`, `persistence`, `defense_evasion`, `discovery`, `command_control`, `anti_detection`, `intelligence`, `network_obfuscator`, `resource_development`, `reconnaissance`, `legacy_apt{28,32,38,41}_research` |

The ratio of "low fidelity placeholder" to "high fidelity" modules is the single biggest item driving the roadmap.
