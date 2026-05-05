# BlueFire-Nexus scenario validation

Snapshot at `main` = `c0b0669`. All 9 scenarios under `scenarios/` were run via
`python -m src.run_scenario --scenario-file <path> --output-json --run-id <id>`
in the project's default config (`config.yaml` with legacy packs enabled in
`simulate` mode at the per-capability level).

## Aggregate

| Scenario | Steps | Success | Blocked | Failure | Detect files | Telem lines |
|---|---:|---:|---:|---:|---:|---:|
| `apt29_credential_access` | 4 | 4 | 0 | 0 | 13 | 4 |
| `fin7_initial_access_to_c2` | 3 | 3 | 0 | 0 | 10 | 3 |
| `healthcare_ransomware` | 4 | 4 | 0 | 0 | 13 | 4 |
| `insider_exfil_dns` | 3 | 3 | 0 | 0 | 10 | 3 |
| `legacy_actor_apt29` | 5 | 5 | 0 | 0 | 10 | 5 |
| `legacy_actor_family_full` | 8 | 8 | 0 | 0 | 22 | 8 |
| `legacy_c2_protocols` | 6 | 6 | 0 | 0 | 7 | 6 |
| `legacy_flagship_blended` | 5 | 5 | 0 | 0 | 16 | 5 |
| `legacy_stealth_research` | 5 | 5 | 0 | 0 | 7 | 5 |

**Every scenario produces:** `report.md`, `report.json`, `risk_summary.json`,
`telemetry.jsonl`, `detections/{sigma,yara_l,spl}/`, `copilot_narrative.md`,
`copilot_plan.txt`, `copilot_detections.md`, `coverage_<run_id>.json`. **All
9 scenarios pass dry-run/simulate without error.**

## Per-scenario findings

### `apt29_credential_access`
- **Strength:** Honest 4-step chain (initial access → exec → anti-detection → exfil). Right shape for an actor-aligned credential-access teaser.
- **Weakness 1 (functional gap):** Declares `T1555` in `attack_coverage` but the third step routes through `anti_detection` (T1027) because no `credential_access` module exists. Telemetry never carries T1555.
- **Weakness 2 (silent ignore):** Step 4 passes `targets: [10.0.0.15]` to `exfiltration` but the module ignores it.
- **Weakness 3 (toy module):** Steps 1 and 3 use placeholder modules — no APT29 flavor in the produced telemetry.
- **Recommendation:** After credential_access module exists (roadmap item 1), repoint step 3 to it with `technique: dpapi_extraction` or similar. Until then, document the T1555/T1027 substitution.

### `fin7_initial_access_to_c2`
- **Strength:** Tight 3-step chain. C2 step uses `https://example.lab/c2` which is properly inside the lab allowlist. PowerShell payload uses an encoded base64 example.
- **Weakness 1 (toy module):** All three steps go through placeholder standard modules. No FIN7-specific tradecraft is reflected in the artifacts.
- **Weakness 2 (no detection differentiation):** `command_control` emits the same hint regardless of channel — so the C2 step's detection draft is generic.
- **Recommendation:** This scenario is the obvious candidate for using a future `legacy_fin7_research` adapter (mirroring the apt29 pattern). Lower priority than the missing tactic modules.

### `healthcare_ransomware`
- **Strength:** Realistic 4-step ransomware-precursor chain (phish → exec → persistence → exfil). `fail_fast: false` is appropriate for an exploration scenario.
- **Weakness 1 (functional gap):** "Ransomware" implies impact (T1486 data encrypted) — but no `impact` module exists, so the chain ends at exfil. The actual ransomware step is missing.
- **Weakness 2 (toy persistence):** Step 3 specifies `technique: scheduled_task` but the persistence hint is hardcoded to T1053 regardless of technique.
- **Recommendation:** Add an `impact` module with `technique: data_encrypted_for_impact` and append a step. Or rename the scenario to "Healthcare ransomware precursor" to set expectations.

### `insider_exfil_dns`
- **Strength:** Three-step chain (discovery → exfil → network obfuscation) with consistent DNS theme. `controlled_domain: exfil.example.lab` is properly inside the lab allowlist.
- **Weakness 1 (silent ignore):** Step 1 passes `discovery_type: files` and `network_touch: true`; `DiscoveryModule` ignores both.
- **Weakness 2 (no chain coupling):** The "files identified" by step 1 don't feed into step 2's `data_set: synthetic_hr_exports`. They're independent calls. A real chain would have step 1 produce an artifact step 2 reads.
- **Weakness 3 (toy modules):** Discovery, exfiltration, and network_obfuscator are all the placeholder versions.
- **Recommendation:** Once Discovery is wired to its legacy class with `discovery_type` honored, this becomes one of the most realistic scenarios. The "step 1 → step 2 chaining" pattern is broader: scenarios cannot pass artifacts between steps today.

### `legacy_actor_apt29`
- **Strength:** Best-modeled actor scenario. Uses `legacy_capability_summary` first to surface the active enablement state, then exercises `legacy_actor_profile` plus `legacy_apt29_research` with two real techniques (phishing + powershell). Detection drafts include APT29-specific ATT&CK tags.
- **Weakness 1 (missing techniques):** The apt29 adapter knows only `phishing`, `powershell`, `process_hollowing`, and a default DNS branch. APT29's real tradecraft (HAMMERTOSS, WMI persistence, Cobalt Strike abuse) isn't represented.
- **Recommendation:** Extend `LegacyApt29ResearchModule._SUPPORTED_TECHNIQUES` to cover more APT29 staples. Cheap, additive.

### `legacy_actor_family_full`
- **Strength:** Exercises every actor adapter in one run. Useful smoke test.
- **Weakness 1 (cookie-cutter actors):** Steps for APT28, APT32, APT38, APT41 all go through `LegacyGenericActorTechniqueModule`. Identical hint shape regardless of actor. No per-actor tradecraft.
- **Weakness 2 (no chained logic):** This scenario is 8 disconnected actor calls, not an adversary chain. Probably correct for a coverage-smoke scenario, but should be labeled as such in the README.
- **Recommendation:** Roadmap item 4 (per-actor adapters) directly addresses this. After that lands, this scenario produces 8 visibly different artifacts.

### `legacy_c2_protocols`
- **Strength:** Most actor-coherent legacy scenario. Each protocol step produces protocol-specific telemetry (TXT chunk size, TLS JA3, QUIC port/ALPN, Solana RPC method). Detection drafts vary per transport. The `legacy_protocol_research` adapter is the gold standard the other adapters should aspire to.
- **Weakness 1 (network_obfuscator_legacy bypasses domain check):** Of the 5 protocols, this one is exempt from `_domain_allowed`. Comment in code is silent on why.
- **Weakness 2 (low telem-to-detection ratio):** 6 telemetry events but only 7 detection files — barely above 1:1. Could emit more detection drafts per event.
- **Recommendation:** Document or fix the `network_obfuscator_legacy` allowlist exemption. Otherwise, this scenario is in good shape.

### `legacy_flagship_blended`
- **Strength:** The most ambitious scenario — actor + protocol + stealth in one chain. Demonstrates blended legacy enablement.
- **Weakness 1 (no chain coupling):** Same independent-call problem as other scenarios. The stealth step doesn't react to the actor or protocol step.
- **Weakness 2 (missing tactics):** Lacks credential access, lateral movement, and impact (the missing modules) — so the "flagship" doesn't actually showcase a complete kill chain.
- **Recommendation:** After the missing modules land, expand this scenario to a true full-chain demo. Until then, it is "blended legacy showcase," which is honest.

### `legacy_stealth_research`
- **Strength:** Exercises all four stealth capabilities (anti_forensic, anti_sandbox, anti_detection_legacy, dynamic_api). Each produces capability-specific telemetry shape.
- **Weakness 1 (no real interaction):** All steps are independent. A real stealth chain would do environment check → if not sandbox → execute payload → cleanup.
- **Weakness 2 (low detection coverage):** 7 detection files for 5 stealth steps is the lowest detection-density of any legacy scenario.
- **Recommendation:** Add a chained variant scenario (`legacy_stealth_chain.yaml`?) that conditions later steps on earlier results. Lower priority.

## Cross-cutting findings

### Steps cannot pass artifacts to later steps
No scenario chains artifacts. Every step takes only its declared `params`; no module reads `previous_step.artifacts`. This is a framework limitation, not a per-scenario fix. **This is the single biggest reason scenarios feel like disconnected calls.** Worth a separate planning doc — possibly a future "step context propagation" feature where each step gets a read-only view of all prior step results.

### `network_touch` is universally ignored
Used in 8 of 9 scenarios; consumed by 0 modules. Either consume it (add a sentinel that asserts no network primitives are called when `network_touch: false` AND `dry_run: true`) or remove it from scenarios.

### `attack_coverage` declared by scenarios is sometimes wider than what runs emit
Already noted in `apt29_credential_access` (T1555 declared, never emitted). Worth a small CI gate that compares declared coverage to emitted telemetry and flags gaps. Could live in `tests/test_scenarios.py` (which already exists per the test file inventory).

### Default config enables legacy packs in simulate mode
`config.yaml` shipped on `main` has `actor_pack.enabled: true`, `c2_pack.enabled: true`, `stealth_pack.enabled: true` with each capability `enabled: true`. The master `enable_all_lab_capabilities: false` is set, so emulate is gated, but per-capability simulate runs by default. This is the right default for purple-team work but should be stated explicitly in README/SECURITY (as of Phase 8 it is, in SECURITY.md).

### Copilot artifacts produced for every run despite no real model
`copilot_narrative.md`, `copilot_plan.txt`, `copilot_detections.md` exist for all 9 scenarios. None contain model-generated content (the default `template` provider returns deterministic strings). See AI/operator audit for the recommendation.

## Low-risk fixes spotted (deferred to follow-up PRs unless flagged)

- `network_obfuscator_legacy` domain-allowlist bypass — needs a 1-line code comment OR an allowlist check. **Holding** (semantic decision).
- `ExecutionModule` logsource hardcoded to `windows` — already in the roadmap as item 6.
- `network_touch` ignored — broader change than a single PR.
- `discovery_type` ignored by DiscoveryModule — being addressed in this cycle's discovery quality pass.

## Done-state for "scenarios feel like real adversary chains"

A scenario passes the bar when:
1. Every step runs through a module that actually consumes the params it's given.
2. Detection drafts vary per input parameter, not per module class.
3. Declared `attack_coverage` matches emitted MITRE technique IDs.
4. Mode/safety state is visible in `report.md` per step.
5. At least one scenario can chain artifacts between steps (later step reads earlier step output).
6. Every actor pack scenario produces visibly different telemetry per actor.
7. Every default-shipped scenario can run in dry-run/simulate without errors. ← **DONE TODAY**
8. Lab/emulate behavior requires explicit opt-in. ← **DONE TODAY**

7 of 8 are achievable through the roadmap items; 5 (artifact chaining) is the deepest lift.
