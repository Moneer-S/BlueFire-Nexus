# BlueFire Nexus

[![tests](https://img.shields.io/badge/tests-pytest-blue)](#development--tests)
[![security](https://img.shields.io/badge/security-bandit%20strict-green)](#development--tests)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](#quickstart)
[![license](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

> **BlueFire Nexus is a high-fidelity, AI-augmented adversary-emulation and purple-team research framework for modeling offensive tradecraft, generating local defensive artifacts, and validating detection logic in controlled environments.**

It is built around four ideas that most security tooling treats as separate concerns:

- **Offensive tradecraft realism.** Actor-inspired chains (APT29 / APT28 / APT32 / APT38 / APT41), C2 protocol research (DNS tunneling, TLS fast-flux, QUIC, RPC), stealth/evasion research, and exfiltration modeling — preserved, gated, and testable rather than sanitised away.
- **Local defensive artifacts.** Every run writes structured telemetry, ATT&CK-mapped detection drafts (Sigma + YARA-L + SPL), purple-team reports, and a risk summary to the run output directory. Local-first by design; no external integrations required.
- **AI-assisted operator analysis.** Optional copilot narratives and detection suggestions, with a deterministic offline fallback so the framework never requires an API key to function.
- **Safe-by-default lab controls.** Dry-run on by default, lab confirmation required for live emulation, allowed-subnet and runtime caps, destructive-operation acknowledgments, registry-wide tests that prove no module can leak side effects in dry-run.

---

## Why it exists

Adversary-emulation tooling tends to fall into one of three traps:

- **Sanitised compliance simulators** that produce green dashboards but no realistic offensive telemetry.
- **Fragmented script collections** that have offensive realism but no orchestration, no telemetry contract, and no safety story.
- **Unsafe operator suites** that have realism and orchestration but no gating, no defensive output, and no clean way to run them in a controlled environment.

BlueFire Nexus tries to bridge these:

- Offensive operator realism — preserved in legacy capability packs and modelled in standard modules.
- Defensive validation — every run produces detection drafts and a risk summary that a SOC analyst can actually consume.
- AI-assisted analysis — copilot artifacts that work offline by default and can be wired to a real provider per operator preference.
- Structured local outputs — predictable artifact paths under `output/<run_id>/`.
- Controlled lab execution — explicit `simulate` / `emulate` / `lab` modes; nothing dangerous happens unless the operator says so.

---

## What it does

- **Adversary-emulation runtime** orchestrating ATT&CK-aligned scenarios from YAML.
- **Module registry** with a single ModuleResult contract enforced by registry-wide tests.
- **Actor / C2 / stealth legacy research packs** wired through gated adapters.
- **Local telemetry** as JSON Lines per run.
- **Detection draft generation** for Sigma rules, YARA-L rules, and Splunk SPL searches.
- **Reports + risk summary** in Markdown and JSON.
- **AI / copilot layer** with offline template fallback and a scaffold for provider-backed runs.
- **Safety / mode controls** (`dry_run`, `simulate`, `emulate`, `lab` confirmation, allowed subnets, max runtime).
- **Mutation engine** for parameter variant generation (Python API today; CLI wiring tracked on the roadmap).

---

## Current baseline

- **Local-first.** Telemetry, reports, detections, and copilot artifacts all land under `output/<run_id>/`.
- **No outbound SIEM exporters in the baseline.** Splunk HEC / OpenSearch / Elasticsearch / NGSIEM connectors were intentionally removed during stabilization. Legacy `telemetry.sinks` config entries naming those types are warned-and-ignored at load time so old configs do not crash and do not silently regain network egress.
- **Dry-run is the default.** A registry-wide test asserts no module invokes `subprocess`, `socket`, `requests`, or `urllib` while `dry_run=True`.
- **Mode model: `simulate` / `emulate` / `lab`.** `simulate` synthesises telemetry locally; `emulate` invokes the real research code paths; `lab` requires explicit `lab_confirmation: true`.
- **Remote integrations are explicit opt-ins.** AI providers are user-configured. Any future remote observability work is roadmap, not current functionality.
- **Advanced offensive modules are gated, not removed.** Actor packs, C2 protocol research, stealth research, and per-OS adapters all ship disabled by default and require either the master lab toggle or per-pack/per-capability enablement.

---

## Quickstart

```bash
git clone https://github.com/Moneer-S/BlueFire-Nexus.git
cd BlueFire-Nexus
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e .
cp .env.example .env

python -m src.run_scenario --profile apt29_credential_access --output-json
```

Then look at `output/<run_id>/`. That is the entire surface area you need to get started.

A broader command reference is in [docs/USAGE_GUIDELINES.md](docs/USAGE_GUIDELINES.md). The architecture, mode model, and ModuleResult contract live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Example output

```
output/<run_id>/
├── telemetry.jsonl              # one JSON event per module step
├── report.md                    # purple-team narrative
├── report.json                  # structured per-step result
├── risk_summary.json            # per-run risk posture
├── detections/
│   ├── sigma/*.yml              # Sigma detection drafts
│   ├── yara_l/*.yaral           # YARA-L detection drafts
│   ├── spl/*.spl                # local Splunk SPL searches (NOT a connector)
│   └── coverage_<run_id>.json   # ATT&CK technique coverage map
├── copilot_narrative.md         # optional AI-augmented narrative
├── copilot_plan.txt             # optional plan output
└── copilot_detections.md        # optional detection-strategy summary
```

Splunk SPL is generated as **local detection-rule output**. It is not a Splunk exporter or SIEM connector.

---

## Core concepts

| Concept | Where it lives | What it does |
|---|---|---|
| Scenario | `scenarios/*.yaml` | Declares an ATT&CK-aligned chain of module steps. |
| Module | `src/core/modules/impl/standard_modules.py` + legacy adapters | Implements one ATT&CK tactic; registered in `BUILTIN_MODULE_CLASSES`. |
| ModuleResult | `src/core/models.py` | Single contract: `status`, `module`, `message`, `techniques`, `artifacts`, `telemetry`, `detection_hints`, `error`, `timestamp`. |
| Telemetry event | `src/core/models.py` (`TelemetryEvent`) | Append-only structured event with `event_type`, `module`, `details`, `severity`, `timestamp`. |
| Detection hint | `ModuleResult.detection_hints` | Drives Sigma / YARA-L / SPL artifact generation. |
| Legacy pack | `src/core/modules/impl/legacy_packs.py` + `legacy_runtime.py` | Actor / C2 / stealth research adapters with explicit lab gates. |
| Mode | scenario param + `legacy_controls.py` | `dry_run`, `simulate`, `emulate`. Determines whether real side effects can run. |

---

## Modes and safety

Every run is shaped by three orthogonal mode controls. Defaults are safe; advanced behaviour requires explicit opt-in.

- **`general.dry_run`** (default `true`). When true, no module invokes real subprocess / socket / HTTP primitives. The contract is enforced by [tests/test_module_safety.py](tests/test_module_safety.py).
- **Legacy capability `mode`**: `simulate` (default for any enabled capability) or `emulate`. `simulate` produces local telemetry/artifacts describing the technique without invoking the real research code. `emulate` requires explicit `lab_confirmation: true` at the global, pack, or capability level.
- **`ExecutionModule.allow_real_execution`** (default `false`). Real `subprocess.run` invocations require BOTH `dry_run=False` AND `allow_real_execution=true`.

Additional safety primitives:

- `general.safeties.allowed_subnets` — orchestrator-level subnet allowlist.
- `general.safeties.max_runtime` — hard ceiling on per-run wall time.
- Destructive-operation acknowledgment — e.g. exfiltration with `destructive=true` is rejected unless `i_understand_this_is_a_lab=true` is also passed.
- Artifact path enforcement — [tests/test_module_artifact_paths.py](tests/test_module_artifact_paths.py) asserts no module writes outside `context["output_dir"]`.
- Bandit strict — every dual-use offensive pattern carries a narrow per-line `# nosec BXXX – <reason>` justification; new unjustified findings fail CI.

Full safety story: [SECURITY.md](SECURITY.md).

---

## Legacy capability packs

Three opt-in research packs preserve the most advanced offensive code paths instead of hiding or deleting them:

- **Actor pack** — APT29 / APT28 / APT32 / APT38 / APT41 research adapters.
- **C2 / protocol pack** — DNS tunneling, TLS fast-flux, QUIC, Solana RPC, network obfuscation.
- **Stealth pack** — anti-forensic, anti-sandbox, anti-detection, dynamic API resolution research.

All packs ship **disabled by default**. Enable globally with the master lab toggle or per-pack/per-capability with explicit opt-in. `simulate` is the default mode for any enabled capability; `emulate` requires lab confirmation.

Full enable/disable surface, preset profiles, and YAML examples: [docs/USAGE_GUIDELINES.md](docs/USAGE_GUIDELINES.md). Per-pack case studies: [docs/case-studies/](docs/case-studies/).

---

## AI / copilot layer

Honest current state:

- **Template / offline provider works.** A deterministic local provider produces copilot artifacts every run with no external dependencies and no API key required. This is the default.
- **Remote provider interfaces exist as scaffolding.** `OpenAICompatibleProvider` is wired to `ProviderFactory` and accepts the names `openai`, `anthropic`, `google`, `ollama`, `llama.cpp`, `lm-studio`, and `openai_compatible`, but the current implementation intentionally does not call out — it returns a stub. Implementing a real provider is on the roadmap; pick one (Ollama is the obvious offline-first choice) rather than ship multiple half-finished integrations.
- **RAG retrieval works.** A small TF-IDF index over `README.md`, `docs/ARCHITECTURE.md`, and the run report powers context for copilot prompts.
- **Mutation engine exists.** `mutate_step_params`, `mutate_steps`, and `mutate_technique` (`src/core/ai/mutation.py`) are functional and tested. They are not yet wired into a CLI flag; see roadmap.
- **Experiment harness works.** `run_experiment` and `run_experiment_series` (`src/core/experiments.py`) support repeated scenario runs with optional jitter.

Full audit: [docs/reports/ai_operator_audit.md](docs/reports/ai_operator_audit.md).

---

## Development & tests

Standard install + test loop:

```bash
pip install -r requirements-dev.txt
pip install -e .

python -m compileall -q src tests
pytest -q
bandit -r src -ll
detect-secrets scan --all-files --baseline .secrets.baseline
pip-audit
```

CI runs the same gates plus gitleaks (history scan) and SBOM generation. Workflows: [.github/workflows/tests.yml](.github/workflows/tests.yml), [.github/workflows/analysis.yml](.github/workflows/analysis.yml).

Three registry-wide enforcement tests run on every module:

- [tests/test_module_contract.py](tests/test_module_contract.py) — every module returns a conformant `ModuleResult` (correct fields, types, status from `success | failure | blocked | skipped | partial_success`).
- [tests/test_module_safety.py](tests/test_module_safety.py) — strict dry-run safety: no module touches `subprocess`, `socket`, `requests`, or `urllib` while `dry_run=True`, in either lab-off or lab-simulate mode.
- [tests/test_module_artifact_paths.py](tests/test_module_artifact_paths.py) — every module writes its files only under `context["output_dir"]` and registers them in `ModuleResult.artifacts`.

Bandit runs strict at `-ll` (medium and higher). Each expected dual-use offensive pattern carries a narrow per-line `# nosec BXXX – <reason>` justification.

---

## Roadmap

Tracked in [docs/reports/next_roadmap.md](docs/reports/next_roadmap.md). Top items:

- **Missing standard modules.** Five ATT&CK tactics (`credential_access`, `lateral_movement`, `privilege_escalation`, `impact`, `collection`) have substantial legacy implementations but no registered standard module yet.
- **Per-input fan-out across modules.** The Discovery module now fans out telemetry/hints by `discovery_type`. Same pattern wanted for `command_control`, `persistence`, `defense_evasion`, `network_obfuscator`, `intelligence`, `reconnaissance`, `resource_development`.
- **Actor-specific adapters.** APT28/32/38/41 currently share a generic adapter; per-actor tradecraft fingerprinting is a quality lift.
- **Mutation engine CLI wiring.** `--mutate <strategy>` on `run_scenario`.
- **AI/operator planning improvements.** Either implement one real provider end-to-end or make copilot artifacts opt-in.
- **Reports / risk summary polish.** Mode badges, blocked-step section, ATT&CK-coverage cross-check.
- **Future observed-telemetry correlation.** Roadmap only; not in current baseline. No remote SIEM exporters or external collectors today.

---

## Status snapshot

- 230 passing tests, 5 intentional skips, 0 failures.
- Bandit strict; 14 narrow per-line `nosec` justifications across 11 source files.
- 21 modules registered (12 standard + 9 legacy adapters).
- 9 shipped scenarios, all passing dry-run.
- Capability inventory: [docs/reports/capability_inventory.md](docs/reports/capability_inventory.md).
- Scenario validation: [docs/reports/scenario_validation.md](docs/reports/scenario_validation.md).
- Autonomous-work changelog: [docs/reports/autonomous_work_log.md](docs/reports/autonomous_work_log.md).

---

## Disclaimer

BlueFire Nexus is **dual-use security research tooling**. Use only in authorized, isolated environments for defensive testing, purple-team validation, and security research. The author and contributors accept no responsibility for misuse.

---

## License

MIT. See [LICENSE](LICENSE).
