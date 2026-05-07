# BlueFire Nexus

[![tests](https://img.shields.io/badge/tests-1376%20passed-blue)](#development--tests)
[![security](https://img.shields.io/badge/security-bandit%20strict-green)](#development--tests)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](#quickstart)
[![license](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

> **A local-first adversary-emulation framework for purple-team validation. Every run produces structured telemetry, ATT&CK-mapped detection drafts, a risk summary, and a static HTML dashboard — without making a single network call.**

BlueFire Nexus runs ATT&CK-aligned scenarios end-to-end on a single machine. Each run lands a complete artifact bundle under `output/<run_id>/`: a JSON manifest, a self-contained `index.html` dashboard, structured telemetry, Sigma / YARA-L / SPL detection drafts, a risk summary, and (optional) AI-augmented narratives. Open `index.html` with `file://` and you get the full picture — no server, no SaaS, no telemetry shipped off the box.

The framework is **dual-use by design**: it preserves realistic offensive tradecraft (APT actor packs, C2 protocol research, stealth and evasion research) but gates that capability behind explicit configuration, lab confirmation, and registry-wide safety tests. The defaults are conservative (`dry_run=True`, all advanced packs disabled, AI offline). Anything that could plausibly leave the box requires an opt-in flag the operator types themselves.

This repository is intended for **authorised purple-team work, detection-engineering research, and security education**. See [§ Limitations & scope](#limitations--scope) below for what it is *not*.

---

## Why this exists

Most adversary-emulation tools land in one of three failure modes:

- **Compliance simulators** with green dashboards and no realistic offensive telemetry.
- **Fragmented script collections** with realism but no orchestration, no telemetry contract, and no safety story.
- **Unsafe operator suites** with realism and orchestration but no gating, no defensive output, and no way to run them in a controlled environment.

BlueFire Nexus tries to bridge these:

- **Offensive realism, preserved.** Per-actor APT adapters, C2 protocol research, stealth and credential-access tradecraft — kept in tree, behind explicit gates.
- **Defensive output, every run.** Sigma / YARA-L / SPL drafts, ATT&CK coverage maps, risk summary — readable by a SOC analyst, not a spreadsheet.
- **Local-first.** No SIEM connectors, no remote observability, no required cloud account. Air-gapped use is supported by default.
- **Reproducible.** Predictable artifact paths, a manifest schema, and a static dashboard that bytes the same output for the same input.
- **Gated, not sanitised.** Dangerous behaviour ships disabled. The "scary" code paths are still in the repo so detection engineers can study them — but you have to choose to run them.

---

## What it does

- **Adversary-emulation runtime** orchestrating ATT&CK-aligned scenarios from YAML.
- **Module registry** with a single `ModuleResult` contract enforced by three registry-wide tests (contract / safety / artifact-path).
- **Step-to-step propagation.** Downstream modules can opt into reading prior steps' artifacts so chains feel like real intrusions, not isolated technique callouts.
- **Actor / C2 / stealth / tactic legacy research packs**, each wired through gated adapters.
- **Local telemetry** as JSON Lines per run.
- **Detection draft generation** for Sigma, YARA-L, and Splunk SPL rule files.
- **Reports + risk summary** in Markdown and JSON.
- **Static HTML dashboard** per run — no JS, no external assets, no network. Open with `file://`.
- **Run manifest** (`manifest.json`) — machine-readable index of every artifact for downstream tooling.
- **AI / copilot layer** with deterministic offline template fallback. Optional remote providers (OpenAI, Anthropic, Gemini, Grok, Ollama, llama.cpp, LM Studio) are equal opt-in targets; nothing is privileged as the default.
- **Safety / mode controls** (`dry_run`, `simulate`, `emulate`, `lab_confirmation`, allowed subnets, max runtime).
- **Mutation engine** for parameter variants (`--mutate <strategy>` on `python -m src.run_scenario`).
- **CLI helpers** for working with prior runs: `list-runs`, `latest-run`, `show-run`, `build-report-view`, `validate-run`.

---

## Current baseline

- **Local-first.** Every artifact lives under `output/<run_id>/`.
- **No outbound SIEM exporters.** Splunk HEC, OpenSearch, Elasticsearch, NGSIEM, and generic HTTP bulk connectors were removed in stabilization. Legacy `telemetry.sinks` config entries naming those types are warn-and-ignored at load time so old configs do not crash and do not silently regain network egress.
- **No remote observability.** Not on the active path. The roadmap notes this as future-only work; nothing in the shipped baseline depends on it.
- **Dry-run is the default.** A registry-wide test asserts no module invokes `subprocess` / `socket` / `requests` / `urllib` / `aiohttp` while `dry_run=True`.
- **Mode model: `simulate` / `emulate` / `lab`.** `simulate` synthesises local telemetry; `emulate` invokes preserved research code paths; `lab` requires explicit `lab_confirmation: true`.
- **Advanced offensive modules are gated, not removed.** Actor packs, C2 protocol research, stealth research, and per-OS adapters ship disabled by default.

---

## Quickstart

```bash
# 1. Clone + install (Linux / macOS — see below for Windows)
git clone https://github.com/Moneer-S/BlueFire-Nexus.git
cd BlueFire-Nexus
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e .
cp .env.example .env

# 2. Run a scenario (simulate-only, dry-run, no network)
python -m src.run_scenario --profile apt29_credential_access --output-json

# 3. Inspect the results
python -m src.core.cli latest-run            # prints a file:// link to index.html
python -m src.core.cli list-runs             # everything in output/
python -m src.core.cli validate-run <run_id> # check the bundle is complete

# 4. Open the static dashboard with file:// (no server required)
#    Linux:   xdg-open output/<run_id>/index.html
#    macOS:   open       output/<run_id>/index.html
#    Windows: start       output\<run_id>\index.html
```

The full demo scenario is `enterprise_intrusion_chain` (12 standard modules, four step-to-step propagation pairs):

```bash
python -m src.run_scenario --profile enterprise_intrusion_chain --output-json
```

Every run writes `manifest.json` (machine-readable index of every artifact) and `index.html` (static dashboard) under `output/<run_id>/`. The dashboard renders the scenario timeline, propagation graph, ATT&CK coverage, telemetry counts, detection drafts, risk summary, and AI provider attribution from the manifest. No JavaScript, no external assets, no network calls — open with `file://` and read.

A broader command reference is in [docs/USAGE_GUIDELINES.md](docs/USAGE_GUIDELINES.md). The architecture, mode model, and ModuleResult contract live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Example output

```
output/<run_id>/
├── manifest.json                # machine-readable index of every artifact below
├── index.html                   # static, browser-viewable run dashboard (no server)
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

### Local report viewer

Every run writes a static, fully self-contained `index.html` next to the manifest. Open it with `file://` in any browser — no server, no external assets, no network calls. The page is one HTML file with an inline `<style>` block and zero JavaScript; every value is HTML-escaped before rendering, every artifact link is run-dir-relative, and the run directory can be moved without breaking the page.

The dashboard is read from `manifest.json` and contains, in order:

1. **Header** — scenario name, run id, status badges, AI provider attribution.
2. **KPI grid** — steps / techniques / detection drafts / telemetry events / blocked steps.
3. **Risk summary** — totals + per-module severity badges (rendered above the timeline so triage starts with severity, not the procedural step list).
4. **Scenario timeline** — ordered steps with module / status / ATT&CK techniques / a `notes` column for non-success rows.
5. **Propagation graph** — `(from_step, to_step, kind)` rows for every `target_from_step` / `source_from_step` consumer pair.
6. **ATT&CK coverage** — technique → emitting steps.
7. **Telemetry summary** — count-only, by event type and by module.
8. **Detection drafts** — per-engine counts + per-step paths.
9. **AI copilot** — provider, model, network state ("offline (template / no network)" by default), fallback marker, link to the artifact.
10. **Artifact quick links** — report.md, report.json, risk_summary.json, telemetry.jsonl, manifest.json, detections/. Each renders as a clickable run-dir-relative link only when the file exists; missing artifacts surface as inert "not present" text.

The CLI exposes five commands for working with runs locally:

```bash
python -m src.core.cli list-runs                # newest first
python -m src.core.cli latest-run               # most recent run detail
python -m src.core.cli show-run <run_id>        # single-run detail
python -m src.core.cli build-report-view <run_id>  # regenerate index.html
python -m src.core.cli validate-run <run_id>    # gate-style bundle check
```

All five honour `general.output_root` / `BLUEFIRE_OUTPUT_ROOT` and accept `--output-root <path>` for ad-hoc discovery. None starts a server. None auto-opens a browser. `validate-run` exits non-zero when the bundle is missing artifacts or has broken viewer links — useful as a CI gate before sharing a run output.

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

Four opt-in research packs preserve the most advanced offensive code paths instead of hiding or deleting them:

- **Actor pack** — APT29 / APT28 / APT32 / APT38 / APT41 research adapters.
- **C2 / protocol pack** — DNS tunneling, TLS fast-flux, QUIC, Solana RPC, network obfuscation.
- **Stealth pack** — anti-forensic, anti-sandbox, anti-detection, dynamic API resolution research.
- **Tactic pack** — credential-access, lateral-movement, privilege-escalation, impact, and collection research adapters wrapping the preserved per-tactic legacy classes (`legacy_credential_access`, `legacy_lateral_movement`, `legacy_privilege_escalation`, `legacy_impact`, `legacy_collection`).

All packs ship **disabled by default**. Enable globally with the master lab toggle or per-pack/per-capability with explicit opt-in. `simulate` is the default mode for any enabled capability; `emulate` requires lab confirmation. The standard tactic modules (`credential_access`, etc.) remain simulate-only and are NOT routed through the legacy adapters; scenarios that want the legacy behaviour must explicitly use `module: legacy_<tactic>`.

Full enable/disable surface, preset profiles, and YAML examples: [docs/USAGE_GUIDELINES.md](docs/USAGE_GUIDELINES.md). Per-pack case studies: [docs/case-studies/](docs/case-studies/).

---

## AI / copilot layer

- **Default is offline / template.** A deterministic local provider produces copilot artifacts every run with no external dependencies and no API key required. Air-gapped use works out of the box.
- **Provider-agnostic interface.** Every provider implements the same `LLMProvider` Protocol (`complete()` text-only + `generate()` rich `ProviderResponse`). Adding or swapping a backend does not require touching the copilot code.
- **No vendor is privileged as the default.** Canonical provider names (`openai`, `anthropic`, `gemini`, `grok`, `ollama`, `openai_compatible`, plus `llama.cpp` / `lm-studio`) are equal optional opt-in targets. Aliases (`google → gemini`, `xai → grok`, `claude → anthropic`) are normalised at factory time.
- **OpenAI-compatible HTTP backend ships** for protocol-compatible names (`openai_compatible`, `openai`, `grok`, `ollama`, `llama.cpp`, `lm-studio`). It uses an injectable transport so tests never touch the network and short-circuits to offline when no `api_base` is configured.
- **Anthropic Messages-API adapter ships** for the `anthropic` canonical name (with `claude` alias). Vendor-specific request/response shape (`x-api-key` header, `anthropic-version` header, top-level `system` field, `content[].text` blocks). Same injectable-transport / short-circuit-to-offline contract as the OpenAI-compatible backend, plus an additional `api_key`-required gate (Anthropic has no local-server analog).
- **Gemini GenerateContent-API adapter ships** for the `gemini` canonical name (with `google` / `google_gemini` aliases). Vendor-specific request/response shape (`x-goog-api-key` header, model in URL path, `contents` array with `parts`, top-level `systemInstruction`, `generationConfig` block, `usageMetadata` normalised into the shared usage keys). Same triple-gate as the Anthropic adapter (`enabled` / `api_base` / `api_key`).
- **API keys via env vars only.** `modules.ai.api_key_env` names the environment variable; the runtime never reads from disk and the key never appears in config files.
- **Optional fallback chain.** `modules.ai.fallback_provider` (typically `template`) routes around primary failures so a remote outage degrades gracefully to deterministic offline output. The fallback marker (`fallback_used: true`, plus `primary_provider` / `primary_error` attribution) appears in every artifact's metadata header.
- **Artifact metadata header.** Every copilot artifact (`copilot_plan.txt`, `copilot_narrative.md`, `copilot_detections.md`) starts with a YAML-front-matter block carrying `provider` / `model` / `generated_at` / `network_disabled` / `fallback_used` so report renderers and operators can attribute output and spot degraded runs without re-parsing the file. When the orchestrator builds a run summary (scenario name, module status counts, technique totals, detection-hint coverage), those fields land in the same header so artifacts reflect actual scenario context — and in the prompt body, so the model sees what ran rather than just `run_id=<x>`. The summariser explicitly does not read `ModuleResult.message`, which is the prompt-injection guard for the upstream-module text channel.
- **RAG retrieval.** A small TF-IDF index over `README.md`, `docs/ARCHITECTURE.md`, and the run report powers context for copilot prompts. No external dependencies.
- **Mutation engine reachable from the CLI.** `python -m src.run_scenario --mutate <strategy>` applies a mutation strategy to every step's params before dispatch. Strategies: `low_noise`, `evasion-lite`, `protocol_shift`, `protocol-shift`. The mutation strategy is recorded in the run summary so mutation is never silent.
- **Experiment harness.** `run_experiment_series` (`src/core/experiments.py`) supports repeated scenario runs with optional bounded jitter.

Full reference: [docs/reports/ai_layer.md](docs/reports/ai_layer.md). Operator-facing config: [docs/USAGE_GUIDELINES.md](docs/USAGE_GUIDELINES.md#ai-provider-configuration).

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

## Limitations & scope

This is a security-research and detection-engineering tool, not a production breach-and-attack platform.

- **Single-host execution.** Scenarios run on the box you launch them on. There is no agent, no controller / agent split, no remote execution mesh.
- **No live destructive behaviour by default.** `dry_run=True`, `simulate` mode, and `allow_real_execution=false` are all in effect on a fresh install. You have to flip multiple gates explicitly to invoke real research code.
- **No outbound integrations in the baseline.** SIEM exporters, remote observability, hosted dashboards, telemetry shipping — none of those exist on the active path. Telemetry is local JSON Lines.
- **AI providers are opt-in.** The default `template` provider is fully offline and deterministic. Remote providers (OpenAI, Anthropic, Gemini, Grok, Ollama, llama.cpp, LM Studio) require explicit `modules.ai.enabled: true` plus an operator-supplied endpoint and (for vendor-specific backends) an API key resolved from an environment variable. No keys are bundled or written to disk.
- **`emulate` mode is gated.** Legacy adapter packs default to `simulate`. `emulate` requires `lab_confirmation: true` and runs preserved research code paths that synthesise local artifacts — they don't open real network sockets in dry-run.
- **For authorised research only.** The framework is dual-use. Use it on systems you own or have written permission to test. See [`SECURITY.md`](SECURITY.md) for the full threat model.
- **Static dashboard, not a live UI.** `output/<run_id>/index.html` re-generates on every run. There is no SPA, no auto-refresh, and no server to host. Re-run the scenario or re-run `build-report-view` for an updated view.

If your use case requires distributed execution, live data shipping, or a hosted dashboard, BlueFire Nexus is not the right tool today.

---

## Roadmap

Tracked in [docs/reports/next_roadmap.md](docs/reports/next_roadmap.md). Top open items:

- **Decide on Grok / OpenAI provider-specific adapters.** Anthropic and Gemini ship as vendor-specific adapters (`AnthropicMessagesBackend` and `GeminiGenerateContentBackend`). `openai`, `grok`, `ollama`, `llama.cpp`, and `lm-studio` work via the OpenAI-compatible HTTP backend; vendor-specific changes for any of them only happen if a real interop gap surfaces. See [docs/reports/ai_layer.md](docs/reports/ai_layer.md).
- **Future observed-telemetry correlation.** Roadmap only; not in current baseline. No remote SIEM exporters or external collectors today.

---

## Status snapshot

- 1376 passing tests, 5 intentional skips, 0 failures (~190s full-suite wallclock).
- Bandit strict; every dual-use offensive pattern carries a narrow per-line `nosec` justification with rationale.
- 31 modules registered (17 standard + 14 legacy adapters), spanning 100+ MITRE ATT&CK techniques.
- 10 shipped scenarios, all passing dry-run; CI gate enforces both static (`declared ⊆ module-can-emit`) and runtime (`declared ⊆ actually-emitted`) ATT&CK alignment.
- Every run produces a complete local report bundle: `manifest.json` (machine-readable index), `index.html` (static browser viewer — no server, no external assets, no network), `report.md`, `report.json`, `risk_summary.json`, `telemetry.jsonl`, `detections/`, plus optional copilot artifacts.
- Step-to-step artifact propagation: the runtime threads a read-only `previous_step_results` mapping into each step's context. The shipped `enterprise_intrusion_chain` scenario demonstrates four consumer pairs end-to-end (`discovery → credential_access`, `credential_access → lateral_movement` source, `collection → exfiltration`, `collection → impact`).
- Cross-provider AI coherence: every documented canonical name (template, openai, anthropic, gemini, grok, ollama, llama.cpp, lm-studio, openai_compatible) routes to a registered backend. Default stays offline / template — no API keys required for normal use, no network calls without explicit `modules.ai.enabled: true` plus operator-supplied endpoint and (for vendor-specific backends) credentials.
- Capability inventory: [docs/reports/capability_inventory.md](docs/reports/capability_inventory.md).
- Scenario coverage: [docs/reports/scenario_validation.md](docs/reports/scenario_validation.md).
- Roadmap: [docs/reports/next_roadmap.md](docs/reports/next_roadmap.md).
- Preserved orphan files: [docs/reports/orphan_files.md](docs/reports/orphan_files.md).

---

## Disclaimer

BlueFire Nexus is **dual-use security research tooling**. Use only in authorized, isolated environments for defensive testing, purple-team validation, and security research. The author and contributors accept no responsibility for misuse.

---

## License

MIT. See [LICENSE](LICENSE).
