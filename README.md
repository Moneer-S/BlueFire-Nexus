# BlueFire Nexus

[![tests](https://img.shields.io/badge/tests-passing-blue)](#development--tests)
[![security](https://img.shields.io/badge/security-bandit%20strict-green)](#development--tests)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](#quickstart)
[![license](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

> A local-first adversary-emulation framework for purple-team validation. Every run produces structured telemetry, ATT&CK-mapped detection drafts, a risk summary, and a static HTML dashboard. No network calls by default.

BlueFire Nexus runs ATT&CK-aligned scenarios end-to-end on a single machine. Each run lands a complete artifact bundle under `output/<run_id>/`: a JSON manifest, a self-contained `index.html` dashboard, structured telemetry, Sigma / YARA-L / SPL detection drafts, a risk summary, and (optional) AI-augmented narratives. Open `index.html` with `file://` to read the run.

The framework is dual-use by design. It preserves realistic offensive tradecraft (APT actor packs, C2 protocol research, stealth and evasion research) but gates that capability behind explicit configuration, lab confirmation, and registry-wide safety tests. Defaults are conservative: `dry_run=True`, advanced packs disabled, AI offline.

This repository is intended for authorized purple-team work, detection-engineering research, and security education. See [§ Limitations & scope](#limitations--scope) for what it is not.

---

## Why this exists

Most adversary-emulation tools land in one of three failure modes:

- Compliance simulators with green dashboards and no realistic offensive telemetry.
- Fragmented script collections with realism but no orchestration, telemetry contract, or safety story.
- Unsafe operator suites with realism and orchestration but no gating or defensive output.

BlueFire Nexus tries to bridge these:

- Offensive realism preserved. Per-actor APT adapters, C2 protocol research, stealth and credential-access tradecraft, kept in tree behind explicit gates.
- Defensive output every run. Sigma / YARA-L / SPL drafts, ATT&CK coverage maps, and a risk summary readable by a SOC analyst.
- Local-first. No SIEM connectors, no remote observability, no required cloud account. Air-gapped use is supported by default.
- Reproducible. Predictable artifact paths, a manifest schema, and a deterministic static dashboard.
- Gated, not sanitised. Dangerous code paths are still in the repo; you have to opt in to run them.

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

# Run a scenario (simulate-only, dry-run, no network)
python -m src.run_scenario --profile apt29_credential_access --output-json

# Inspect the results
python -m src.core.cli latest-run            # prints a file:// link to index.html
python -m src.core.cli list-runs             # everything in output/
python -m src.core.cli validate-run <run_id> # check the bundle is complete

# Open the static dashboard with file:// (no server required)
#   Linux:   xdg-open output/<run_id>/index.html
#   macOS:   open       output/<run_id>/index.html
#   Windows: start       output\<run_id>\index.html
```

The default flow is fully offline. No `.env` file, no API key, no network call. The deterministic template AI provider produces copilot artifacts without external dependencies.

To enable a remote AI provider, copy `.env.example` to `.env` and set the relevant key. See [docs/USAGE_GUIDELINES.md](docs/USAGE_GUIDELINES.md#ai-provider-configuration).

The full demo scenario is `enterprise_intrusion_chain` (12 standard modules, five step-to-step propagation pairs):

```bash
python -m src.run_scenario --profile enterprise_intrusion_chain --output-json
```

A broader CLI / scenario / configuration reference is in [docs/USAGE_GUIDELINES.md](docs/USAGE_GUIDELINES.md). Architecture and the `ModuleResult` contract live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## What a run produces

```
output/
├── index.html                   # top-level aggregator listing every run on disk

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

Splunk SPL is generated as local detection-rule output. It is not a Splunk exporter or SIEM connector.

### Detection draft maturity

The three engines are not equally mature. Generated drafts are starting points for a detection engineer, not finished detections to deploy verbatim:

- Sigma (most mature). Full document with `title`, `id`, `logsource`, `detection.selection`, `detection.condition`, `tags`, `level`. Reusable in a SIEM pipeline after review.
- YARA-L (medium). UDM event mapping derived from the same Sigma `logsource` and `detection.selection`. Usable as a Chronicle / Google SecOps starting point after parser-field review.
- SPL (draft / starter). Each `.spl` file carries a leading multi-line backtick header marking it as a draft. Adjust `index=` and `sourcetype=` per environment before deploying.

The dashboard's "Detection drafts" KPI counts every file written across all three engines. Treat the count as scope ("how many techniques fired?"), not maturity ("how many production detections do I have?"). The `coverage_<run_id>.json` sibling enumerates each draft's module / technique / engine paths for programmatic readouts.

### Static dashboard

`index.html` is one HTML file with an inline `<style>` block and zero JavaScript. Every value is HTML-escaped, every artifact link is run-dir-relative, and the run directory can be moved or zipped without breaking the page.

The dashboard renders, in order:

1. Header. Scenario name, run id, status / dry_run / AI-mode badges, severity badge, scenario `objective:` paragraphs, AI provider attribution.
2. KPI grid. Steps, techniques, detection drafts, telemetry events, blocked steps, plus a "Module status" mini-chart (pure-CSS bars).
3. Risk summary. Tier totals plus a per-module table with severity badge, score, mode, and rationale (`tactic_base=<tactic>`, `matters_because=<chain-position text>`).
4. Scenario timeline. Ordered steps with status, per-step severity column, ATT&CK techniques, and a notes column for non-success rows.
5. Propagation graph. From-step / to-step / kind rows plus a defender-facing narrative column.
6. ATT&CK coverage. Technique to emitting steps.
7. Telemetry summary. Counts by event type and module, rendered as deterministic CSS bar charts.
8. Detection drafts. Per-engine counts plus per-step paths.
9. AI copilot. Provider, model, network state, fallback marker, link to the artifact.
10. Artifact quick links. Each renders only when the file exists; missing artifacts surface as inert "not present" text.

The CLI exposes six commands for working with runs locally:

```bash
python -m src.core.cli list-runs                   # newest first
python -m src.core.cli latest-run                  # most recent run detail
python -m src.core.cli show-run <run_id>           # single-run detail
python -m src.core.cli build-report-view <run_id>  # regenerate per-run index.html
python -m src.core.cli build-output-index          # regenerate top-level output/index.html
python -m src.core.cli validate-run <run_id>       # gate-style bundle check
```

All six honour `general.output_root` / `BLUEFIRE_OUTPUT_ROOT` and accept `--output-root <path>` for ad-hoc discovery. None starts a server. None auto-opens a browser. `validate-run` exits non-zero when the bundle is missing artifacts or has broken viewer links, useful as a CI gate before sharing a run output.

The top-level `output/index.html` aggregator lists every run on disk newest-first with scenario name, status, severity, started timestamp, step count, and quick links into each run's viewer / manifest / report / risk summary. Same self-contained constraints as the per-run dashboard.

---

## Modes and safety

Every run is shaped by three orthogonal mode controls. Defaults are safe; advanced behaviour requires explicit opt-in.

- `general.dry_run` (default `true`). When true, no module invokes real subprocess / socket / HTTP primitives. Enforced by [tests/test_module_safety.py](tests/test_module_safety.py).
- Legacy capability `mode`: `simulate` (default for any enabled capability) or `emulate`. `emulate` requires explicit `lab_confirmation: true`.
- `ExecutionModule.allow_real_execution` (default `false`). Real `subprocess.run` invocations require BOTH `dry_run=False` AND `allow_real_execution=true`.

Additional safety primitives:

- `general.safeties.allowed_subnets`: orchestrator-level subnet allowlist.
- `general.safeties.max_runtime`: hard ceiling on per-run wall time.
- Destructive-operation acknowledgment: e.g. exfiltration with `destructive=true` is rejected unless `i_understand_this_is_a_lab=true` is also passed.
- Artifact path enforcement: [tests/test_module_artifact_paths.py](tests/test_module_artifact_paths.py) asserts no module writes outside `context["output_dir"]`.
- Bandit strict at `-ll`. Every dual-use offensive pattern carries a narrow per-line `# nosec BXXX` justification.

Full safety story: [SECURITY.md](SECURITY.md).

---

## Legacy capability packs

Four opt-in research packs preserve the most advanced offensive code paths instead of hiding or deleting them:

- Actor pack. APT29 / APT28 / APT32 / APT38 / APT41 research adapters.
- C2 / protocol pack. DNS tunneling, TLS fast-flux, QUIC, Solana RPC, network obfuscation.
- Stealth pack. Anti-forensic, anti-sandbox, anti-detection, dynamic API resolution research.
- Tactic pack. Credential-access, lateral-movement, privilege-escalation, impact, and collection research adapters wrapping the preserved per-tactic legacy classes.

All packs ship disabled by default. Enable globally with the master lab toggle or per-pack/per-capability with explicit opt-in. `simulate` is the default mode for any enabled capability; `emulate` requires `lab_confirmation: true`. The standard tactic modules (`credential_access`, etc.) remain simulate-only and are NOT routed through the legacy adapters; scenarios that want the legacy behaviour must use `module: legacy_<tactic>` explicitly.

Full enable/disable surface, preset profiles, and YAML examples: [docs/USAGE_GUIDELINES.md](docs/USAGE_GUIDELINES.md). Per-pack case studies: [docs/case-studies/](docs/case-studies/).

---

## AI / copilot layer

- Default is offline / template. A deterministic local provider produces copilot artifacts every run with no external dependencies and no API key required.
- Provider-agnostic interface. Canonical names (`openai`, `anthropic`, `gemini`, `grok`, `ollama`, `openai_compatible`, `llama.cpp`, `lm-studio`) are equal optional opt-in targets. No vendor is privileged as the default. Aliases (`google` to `gemini`, `xai` to `grok`, `claude` to `anthropic`) are normalised at factory time.
- API keys via env vars only. `modules.ai.api_key_env` names the environment variable; the runtime never reads from disk and the key never appears in config files.
- Optional fallback chain. `modules.ai.fallback_provider` (typically `template`) routes around primary failures so a remote outage degrades gracefully to deterministic offline output.
- Artifact metadata header. Every copilot artifact starts with a YAML-front-matter block carrying `provider`, `model`, `generated_at`, `network_disabled`, `fallback_used`, and (when present) the run's scenario summary so artifacts reflect actual scenario context.

Full reference: [docs/reports/ai_layer.md](docs/reports/ai_layer.md). Operator-facing config: [docs/USAGE_GUIDELINES.md](docs/USAGE_GUIDELINES.md#ai-provider-configuration).

---

## Development & tests

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

- [tests/test_module_contract.py](tests/test_module_contract.py): every module returns a conformant `ModuleResult` (correct fields, types, status from `success | failure | blocked | skipped | partial_success`).
- [tests/test_module_safety.py](tests/test_module_safety.py): no module touches `subprocess`, `socket`, `requests`, or `urllib` while `dry_run=True`, in either lab-off or lab-simulate mode.
- [tests/test_module_artifact_paths.py](tests/test_module_artifact_paths.py): every module writes its files only under `context["output_dir"]` and registers them in `ModuleResult.artifacts`.

---

## Limitations & scope

This is a security-research and detection-engineering tool, not a production breach-and-attack platform.

- Single-host execution. Scenarios run on the box you launch them on. No agent, no controller / agent split, no remote execution mesh.
- No live destructive behaviour by default. `dry_run=True`, `simulate` mode, and `allow_real_execution=false` are all in effect on a fresh install. You have to flip multiple gates explicitly to invoke real research code.
- No outbound integrations in the baseline. SIEM exporters, remote observability, hosted dashboards, telemetry shipping: none of those exist on the active path. Telemetry is local JSON Lines.
- AI providers are opt-in. The default `template` provider is fully offline and deterministic. Remote providers require explicit `modules.ai.enabled: true` plus an operator-supplied endpoint and (for vendor-specific backends) an API key resolved from an environment variable. No keys are bundled or written to disk.
- `emulate` mode is gated. Legacy adapter packs default to `simulate`. `emulate` requires `lab_confirmation: true` and runs preserved research code paths that synthesise local artifacts; they do not open real network sockets in dry-run.
- For authorized research only. The framework is dual-use. Use it on systems you own or have written permission to test. See [SECURITY.md](SECURITY.md) for the full threat model.
- Static dashboard, not a live UI. `output/<run_id>/index.html` regenerates on every run. There is no SPA, no auto-refresh, and no server. Re-run the scenario or `build-report-view` for an updated view.

If your use case requires distributed execution, live data shipping, or a hosted dashboard, BlueFire Nexus is not the right tool today.

---

## Further reading

- Architecture and ModuleResult contract: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Operator usage and CLI reference: [docs/USAGE_GUIDELINES.md](docs/USAGE_GUIDELINES.md)
- Security and threat model: [SECURITY.md](SECURITY.md)
- Capability inventory: [docs/reports/capability_inventory.md](docs/reports/capability_inventory.md)
- Scenario validation: [docs/reports/scenario_validation.md](docs/reports/scenario_validation.md)
- AI layer reference: [docs/reports/ai_layer.md](docs/reports/ai_layer.md)
- Per-pack case studies: [docs/case-studies/](docs/case-studies/)

---

## Disclaimer

BlueFire Nexus is dual-use security research tooling. Use only in authorized, isolated environments for defensive testing, purple-team validation, and security research. The author and contributors accept no responsibility for misuse.

---

## License

MIT. See [LICENSE](LICENSE).
