# Changelog

All notable changes to BlueFire-Nexus are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The detailed merged-PR history lives in
[`docs/reports/next_roadmap.md`](docs/reports/next_roadmap.md).
This file summarises the deltas at the version-tag granularity.

## [Unreleased]

### Changed

- Risk scoring (`src/core/risk.py`) now uses a tactic-aware base
  score for standard modules so end-of-chain destructive tactics
  (e.g. `impact` -> 85 base, `exfiltration` -> 75 base) surface
  as `critical` / `high` severity, while pre-foothold tactics
  (`reconnaissance` / `resource_development` -> 25 base) stay
  `low`. Previously every standard-module result landed at score
  35-55 ("low" / "medium") regardless of tactic — a successful
  ransomware-impact step scored the same as a benign file-discovery
  step. Modules whose `name` is not in the new
  `_TACTIC_BASE_SCORES` map keep the historic default base (35),
  preserving behaviour for out-of-tree callers. Legacy adapter
  scoring is unchanged (the legacy branch still wins via `pack`
  presence in artifacts).
- `anti_detection` standard module now selects from a 12-entry
  technique profile catalog (`memory_evasion`, `code_obfuscation`,
  `anti_debug`, `anti_sandbox`, `anti_vm`, `timestomp`, `log_clear`,
  `dynamic_api`, `reflective_loading`, `process_hollowing`,
  `string_encryption`, `api_unhooking`). Each entry maps to a
  real defense-evasion ATT&CK sub-technique and emits a Sigma-style
  draft using Sysmon-recognisable Windows event field names
  (`ParentImage`, `CommandLine`, `TargetFilename`, `TargetObject`,
  `CallTrace`, `ImageLoaded`). The previous behaviour was a single
  hardcoded handler that always emitted T1027 with the synthetic
  `anti_detection.method` field as the detection key — Sigma rules
  generated from that could not fire on any real telemetry.
- `scenarios/apt29_credential_access.yaml` `attack_coverage` swap
  T1027 → T1055 to match the upgraded `memory_evasion` profile
  (which is properly Process Injection, not Obfuscated Files).

### Tests

- New `tests/test_anti_detection_module.py` (+24): per-method
  MITRE/event-type fan-out, distinct event types per profile,
  logsource diversity assertion, real-Sysmon-field invariant,
  target propagation via `target_from_step`, no-regression to
  the `anti_detection.method` synthetic field.
- `tests/test_risk.py` extended (+12) with tactic-aware
  invariants: impact -> critical, exfiltration -> high,
  discovery -> low, ordering across recon -> initial_access ->
  credential_access -> exfiltration -> impact, blocked-impact
  dampener, errored-recon floor, unknown-module fallback,
  legacy-branch precedence preservation.
- `tests/test_fanout_batch.py` parametrization extended to cover
  `AntiDetectionModule` (+5 tests via the existing 5 fan-out
  invariants × the new module).

## [3.0.0-rc1] - 2026-05-07

First release-candidate of the rebuilt local-first adversary-
emulation baseline. Major-version bump from `v2.8.0` reflects
that the artifact contract, module registry, AI layer, and
safety model have all been re-architected since the prior
release lineage; existing `v2.x` integrations should treat this
as a breaking change and re-validate against the new module
registry and manifest schema.

This is a **release candidate**: the maintainer may publish
`-rc2`, `-rc3`, etc. in response to operator feedback before
cutting the bare `v3.0.0` tag.

Headline story (full per-PR history lives in
[`docs/reports/next_roadmap.md`](docs/reports/next_roadmap.md)):

### Added

- **Local report viewer.** Every run now writes
  `output/<run_id>/manifest.json` (machine-readable index of
  every artifact) and `output/<run_id>/index.html` (a static,
  fully self-contained dashboard — no JavaScript, no external
  assets, no network calls). Viewer renders the scenario
  timeline, propagation graph, ATT&CK coverage, telemetry
  counts, detection drafts, risk summary, and AI provider
  attribution.
- **CLI commands for runs.** `list-runs`, `latest-run`,
  `show-run`, `build-report-view`, `build-output-index`, and
  `validate-run` round out the local-only workflow. None starts
  a server or auto-opens a browser.
- **Top-level run index aggregator.** A static `output/index.html`
  page lists every run newest-first with quick links into each
  run's viewer / manifest / report / risk summary. Same
  self-contained constraints as the per-run viewer (no JS, no
  external assets, no network). The orchestrator refreshes the
  aggregator after every run; `list-runs` / `latest-run`
  surface a `file://` link to it when present.
- **Pure-CSS mini-charts in the run viewer.** Telemetry counts
  by type and by module render as deterministic horizontal bar
  charts (alphabetical key order, widths clamped to 1–100%);
  the KPI grid gains a "Module status" card with tier-coloured
  bars for success / blocked / error / skipped step counts.
  Still pure HTML + inline CSS — no JavaScript, no SVG, no
  external assets.
- **Provider-agnostic AI layer.** `template` (offline default),
  `openai_compatible`, `openai`, `anthropic`, `gemini`, `grok`,
  `ollama`, `llama.cpp`, and `lm-studio` all route through a
  shared `ProviderFactory`. Anthropic and Gemini have
  vendor-specific adapters; the rest use the shared
  OpenAI-compatible HTTP backend. Default is offline /
  template — no API keys required.
- **Step-to-step propagation.** Four consumer pairs are
  demonstrated end-to-end in `enterprise_intrusion_chain`:
  `discovery → credential_access`,
  `credential_access → lateral_movement` (source axis),
  `collection → exfiltration`, and `collection → impact`.
- **Cross-cutting simple-mode presets.** `local_safe`,
  `lab_legacy_enabled`, `ai_enabled`, `ai_disabled`, and
  `strict_local` (loopback-only safety gates).

### Changed

- `--output-json` now produces JSON-only stdout so the README
  quickstart command pipes cleanly into `jq`. Advisory rich
  output routes to stderr.
- README quickstart is now a four-step end-to-end walkthrough
  (clone+install / run / inspect / open) with platform
  variants for `open` / `xdg-open` / `start`.
- Static viewer renders risk summary above the scenario
  timeline; per-module severity badges use the same colour
  palette as the status badges; timeline carries a `notes`
  column for non-success rows.
- `find_run_dir` and `validate_run_bundle` reject path-shaped
  run ids and out-of-bundle hrefs respectively, so neither
  command can read or write outside the configured output
  root.

### Security

- Default `dry_run: true` enforced by registry-wide tests
  (`tests/test_module_safety.py`). No module invokes
  `subprocess` / `socket` / `requests` / `urllib` while
  `dry_run` is on.
- No SIEM exporters or remote observability anywhere on the
  active path. Legacy `telemetry.sinks` config entries naming
  removed remote types are warn-and-ignored at load time.
- Provider calls require explicit `modules.ai.enabled: true`
  plus an operator-supplied endpoint (and, for vendor-specific
  backends, a credential resolved from an environment variable).
- AI keys are read from environment variables only; never
  bundled, never written to disk.

### Tests

- Cross-adapter parity audit across the seven `legacy_*`
  modules (77 parametrised tests) plus per-capability depth
  tests for `legacy_protocol_research` and
  `legacy_stealth_research`.
- 10-test enterprise-chain quality invariant suite (unique
  step ids, every step in dry-mode, forward-reference detection
  on propagation slots, all four pairs demonstrated, declared
  ATT&CK coverage matches runtime emitted coverage).
- 18-test demo-bundle validator suite (no broken viewer links,
  no external schemes, no absolute paths, complete artifact
  set on both flagship scenarios).
- 10-test quickstart smoke harness exercising the full README
  end-to-end via subprocess.
- Final baseline at the rc1 cut: **1525 passed, 5 skipped, 0
  failed** (~98-110s wallclock).

### Pre-rc1 polish fixes

Five focused PRs landed between the original rc1 cut and the
current rc1 baseline, each surfaced by a fresh-clone Windows
smoke run and pinned by tests so they cannot regress:

- **YARA-L `meta.run_id` correlation parity** (PR #89). The
  detection engine wrote real run ids into Sigma rules but
  hardcoded `run_id = "manual"` in YARA-L. A defender
  correlating Sigma <-> YARA-L drafts on `run_id` could not.
  Fixed: `generate_yara_l` now accepts a keyword-only `run_id`
  and the engine threads the real value through.
- **SPL upgrade from metadata echo to real draft** (PR #89).
  The previous renderer emitted `| makeresults | eval ...`
  only — round-tripped run metadata, never touched any data
  source. New shape maps the Sigma `logsource` block onto
  common Splunk sourcetypes (`WinEventLog:Security`, `Sysmon`,
  `linux_audit`, `stream:dns`, etc.), surfaces the Sigma
  `selection` clause as `where` filters, attributes the search
  to the run via `eval`, aggregates with `stats`, and carries
  a leading multi-line backtick `DRAFT detection search`
  comment header so the dashboard cannot oversell maturity.
  Honest README framing in the new "Detection draft maturity"
  section spells out: Sigma most mature, YARA-L medium, SPL
  draft / starter.
- **Cross-platform-safe filenames** (PR #94). The orchestrator
  builds module-result keys as `f"{module}:{step_id}"` to
  disambiguate steps that reuse the same module. That colon
  flowed straight into the detection-artifact filename. On
  NTFS, Windows interprets `:` as the Alternate Data Stream
  separator; the visible filename truncated and the rule body
  was silently lost into an ADS, leaving 0-byte detection
  files behind. Fixed: a `_safe_filename_component` helper
  replaces unsafe characters (`: * ? " < > | / \`) with `__`;
  the manifest / coverage records still carry the original
  colon-separated key.
- **Windows CLI mojibake + `file://` URL on its own line**
  (PR #91). Em-dash (U+2014) in user-facing CLI strings
  rendered as `?` on Windows non-UTF-8 terminals. `file://`
  viewer URLs printed inline could be wrapped by rich's word
  wrap, breaking copy-paste. Fixed: every em-dash in
  `src/core/cli.py` replaced with ASCII (source-level invariant
  pinned by test); URLs now print on a standalone line via
  `console.print(uri, no_wrap=True, overflow="ignore")`.
- **README `.env` quickstart drift** (PR #92). The prior
  `cp .env.example .env` step in the canonical quickstart was
  misleading — the default offline / template AI flow does not
  need `.env` at all. Moved out of the canonical block; framed
  as "only needed when enabling a remote AI provider" in a
  follow-up paragraph that points to USAGE_GUIDELINES.
- **Offline TemplateProvider artifact quality** (PR #93). The
  template provider previously returned a generic 5-line stub
  for every prompt. New behaviour parses the orchestrator's
  `[run summary]` block out of the prompt and renders an
  intent-aware artifact: SOC narrative for `narrate` (with
  step-by-step timeline replay, blocked-step callouts,
  run-specific next-validation paths under `output/<run_id>/`);
  detection-strategy summary for `suggest_detections`
  (per-technique pointers + honest maturity framing);
  scenario YAML skeleton for `plan`. Stays deterministic, no
  network, no API key required.

### Removed

- SIEM exporters and remote observability connectors (Splunk
  HEC, OpenSearch, Elasticsearch, NGSIEM, generic HTTP bulk).
  Legacy `telemetry.sinks` config entries naming removed
  remote types are warn-and-ignored at load time so old configs
  do not crash and do not silently regain network egress.

### Notes for operators upgrading from `v2.8.0`

- The artifact contract has changed. Every run now produces a
  `manifest.json` with a stable schema (see
  `src/core/reporting/manifest.py`) and a self-contained
  `index.html` viewer. Downstream tooling that previously
  parsed `report.json` directly should migrate to reading
  `manifest.json` first.
- The module registry has been re-architected. Standard tactic
  modules are simulate-first and never auto-route through
  legacy code paths; scenarios that need legacy behaviour must
  use an explicit `module: legacy_<tactic>` adapter. The
  `enable_all_lab_capabilities` master toggle, per-pack mode
  flags, and per-capability `lab_confirmation` gates are
  unchanged in shape but the dispatch surface they govern has
  been re-grouped.
- The AI layer is provider-agnostic. The default has remained
  offline / template — no network calls, no API keys required
  for default use. Operator-facing config keys (`modules.ai.*`
  + `ai_providers.<name>.*`) are documented in
  `docs/USAGE_GUIDELINES.md` § AI provider configuration.

## [2.8.0] - 2025-02-23

Last published release of the prior lineage. Predates the
artifact-contract / module-registry / AI-layer rebuild. Kept on
GitHub Releases for historical reference; operators on `v2.8.0`
should treat `v3.0.0-rc1` as a breaking-change upgrade and
re-validate against the new manifest / viewer contract.

## [1.0.0] - 2024-03-20

Pre-`v2.8.0` historical entry. Initial public release of the
earlier lineage. Module framework, scenario runtime, local
telemetry, ATT&CK-mapped detection drafts, purple-team reports,
and gated legacy capability packs. Predates the `v2.8.0`
published release and the `v3.0.0-rc1` rebuild; kept here for
context only.

## [0.1.0] - 2024-03-01

Pre-`v2.8.0` historical entry. Initial development release.
