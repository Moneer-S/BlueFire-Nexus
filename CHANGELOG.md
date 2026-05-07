# Changelog

All notable changes to BlueFire-Nexus are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The detailed merged-PR history lives in
[`docs/reports/next_roadmap.md`](docs/reports/next_roadmap.md).
This file summarises the deltas at the version-tag granularity.

## [Unreleased]

This section captures changes since the last tagged release.

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

## [1.0.0] - 2024-03-20

Initial public release. Module framework, scenario runtime,
local telemetry, ATT&CK-mapped detection drafts, purple-team
reports, and gated legacy capability packs.

## [0.1.0] - 2024-03-01

Initial development release.
