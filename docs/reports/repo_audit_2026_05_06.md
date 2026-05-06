# Repository accounting + integration audit (2026-05-06)

Whole-repo maintenance pass to confirm every meaningful file, scenario,
test, CLI command, and doc claim is accounted for, tested, or
intentionally preserved. Frame is project maintenance — no behavioural
or architectural redesign.

## Summary

| Area | Status |
|---|---|
| File inventory | 118 .py files in `src/`. All accounted for under one of: active runtime / standard module / legacy adapter / preserved legacy / AI / reporting / support / CLI / examples / orphan-low-value (3 files). |
| Import reachability | Active graph traces from `BlueFireNexus`, the typer CLI, and `src.run_scenario`. `legacy_runtime.py` uses `importlib.import_module` for preserved-legacy code, which both defers heavy imports and breaks any latent cycles. No circular import risks detected. |
| Import-time side effects | One file (`src/core/crypto.py`) imported the optional `pqcrypto` package at top level; fixed in this PR by deferring the import to first use. Other `import ctypes` references are platform-dispatched at call time, not at import. No subprocess / network / file-write at import time. |
| CLI surface | `src/run_scenario.py` (argparse) + 16 typer commands in `src/core/cli.py`. All `--help` reachable. Two commands (`risk-summary`, `legacy-run-risk`) hardcoded `Path("output")` instead of honouring `general.output_root` / `BLUEFIRE_OUTPUT_ROOT`; fixed in this PR via a new module-level `resolve_output_root` helper. |
| Remote SIEM / exporter behaviour | None. The `REMOVED_REMOTE_SINK_TYPES` warn-and-ignore guard in `src/core/telemetry/sinks.py` covers `splunk` / `splunk_hec` / `opensearch` / `elasticsearch` / `ngsiem` / `http_bulk`. No HTTP / syslog / network sink calls anywhere on the active path. |
| Scenario coverage | 10 scenarios. `enterprise_intrusion_chain` is the only full kill-chain; the rest are tactic-slice or legacy-adapter exercises. `previous_step_results` is plumbed through the runtime but no scenario consumes it yet (per-module opt-in is intentional). |
| Test coverage | 683 passing tests, 5 intentional skips, 0 failures. Two coverage gaps closed in this PR: dedicated `test_risk.py` (17 tests) and `test_module_registry.py` (7 tests). |
| Docs consistency | README counts (tests / modules / scenarios) match current state. No internal-process notes detected. No SIEM-exporter claims. AI-provider claims match the offline-template default in code. |

## Inventory categories

| Category | Files | Notes |
|---|---:|---|
| Active runtime | ~38 | Reachable from `BlueFireNexus.__init__`, `run_scenario_file`, `execute_operation`, both CLI entrypoints. |
| Standard tactic modules | 1 file (17 classes) | `src/core/modules/impl/standard_modules.py`. |
| Legacy adapters | 1 file (14 classes) + `legacy_base.py` + `legacy_runtime.py` | `src/core/modules/impl/legacy_packs.py`. |
| Preserved legacy classes | ~40 | Per-tactic, per-OS, actor classes, C2 protocol research. Loaded via `importlib.import_module(...)` from `legacy_runtime.py`; preserved by design for lab-gated emulate-mode use. |
| AI / operator | 5 | `src/core/ai/{copilot,providers,rag,mutation,legacy_compat}.py`. All actively imported. |
| Reporting | 5 | `src/core/reporting/*.py`. |
| Support | 12 | telemetry, safety, config, models, utils. |
| CLI | 3 | `run_scenario.py`, `core/cli.py`, `core/bluefire.py` (one-line shim). |
| Examples | 2 | `src/examples/`. |
| Orphan / low-value preserved code | 3 | See "Orphans" below. |

### Orphans (preserved, not deleted)

Three files are not currently imported by any runtime or test path,
but each represents preserved capability rather than accidental
abandonment. Per the project's non-negotiable to not remove
adversary-emulation capability, none are deleted in this PR. Surfaced
here for awareness.

- `src/core/bluefire.py` — two-line shim re-exporting `cli.main`. Safe
  to delete only if README / packaging metadata stop referring to it
  as an entrypoint.
- `src/legal_safeguards.py` — `secure_wipe(path)` defensive helper.
  Plausible legacy preservation; review before any future cleanup.
- `src/modules/evasion_techniques.py` — Windows-only memory-evasion
  research class with explicit `nosec B413` justification and a
  pycryptodome dependency. Stale alternate location predating
  `src/core/`.

## Bugs fixed in this PR

| Source of finding | Fix |
|---|---|
| CLI audit | `src/core/cli.py:303` (`risk-summary`) and `:584` (`legacy-run-risk`) used hardcoded `Path("output")`, ignoring `general.output_root` / `BLUEFIRE_OUTPUT_ROOT`. Routed through a new module-level `resolve_output_root` helper extracted from `BlueFireNexus._output_root`. |
| Inventory audit | `src/core/crypto.py` imported `pqcrypto.sign.dilithium3` at top level; importing the module at all crashed on hosts without that optional dep. Lazy-imported inside `QuantumCrypto.__init__` with a clear error message; preserved class semantics. |
| Test coverage audit | No dedicated `test_risk.py`; `score_module_result` and `severity_from_score` were only exercised indirectly through reporting tests. Added 17 direct tests covering severity bands, standard-vs-legacy paths, runtime warnings, status deltas, clamping, and detection-hint fallbacks. |
| Test coverage audit | No dedicated `test_module_registry.py`; the 17-standard / 14-legacy registry shape was only checked indirectly via contract tests. Added 7 tests pinning expected names, name/instance agreement, no standard/legacy collisions, and stable `BUILTIN_MODULE_CLASSES` ordering. |

## Areas not addressed (out of scope; surfaced for follow-up)

These are observations, not requested changes:

- Three orphan files surfaced above. Decision needed before any
  archival / deletion.
- Several scenarios could opportunistically demonstrate
  `previous_step_results` consumption once individual modules opt
  into reading it (the runtime plumbing is already live).
- `src/core/ai/rag.py` is implemented but has no dedicated test file.
- `command_control` legacy adapter has fewer tests than its peers
  (1 vs. ~8 each).
- `src/core/experiments.py` coverage is essentially smoke; failure
  paths and seed-determinism cases are unsampled.

## Validation

- `pytest tests/test_risk.py tests/test_module_registry.py -v` → 24 passed
- `pytest tests/` → **683 passed, 5 skipped, 0 failed** (~41s)
- `bandit -r src -ll` → 0 medium / 0 high
- `compileall -q src tests` → clean
