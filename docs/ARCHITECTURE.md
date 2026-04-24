# BlueFire-Nexus Architecture

This document describes the secure, modular architecture used by BlueFire-Nexus.

## High-Level Design

```mermaid
flowchart LR
    cli["CLI (scripts/bluefire.sh + src/run_scenario.py + src/core/cli.py)"] --> orchestrator["BlueFireNexus Orchestrator"]
    scenarioLib["scenarios/*.yaml"] --> orchestrator
    config["config.yaml + .env"] --> orchestrator
    orchestrator --> moduleRegistry["Module Registry (src/core/modules/registry.py)"]
    moduleRegistry --> modules["Runtime Modules (src/core/modules/impl/standard_modules.py)"]
    modules --> telemetry["Telemetry Bus (src/core/telemetry)"]
    modules --> detections["Detection Engine (src/core/detections)"]
    modules --> report["Purple Report (src/core/reporting.py)"]
    orchestrator --> safety["Safety Gate (src/core/safety.py)"]
    report --> copilot["AI Copilot + RAG (src/core/ai)"]
```

## Execution Flow

1. CLI resolves a scenario profile or scenario file.
2. `BlueFireNexus` loads config via `ConfigManager`.
3. `SafetyGate` enforces:
   - `general.dry_run` behavior
   - `general.safeties.allowed_subnets`
   - `general.safeties.max_runtime`
   - destructive-operation acknowledgment
4. Module registry builds runtime modules (plus optional plugins).
5. Each step returns a normalized `ModuleResult`.
6. Telemetry events are emitted via sink adapters (JSONL default, remote sinks opt-in).
7. Detection artifacts (Sigma, YARA-L, SPL) are generated per module result.
8. A purple-team report is written and optionally augmented by AI copilot output.

## Key Components

- `src/core/bluefire_nexus.py`: orchestrator and scenario runner
- `src/core/config.py`: safe-by-default config loader
- `src/core/models.py`: `ModuleResult`, `TelemetryEvent`, `RunContext`
- `src/core/modules/base.py`: module contract
- `src/core/modules/registry.py`: module assembly + plugin merge
- `src/core/telemetry/sinks.py`: JSONL, OpenSearch, Elasticsearch, NGSIEM, Splunk HEC sinks
- `src/core/telemetry/bus.py`: fan-out bus
- `src/core/detections/engine.py`: detection artifact generation
- `src/core/ai/copilot.py`: plan/narrate/suggest workflows
- `src/core/ai/rag.py`: lightweight local retrieval index

## Security Model

- No secret values are committed; environment values are loaded from `.env` templates.
- Remote telemetry and AI calls are disabled by default unless explicitly configured.
- Runtime safety checks prevent out-of-scope targeting and unsafe operations.
- Security scanning and dependency auditing are enforced in CI.
