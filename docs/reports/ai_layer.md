# BlueFire Nexus AI / operator-planning layer

Reference for the optional AI components under `src/core/ai/` and
`src/core/experiments.py`. The framework is designed to run fully
offline by default; nothing in the AI layer requires an API key for
normal operation.

## Components

| Component | Purpose | Offline-capable |
|---|---|---|
| `src/core/ai/providers.py` | Provider abstraction. Ships with a deterministic `TemplateProvider` (default) and a scaffold for `OpenAICompatibleProvider`. | Yes (template) |
| `src/core/ai/copilot.py` | Plan / narrate / detection-suggestion workflows. Writes `copilot_plan.txt`, `copilot_narrative.md`, `copilot_detections.md` to the run directory when enabled. | Yes (template fallback) |
| `src/core/ai/rag.py` | TF-IDF retrieval over markdown / text / json / yaml files. Used by the copilot for context. No external dependencies. | Yes |
| `src/core/ai/mutation.py` | Parameter mutation strategies (`low_noise`, `evasion-lite`, `protocol_shift`). Reachable from the CLI as `--mutate <strategy>`. | Yes |
| `src/core/experiments.py` | Repeated scenario runs with optional bounded jitter. | Yes |

## Provider configuration

`config.yaml` exposes the AI provider via `modules.ai.provider`:

```yaml
modules:
  ai:
    enabled: false
    provider: "template"   # or: openai, anthropic, google, ollama, lm-studio, openai_compatible
    model: "default"
    api_base: ""
```

- `template` / `none` — deterministic local fallback. No external
  dependencies, no API keys, suitable for air-gapped use.
- Remote provider names are recognized by `ProviderFactory` and produce
  a structured stub response. Real provider plumbing for any specific
  backend is planned but not active in the current baseline.

The default copilot workflow always works without API keys via the
template fallback. Enabling a remote provider is an explicit opt-in via
the config above.

## Mutation engine

The mutation engine generates safe parameter variants for repeated
scenario research. Reachable from the CLI:

```bash
python -m src.run_scenario --scenario-file scenarios/<x>.yaml --mutate low_noise
```

Available strategies:

- `low_noise` — replaces noisy commands (e.g. `echo` → `printf`) and
  bumps timing jitter.
- `evasion-lite` — alias for `low_noise`.
- `protocol_shift` — rotates the `protocol` parameter (`http` → `dns` →
  `https` → `http`) and bumps the retry interval.
- `protocol-shift` — alias for `protocol_shift`.

The mutation strategy is recorded in `report.json` as
`mutation_strategy` and printed in the run summary so mutation is never
silent.

## Experiment harness

For repeated scenario runs with optional bounded jitter:

```python
from src.core.experiments import run_experiment_series

summary = run_experiment_series(
    "scenarios/apt29_credential_access.yaml",
    iterations=3,
    jitter=False,
)
```

Output: `output/experiment-<scenario_id>/summary.json` with per-iteration
result records.

## Copilot artifacts

When the AI module is enabled, every run writes optional artifacts to
the run directory:

- `copilot_plan.txt` — scenario-plan output for a natural-language goal.
- `copilot_narrative.md` — SOC-style incident narrative for the run.
- `copilot_detections.md` — detection-strategy summary keyed off
  emitted telemetry.

With the default template provider, these artifacts contain
deterministic structured summaries derived from the run report and
RAG-retrieved documentation. With a remote provider configured, they
would contain model-generated content. Either way, the artifacts are
local-only.

## Roadmap

A real end-to-end provider implementation (most likely Ollama for
offline-first or OpenAI-compatible for BYOK) is planned. Until then,
the framework remains fully offline-capable via the template provider.
