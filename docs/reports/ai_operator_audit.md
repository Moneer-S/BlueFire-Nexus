# BlueFire-Nexus AI / operator-planning layer audit

Snapshot at `main` = `c0b0669`. Audits `src/core/ai/`, `src/core/experiments.py`,
and the AI invocation paths in `src/core/bluefire_nexus.py` and the CLI.

## Scope

- `src/core/ai/__init__.py` (7 lines)
- `src/core/ai/copilot.py` (76 lines)
- `src/core/ai/legacy_compat.py` (17 lines)
- `src/core/ai/mutation.py` (129 lines)
- `src/core/ai/providers.py` (84 lines)
- `src/core/ai/rag.py` (98 lines)
- `src/core/experiments.py` (192 lines)
- Test coverage: `tests/test_copilot.py`, `tests/test_mutation.py`, `tests/test_experiments.py`, `tests/test_experiments_jitter.py`

Total: ~600 lines of code, ~5 test files.

## Component-by-component

### `providers.py` — partially functional
- `LLMProvider` (Protocol) — declares `name`, `model`, `complete(prompt, context)`.
- `TemplateProvider` — **fully functional offline.** Returns a deterministic stub message that includes a `prompt_summary` and a `context_preview`. No external dependencies.
- `OpenAICompatibleProvider` — **DEAD CODE (intentionally inert).** `complete()` body explicitly does NOT call any external API even if `endpoint` and `api_key` are configured; it returns a hardcoded string saying "Network completion is intentionally disabled by default." There is no plumbing to actually invoke OpenAI / Anthropic / Google / Ollama / LM Studio / llama.cpp despite all 7 names being listed in `SUPPORTED_REMOTE`.
- `ProviderFactory.build()` — returns `TemplateProvider` for `template`/`none`, returns the inert `OpenAICompatibleProvider` for any of the 7 "supported" remote names, falls back to `TemplateProvider` otherwise.

**What works offline:** TemplateProvider only.
**What requires API keys:** Nothing — even with keys, the OpenAICompatibleProvider does not use them.
**What is dead code:** The remote-provider branch is theatre. None of the 7 named providers actually call out.

### `copilot.py` — wired to provider but inherits its inertness
- `AICopilot.__init__` builds an `RAGIndex` over `README.md`, `docs/ARCHITECTURE.md`, and the run's `report.md` (which doesn't exist when copilot is constructed at run start).
- `_ask(prompt)` runs a TF-IDF search through the RAG index, then calls `provider.complete(prompt, context)`. Always lands on a real provider call — but as noted above, that call is a stub.
- `plan(goal)` writes `copilot_plan.txt`.
- `narrate(run_id)` writes `copilot_narrative.md`.
- `suggest_detections(run_id, metadata)` writes `copilot_detections.md`.

**What works:** All three methods write artifact files for every run, with deterministic fallback content. The RAG retrieval works.

**What is misleading:** The artifacts' presence implies AI involvement. With the default config they contain no model-generated content — they contain whatever `TemplateProvider.complete()` returns plus a context preview from the RAG retrieval. Operators reading `copilot_narrative.md` may assume an LLM authored it.

**Test coverage:** `tests/test_copilot.py` exists and is presumably testing the offline-fallback path (passes in CI). Does not test what happens when a real provider should be called (because no real provider is wired).

### `rag.py` — functional, simple, useful
- TF-IDF retrieval over markdown/text/json/yaml files. ~98 lines, no external deps. Already cited in `copilot.py` and could be used independently.
- One `# nosec B112` (silent error continue when reading unreadable files). Justified inline.
- No tests dedicated to this module specifically.
- **Status: works, useful, under-leveraged.** Could power a "suggest similar prior runs" feature without any provider work.

### `mutation.py` — functional but disconnected from runs
- `mutate_step_params(params, *, allowed, strategy="low_noise")` — applies `_apply_strategy_mutation` if `allowed=True`, otherwise returns identity. Returns a `MutationResult` dataclass with `original`, `mutated`, `rationale`.
- `mutate_steps(steps, *, allowed, strategy)` — list version.
- `mutate_technique(module_name, base_params, *, strategy="evasion-lite", run_id="unknown")` — generates a lab-scoped mutation payload that forces `i_understand_this_is_a_lab=True`, `network_touch=False`, `dry_run_only=True`. Returns a richer dict.
- Strategies recognized: `low_noise` / `evasion-lite` (command and timing tweaks), `protocol_shift` / `protocol-shift` (http→dns→https→http rotation, retry interval bump), anything else (generic variant marker).
- Test coverage: `tests/test_mutation.py` exists.

**What works offline:** All of it. No provider involvement.

**The disconnect:** None of the three functions are called from `run_scenario.py`, the Typer CLI in `src/core/cli.py`, or `BlueFireNexus.run_scenario_file`. There is no `--mutate` flag. The mutation engine is purely a Python API; if you want to use it, you have to import it yourself.

### `experiments.py` — functional, wired to scenarios, half-AI
- `run_experiment(nexus, scenario_path, runs=5, seed=None, jitter=False)` — runs the same scenario N times. Optional `jitter=True` enables `_mutate_run_params` which adds bounded random noise to step params between runs.
- `run_experiment_series(scenario_path, iterations=3, jitter=False)` — wrapper for tests/CLI returning a dict summary. Spins up its own `BlueFireNexus()`.
- The "mutation" here is decorated random params (`intensity: low|medium`, `noise_ratio: 0.05-0.20`, `variant: baseline|alt-path`), NOT a call to `mutation.py`. So `experiments.py` and `mutation.py` are independent rather than composable.

**Test coverage:** `tests/test_experiments.py`, `tests/test_experiments_jitter.py`. Both exist and pass.

**What works offline:** All of it. No provider involvement.

**Disconnect:** `experiments.py` cannot use `mutation.py` strategies (`low_noise`, `protocol_shift`). The two AI-adjacent components don't compose.

### `legacy_compat.py` — small alias layer
- `AIProvider = LLMProvider` re-export.
- `build_provider(config)` — old-shape helper that calls `ProviderFactory.build`.
- 17 lines, no tests dedicated.
- **Status: harmless, low value.** Could be removed if no caller imports it; safer to keep as a compat shim.

## Path-by-path decision matrix

| Path | Today | Recommended near-term action |
|---|---|---|
| Default `template` provider | works offline; deterministic stub artifacts every run | Mark explicitly in copilot output that this is template content, OR skip writing copilot artifacts when provider is template |
| Remote providers (7 names listed) | inert stub regardless of config | Either remove from `SUPPORTED_REMOTE` until implemented, OR implement one (Ollama is best fit for offline-first) |
| RAG retrieval | works, used by copilot | Could be exposed as a CLI tool: "find related prior runs / docs for query X" |
| `mutation.mutate_*` | works as Python API; not reachable from CLI | Add `--mutate <strategy>` to `run_scenario` |
| `experiments.run_experiment*` | works; reachable from CLI presumably; jitter is independent of mutation | Compose: let `--jitter` use a `mutation.py` strategy by name |
| `legacy_compat.AIProvider` | works | Leave alone |

## What works offline

| Component | Works offline? |
|---|:-:|
| `RAGIndex` | yes |
| `TemplateProvider` | yes |
| `OpenAICompatibleProvider` | yes (returns stub even with keys) |
| `AICopilot.plan/narrate/suggest_detections` | yes (via TemplateProvider fallback) |
| `mutate_step_params/steps/technique` | yes |
| `run_experiment/run_experiment_series` | yes (no provider use) |

**Headline:** the entire AI layer works offline. None of it requires API keys today, because none of it actually calls a remote service. That's the trade for the "intentionally inert" remote provider — operators can run BlueFire fully air-gapped without errors.

## What requires API keys

**Nothing currently.** That is both a feature (offline-first by default) and a bug (the keys configured in `.env.example` for AI providers are unused).

## Dead code

- `OpenAICompatibleProvider.complete()` body — explicitly returns a "completion is intentionally disabled" string. Either implement or delete the surrounding theatre.
- The 6 unimplemented provider names in `ProviderFactory.SUPPORTED_REMOTE` (`openai`, `anthropic`, `google`, `ollama`, `llama.cpp`, `lm-studio`). All map to the inert provider.

## Where AI can enrich adversary-chain planning (today, with TemplateProvider)

Even without a real LLM:
- **Detection-coverage explanation.** Use the RAG index to surface the docs section that explains a particular detection hint. Could be deterministic and useful.
- **Scenario validation.** Cross-reference declared `attack_coverage` to emitted MITRE techniques (already in scenario_validation roadmap).
- **Run summary.** Replace the `TemplateProvider`-generated copilot narrative with a deterministic structured summary built from `report.json` (timestamp, modules, detection-hint count, mode badges) — actually useful, no model required.

## Where AI can mutate scenarios safely

`mutation.py` already has the gating story right (`allowed=True` required, `i_understand_this_is_a_lab=True` enforced for `mutate_technique`). The missing piece is operator reachability: a CLI flag, a config setting, or a scenario-file directive that says "apply this mutation strategy to all steps." Once reachable, the safety story holds.

## Recommended sequencing (no work in this audit cycle)

1. **Make copilot opt-in.** Today it produces artifacts even when the provider is inert. Default to NOT writing copilot artifacts unless the user opts into copilot in config. This is honest and saves disk.
2. **Implement deterministic copilot fallback that's actually useful.** Replace the `TemplateProvider`-generated narrative with a structured summary built from `report.json`. Mark it clearly as deterministic, not LLM-authored.
3. **Pick one real provider and implement it end-to-end.** Ollama is the offline-first choice; OpenAI-compatible is the BYOK choice. Don't add multiple at once.
4. **Wire `mutation.py` into `run_scenario --mutate`.** Cover with a test.
5. **Compose `experiments.py` with `mutation.py` strategies** (the `--jitter` flag could accept a `mutation.py` strategy name).
6. **Remove or implement the 6 unimplemented `SUPPORTED_REMOTE` names.** No middle-ground; either commit or delete.

## Small bugs noted (none fixed in this audit cycle)

- `AICopilot.__init__` adds `run_dir / "report.md"` to the RAG index at construction time, but `report.md` doesn't exist until the run finishes. The RAG add is silently a no-op for that source on first construction. Cosmetic; could be deferred to first `_ask` call.
- `Path.cwd()` in `AICopilot.__init__` is fragile — if the caller changes cwd between import and instantiation, RAG sources point to the wrong project root. Should accept project_root as a parameter.

## Headline

The AI layer is **scaffolding with a working skeleton, no real model anywhere, and one decoupled-but-functional mutation engine the operator can't reach from the CLI.** The TemplateProvider + RAG combination produces honest deterministic artifacts that aren't really "AI." The right next step is to either (a) make those artifacts genuinely useful as deterministic structured summaries and stop calling them "copilot," or (b) implement one real provider end-to-end (Ollama is the obvious offline-first choice). Picking neither and shipping the current state long-term will erode trust in the AI value prop.
