# BlueFire Nexus AI / operator-planning layer

Reference for the optional AI components under `src/core/ai/` and
`src/core/experiments.py`. The framework is designed to run fully
offline by default; nothing in the AI layer requires an API key for
normal operation. **No vendor is privileged as the default.**

## Components

| Component | Purpose | Offline-capable |
|---|---|---|
| `src/core/ai/types.py` | `ProviderOptions` (per-call options: system, temperature, max_tokens, timeout, metadata) and `ProviderResponse` (structured result: text, provider, model, usage, finish_reason, fallback_used, network_disabled, error, metadata). | n/a (data shapes) |
| `src/core/ai/providers.py` | `LLMProvider` Protocol exposing both `complete()` (legacy text) and `generate()` (rich response). `TemplateProvider` (deterministic offline default) and `OpenAICompatibleProvider` (vendor-neutral keyless stub for canonical names without an HTTP backend). `ProviderFactory` with alias normalisation and `register_provider(...)` hook for backends. | Yes (template / stub) |
| `src/core/ai/transport.py` | Injectable HTTP transport: `HTTPResponse` dataclass, `HTTPTransport` Protocol, `UrllibTransport` stdlib-only implementation. Rejects non-HTTP(S) URL schemes before issuing the request (B310 guard). | Yes (transport itself) |
| `src/core/ai/backends/openai_compatible.py` | `OpenAICompatibleHTTPBackend` — speaks the OpenAI chat-completions request/response shape over the injectable transport. Auto-registers for `openai_compatible`, `openai`, `grok`, `ollama`, `llama.cpp`, `lm-studio`. Short-circuits to offline when no `api_base` is set. | Yes (short-circuit) |
| `src/core/ai/fallback.py` | `FallbackChainProvider` — wraps a primary provider with an optional fallback. Primary success passes through unchanged; primary error invokes the fallback and records `fallback_used` + attribution metadata. | Yes (when wrapping template) |
| `src/core/ai/copilot.py` | Plan / narrate / detection-suggestion workflows. Every artifact carries a YAML-front-matter metadata header. Wraps the primary in a `FallbackChainProvider` when `modules.ai.fallback_provider` is set. | Yes (template fallback) |
| `src/core/ai/rag.py` | TF-IDF retrieval over markdown / text / json / yaml files. Used by the copilot for context. No external dependencies. | Yes |
| `src/core/ai/mutation.py` | Parameter mutation strategies (`low_noise`, `evasion-lite`, `protocol_shift`). Reachable from the CLI as `--mutate <strategy>`. | Yes |
| `src/core/experiments.py` | Repeated scenario runs with optional bounded jitter. | Yes |

## Provider catalogue

`ProviderFactory.known_canonical_names()` returns the canonical
provider names. Aliases are normalised at factory time (you can use
the alias in config; the runtime stores and reports the canonical
name).

| Canonical | Aliases | Backend (today) |
|---|---|---|
| `template` | (offline names: `none`, `""`) | `TemplateProvider` (deterministic offline) |
| `openai_compatible` | — | `OpenAICompatibleHTTPBackend` (HTTP) |
| `openai` | — | `OpenAICompatibleHTTPBackend` (HTTP) |
| `grok` | `xai`, `x.ai` | `OpenAICompatibleHTTPBackend` (HTTP) |
| `ollama` | — | `OpenAICompatibleHTTPBackend` (HTTP) |
| `llama.cpp` | — | `OpenAICompatibleHTTPBackend` (HTTP) |
| `lm-studio` | — | `OpenAICompatibleHTTPBackend` (HTTP) |
| `anthropic` | `claude` | `OpenAICompatibleProvider` (keyless stub — Messages-API adapter pending) |
| `gemini` | `google`, `google_gemini` | `OpenAICompatibleProvider` (keyless stub — GenerateContent-API adapter pending) |

Backend dispatch goes through `ProviderFactory._REGISTRY`. Phase 2
auto-registers the OpenAI-compatible HTTP backend at import time
for the canonical names whose API actually speaks that shape. The
hook for adding a new backend is one line:

```python
from src.core.ai import ProviderFactory

def my_anthropic_factory(*, provider, model, api_base, api_key,
                          provider_settings, ai_config, **_kwargs):
    return MyAnthropicAdapter(...)

ProviderFactory.register_provider("anthropic", my_anthropic_factory)
```

Unknown canonical names raise `ValueError` so registry typos fail
loudly.

## Provider configuration

`config.yaml` exposes the AI provider via `modules.ai.*`:

```yaml
modules:
  ai:
    enabled: false              # opt-in copilot artifacts
    provider: template          # default: deterministic, offline
    model: default
    api_base: ""                # endpoint URL (when applicable)
    api_key_env: ""             # name of env var holding the API key
    timeout: 30                 # per-request timeout in seconds
    max_tokens: 1024            # length cap
    temperature: null           # null = use the provider's default
    fallback_provider: ""       # "" = none; "template" = degrade to offline
```

- `template` / `none` — deterministic local fallback. No external
  dependencies, no API keys, suitable for air-gapped use.
- HTTP-backed names (see catalogue) issue real requests only when
  BOTH gates are passed:
  - `modules.ai.enabled: true` (the runtime gate; the backend
    short-circuits to `network_disabled=True` whenever this is
    false, regardless of `api_base`).
  - `modules.ai.api_base` is a non-empty `http://` or `https://`
    URL (`UrllibTransport` rejects anything else at the transport
    boundary).
  When either gate fails, the backend returns
  `ProviderResponse(network_disabled=True, error=...)` and never
  invokes the transport. `api_key_env` is NOT a gate — local
  servers (Ollama, llama.cpp, LM Studio) typically need no auth
  header and the backend omits it when the resolved key is empty;
  vendors that require auth respond with `401`, which surfaces as
  a structured `error="http 401: ..."` rather than crashing the
  run.
- Stub-backed names (`anthropic`, `gemini` today) always return a
  structured offline placeholder response — they will gain real
  backends through `register_provider(...)` without changing
  config shape.

The `ai_providers.<name>` block layered alongside `modules.ai`
holds vendor-specific extras (organisation IDs, custom headers).
`get_ai_config` merges them so operators can stash provider
settings in one place:

```yaml
modules:
  ai:
    enabled: true
    provider: openai_compatible
    model: ""                   # filled from ai_providers.openai_compatible.model
    api_base: ""                # filled from ai_providers.openai_compatible.api_base

ai_providers:
  openai_compatible:
    api_base: "https://lab-vendor.example/v1"
    model: "lab-model"
    headers:
      X-Title: "BlueFire Nexus"
```

The `headers` sub-key of a provider settings block is forwarded
into the HTTP backend's request headers, so operators can add
vendor-specific tags without modifying source.

## Default-config zero-network proof

Out of the box (`provider: template`, `enabled: false`):

1. `is_offline_ai(config)` returns `True`.
2. `from_ai_config(...)` returns `TemplateProvider(...)`. No HTTP
   code path is reachable.
3. The copilot's provider is the bare `TemplateProvider` (no
   fallback chain wrapper), and its `generate()` call returns
   `ProviderResponse(network_disabled=True, finish_reason="stop")`.
4. Even after enabling AI but without setting `api_base`, the
   HTTP backend's first action is the offline short-circuit
   (`api_base not configured`); the transport is never called.
5. The `UrllibTransport` scheme guard adds defense in depth:
   even a typo'd `api_base: file:///etc/passwd` is rejected at
   the transport boundary with a `ValueError`.

## Fallback chain

`modules.ai.fallback_provider` opts into the
`FallbackChainProvider` wrapper. When set to a known canonical
name different from the primary, primary failures (transport
errors, non-2xx responses, malformed payloads) transparently
retry via the fallback. Setting `fallback_provider: template` is
the safest choice — the template provider never fails and never
makes network calls. The wrapper itself never raises; every
failure surface comes through `ProviderResponse.error`.

When the fallback fires, the response carries:

- `fallback_used = True`
- `metadata["primary_provider"]` — the canonical name of the
  primary provider that failed
- `metadata["primary_error"]` — the original error string

These fields appear in the artifact metadata header so report
renderers can flag degraded runs without re-querying the
provider.

## Copilot artifacts

When the AI module is enabled, every run writes optional artifacts
to the run directory:

- `copilot_plan.txt` — scenario-plan output for a natural-language goal.
- `copilot_narrative.md` — SOC-style incident narrative for the run.
- `copilot_detections.md` — detection-strategy summary keyed off
  emitted telemetry.

Every artifact starts with a YAML-front-matter-style metadata
header (readable as both Markdown frontmatter and plain-text
preamble):

```
---
provider: openai
model: gpt-4o-mini
generated_at: 2026-05-06T23:50:12Z
network_disabled: false
fallback_used: false
finish_reason: stop
---

[the actual artifact content here]
```

When a fallback fired, the header also carries `primary_provider`
and `primary_error`. When the primary failed and no fallback was
configured, the header carries `error: ...` and the body contains
a clear placeholder (`[no content returned by provider; see
header for details]`) so the artifact is informative without
crashing the pipeline.

The same metadata is exposed in the dict returned by every public
copilot method (`plan`, `narrate`, `suggest_detections`):

```python
result = copilot.narrate("run-1")
# result == {
#   "path": ".../copilot_narrative.md",
#   "content": "<model body>",
#   "provider": "openai",
#   "model": "gpt-4o-mini",
#   "generated_at": "2026-05-06T23:50:12Z",
#   "network_disabled": False,
#   "fallback_used": False,
#   "error": None,
# }
```

## API keys, env vars, and secrets

API keys are read **from environment variables only**. Set
`modules.ai.api_key_env` to the name of the env var that holds the
key:

```yaml
modules:
  ai:
    enabled: true
    provider: openai
    api_base: "https://api.openai.com/v1"
    api_key_env: "OPENAI_API_KEY"   # reads os.environ["OPENAI_API_KEY"]
```

The runtime never reads the key from disk and the key never
appears in the config file. A missing env var becomes an empty
`api_key`. Backends handle empty keys per their semantics:

- HTTP backend: omits the `Authorization: Bearer ...` header so
  local servers (Ollama, llama.cpp) work without auth. Vendors
  that require auth will respond with a 401, which surfaces in
  `ProviderResponse(error="http 401: ...")` — exactly the right
  signal for the operator without crashing the run.
- Keyless stub: ignores the key entirely.

## HTTP transport security

The HTTP backend's transport is injectable. Tests inject a mock
transport (no real network call). Production uses the stdlib
`UrllibTransport`, which:

- Rejects any URL whose scheme is not `http` or `https` *before*
  issuing the call. Misconfigured `api_base: file:///etc/...` or
  `ftp://...` raises `ValueError` at the transport boundary.
- Never raises for non-2xx status codes. Upstream `429` /
  `500` / etc. surface as `HTTPResponse(status_code=...)` so the
  backend can decide whether to retry, fall back, or report.
- Sets a request timeout per-call (driven by `modules.ai.timeout`
  with optional per-call override via `ProviderOptions.timeout`).
- Does NOT pin certificates or override the default TLS context.
  Operators relying on private CAs configure the Python TLS trust
  store the same way they would for any other HTTPS client.

## Mutation engine

The mutation engine generates safe parameter variants for repeated
scenario research. Reachable from the CLI:

```bash
python -m src.run_scenario --scenario-file scenarios/<x>.yaml --mutate low_noise
```

Available strategies:

- `low_noise` — replaces noisy commands (e.g. `echo` → `printf`)
  and bumps timing jitter.
- `evasion-lite` — alias for `low_noise`.
- `protocol_shift` — rotates the `protocol` parameter (`http` →
  `dns` → `https` → `http`) and bumps the retry interval.
- `protocol-shift` — alias for `protocol_shift`.

The mutation strategy is recorded in `report.json` as
`mutation_strategy` and printed in the run summary so mutation is
never silent.

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

Output: `output/experiment-<scenario_id>/summary.json` with per-
iteration result records.

## Roadmap

- **Provider-specific adapters** for `anthropic` (Messages API)
  and `gemini` (GenerateContent API). Each adapter registers via
  `ProviderFactory.register_provider("<canonical>", factory)` and
  speaks the vendor's actual request/response shape. The
  interface, registry, transport, and fallback wrapper are
  already in place; the adapters are additive and do not require
  re-plumbing.
- **MCP / connectors** as a future option. Not a current
  requirement; nothing in the shipped baseline depends on them.
- **No remote observability / SIEM exporters.** The roadmap
  remains intentionally empty here. The local-first telemetry
  baseline is the durable contract.
