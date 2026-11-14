# Configuration

BlueFire has two effect modes, `simulate` and `execute`. AI autonomy is a separate setting with
the values `off`, `assist`, and `auto`; it never creates a third mode or expands execution
authority.

Start from the packaged example:

```bash
bluefire scenario list
bluefire resources list runner_profile
```

Those commands use the packaged canonical example. Pass `--config PATH` before the command only
when reviewing an explicit local configuration file.

Runner profiles bind environment type, supported platforms, scope references, capabilities,
safety tiers, action allowlists and denylists, approval, collectors, budgets, and cleanup policy.
Choose the least-privilege profile that supports the scenario. Execute preflight must bind the
exact current runner identity, inventory, profile, target scope, policy, and approval.

## Secrets and providers

Configuration stores environment-variable references or opaque credential handles, never a raw
secret. The browser does not read provider values. Resolve each handle only inside the boundary
that needs it, and do not place credentials in graphs, run bundles, evidence, screenshots, logs,
fixtures, or model prompts.

The deterministic offline AI provider is the release-safe default. The OpenAI-compatible path is
optional and environment-dependent; configure its endpoint, model, limits, redaction policy, and
credential-reference name, then review the external-data disclosure before enabling it.

The AWS identity lab follows the same rule: deterministic local Simulate and Execute interfaces
use opaque lab handles, while a real-provider smoke requires explicitly supplied authorized lab
credentials and remains outside offline acceptance.

## External-engine development settings

There is no supported operator setting that enables Strix in RC2 or in an ordinary development
wheel. `STRIX_RUNTIME_BACKEND` is controller-owned launch material, not a user configuration
escape hatch. The maintained adapter still selects the stock `docker` value, while the restricted
`bluefire-controlled` backend and relay contracts are implemented but not yet selected by a
concrete installed attempt factory. Changing that environment value, injecting a package path, or
supplying a Docker image cannot create runtime admission.

The controlled mechanics provider has the fixed label **Test provider**, the default fixture model
`bluefire-controlled-strix-mechanics-v1`, and `live_model_proof: false`. It is suitable only for
model-independent interaction and lifecycle tests. Its current [tool conformance profile](strix-test-provider-conformance.md)
validates offline candidates but has no enrolled wire-schema digest, so provider serving is unavailable.
Do not relabel test output as live inference or put a real provider credential into its configuration.

External-engine target inputs remain typed and scope-bound. A local-directory target must name a
disposable copy; an API specification URL does not widen authority to referenced hosts; and MCP
client configuration does not admit an arbitrary remote tool server. Backend choice, exact image,
target and model relays, provider handle, budgets, cancellation, evidence retention, and cleanup
must come from the controller's versioned admission and action material. Missing material is an
unavailable readiness result, not a reason to fall back to the stock backend.

## Durable and browser-local settings

Backend settings and resources are versioned, schema-validated records. Theme and the starting
mode/autonomy choices are browser preferences, not execution authority. Confirm effective values
in preflight and the finalized run bundle. See [Runner profiles](RUNNER_PROFILES.md), [AI
Planner](AI_PLANNER.md), and [User guide](USER_GUIDE.md).
