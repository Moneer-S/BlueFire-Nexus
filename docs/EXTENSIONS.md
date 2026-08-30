# Extensions

BlueFire deliberately separates declarative plugins from executable action packages.

## Declarative plugins

A plugin manifest adds reviewed metadata only. It cannot import Python, load a native library,
run a command, or add execution authority. Use [Plugin manifest SDK](PLUGIN_SDK.md) for its strict
schema and lifecycle.

## Executable action packages

The portable executable extension boundary is a signed, content-addressed action package with a
bounded WASM provider. The package binds publisher trust, semantic version, artifact digest,
typed parameter and result contracts, capabilities, safety tier, platforms, cleanup, provenance,
license, runner compatibility, and resource limits.

The provider ABI permits fixed memory and one entry point with no host imports. Install,
activate, deactivate, upgrade, and remove are explicit operations. Unknown publishers, altered
content, incompatible inventory, imports, unexpected exports, oversized resources, and stale
activation records are refused. Model output can select only a registered compatible action; it
cannot supply a module or reach a shell.

Compiled first-party actions remain appropriate for narrow platform integrations. They must
follow the same typed logical contract, least-privilege profile, independent observation, and
receipt-bound cleanup rules. See [Action SDK](ACTION_SDK.md) and [Behavior authoring](BEHAVIOR_AUTHORING.md).
