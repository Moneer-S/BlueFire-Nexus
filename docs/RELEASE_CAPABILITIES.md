# Release capability classification

This matrix is the concise public boundary for the current release. A label describes the proof
available; it does not grant authorization.

## Shipped

- Local Python control plane, packaged React operator UI, and bounded Rust runner.
- Exactly two modes (`simulate`, `execute`) and independent AI autonomy (`off`, `assist`, `auto`).
- Typed behavior graphs, policy and approval, independent collectors, detection lifecycle,
  content-addressed run bundles, materialized checkpoint replay, and comparison.
- Signed no-host-import WASM action-package lifecycle and reviewed compiled first-party actions.
- Bounded endpoint/identity lab behavior, same-host disposable peer handoff, transparent telemetry
  shaping, deterministic AWS identity lab integration, and authoritative cleanup.

## Environment-dependent

- Packaged native Execute depends on a matching platform artifact and current local enrollment.
- Linux/container Execute needs an explicitly prepared disposable distribution and locked wheel
  set. Native audit, Sysmon/Event Log, SIEM/EDR, and cloud audit adapters need their platforms and
  operator configuration.
- pySigma/SQLite and YARA require their pinned optional packages. Real OpenAI-compatible and AWS
  provider smoke paths require operator-supplied authorized credentials through references or
  opaque handles; offline acceptance uses deterministic providers.

## Structural

- macOS package metadata, contracts, and error classification are checked when no macOS host is
  present; that is not dynamic macOS execution proof.
- Unconfigured collector and external-provider interfaces report readiness and limitations rather
  than claiming observation or provider success.

## Restricted

- The persistence behavior is one fixed non-executable runner-owned canary, not a host startup
  mechanism.
- There is no arbitrary shell, command, script, payload, remote target, host-import WASM,
  cross-host enrollment, multi-user server, production defense deployment, or credential dump.
- Declarative plugins remain metadata-only. Broad `research.*` credential, remote lateral, and
  defense-evasion families remain non-executable research contracts.

See [Responsible use](RESPONSIBLE_USE.md) and [Security](../SECURITY.md) before Execute.
