# Installation

BlueFire Nexus is a local-first application. Install it in a fresh environment and keep its
state outside the source checkout.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install path/to/the-reviewed-bluefire-nexus-wheel.whl
bluefire --help
bluefire ui
```

Install only a reviewed wheel from the release artifacts; no public package index is assumed.
The release is distributed as a platform-tagged wheel containing the Python control plane,
packaged web UI, canonical data, and a manifest-bound native runner for that platform. A source
checkout is not required for normal operation. Development installs remain documented in
[Development](DEVELOPMENT.md).

## Prepare Execute

Simulate works without a runner. Execute additionally needs a compatible packaged native
artifact and a private local enrollment:

```bash
bluefire runner bootstrap
bluefire runner start
bluefire runner status
```

Bootstrap verifies the packaged runner manifest and digest, installs it under the private
per-user BlueFire root, and creates local trust. It does not install an administrator service.
The UI's Getting Started and Runs pages expose the same bootstrap, readiness, preflight, and
one-time approval flow.

## Platform packages

Use only a wheel whose platform and architecture match the host. Windows and Linux x86-64
artifacts receive dynamic release proof. macOS metadata and contracts remain structural until a
macOS release host builds and exercises that package. A missing compatible artifact must remain
an unavailable readiness result; never substitute an unverified binary.

## Upgrade or remove

Stop the managed runner before replacing or removing it. Re-run bootstrap after an upgrade so
the current manifest, binary digest, inventory, and enrollment are reconciled. Preserve run
bundles needed for review, but remove disposable lab state only through its receipt-bound cleanup
workflow. See [Runner deployment](RUNNER_DEPLOYMENT.md).
