# Installation

BlueFire Nexus is a local-first application requiring Python 3.10 or newer. This checkout is an
unreleased candidate; these instructions do not identify a published release or package-index
entry. Use a reviewed wheel matching your platform. It contains the Python control plane,
packaged web UI, canonical data and the platform's manifest-bound native runner.

Replace the wheel placeholder below with that file. Replace the workspace placeholder with one
**absolute directory** outside the source checkout and virtual environment; keep that path for
future launches and upgrades.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install "path/to/the-reviewed-bluefire-nexus-wheel.whl"
bluefire --runs-dir "path/to/your/bluefire-workspace" ui
```

Normal operation does not require a source checkout or developer dependencies. Package installation
resolves runtime dependencies; the `[dev]` extra is for source development only, as described in
[Development](DEVELOPMENT.md).

## First browser session

The launcher attempts to open the browser once the loopback listener is ready. If opening fails,
use the complete one-use URL printed in the terminal to enter the same running UI. For manual
opening, use `bluefire --runs-dir "path/to/your/bluefire-workspace" ui --no-browser`.
Keep the launching terminal running; closing the browser tab does not stop the local service.

Start in **Experiments**, open a packaged experiment or create one, then inspect it in **Build**.
Save a version after editing. In **Runs**, choose **Review new run**, select **Simulate** and AI
**Off**, run preflight and submit the Simulate job. Inspect its saved result before moving to
Execute. Simulate needs neither a runner nor a model account. Follow the
[operator guide](OPERATOR_GUIDE.md) for the current UI walkthrough.

The default listener is `127.0.0.1:8765`. It is a same-user local session, not a remote service.
Saved versions, rules, jobs and run bundles use the selected workspace. Reuse the same absolute
`--runs-dir` when restarting; changing it opens a different workspace. Unsaved browser drafts
are separate from saved product records.

## Prepare Execute

Execute additionally needs a compatible packaged native artifact and private local enrollment.
Use **Runs > Review new run** to select the Execute profile and scope, resolve runner readiness,
then inspect preflight and the fresh one-time approval. Opening this review does not run actions.
See the [operator guide](OPERATOR_GUIDE.md) before proceeding.

The equivalent runner setup commands use the same workspace and an explicitly selected profile
(replace `PROFILE_ID` with the profile you reviewed):

```bash
bluefire --runs-dir "path/to/your/bluefire-workspace" runner bootstrap --profile PROFILE_ID
bluefire --runs-dir "path/to/your/bluefire-workspace" runner start --profile PROFILE_ID
bluefire --runs-dir "path/to/your/bluefire-workspace" runner status --profile PROFILE_ID
```

Bootstrap verifies the packaged runner manifest and digest, installs it under the private
per-user BlueFire root, and creates local trust. It does not install an administrator service.

## Platform packages

Use only a wheel whose platform and architecture match the host. Windows and Linux x86-64
artifacts receive dynamic release proof. macOS metadata and contracts remain structural until a
macOS release host builds and exercises that package. A missing compatible artifact must remain
an unavailable readiness result; never substitute an unverified binary.

## Upgrade or remove

Finish or stop active jobs and confirm cleanup, stop the managed runner, then stop the UI in its
launching terminal before replacing the package. Install the next reviewed wheel in the same
environment and launch with the **same absolute `--runs-dir`**; preserve the whole workspace,
including its product database and run bundles. Reopen saved experiments and run history to
check that you are in the intended workspace.

Re-run bootstrap before the next Execute session so the current manifest, binary digest,
inventory and enrollment are reconciled. Remove disposable lab state only through its
receipt-bound cleanup workflow. See [Runner deployment](RUNNER_DEPLOYMENT.md).
