# Installation

BlueFire Nexus requires Python 3.10 or newer. Its platform wheel includes the application,
web interface, example experiments and native runner. V3 is currently an unreleased PR
candidate; obtain its wheel from the actual PR build below.

## Download the candidate

Open [PR #200's checks](https://github.com/Moneer-S/BlueFire-Nexus/pull/200/checks)
and select the **tests** run for the candidate you intend to install. Open that run's
**Summary**, then download the matching artifact from **Artifacts** after its native-wheel
job succeeds. This follows the selected candidate instead of a fixed link to an older build.
GitHub may require you to sign in to download an Actions artifact.

| Computer | Artifact | Wheel inside the ZIP |
|---|---|---|
| Windows x86-64 | `bluefire-native-wheel-windows-x86_64` | `bluefire_nexus-3.0.0-py3-none-win_amd64.whl` |
| Linux x86-64 | `bluefire-native-wheel-linux-x86_64` | `bluefire_nexus-3.0.0-py3-none-linux_x86_64.whl` |
| macOS Intel | `bluefire-native-wheel-macos-x86_64` | `bluefire_nexus-3.0.0-py3-none-macosx_11_0_x86_64.whl` |

Choose the **native-wheel** artifact, not a standalone runner executable. Create a fresh
`bluefire-v3` directory, extract the ZIP, and put its `.whl` file in a `wheels` subdirectory.
Keep the wheel intact. These builds target the architectures listed above; an incompatible
wheel cannot be installed on another architecture.

## Install and open

Open a terminal in that `bluefire-v3` directory. On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .\wheels\bluefire_nexus-3.0.0-py3-none-win_amd64.whl
.\.venv\Scripts\bluefire.exe --runs-dir (Join-Path $PWD 'workspace') ui
```

On Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ./wheels/bluefire_nexus-3.0.0-py3-none-linux_x86_64.whl
.venv/bin/bluefire --runs-dir "$PWD/workspace" ui
```

On Intel macOS, use the same commands with
`bluefire_nexus-3.0.0-py3-none-macosx_11_0_x86_64.whl` in the install command.
The commands keep the virtual environment and saved workspace separate. Reuse this workspace
path when restarting or upgrading.

Normal operation does not require a source checkout or developer dependencies. Package installation
resolves runtime dependencies; the `[dev]` extra is for source development only, as described in
[Development](DEVELOPMENT.md).

## First browser session

The launcher attempts to open the browser once the loopback listener is ready. If opening fails,
use the complete one-use URL printed in the terminal to enter the same running UI. For manual
opening, use `bluefire --runs-dir "path/to/your/bluefire-workspace" ui --no-browser`.
Keep the launching terminal running; closing the browser tab does not stop the local service.

Start in **Experiments**, open a packaged experiment or create one, then inspect it in **Build**.
Save a version after editing. For a preview, choose **Runs > Review new run**, select
**Simulate**, AI **Off** and **Local simulation**, run preflight and submit the Simulate job.
Inspect its saved result. Simulate needs neither a runner nor a model account and is optional;
for real effects, continue with **Prepare Execute** below. Follow the
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

Use only a wheel whose platform and architecture match the host. The linked candidate build
checks wheel installation and packaged runner identity on Windows, Linux and Intel macOS.
Individual actions still declare their supported platforms; installing a wheel does not make
every action available on that computer. Consult the PR's current checks for full test results.
A missing compatible artifact remains an unavailable readiness result.

## Upgrade or remove

Finish or stop active jobs and confirm cleanup, stop the managed runner, then stop the UI in its
launching terminal before replacing the package. Install the next reviewed wheel in the same
environment and launch with the **same absolute `--runs-dir`**; preserve the whole workspace,
including its product database and run bundles. Reopen saved experiments and run history to
check that you are in the intended workspace.

Before the next Execute session, open **Runners** and select the intended profile. With the
runner stopped, choose **Review runner upgrade**, inspect the current and candidate artifacts
and retained-history summary, then choose **Apply reviewed runner upgrade**. Complete review
and application in the same lab session. The upgrade preserves enrollment, the sandbox,
completed execution history and durable results; it does not approve an experiment.

If review is refused, keep the runner stopped and address the reported blocker before requesting
a fresh review. Do not delete history or pending recovery records to make bootstrap succeed.
Remove disposable lab state only through its receipt-bound cleanup workflow. See
[Runner deployment](RUNNER_DEPLOYMENT.md).
