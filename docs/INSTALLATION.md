# Installation

BlueFire Nexus requires 64-bit Python 3.10 or newer, a compatible desktop operating
system/architecture, and a local browser. The current CI package matrix targets Windows
x86-64, Linux x86-64, Intel macOS on macOS 15, and Apple Silicon on macOS 26. Install the
matching platform wheel below. It includes the application, browser interface, example
experiments, and packaged runner. These are V3 development builds from CI, not a published
stable release. You do not need a source checkout, Node.js, Rust, or frontend build tools.

## Download the candidate

Open the [tests workflow on main](https://github.com/Moneer-S/BlueFire-Nexus/actions/workflows/tests.yml?query=branch%3Amain).
Choose a successful run for the exact `main` commit you intend to install. Open the run's
**Summary** and download its platform artifact from **Artifacts**. Do not select an artifact
from a different commit. GitHub may require you to sign in to download an Actions artifact.

| Computer | Artifact | Wheel inside the ZIP |
|---|---|---|
| Windows x86-64 | `bluefire-native-wheel-windows-x86_64` | `bluefire_nexus-3.0.0-py3-none-win_amd64.whl` |
| Linux x86-64 | `bluefire-native-wheel-linux-x86_64` | `bluefire_nexus-3.0.0-py3-none-linux_x86_64.whl` |
| macOS Intel | `bluefire-native-wheel-macos-x86_64` | `bluefire_nexus-3.0.0-py3-none-macosx_11_0_x86_64.whl` |
| macOS Apple Silicon | `bluefire-macos-26-arm64-abi-protocol` | `bluefire_nexus-3.0.0-py3-none-macosx_11_0_arm64.whl` |

Choose the matching artifact, not a standalone runner executable. The Apple Silicon artifact
also contains build and installed-wheel evidence. Create a `bluefire-v3` directory, extract the
ZIP, and put its `.whl` file intact in a `wheels` subdirectory. These wheels are specific to
the listed operating systems and architectures; do not use an Intel wheel on Apple Silicon or
vice versa. The CI package checks are not a published release or proof of effective access on
your computer. The macOS wheel tags contain `macosx_11_0`, but that compatibility tag does not
mean every macOS 11 or newer version was validated. Check the requirements for the particular
method and local operating system you intend to use.

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
`bluefire_nexus-3.0.0-py3-none-macosx_11_0_x86_64.whl` in the install command. On Apple
Silicon, use `bluefire_nexus-3.0.0-py3-none-macosx_11_0_arm64.whl` instead. Keep the virtual
environment and saved workspace in separate directories. Reuse the same absolute workspace
path when restarting the same installation.

Normal operation does not require a source checkout or developer dependencies. Package installation
resolves runtime dependencies; the `[dev]` extra is for source development only, as described in
[Development](DEVELOPMENT.md).

## First browser session

The launcher opens your default browser when the loopback listener is ready and prints a
one-time connection code in the terminal. Enter that code in the browser. If the browser does
not open, visit the local console address printed in the terminal and enter the code. For a
manual launch, run `bluefire --runs-dir "path/to/your/bluefire-workspace" ui --no-browser`;
this prints a one-use URL containing the connection capability. Treat both the code and that
URL as credentials and do not share or log them. Keep the launching terminal running; closing
the browser tab does not stop the service.

Start in **Experiments**, open a packaged experiment or create one, then inspect it in **Build**.
Save a version after editing. For a preview, choose **Runs > Review new run**, select
**Simulate**, AI **Off** and **Local simulation**, run preflight and submit the Simulate job.
Inspect its saved result. Simulate needs neither a runner nor a model account and is optional;
for real effects, continue with **Prepare Execute** below. Follow the
[operator guide](OPERATOR_GUIDE.md) for the current UI walkthrough.

The default listener is `127.0.0.1:8765` and is for local use, not a remote service. Do not
expose it through a network bind, tunnel, or proxy. The connection code is exchanged for a
same-user browser session. Saved versions, rules, jobs, and run bundles use the directory named
by `--runs-dir`; changing that path opens a different workspace. Unsaved drafts live in the
browser and are not included in the workspace backup unless you save or export them.

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

Use only a wheel whose platform and architecture match the host. The workflow installs the
candidate wheel and checks packaged runner identity for its platform target. This is package
validation, not proof that an action has effective access on a particular computer. Individual
actions still declare their supported platforms; installing a wheel does not make every action
available on that computer. Review the selected workflow run for its test results. A missing
compatible artifact remains an unavailable readiness result.

## Upgrade or remove

Finish or stop active jobs and confirm cleanup, stop the managed runner, then stop the UI in its
launching terminal before replacing the package. Keep a backup of the complete workspace while
the service is stopped. The wheel and Python virtual environment are separate from that
workspace, which contains the product database and run bundles. Unsaved browser drafts are
separate; save or export them before replacing the environment if they matter.

Current development wheels share the `3.0.0` package version. For each candidate, prefer a new
virtual environment and keep the previous one available until the candidate is accepted. Launch
the candidate with the same absolute `--runs-dir` only when you intend to open that workspace.
For an isolated trial, use a copy of the workspace: a newer build may migrate saved data, so do
not assume an older build can reopen a workspace after it has been opened by a newer one. A
different `--runs-dir` is a different workspace; it does not replace or merge the original.
Reopen saved experiments and run history to confirm the selected workspace.

Before the next Execute session, open **Runners** and select the intended profile. With the
runner stopped, choose **Review runner upgrade**, inspect the current and candidate artifacts
and retained-history summary, then choose **Apply reviewed runner upgrade**. The review also
shows **Recovery after restart**. If it is **Not verified**, finish the upgrade before restarting
the lab or computer. If recovery is verified and an upgrade is interrupted, reopen **Runners**
and request a fresh review of the retained state before applying recovery.
The upgrade preserves enrollment, the sandbox,
completed execution history and durable results; it does not approve an experiment.

If review is refused, keep the runner stopped and address the reported blocker before requesting
a fresh review. Do not delete history or pending recovery records to make bootstrap succeed.
Remove disposable lab state only through its receipt-bound cleanup workflow. See
[Runner deployment](RUNNER_DEPLOYMENT.md).
