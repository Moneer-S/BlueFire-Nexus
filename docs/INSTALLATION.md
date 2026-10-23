# Installation

BlueFire Nexus requires 64-bit Python 3.10 or newer, a compatible desktop operating
system/architecture, and a local browser. The 3.0.0-rc2 wheels target Windows x86-64, Linux
x86-64, Intel macOS, and Apple Silicon. Each wheel includes the application, browser interface,
example experiments, and packaged runner. You do not need a source checkout, Node.js, Rust, or
frontend build tools.

<a id="download-the-candidate"></a>
## Download the prerelease

When published, download `SHA256SUMS` and the matching wheel from the [3.0.0-rc2 GitHub
release](https://github.com/Moneer-S/BlueFire-Nexus/releases/tag/v3.0.0-rc2). Until those
assets are available, use the [tests workflow](https://github.com/Moneer-S/BlueFire-Nexus/actions/workflows/tests.yml)
to find a successful run for the exact source commit of the candidate you intend to install;
download its wheel artifact and do not use an artifact from another commit. GitHub may require
sign-in to download CI artifacts. Use the exact wheel filename for the platform:

| Computer | Wheel |
|---|---|
| Windows x86-64 | `bluefire_nexus-3.0.0rc2-py3-none-win_amd64.whl` |
| Linux x86-64 | `bluefire_nexus-3.0.0rc2-py3-none-linux_x86_64.whl` |
| macOS Intel | `bluefire_nexus-3.0.0rc2-py3-none-macosx_11_0_x86_64.whl` |
| macOS Apple Silicon | `bluefire_nexus-3.0.0rc2-py3-none-macosx_11_0_arm64.whl` |

For published release assets, `SHA256SUMS` has one digest paired with each exact wheel
filename. Calculate the matching wheel's SHA-256 and compare it with the row carrying that
exact filename: use
`Get-FileHash <wheel> -Algorithm SHA256` in PowerShell, `sha256sum <wheel>` on Linux, or
`shasum -a 256 <wheel>` on macOS. These unsigned checksums detect an asset mismatch; they do
not independently attest publisher identity. Do not use an Intel wheel on Apple Silicon or
vice versa. The `macosx_11_0` wheel tag is a compatibility tag, not evidence that every macOS
11 or newer version was validated. Hosted native smoke coverage is on Intel macOS 15 and Apple
Silicon macOS 26; check requirements for the particular method and local OS.

Create a `bluefire-v3` directory with a `wheels` subdirectory, and put `SHA256SUMS` in
`bluefire-v3` when provided. A GitHub release downloads the wheel directly: move that intact
`.whl` into `bluefire-v3/wheels`. A CI artifact downloads as a ZIP: extract that archive, locate
the matching `.whl` inside its nested folders, and move the intact wheel into the same `wheels`
subdirectory. Do not extract the `.whl` itself. For an unpublished CI candidate, the release
`SHA256SUMS` may not yet be available. Open a terminal in `bluefire-v3` and run the commands
below.

## Install and open

Open a terminal in that `bluefire-v3` directory. On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .\wheels\bluefire_nexus-3.0.0rc2-py3-none-win_amd64.whl
.\.venv\Scripts\bluefire.exe --runs-dir (Join-Path $PWD 'workspace') ui
```

On Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ./wheels/bluefire_nexus-3.0.0rc2-py3-none-linux_x86_64.whl
.venv/bin/bluefire --runs-dir "$PWD/workspace" ui
```

On Intel macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ./wheels/bluefire_nexus-3.0.0rc2-py3-none-macosx_11_0_x86_64.whl
.venv/bin/bluefire --runs-dir "$PWD/workspace" ui
```

On Apple Silicon:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ./wheels/bluefire_nexus-3.0.0rc2-py3-none-macosx_11_0_arm64.whl
.venv/bin/bluefire --runs-dir "$PWD/workspace" ui
```

Keep the virtual environment and saved workspace in separate directories. Reuse the same
absolute workspace path when restarting the same installation.

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

Use only a wheel whose platform and architecture match the host. Windows hosted CI on Server
2025 checks generated process-tree cancellation; this is not Windows 11 or effective-access
validation. Hosted macOS 15 Intel and macOS 26 Apple Silicon wheel smoke checks run an installed
packaged native runner through a generated fixture, discovery, and receipt-bound cleanup. On
Apple Silicon, the file-access check is protocol/ABI-only and reports that it did not perform
live file access; it does not prove effective access. These checks are not customer-machine
validation. Native action support varies by method and platform; installing a wheel does not
make every action available. A missing compatible artifact remains an unavailable readiness
result. Generated fixtures and hosted CI do not establish Active Directory or AWS validation.
S3 audit dispatch remains gated by `DISPATCH_RELEASED = false`.

## Upgrade or remove

Finish or stop active jobs and confirm cleanup, stop the managed runner, then stop the UI in its
launching terminal before replacing the package. Keep a backup of the complete workspace while
the service is stopped. The wheel and Python virtual environment are separate from that
workspace, which contains the product database and run bundles. Unsaved browser drafts are
separate; save or export them before replacing the environment if they matter.

The existing development wheel is version `3.0.0`; the RC2 wheel is `3.0.0rc2`.
Install RC2 into a new virtual environment and keep the old development environment available
until you have checked the candidate. Stop the service before changing environments. Launch
RC2 with the same absolute `--runs-dir` only when you intend it to open that workspace. For an
isolated trial, use a copy: RC2 may migrate saved data, so do not assume the older development
build can reopen a workspace after RC2 has opened it. A different `--runs-dir` is a different
workspace; it does not replace or merge the original. Reopen saved experiments and run history
to confirm the selected workspace.

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
