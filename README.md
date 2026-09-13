<p align="center">
  <img src="docs/assets/brand/bluefire-mark.svg" alt="" width="46" height="54">
</p>

<h1 align="center">BlueFire Nexus</h1>

<p align="center"><strong>A visual workspace for purple teaming and detection engineering.</strong></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-64748b?style=flat" alt="License: MIT"></a>
  <a href="docs/INSTALLATION.md"><img src="https://img.shields.io/badge/Python-3.10%2B-64748b?style=flat" alt="Requires Python 3.10 or newer"></a>
  <a href="https://github.com/Moneer-S/BlueFire-Nexus/issues/201"><img src="https://img.shields.io/badge/status-V3%20development-2563eb?style=flat" alt="V3 in development"></a>
</p>

<p align="center">
  <a href="#get-started">Get started</a> ·
  <a href="#build-the-experiment">Workflow</a> ·
  <a href="docs/OPERATOR_GUIDE.md">Documentation</a> ·
  <a href="https://github.com/Moneer-S/BlueFire-Nexus/issues/201">Roadmap</a>
</p>

BlueFire Nexus is an open-source purple-team framework for building repeatable security tests and improving detections. Connect individual actions into an attack chain, run it in your lab, and inspect the results. Change a method or detection rule, repeat the experiment, and compare the outcome.

The graph editor, run history, detection tools, and optional AI Assistant work in the same local application.

![Walkthrough of an experiment and its saved results](docs/assets/screenshots/walkthrough.gif)

*Reviewing an experiment and its saved results in the local application.*

## Get started

Download a [development build for your platform](docs/INSTALLATION.md#download-the-candidate). The package includes the application, browser interface, examples, and native runner. You need Python 3.10 or newer; you do not need to build the frontend.

Create a `bluefire-v3` folder, extract the downloaded artifact ZIP, and put its intact wheel in a `wheels` subfolder. Run the commands for your platform from `bluefire-v3`.

<details>
<summary><strong>Windows x86-64</strong></summary>

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .\wheels\bluefire_nexus-3.0.0-py3-none-win_amd64.whl
.\.venv\Scripts\bluefire.exe --runs-dir (Join-Path $PWD 'workspace') ui
```

</details>

<details>
<summary><strong>Linux x86-64</strong></summary>

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ./wheels/bluefire_nexus-3.0.0-py3-none-linux_x86_64.whl
.venv/bin/bluefire --runs-dir "$PWD/workspace" ui
```

</details>

<details>
<summary><strong>Intel macOS</strong></summary>

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ./wheels/bluefire_nexus-3.0.0-py3-none-macosx_11_0_x86_64.whl
.venv/bin/bluefire --runs-dir "$PWD/workspace" ui
```

</details>

The launcher opens your browser. If it cannot, open the URL printed in the terminal. Keep the terminal running and reuse the same `workspace` folder when you restart.

Open an example in **Experiments** to inspect or edit it in **Build**. Choose **Simulate** to preview the steps without performing their actions, or **Execute** to run them after setting up a compatible runner and reviewing the plan. Simulation does not need an AI account. See [running an experiment](docs/OPERATOR_GUIDE.md) and [the disposable Linux lab](docs/PREPARED_LINUX_LAB.md) for setup.

## Build the experiment

Choose the steps, how each step runs, and what happens next if it succeeds, fails, or is blocked. Edit parameters in the graph, add compatible alternatives, and save the experiment for another run.

Work directly in the editor or use the Assistant to draft and revise the plan. You can inspect its proposed changes before applying them.

![An experiment open in the Build workspace](docs/assets/screenshots/builder.png)

## Follow the run

Review the path taken, collected files and observations, errors, and cleanup status. Open a step to inspect its details rather than reconstructing the sequence from separate tool logs.

A step reporting success and a collector confirming its effects are shown separately. Saved results remain available for inspection, comparison, and export.

## Improve the detection

Use **Detection Lab** to write a rule, evaluate it against a run's observations, and inspect the matching records. Test activity you want to catch alongside examples that should not match. Save a revised rule without losing the previous version or its results.

![A saved detection rule open in Detection Lab](docs/assets/screenshots/detection-lab.png)

Repeat the experiment or change a method, then open **Compare** to see the differences between runs. Compare rule evaluations separately to see which records each revision matched. Export the results when you need to share or investigate them further.

![The Compare workspace with two selected runs](docs/assets/screenshots/compare.png)

## Work with your model

The optional Assistant works beside the graph and results. It supports experiment planning, supported edits, and detection drafting and revision. Connect a compatible provider when you need it; manual operation remains available without one.

**Assist** asks you to review proposed changes. For supported operations, **Auto** can choose from alternatives included in the run you approved. It cannot add new targets or permissions. **Off** follows the saved plan without calling a model.

See [model setup and supported operations](docs/AI_PLANNER.md). Live-provider validation is still in progress, and external providers may charge for usage.

## Under the hood

Python coordinates experiments and detection evaluation. The Rust runner performs supported actions. React provides the interface, and SQLite stores the workspace's saved records.

The framework includes native methods and reviewed external-tool adaptations, including a Linux gzip test adapted from Atomic Red Team. Detection backends include local SQLite, Sigma conversion to SQLite, and YARA for file content, subject to the installed backend requirements.

[Architecture](docs/ARCHITECTURE.md) · [Execution](docs/EXECUTION_MODEL.md) · [Detection backends](docs/DETECTION_LAB.md) · [Reviewed T1082 source intake](docs/SOURCE_INTAKE.md) · [Development](docs/DEVELOPMENT.md) · [Contributing](CONTRIBUTING.md)

## Current scope

V3 is a development build, not a stable release. The included examples focus on local endpoint and file-collection tests using generated lab data. Execution support varies by method and platform. Remote runners, broad Active Directory coverage, and production EDR/SIEM collection integrations are not shipped.

Broader technique coverage, graph usability, and final release validation are active work. See the [capability reference](docs/RELEASE_CAPABILITIES.md) and [roadmap](https://github.com/Moneer-S/BlueFire-Nexus/issues/201).

## License

[MIT](LICENSE). Third-party components retain their own [licenses and attribution](THIRD_PARTY_NOTICES.md).

Use BlueFire only on systems you own or are authorized to test. Keep the web service local. For security reports, follow [SECURITY.md](SECURITY.md).
