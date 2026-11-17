# Third-party notices

The lab (`lab/`, `.github/workflows/lab.yml`) copies none of the following into this repository.
Each is fetched at the pinned version during a CI job and runs as a separate program on the
hosted runner. The pins are the `env` values at the top of the workflow, except for Tetragon,
which only the sensor spike tried (runs 43802339233 and 43803220104), whose version is the one
those runs installed.

| Project | Pin | Licence | Use |
|---|---|---|---|
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | commit `a0e3f9bc` | MIT, Copyright (c) 2018 Red Canary, Inc. | Published attack test definitions |
| [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) | commit `8af478bb` | MIT | Executor for the test definitions |
| [powershell-yaml](https://github.com/cloudbase/powershell-yaml) | 0.4.12 | Apache-2.0 | Dependency of the executor |
| [Sysmon for Linux](https://github.com/microsoft/SysmonForLinux) | 1.6.0 | MIT, with GPL-2.0 for its eBPF programs | Sensor on the lab target |
| [SysinternalsEBPF](https://github.com/microsoft/SysinternalsEBPF) | 2.3.0 | LGPL-2.1 | Library the sensor depends on |
| [SigmaHQ rules](https://github.com/SigmaHQ/sigma) | release `r2026-07-01`, commit `552f3fee` | [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License) | Detection rules. Output that names a matched rule keeps the rule's author |
| [Zircolite](https://github.com/wagga40/Zircolite) | 4.7.1 | LGPL-3.0-or-later | Rule engine, run as a separate program |
| [Linux audit daemon](https://github.com/linux-audit/audit-userspace) | Ubuntu 24.04 package `auditd` `1:3.1.2-2.1ubuntu0.1` | GPL-2.0 | Second sensor on the lab target, with the rules in `lab/sensors/audit.rules` |
| [Tetragon](https://github.com/cilium/tetragon) | 1.8.0 | Apache-2.0 | Sensor tried in the spike |

The lab's Python package depends on [PyYAML](https://github.com/yaml/pyyaml) (MIT), installed
from PyPI. Its tests and lint use [pytest](https://github.com/pytest-dev/pytest) (MIT) and
[Ruff](https://github.com/astral-sh/ruff) (MIT), installed the same way in CI.

The checks in `.github/workflows/checks.yml` run [gitleaks](https://github.com/gitleaks/gitleaks)
(MIT), a release binary pinned by digest, and [detect-secrets](https://github.com/Yelp/detect-secrets)
(Apache-2.0) from PyPI.
