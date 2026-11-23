# Third-party notices

The [lab workflow](.github/workflows/lab.yml) pins the programs, libraries, test definitions
and detection rules it fetches. Each `lab-run` artifact includes the SigmaHQ rules used and
their license. Tetragon was used only in the earlier sensor trials,
[run 43802339233](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/43802339233) and
[run 43803220104](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/43803220104).

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
| [geerlingguy.node_exporter](https://github.com/geerlingguy/ansible-role-node_exporter) | tag `2.2.0`, commit `0df55616` | MIT | Ansible role applied on the lab target as ordinary activity that the lab's own rules must stay quiet on |
| [node_exporter](https://github.com/prometheus/node_exporter) | 1.13.1, downloaded by the role | Apache-2.0 | The program that role installs and starts |
| [jq](https://github.com/jqlang/jq) | release `jq-1.8.2`, tarball pinned by digest | MIT, with other licences for parts (see its `COPYING`) | Built from source on the lab target as ordinary activity |
| Ubuntu packages [vsftpd](https://packages.ubuntu.com/noble/vsftpd), [sysstat](https://packages.ubuntu.com/noble/sysstat), [redis-server](https://packages.ubuntu.com/noble/redis-server) | the versions Ubuntu 24.04's archive serves on the day of the run | GPL-2.0, GPL-2.0-or-later, BSD-3-Clause | Installed and removed on the lab target as ordinary activity |

A run started by hand can be given another Sigma rule set, sensor settings or an image as
inputs. What such a run fetches is named in its report and travels in its artifact with the
licence files found beside it. The runs this repository's documents link used these:

| Project | Pin | Licence | Use |
|---|---|---|---|
| [rustinel-rules](https://github.com/Karib0u/rustinel-rules) | commit `26793460`, folder `rules/sigma/linux` | its `LICENSE`, headed "Detection Rule License (DRL) 1.1": use and redistribution with the notice and each rule's author kept | Rule set evaluated as a column of its own |

The lab's Python package depends on [PyYAML](https://github.com/yaml/pyyaml) (MIT), installed
from PyPI. Its tests and lint use [pytest](https://github.com/pytest-dev/pytest) (MIT) and
[Ruff](https://github.com/astral-sh/ruff) (MIT), installed the same way in CI.

The checks in `.github/workflows/checks.yml` run [gitleaks](https://github.com/gitleaks/gitleaks)
(MIT), a release binary pinned by digest, and [detect-secrets](https://github.com/Yelp/detect-secrets)
(Apache-2.0) from PyPI.
