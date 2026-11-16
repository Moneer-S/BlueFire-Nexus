# BlueFire lab

A test bench for defenders. It runs published attack tests on a disposable lab
target, records what the sensors on that target saw and which detection rules
fired, and reports both plainly.

## What is shown today

No report exists yet: the bench has not taken a set of tests through the whole
loop.

A spike on GitHub-hosted `ubuntu-24.04` runners has shown what the bench can
build on. It used harmless probe commands and one discovery test. Each finding
names the run that shows it. Both runs are from 16 November 2026. GitHub keeps
their logs for 90 days and their artifacts for 14.

- Run A: [43802339233](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/43802339233)
- Run B: [43803220104](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/43803220104)

### Sensors

| Finding | Shown by |
| --- | --- |
| Sysmon for Linux 1.6.0 installs from the Microsoft package repository that the image already has, and loads on kernel 7.0.0-1014-aws and on kernel 7.0.0-1017-azure. The `ubuntu-24.04` label handed out both. | Run A, job "sensor spike (Sysmon for Linux)"; run B, job "loop spike" |
| It records process starts and ends, file creation and deletion, and network connections. A 6,051-character command line arrives whole in the journal and in `/var/log/syslog`. | Run A, same job |
| When it stops, Sysmon logs how many events it lost (`Lost events: 0, in 0 notifications`). | Run A, same job, step "Export and summarise the events" |
| For the processes that PowerShell started, Sysmon reported a parent id (4032) that is not PowerShell's process id (4013), and no parent GUID or parent image. Its `ParentCommandLine` field held only the parent's first argument. | Run B, job "loop spike", session 5 in the step "Export and summarise the events"; the GUID and image fields are in the artifact `spike-loop`, file `sysmon.txt` |
| auditd 3.1.2 starts on the runner. With an `execve` rule loaded it records a 6,000-character argument whole, and `auditctl -s` shows its `lost` counter. | Run B, job "sensor spike (auditd)" |
| Tetragon 1.8.0 runs as a container on the runner and reported the first probe within two seconds, with whole arguments and with counters of lost events. With its default configuration it reported process starts and exits only. | Run A, job "sensor spike (Tetragon)" |

### Tying events to a test

| Finding | Shown by |
| --- | --- |
| A child that detaches from its parent (a double fork, or `setsid` from a subshell) is reported with parent 1 by Sysmon, auditd and Tetragon. Process ancestry alone loses it. | Run A, Sysmon and Tetragon jobs; run B, auditd job |
| Writing the login uid before a step starts a new kernel audit session. Every process of the step keeps that session id, detached ones included. Sysmon reports it as `TerminalSessionId` and auditd as `ses`. | Run B, job "loop spike", step "Export and summarise the events"; run B, auditd job |

### Running a test and evaluating rules

| Finding | Shown by |
| --- | --- |
| Invoke-AtomicRedTeam 2.1.0 on PowerShell 7.6.10 runs a Linux test for an unprivileged account as a single `sh -c` line. Its execution log names that process's id and exit code. | Run B, job "loop spike", step "Run probes and one real test" |
| Around the test the executor runs commands of its own (`hostname`, `whoami`, `id`, `ip`). They land in the same telemetry and match discovery rules, so they have to be told apart from the test. | Run B, same job, session 5 in the step "Export and summarise the events" |
| An `iptables` owner rule rejects the test account's outbound traffic while the runner's own account keeps its network. | Run B, same job, step "Block outbound traffic for the test account" |
| Zircolite 4.7.1 converts the 122 Linux process rules of SigmaHQ release r2026-07-01 and evaluates them over the Sysmon output in under a second. | Run B, same job, step "Evaluate the pinned Sigma rules with Zircolite" |
| Process rules also match events that are not process starts, unless the events are split by type first. | Run B, artifact `spike-loop`, file `detected.json` |

## Not yet shown

- A set of tests taken through the whole loop, with a report.
- Any change to a defense, and its effect.

## How to run it

The spike is the `lab` workflow, [`.github/workflows/lab.yml`](../.github/workflows/lab.yml).
It runs on pull requests that change `lab/`, and it can be started by hand from
the Actions tab. Attack tests run on hosted runners only, never on a developer
machine.
