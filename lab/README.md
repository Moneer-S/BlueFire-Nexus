# BlueFire lab

A test bench for defenders. It runs published attack tests on a disposable lab
target, records what a sensor on that target saw, evaluates pinned detection
rules over those records, and reports two answers for every test: did the
technique take effect, and what did the defense see.

## What it shows today

Everything in this section comes from one run of the `lab` workflow:
[run 43808649201](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/43808649201),
16 November 2026. Its run page shows the table below, and its artifact
`lab-run` holds the sensor's raw output (`sysmon.txt`), the answers with what
each rests on (`results.json`) and the full report (`report.html`). GitHub keeps
both for 90 days.

- **Target:** a GitHub-hosted `ubuntu-24.04` runner (Ubuntu 24.04.5, kernel
  7.0.0-1014-aws, runner image 20261111.127.1).
- **Tests:** 17 Linux tests from Atomic Red Team at commit `a0e3f9bc`, run
  unchanged by its executor, Invoke-AtomicRedTeam, at commit `8af478bb`.
- **Sensor:** Sysmon for Linux 1.6.0 with the configuration in
  [`sensors/sysmon.xml`](sensors/sysmon.xml).
- **Rules:** the 135 Linux rules of SigmaHQ release r2026-07-01 that match what
  this sensor records (122 for process creation, 8 for file events, 5 for
  network connections), evaluated by Zircolite 4.7.1.

All 17 tests took effect. One of them raised an alert, meaning a match of a rule
of level high or critical:

| Test | Visibility | Highest level among the rules that matched |
| --- | --- | --- |
| T1059.004 Shell Creation using awk command | alert | high |
| T1053.003 Cron - Replace crontab with referenced file | telemetry only | medium |
| T1222.002 chmod - Change file or folder mode (numeric mode) | telemetry only | medium |
| T1548.001 Set a SetUID flag on file | telemetry only | medium |
| T1036.003 Masquerading as FreeBSD or Linux crond process | telemetry only | medium |
| T1027 Decode base64 Data into Script | telemetry only | medium |
| T1069.001 Permission Groups Discovery (Local) | telemetry only | low |
| T1518.001 Security Software Discovery - ps (Linux) | telemetry only | low |
| T1140 Linux Base64 Encoded Shebang in CLI | telemetry only | low |
| T1059.004 Obfuscated command line scripts | telemetry only | low |
| T1082 List OS Information | telemetry only | informational |
| T1053.006 Create Systemd Service and Timer | telemetry only | none matched |
| T1543.002 Create Systemd Service | telemetry only | none matched |
| T1136.001 Create a user account on a Linux system | telemetry only | none matched |
| T1098.004 Modify SSH Authorized Keys | telemetry only | none matched |
| T1070.003 Clear Bash history (truncate) | telemetry only | none matched |
| T1546.004 Add command to .bashrc | no telemetry | none matched |

What that means for a defender, under this sensor configuration and these
rules:

- Fifteen tests did what they do and the sensor recorded it, but no rule of an
  alert level fired. These are the gaps a new rule can close.
- Appending a command to `~/.bashrc` left nothing. The shell's own `echo` starts
  no process, and Sysmon for Linux reports a file only as created, and only
  while it is less than 100 ms old
  ([its source](https://github.com/microsoft/Sysmon-Linux/blob/962934f7e710a8e860ed5020f2068c6eba6aff64/ebpfKern/sysmonFileOpen.c)).
  This gap needs a sensor change before any rule can see it.
- Some rules matched only the one shell process that carries a test's whole
  command line, such as the medium rules for base64 piped into a shell on
  T1140. The report shows them, and does not count them as detections.

The canary, a test the pinned rules are known to catch (T1070.003, history
removal with `rm`), raised its alert at the start and at the end of the run. A
harmless command (T1082, `hostname`) ran through the same executor and raised
none.

## Hardening that blocks a technique

In [run 44014254015](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44014254015)
(17 November 2026, same runner image and kernel, the same 17 tests with the same
answers), four tests ran once more after all the others, each with one
hardening change in place. All four changes blocked their technique: the test
ran with its prerequisites met and did not take effect, while it had taken
effect without the change earlier in the same run. What each test printed
shows why:

| Test | Hardening change | What the test printed |
| --- | --- | --- |
| T1053.003 Cron - Replace crontab with referenced file | crontab limited to root with `/etc/cron.allow` | `You (bluefire-lab) are not allowed to use this program (crontab)` |
| T1098.004 Modify SSH Authorized Keys | the account's `~/.ssh` and `authorized_keys` owned by root | `cannot create /home/bluefire-lab/.ssh/authorized_keys: Permission denied` |
| T1546.004 Add command to .bashrc | the account's `~/.bashrc` made immutable | `cannot create /home/bluefire-lab/.bashrc: Operation not permitted` |
| T1036.003 Masquerading as FreeBSD or Linux crond process | `/tmp` mounted with `noexec`, `nosuid` and `nodev` | `/tmp/crond: Permission denied` |

Each change was tried against one published test. What it leaves open was not
tried: jobs that root adds under `/etc/cron.d`, keys that root adds for the
account, the account's other shell start files such as `~/.profile`, and
programs run from `/dev/shm` or the account's home folder. The changes are
defined in [`pinned-tests.yaml`](pinned-tests.yaml) under `defenses`.

## How a run works

1. The `lab` workflow ([`.github/workflows/lab.yml`](../.github/workflows/lab.yml))
   installs the sensor, and fetches the tests, the executor, the rules and the
   rule engine at pinned versions. Nothing of theirs is copied into this
   repository: see [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
2. `bluefire-lab run` waits until the sensor reports a probe command. It then
   runs the tests on [`pinned-tests.yaml`](pinned-tests.yaml) one at a time,
   with the canary first and last and the harmless command second, and then
   once more each test that names a hardening change, with the change in place.
   Root puts the change in place after the test's preparation and removes it
   after its cleanup. Each runs
   as an unprivileged account whose outbound traffic is rejected, or as root
   when the test declares that it needs it. Every step (preparation, a marker
   before and after the test, the test, an effect check, the cleanup) runs in a
   kernel audit session of its own.
3. `bluefire-lab evaluate` computes `results.json` from the files the run
   leaves. An event belongs to a test when its process is in the audit session
   of the test's attack step. Two more rules apply inside the test's window,
   between its markers. What cron starts for the test account belongs to a
   test run as that account. What systemd starts belongs to a test run as root,
   unless the same command also ran outside every test's window. The executor's
   own commands, the test's preparation and cleanup, and the shell process that
   carries the whole command line are left out.
4. `bluefire-lab report` writes `report.html`, one file that opens offline, and
   the same table for the run page.

Five controls must pass, or the run fails as a whole:

- **readiness:** the sensor reported a probe before the first test;
- **markers:** both markers of every test are in the telemetry;
- **loss:** the sensor reported no lost events, and none of its numbered
  records is missing from what was read;
- **canary:** the known-detected test took effect and alerted, first and last;
- **control:** the harmless command raised no alert.

## Limits

- "No telemetry" means none under the pinned sensor configuration. Sysmon for
  Linux records process starts and ends, network connections, file deletions,
  and file creations. A file counts as created when it is opened for creation
  and its three timestamps are equal and less than 100 ms old, so an append
  right after a file was created can show up as a creation too. Writes to
  older files, reads, and permission changes are not recorded.
- A process that systemd starts for a test that runs as root is tied to the
  test by time, inside the test's window, and not by process ancestry.
- Outbound traffic is rejected for the test account only, not for tests that
  run as root.
- One runner runs the whole list in sequence, and GitHub hands out runners with
  different kernels under the same label: kernels 7.0.0-1014-aws and
  7.0.0-1017-azure have both been seen.

## Not yet shown

- A new detection rule, or a sensor change, and its effect on a fresh run.
- Tests on Windows, attack chains of several steps, and a lab on a local
  machine.

## How to run it

The workflow runs on pull requests that change `lab/`, on a weekly schedule,
and by hand from the Actions tab. Attack tests run on GitHub-hosted runners
only: `bluefire-lab run` refuses to start anywhere else.

The answers can be computed again from a run's artifact, on any machine:

```bash
pip install ./lab
bluefire-lab evaluate <folder of the unpacked artifact> --engine <path to Zircolite 4.7.1>
bluefire-lab report <folder of the unpacked artifact>
```

## Before the loop: the sensor spike

Two runs on hosted runners tried sensors with harmless probe commands. Both are
from 16 November 2026, their logs are kept for 90 days and their artifacts
for 14: [run A](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/43802339233)
and [run B](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/43803220104).

- Sysmon for Linux 1.6.0, auditd 3.1.2 and Tetragon 1.8.0 all load on the
  runners' 7.0 kernels (runs A and B). Sysmon delivered a 6,051-character
  command line whole (run A).
- A child that detaches from its parent is reported with parent 1 by all three
  sensors, so process ancestry alone loses it (runs A and B). A kernel audit
  session, started by writing the login uid before a step, stays with every
  process of the step, detached ones included (run B). That is why the lab ties
  events to tests by session.
- Sysmon gives no parent identity to processes that PowerShell starts (run B),
  a known issue upstream (microsoft/Sysmon-Linux issue 253).
