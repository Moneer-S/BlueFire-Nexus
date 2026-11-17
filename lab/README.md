# BlueFire lab

A test bench for defenders. It runs published attack tests on a disposable lab
target, records what a sensor on that target saw, evaluates pinned detection
rules over those records, and reports two answers for every test: did the
technique take effect, and what did the defense see.

## What it shows today

Everything in this section comes from one run of the `lab` workflow:
[run 44019934793](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44019934793),
17 November 2026. Its run page shows the same answers in a longer table, and
its artifact `lab-run` holds the sensor's raw output (`sysmon.txt`), the
answers with what each rests on (`results.json`) and the full report
(`report.html`). GitHub keeps both for 90 days. An earlier run of the same tests,
[run 43808649201](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/43808649201)
on 16 November, gave the same answers before the controls were tightened.

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
of level high or critical on an event of the test:

| Test | Visibility | Highest level among the rules that matched an event of the test |
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
  alert level fired. These are gaps that a rule could close. Whether one closes
  them without false alarms is not shown by this run.
- Appending a command to `~/.bashrc` left nothing besides the start of the one
  shell process whose command line holds the whole append. The shell's own
  `echo` starts no process, and Sysmon for Linux reports a file only as created,
  and only while it is less than 100 ms old
  ([its source](https://github.com/microsoft/Sysmon-Linux/blob/962934f7e710a8e860ed5020f2068c6eba6aff64/ebpfKern/sysmonFileOpen.c)).
  This gap needs a sensor change before any rule can see the write itself.
- On nine of the tests, rules of level medium matched only that shell process,
  which carries a test's whole command line: three of them on T1140, for base64
  piped into a shell. The report shows them, and does not count them as
  detections.

The canary, a test the pinned rules are known to catch (T1070.003, history
removal with `rm`), raised its alert at the start and at the end of the run. A
harmless command (T1082, `hostname`) ran through the same executor and raised
none.

## Hardening that blocks a technique

In [run 44020766356](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44020766356)
(17 November 2026, same runner image and kernel, the same 17 tests with the same
answers), four tests ran once more after all the other tests, before the
closing canary, each with one hardening change in place. All four changes
blocked their technique: the test
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
tried: jobs that root adds under `/etc/cron.d`; keys that root adds for the
account, and moving the root-owned `~/.ssh` aside, which the account can do
because it owns its home folder; the account's other shell start files such as
`~/.profile`; and programs run from `/dev/shm` or the account's home folder, or
a script in `/tmp` run through an interpreter. The changes are defined in
[`pinned-tests.yaml`](pinned-tests.yaml) under `defenses`.

## Detection rules of the lab's own

[`rules/linux`](rules/linux) holds Sigma rules this repository adds for tests
that took effect and left telemetry, but raised no alert from the pinned rules.
A rule describes what the technique does: for example any `chmod` mode that
sets the setuid or setgid bit, symbolic or numeric, and not only the mode a test
uses. It is accepted only when all three of these hold in the same run:

- it alerts on the test it was written for;
- every published procedure it alerts on ran again with changed input arguments
  (the `variants` in [`pinned-tests.yaml`](pinned-tests.yaml)), and it alerted
  on each of those runs;
- it matches nothing in the ordinary activity: a baseline of ordinary
  administration with the same tools and files, run as root and as the test
  account, and the runner's own work outside the tests. The baseline adds and
  deletes accounts, among them a system account without a login shell; writes
  a systemd drop-in with a shell, copies a whole unit file into place with `cp`
  and masks a unit; changes file modes without the setuid or setgid bit;
  truncates and copies files that are not history files, and truncates one to
  a size other than zero; and runs a program from `/tmp`.

This has a limit. Changed input arguments show that a rule does not depend on
the values they set, such as an account name or a file path. They cannot show
that a rule does not depend on what a test fixes in its command, such as the
options it passes to `useradd` or the mode it gives `chmod`: a rule written for
exactly those would be accepted as well. Where a test lets a run change what a
rule looks at, a variant does: the history tests run again on `~/.histfile` and
`~/.history`, whose names lack `_history`. Beyond that, each rule's description
says which spellings it covers, and only the spellings the tests use have been
seen in a run.

The visibility answer stays the pinned rules' alone. A second column in the
report gives the answer with the accepted rules counted too, and a rule that is
not accepted changes no answer. In
[run 44022042190](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44022042190)
(17 November 2026, kernel 7.0.0-1014-aws), with two more published procedures
in the list, all 19 tests took effect. One raised an alert with the pinned
rules, and 8 with the accepted rules as well:

| Rule | Alerts on | Runs with changed input arguments | Verdict |
| --- | --- | --- | --- |
| [Systemd Unit File Written By A Shell](rules/linux/file_event/file_event_lnx_systemd_unit_written_by_shell.yml) | T1053.006 Create Systemd Service and Timer, T1543.002 Create Systemd Service | alerted on 2 of 2 | accepted |
| [System Account Created With A Login Shell](rules/linux/process_creation/proc_creation_lnx_system_account_with_login_shell.yml) | T1136.001 Create a user account on a Linux system | alerted on 1 of 1 | accepted |
| [Setuid Or Setgid Bit Set With Chmod](rules/linux/process_creation/proc_creation_lnx_chmod_setuid_setgid.yml) | T1548.001 Set a SetUID flag on file, T1548.001 Set a SetGID flag on file | alerted on 2 of 2, one for each | accepted |
| [Shell History File Emptied](rules/linux/process_creation/proc_creation_lnx_history_file_emptied.yml) | T1070.003 Clear Bash history (truncate), T1070.003 Clear Bash history (ln dev/null) | alerted on 3 of 3, on `~/.zsh_history`, `~/.histfile` and `~/.history` | accepted |
| [Program Named Like A System Daemon Run From A Temporary Folder](rules/linux/process_creation/proc_creation_lnx_daemon_name_from_temp_folder.yml) | T1036.003 Masquerading as FreeBSD or Linux crond process | none: the test has no input arguments to change | not accepted |

Three of the accepted rules alert on two published procedures each, and one
covers a single procedure. In the same run the baseline left 226 events and the
runner's own work outside the tests 2,269. None of the lab's rules matched any
of them, while ten pinned rules did. One of those is of level high: the
canary's own rule, "History File Deletion", matched the baseline's removal of a
copy of a history file (`rm ~/.bash_history.bak`, record 1090). The others are
medium or lower, for example "User Has Been Deleted Via Userdel" on the
baseline's `userdel`.

The baseline is a short script, not days of real administration, so a rule that
stays quiet on it can still be noisy elsewhere. One such case is known: the
rule for a unit file written by a shell also alerts when an administrator
writes a new unit by hand. A draft that could not fire with this sensor is kept
in [`rules/rejected`](rules/rejected) with the reason.

## How a run works

1. The `lab` workflow ([`.github/workflows/lab.yml`](../.github/workflows/lab.yml))
   installs the sensor, and fetches the tests, the executor, the rules and the
   rule engine at pinned versions. Nothing of theirs is copied into this
   repository: see [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
2. `bluefire-lab run` waits until the sensor reports a probe command. It then
   runs the tests on [`pinned-tests.yaml`](pinned-tests.yaml) one at a time,
   with the canary first and last, the harmless command second and the
   baseline of ordinary administration third. After the tests and before the
   closing canary, it runs once more each test that names a hardening change,
   with the change in place, and each test that names variants, with their
   input arguments. Root puts a change in place after the test's preparation
   and removes it after its cleanup. Each test runs
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
   own commands and the test's preparation and cleanup are left out. So are the
   start and end of the shell process that carries the whole command line
   (`sh -c` or `bash -c`, as the test declares); files it writes count as the
   test's. It then judges each of the lab's own rules on the tests, their
   variants and the ordinary activity.
4. `bluefire-lab report` writes `report.html`, one file that loads nothing from
   elsewhere when it opens (it refuses to write one that would), and the same
   table for the run page.
5. A separate job, which runs no test, compares the run with the latest
   successful run on `main` (`bluefire-lab compare`) and writes to the run page
   which answers changed and what changed under them: events, rules that
   match, a rule of the lab's own accepted now and how many published
   procedures it covers, or a hardening change that blocks now.

Seven controls must pass, or the run fails as a whole:

- **readiness:** the sensor reported a probe before the first test began;
- **markers:** both markers and the launcher of every test are in the
  telemetry, and no answer is left inconclusive, for example because a
  hardening change could not be put in place or a test ran out of time with
  one;
- **changes:** every hardening change that was put in place was removed again
  after its test;
- **loss:** the sensor reported its counts of lost and bad events once each,
  both zero, and none of its numbered records is missing from what was read or
  appears twice;
- **engine:** the rule engine loaded every rule and read every event it was
  given, and the sensor recorded every kind of event the rules describe;
- **canary:** the known-detected test took effect and alerted, first and last;
- **control:** the harmless command took effect and raised no alert.

## Limits

- "No telemetry" means none under the pinned sensor configuration. Sysmon for
  Linux records process starts and ends, network connections, file deletions,
  and file creations. A file counts as created when it is opened for creation
  and its three timestamps are equal and less than 100 ms old. So a write to an
  existing file shows up as a creation when it leaves those timestamps fresh,
  as a read followed by an overwrite does (T1098.004 in the run above). An
  append that leaves the access time old, like the one to `~/.bashrc`, is not
  recorded, and neither are reads and permission changes.
- A process that systemd starts for a test that runs as root is tied to the
  test by time, inside the test's window, and not by process ancestry. The
  runner's own timers are stopped before the tests, so that their units do not
  start inside such a window.
- Outbound traffic, name lookups included, is rejected for the test account
  only, not for tests that run as root.
- Two tests are checked more weakly than the rest. The awk shell escape
  (T1059.004) has no check of its own that could fail: awk exits with status 0
  whether or not the shell starts, so its "took effect" rests on the command
  having run. The security software discovery (T1518.001) is checked by a text
  that `ps` also prints for the test's own `grep`, so the check shows only that
  `ps` ran.
- One runner runs the whole list in sequence, and GitHub hands out runners with
  different kernels under the same label: kernels 7.0.0-1014-aws (the run
  above) and 7.0.0-1017-azure (run B of the sensor spike below) have both been
  seen.

## Not yet shown

- A sensor change, and its effect on a fresh run.
- Tests on Windows, attack chains of several steps, and a lab on a local
  machine.

## How to run it

The workflow runs on pull requests that change `lab/`, on a weekly schedule,
and by hand from the Actions tab. Attack tests run on GitHub-hosted runners
only: `bluefire-lab run` refuses to start unless `RUNNER_ENVIRONMENT` is
`github-hosted`, which GitHub sets on its own runners. That guards against
starting it by mistake anywhere else; it cannot stop someone who sets the
variable on purpose.

The answers can be computed again from a run's artifact, on any machine:

```bash
pip install ./lab
bluefire-lab evaluate <folder of the unpacked artifact> --engine <path to Zircolite 4.7.1>
bluefire-lab report <folder of the unpacked artifact>
```

Two runs' artifacts can be compared the same way:

```bash
bluefire-lab compare <folder of the earlier run> <folder of the later run>
```

## Before the loop: the sensor spike

Two runs on hosted runners tried sensors with harmless probe commands. Both are
from 16 November 2026, their logs are kept for 90 days and their artifacts
until 30 November 2026: [run A](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/43802339233)
and [run B](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/43803220104).
Run A ended as failed, in a step that only printed a summary of auditd's
records after auditd had loaded and recorded. Which kernel each sensor job had
is in the artifacts only.

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
