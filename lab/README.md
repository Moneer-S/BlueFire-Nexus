# BlueFire lab

A test bench for defenders. It runs published attack tests on a disposable lab
target, records what the sensors on that target saw, evaluates pinned detection
rules over those records, and reports two answers for every test: did the
technique take effect, and what did the defense see.

## What it shows today

Everything in this section comes from one run of the `lab` workflow:
[run 44055611236](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44055611236),
17 November 2026. Its run page shows the same answers in a longer table, and
its artifact `lab-run` holds the sensors' raw output (`sysmon.txt` and
`audit.txt`), the answers with what each rests on (`results.json`) and the full
report (`report.html`). GitHub keeps both for 90 days.

- **Target:** a GitHub-hosted `ubuntu-24.04` runner (Ubuntu 24.04.5, kernel
  7.0.0-1014-aws, runner image 20261111.127.1).
- **Tests:** 49 Linux tests from Atomic Red Team at commit `a0e3f9bc`, run
  unchanged by its executor, Invoke-AtomicRedTeam, at commit `8af478bb`. Two
  run with one input argument changed; [`pinned-tests.yaml`](pinned-tests.yaml)
  says which and why.
- **Sensors:** Sysmon for Linux 1.6.0 with the configuration in
  [`sensors/sysmon.xml`](sensors/sysmon.xml), and auditd 3.1.2 with the rules
  in [`sensors/audit.rules`](sensors/audit.rules): watches on the shell start
  files, and the process starts of the lab's own steps and of what cron or a
  login starts.
- **Rules:** the 188 Linux rules of SigmaHQ release r2026-07-01 for the kinds
  of event these sensors record (122 for process creation, 8 for file events,
  5 for network connections, 53 for auditd), evaluated by Zircolite 4.7.1.
  Many of the 53 auditd rules look at records this auditd configuration does
  not produce: system calls it does not audit, files it does not watch, audit
  keys it does not set. In this run 18 of them matched anything.

All 49 tests took effect. Three of them raised an alert, meaning a match of a
rule of level high or critical on an event of the test. The last column counts
the lab's own rules too, those the run accepted: see
[Detection rules of the lab's own](#detection-rules-of-the-labs-own).

| Test | Visibility with the pinned rules (highest level that matched) | With the lab's rules too |
| --- | --- | --- |
| T1082 List OS Information | telemetry only (low) | telemetry only |
| T1069.001 Permission Groups Discovery (Local) | telemetry only (low) | telemetry only |
| T1518.001 Security Software Discovery - ps (Linux) | telemetry only (low) | telemetry only |
| T1057 Process Discovery - ps | telemetry only (none matched) | telemetry only |
| T1049 System Network Connections Discovery via ss or lsof (Linux/MacOS) | telemetry only (informational) | telemetry only |
| T1083 Nix File and Directory Discovery 2 | telemetry only (informational) | telemetry only |
| T1087.001 View accounts with UID 0 | telemetry only (none matched) | telemetry only |
| T1201 Examine password expiration policy - All Linux | telemetry only (none matched) | telemetry only |
| T1053.003 Cron - Replace crontab with referenced file | telemetry only (medium) | telemetry only |
| T1053.006 Create Systemd Service and Timer | telemetry only (low) | alert |
| T1543.002 Create Systemd Service | telemetry only (low) | alert |
| T1136.001 Create a user account on a Linux system | telemetry only (medium) | alert |
| T1098.004 Modify SSH Authorized Keys | telemetry only (none matched) | telemetry only |
| T1546.004 Add command to .bashrc | telemetry only (medium) | telemetry only |
| T1037.004 rc.local | telemetry only (medium) | telemetry only |
| T1546.005 Trap EXIT | telemetry only (medium) | telemetry only |
| T1546.018 Python Startup Hook - usercustomize.py (Linux / MacOS) | telemetry only (medium) | alert |
| T1569.003 Enable systemd Service for Persistence with Auto-Restart | telemetry only (low) | alert |
| T1556.003 Malicious PAM rule | telemetry only (none matched) | telemetry only |
| T1078.003 Reactivate a locked/expired account (Linux) | telemetry only (medium) | telemetry only |
| T1552.003 Search Through Bash History | telemetry only (medium) | telemetry only |
| T1552.004 Discover Private SSH Keys | telemetry only (medium) | alert |
| T1222.002 chmod - Change file or folder mode (numeric mode) | telemetry only (medium) | telemetry only |
| T1548.001 Set a SetUID flag on file | telemetry only (medium) | alert |
| T1548.001 Set a SetGID flag on file | telemetry only (medium) | alert |
| T1036.003 Masquerading as FreeBSD or Linux crond process | telemetry only (medium) | telemetry only |
| T1036.005 Execute a process from a directory masquerading as the current parent directory | telemetry only (low) | alert |
| T1564.001 Create a hidden file in a hidden directory | telemetry only (low) | telemetry only |
| T1070.006 Set a file's modification timestamp | telemetry only (medium) | telemetry only |
| T1070.003 Clear Bash history (truncate) | alert (high) | alert |
| T1070.003 Clear Bash history (ln dev/null) | telemetry only (medium) | alert |
| T1685.006 rm -rf | telemetry only (medium) | telemetry only |
| T1027 Decode base64 Data into Script | telemetry only (medium) | telemetry only |
| T1140 Linux Base64 Encoded Shebang in CLI | telemetry only (low) | telemetry only |
| T1059.004 Obfuscated command line scripts | telemetry only (low) | telemetry only |
| T1059.004 Shell Creation using awk command | alert (high) | alert |
| T1027.002 Binary simply packed by UPX (linux) | telemetry only (medium) | telemetry only |
| T1027.004 C compile | telemetry only (medium) | telemetry only |
| T1027.013 Password-Protected ZIP Payload Extraction and Execution | telemetry only (low) | alert |
| T1574.006 Shared Library Injection via LD_PRELOAD | telemetry only (none matched) | telemetry only |
| T1055.009 Inplace Instruction Overwrite | telemetry only (none matched) | telemetry only |
| T1560.001 Encrypts collected data with AES-256 and Base64 | telemetry only (low) | telemetry only |
| T1560.002 Compressing data using tarfile in Python (FreeBSD/Linux) | telemetry only (none matched) | telemetry only |
| T1030 Data Transfer Size Limits | telemetry only (low) | telemetry only |
| T1486 Encrypt files using openssl (FreeBSD/Linux) | telemetry only (none matched) | telemetry only |
| T1489 Linux - Stop service using systemctl | telemetry only (medium) | telemetry only |
| T1685 Disable ASLR Via sysctl parameters - Linux | alert (high) | alert |
| T1553.004 Install root CA on Debian/Ubuntu | telemetry only (medium) | telemetry only |
| T1548.003 Unlimited sudo cache timeout | telemetry only (medium) | telemetry only |

What that means for a defender, under these sensors and these rules:

- 46 tests took effect and left telemetry besides their launcher's start, but
  no pinned rule of an alert level fired. The lab's own rules close 11 of these
  gaps; 35 stay open. How much of a technique its telemetry shows differs: for
  the preloaded library (T1574.006) it is only the `ls` that ran, because
  Sysmon does not record the environment variable that carries the technique,
  so no rule over that telemetry could close the gap.
- Of the three pinned alerts, one would also fire on ordinary work. The alert
  on emptying the history with `truncate` (T1070.003) comes from "Binary
  Padding - Linux", a rule for another technique that matches any
  `truncate -s`: it matched the baseline's three ordinary uses of `truncate`
  in the same run. The other two, the awk shell escape and turning ASLR off
  with `sysctl` (T1685), matched nothing ordinary.
- No test left no telemetry: auditd's watch on the shell start files records
  the append to `~/.bashrc` that Sysmon cannot see. Recording process starts as
  well raised two of the alerts: see
  [A sensor change that makes a gap visible](#a-sensor-change-that-makes-a-gap-visible).
- On 25 of the tests, rules of level medium or lower matched only the one shell
  process whose command line holds the whole test. The report shows them, and
  does not count them as detections.

The canary, a test the pinned rules are known to catch (T1070.003, history
removal with `rm`), raised its alert at the start and at the end of the run. A
harmless command (T1082, `hostname`) ran through the same executor and raised
none. The first run of these 49 tests,
[run 44033742721](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44033742721),
before auditd recorded process starts, gave the same answers apart from the two
tests that change made alerts and one more: the in-place instruction overwrite
(T1055.009) had not taken effect, because the lab ended the process the test
writes into before that process ran what was written. The test now waits five
seconds before its check.

## Hardening that blocks a technique

In [run 44035796630](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44035796630),
nine tests ran once more after all the other tests, before the closing canary,
each with one of four hardening changes in place; one change, `/tmp` mounted
`noexec`, was tried on six tests. Eight of the nine runs were blocked: the test
ran with its prerequisites met and did not take effect, while it had taken
effect without the change earlier in the same run. What each test printed
shows why:

| Test | Hardening change | What the test printed |
| --- | --- | --- |
| T1053.003 Cron - Replace crontab with referenced file | crontab limited to root with `/etc/cron.allow` | `You (bluefire-lab) are not allowed to use this program (crontab)` |
| T1098.004 Modify SSH Authorized Keys | the account's `~/.ssh` and `authorized_keys` owned by root | `cannot create /home/bluefire-lab/.ssh/authorized_keys: Permission denied` |
| T1546.004 Add command to .bashrc | the account's `~/.bashrc` made immutable | `cannot create /home/bluefire-lab/.bashrc: Operation not permitted` |
| T1036.003 Masquerading as FreeBSD or Linux crond process | `/tmp` mounted with `noexec`, `nosuid` and `nodev` | `/tmp/crond: Permission denied` |
| T1027.002 Binary simply packed by UPX (linux) | the same `/tmp` | `/tmp/packed_bin: Permission denied` |
| T1027.004 C compile | the same `/tmp`, where the test compiles | `./a.out: Permission denied` |
| T1574.006 Shared Library Injection via LD_PRELOAD | the same `/tmp` | `object '/tmp/T1574006.so' from LD_PRELOAD cannot be preloaded (failed to map segment from shared object): ignored.` |
| T1569.003 Enable systemd Service for Persistence with Auto-Restart | the same `/tmp`, where its service's program is | `ExecStart=/tmp/atomic_payload.sh (code=exited, status=203/EXEC)` |

The ninth run was not blocked. With `/tmp` mounted `noexec`, the
password-protected ZIP payload (T1027.013) still printed `T1027.013: Payload
extracted from encrypted ZIP`: it runs its script through `bash`, which the
mount does not stop. So that change blocked five of the six published
procedures it was tried on, and the comparison of runs says the same for each
change. The first four rows were first shown in
[run 44020766356](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44020766356).

Each change was tried against the published tests in the table. What it leaves
open beyond the script run through an interpreter was not tried: jobs that root
adds under `/etc/cron.d`; keys that root adds for the account, and moving the
root-owned `~/.ssh` aside, which the account can do because it owns its home
folder; the account's other shell start files such as `~/.profile`; and
programs run from `/dev/shm` or the account's home folder. The changes are
defined in [`pinned-tests.yaml`](pinned-tests.yaml) under `defenses`.

## Detection rules of the lab's own

[`rules/linux`](rules/linux) holds Sigma rules this repository adds for tests
that took effect and left telemetry, but raised no alert from the pinned rules.
A rule describes what the technique does: for example any `chmod` mode that
sets the setuid or setgid bit, symbolic or numeric, and not only the mode a test
uses. It is accepted only when all three of these hold in the same run:

- it alerts on at least one published test;
- every published procedure it alerts on ran again with changed input arguments
  (the `variants` in [`pinned-tests.yaml`](pinned-tests.yaml)) and took effect,
  and it alerted on each of those runs;
- it matches nothing in the ordinary activity: a baseline of ordinary
  administration with the same tools and files, run as root and as the test
  account, and the runner's and the lab's own work outside the tests. The
  baseline adds and
  deletes accounts, among them a system account without a login shell; writes
  a systemd drop-in with a shell, copies a whole unit file into place with `cp`
  and masks a unit; changes file modes without the setuid or setgid bit;
  truncates and copies files that are not history files, and truncates one to
  a size other than zero; runs a program from `/tmp` and one from
  `~/.local/bin`; searches with `find` for files by other names; zips and
  unzips a file without a password; and writes an ordinary module into the
  account's own Python site folder.

This has a limit. Changed input arguments show that a rule does not depend on
the values they set, such as an account name or a file path. They cannot show
that a rule does not depend on what a test fixes in its command, such as the
options it passes to `useradd` or the mode it gives `chmod`: a rule written for
exactly those would be accepted as well. Where a test lets a run change what a
rule looks at, a variant does so for some rules and not yet for others: the
history tests run again on `~/.histfile` and `~/.history`, and the key search on
`id_ed25519`, but the systemd tests' variants change a unit's name and not the
folder it is written to, though two of those tests, T1053.006 and T1543.002,
allow that too. Beyond that, each
rule's description says which spellings it covers, and only the spellings the
tests use have been seen in a run.

The visibility answer stays the pinned rules' alone. A second column in the
report gives the answer with the accepted rules counted too, and a rule that is
not accepted changes no answer. In
[run 44055611236](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44055611236),
three of the 49 tests raised an alert with the pinned rules, and 14 with the
accepted rules as well:

| Rule | Alerts on | Runs with changed input arguments | Verdict |
| --- | --- | --- | --- |
| [Systemd Unit File Written By A Shell](rules/linux/file_event/file_event_lnx_systemd_unit_written_by_shell.yml) | T1053.006 Create Systemd Service and Timer, T1543.002 Create Systemd Service, T1569.003 Enable systemd Service for Persistence with Auto-Restart | alerted on 3 of 3 | accepted |
| [System Account Created With A Login Shell](rules/linux/process_creation/proc_creation_lnx_system_account_with_login_shell.yml) | T1136.001 Create a user account on a Linux system | alerted on 1 of 1 | accepted |
| [Setuid Or Setgid Bit Set With Chmod](rules/linux/process_creation/proc_creation_lnx_chmod_setuid_setgid.yml) | T1548.001 Set a SetUID flag on file, T1548.001 Set a SetGID flag on file | alerted on 2 of 2, one for each | accepted |
| [Shell History File Emptied](rules/linux/process_creation/proc_creation_lnx_history_file_emptied.yml) | T1070.003 Clear Bash history (truncate), T1070.003 Clear Bash history (ln dev/null) | alerted on 3 of 3, on `~/.zsh_history`, `~/.histfile` and `~/.history` | accepted |
| [Python Startup Hook File Written](rules/linux/file_event/file_event_lnx_python_startup_hook_written.yml) | T1546.018 Python Startup Hook - usercustomize.py (Linux / MacOS) | alerted on 1 of 1, with `python3.12` | accepted |
| [Private Key Files Searched With Find](rules/linux/process_creation/proc_creation_lnx_find_private_keys.yml) | T1552.004 Discover Private SSH Keys | alerted on 1 of 1, for `id_ed25519` | accepted |
| [Program Run From A Folder Named Like Dots](rules/linux/process_creation/proc_creation_lnx_program_in_dots_folder.yml) | T1036.005 Execute a process from a directory masquerading as the current parent directory | alerted on 1 of 1 | accepted |
| [Archive Extracted With A Password On The Command Line](rules/linux/process_creation/proc_creation_lnx_archive_extracted_with_password.yml) | T1027.013 Password-Protected ZIP Payload Extraction and Execution | alerted on 1 of 1, with another password | accepted |
| [Program Named Like A System Daemon Run From A Temporary Folder](rules/linux/process_creation/proc_creation_lnx_daemon_name_from_temp_folder.yml) | T1036.003 Masquerading as FreeBSD or Linux crond process | none: the test has no input arguments to change | not accepted |

The rule for a unit file written by a shell was written for the first two of
its procedures. It also alerts on the third, T1569.003, added to the list
later, and on that procedure's run with changed input arguments. Two other
accepted rules alert on two published procedures each, and five cover a single
procedure each so far. In the same run the baseline left 385 events and the
runner's and the lab's own work outside the tests 6,445, much of it the lab's
own driver switching accounts and sessions. None of the lab's rules matched any
of them, while 20 pinned rules did. Two of those are of level high: the
canary's own rule, "History File Deletion", matched the baseline's removal of a
copy of a history file (`rm ~/.bash_history.bak`, record 1112), and "Binary
Padding - Linux" its three uses of `truncate`. The others are medium or lower,
for example "User Has Been Deleted Via Userdel" on the baseline's `userdel`.

The baseline is a short script, not days of real administration, so a rule that
stays quiet on it can still be noisy elsewhere. One such case is known: the
rule for a unit file written by a shell also alerts when an administrator
writes a new unit by hand. A draft that could not fire with this sensor is kept
in [`rules/rejected`](rules/rejected) with the reason.

## What the target has

Each run starts with an inventory of the target, and chooses the tests by it.
In [run 44028032549](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44028032549)
(17 November 2026) the hosted runner had 5 accounts that can log in (`root`,
`runner`, the lab's own test account, and `packer` and `postgres`, which come
with the runner image), 26 running services before the lab started its sensors
(auditd among them, which the job installs), and 9 listening TCP and UDP addresses,
among them TCP port 22, the port SSH uses, on every address. Sysmon for Linux
and auditd were both active once started. Every program the tests name (`awk`,
`crontab`, `systemctl`, `useradd`) was there, so no test was left out. That a
missing program leaves its tests out is shown by the unit tests only, not yet
by a run.

## A sensor change that makes a gap visible

Sysmon for Linux reports a write to a file only when it leaves the file looking
newly created (see [Limits](#limits)), so with Sysmon alone appending a command
to `~/.bashrc` (T1546.004) left no telemetry, for example in
[run 44019934793](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44019934793).
With auditd
recording beside Sysmon, watching the shell start files listed in
[`sensors/audit.rules`](sensors/audit.rules), it did in
[run 44029759448](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44029759448)
(17 November 2026, kernel 7.0.0-1014-aws). auditd recorded the shell opening
`/home/bluefire-lab/.bashrc` for writing, in the audit session of the test's
attack step. Two pinned SigmaHQ auditd rules matched that record, "Unix Shell
Configuration Modification" (medium) and "Use Of Hidden Paths Or Files" (low),
so the test went from no telemetry to telemetry only. No test in the run is
left without telemetry.

The same test run with the account's `~/.bashrc` made immutable was still
blocked, and auditd recorded its write attempt too, refused by the kernel. Only
these two runs wrote to a watched file. The run's comparison with the latest
run on `main` finds them the only two of its 34 runs of a test whose answers
changed.

auditd also recorded what some of the tests' own programs report: `useradd`
adding the account of T1136.001, which the pinned auditd rule "Creation Of An
User Account" (medium) matched; `sudo` running each command of the setuid and
setgid tests; and cron starting the job the crontab test planted. None of these
changed an answer. All seven controls passed, with auditd's probe recorded
before the first test and its own count of lost records at 0 before and after.

### Process starts recorded by auditd too

With file watches alone, 3 of the 53 pinned auditd rules matched anything: many
of them look for a program's start and its arguments (EXECVE records). auditd
now records process starts as well: those of processes with a login uid. The
lab sets one at the start of every step, and cron and logins set one too, so
the machine's own cron jobs and what cron or a login starts for a test are
recorded as well; the runner's agent and what systemd starts have none. In
[run 44055611236](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44055611236)
18 auditd rules matched something, and two tests went from telemetry only to
an alert by a pinned rule:

| Test | Rule that alerts now |
| --- | --- |
| T1685 Disable ASLR Via sysctl parameters - Linux | ASLR Disabled Via Sysctl or Direct Syscall - Linux (high), on `sysctl -w kernel.randomize_va_space=0` |
| T1070.003 Clear Bash history (truncate) | Binary Padding - Linux (high), on `truncate -s0 ~/.bash_history` |

The second rule is for another technique and matches any `truncate -s`: it
matched the baseline's three ordinary uses of `truncate` in the same run, so a
defender would see it on ordinary work too. Compared with
[run 44055556881](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44055556881),
the same tests without this change, only these two tests and the history
test's two runs with changed input arguments changed their answers, of 74.

Two things had to change with it. A shell given one command can become that
command in the same process (`bash -c "sysctl ..."`), so only the first program
start of the launcher's process is the launcher's, which, holding the whole
test, is never counted as a detection; the ASLR test's `sysctl` start, in the
same process, is the test's. And auditd rotates its log at 8 MB by default,
which it did during the first run with this change: the lab now sets it not to
rotate, and the loss control fails a run in which it did.

## How a run works

1. The `lab` workflow ([`.github/workflows/lab.yml`](../.github/workflows/lab.yml))
   installs the two sensors, and fetches the tests, the executor, the rules and
   the rule engine at pinned versions. Nothing of theirs is copied into this
   repository: see [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md). The
   sensors are Sysmon for Linux, with [`sensors/sysmon.xml`](sensors/sysmon.xml),
   and auditd, with the file watches in [`sensors/audit.rules`](sensors/audit.rules).
2. `bluefire-lab run` stops at once, with the reason, if the target lacks
   `systemctl` or `ss`, which the lab itself needs. Before it starts the
   sensors, it takes an inventory of the target: the accounts that can log
   in, the running services, the listening addresses, and where each program
   the tests need is (`needs` in [`pinned-tests.yaml`](pinned-tests.yaml)).
   A test whose program is missing is left out, with its hardened runs and
   variants, and the report and the run page list it with the reason. After
   starting the sensors it records which of them are active, and waits until
   Sysmon reports a probe command and auditd a probe write to a file it
   watches. It then
   runs the tests on [`pinned-tests.yaml`](pinned-tests.yaml) one at a time,
   with the canary first and last, the harmless command second and the
   baseline of ordinary administration third. After the tests and before the
   closing canary, it runs once more each test that names a hardening change,
   with the change in place, and each test that names variants, with their
   input arguments. Root puts a change in place after the test's preparation
   and removes it after its cleanup. Each test runs
   as an unprivileged account whose outbound traffic is rejected, or as root
   when the test declares that it needs it. The account cannot change the
   lab's own files: the tests, the executor, the rules, the rule engine, the
   lab and the run's folder. The job checks that before the first test, and
   fails if it can, as it did in
   [run 44036033449](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44036033449)
   before those files were made read-only for it; in the runs before that
   change, among them 44035796630, the account wrote the six files of the
   in-place instruction overwrite's prerequisite into the pinned tests'
   folder. Every step (preparation, a marker
   before and after the test, the test, an effect check, the cleanup) runs in a
   kernel audit session of its own.
3. `bluefire-lab evaluate` computes `results.json` from the files the run
   leaves. A Sysmon event belongs to a test when its process is in the audit
   session of the test's attack step. Two more rules apply inside the test's
   window, between its markers. What cron starts for the test account belongs
   to a test run as that account. What systemd starts belongs to a test run as
   root, unless the same command also ran outside every test's window. The
   executor's own commands and the test's preparation and cleanup are left out.
   So are the start and end of the shell process that carries the whole command
   line (`sh -c` or `bash -c`, as the test declares); files it writes count as
   the test's. An auditd record belongs to a test when its process is one that
   belongs to the test by those rules, which leaves out the driver's own
   records in the same session. It then judges each of the lab's own rules on
   the tests, their variants and the ordinary activity.
4. `bluefire-lab report` writes `report.html`, one file that loads nothing from
   elsewhere when it opens (it refuses to write one that would), and the same
   table for the run page.
5. A separate job, which runs no test, compares the run with the latest
   successful run on `main` (`bluefire-lab compare`) and writes to the run page
   which answers changed and what changed under them: events, rules that
   match, a rule of the lab's own accepted now and how many published
   procedures it covers, or a hardening change that blocks now.

Seven controls must pass, or the run fails as a whole:

- **readiness:** both sensors recorded their probe before the first test began;
- **markers:** both markers and the launcher of every test are in the
  telemetry, and no answer is left inconclusive, for example because a
  hardening change could not be put in place or a test ran out of time with
  one;
- **changes:** every hardening change that was put in place was removed again
  after its test;
- **loss:** Sysmon reported its counts of lost and bad events once each, both
  zero, and none of its numbered records is missing from what was read or
  appears twice; and auditd's own count of lost records did not move during the
  run, nor did auditd rotate its log, which would leave records out of the
  export;
- **engine:** the rule engine loaded every rule and read every event it was
  given, and every category of rules had events to evaluate. That does not
  mean every rule could match: see the auditd limit below;
- **canary:** the known-detected test took effect and alerted, first and last;
- **control:** the harmless command took effect and raised no alert.

## Limits

- "No telemetry" means none under the pinned sensor configuration. Sysmon for
  Linux records process starts and ends, network connections, file deletions,
  and file creations. A file counts as created when it is opened for creation
  and its three timestamps are equal and less than 100 ms old. So a write to an
  existing file can show up as a creation when it leaves those timestamps
  fresh, as a read followed by an overwrite did for T1098.004 in run
  44035796630, though not in every run: whether it does depends on timing. An
  append that leaves the access time old, like the one to `~/.bashrc`, is not
  recorded by Sysmon, and neither are reads, permission changes and process
  environments. While `/tmp` is bind-mounted for the `noexec` change, Sysmon
  names files under it with the folder twice (`/tmp/tmp/crond`).
- auditd watches only the shell start files in
  [`sensors/audit.rules`](sensors/audit.rules), for writes and for changes of
  permissions, owner and extended attributes; `chattr`'s file flags, such as
  immutable, are not among them. It records the process starts of processes
  with a login uid, not those without one, such as what systemd starts for a
  test that runs as root. A start the kernel refused because no such file
  existed, as when a shell tries each folder of its search path, is not
  counted; one refused for another reason, such as `noexec`, is. So many pinned
  auditd rules cannot match under it: those about other system calls, other
  files, or audit keys it does not set. Besides the watches it records what
  programs report about themselves, such as `useradd` adding an account or
  `sudo` running a command, and those records count for the test whose process
  wrote them. auditd's record of a process's command line (PROCTITLE) keeps
  the shell's, the whole test, after the shell has become the one command it
  was given; no pinned rule reads that record, and the report names a program
  start by its own arguments.
- A process that systemd starts for a test that runs as root is tied to the
  test by time, inside the test's window, and not by process ancestry. The
  runner's own timers are stopped before the tests, so that their units do not
  start inside such a window, and systemd's own steps are left out. A late
  step of systemd for an earlier test can still land in a later root test's
  window: in run 44040235251 logind's removal of the runtime folder of the
  account T1078.003 logs in as, 10 s after that test, was tied to T1548.001,
  which changed none of its answers. That removal is left out now; setting the
  folder up, when a test logs in, stays the test's.
- Outbound traffic, name lookups included, is rejected for the test account
  only, not for tests that run as root. The job checks a name lookup and a
  connection to an address it looked up itself before the tests.
- Two tests are checked more weakly than the rest. The awk shell escape
  (T1059.004) has no check of its own that could fail: awk exits with status 0
  whether or not the shell starts, so its "took effect" rests on the command
  having run. The security software discovery (T1518.001) is checked by a text
  that `ps` also prints for the test's own `grep`, so the check shows only that
  `ps` ran.
- One runner runs the whole list in sequence (the job takes about twelve
  minutes), and GitHub hands out runners with different kernels under the same
  label:
  kernels 7.0.0-1014-aws (the run above) and 7.0.0-1017-azure (run
  44035796630, the same 49 tests) have both been seen.

## Not yet shown

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
