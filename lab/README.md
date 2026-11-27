# BlueFire lab

A test bench for defenders. It runs published attack tests on a disposable lab
target, records what the sensors on that target saw, evaluates pinned detection
rules over those records, and reports two answers for every test: did the
technique take effect, and what did the defense see.

In this document:

- [The bench on one host](#what-it-shows-today), and what its runs show.
- [Hardening that blocks a technique](#hardening-that-blocks-a-technique), and [the lab's own detection rules](#detection-rules-of-the-labs-own).
- [A sensor change that makes a gap visible](#a-sensor-change-that-makes-a-gap-visible).
- [The range and its seal](#a-range-and-its-seal): a network of throwaway containers with no route out.
- Range one: [its hosts](#range-one-its-hosts), [its ordinary activity](#range-one-ordinary-activity), [its path of published tests](#range-one-the-path), [the path's score and recording](#range-one-the-score-and-the-recording) and [its defenses](#range-one-its-defenses).
- [Comparing two runs](#comparing-two-recordings).
- [The defender loop](#the-defender-loop-so-far): a test nobody saw, a sensor change, then a new rule.
- [How to run it](#how-to-run-it).
- [Limits](#limits).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../docs/report-dark.png">
  <img src="../docs/report-light.png" width="1280" alt="Report for run 44133154347 showing the outcome totals, runner details and first rows of the results table.">
</picture>

The top of the report of
[run 44133154347](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44133154347),
as that run's job pictured it. The whole report is in the run's artifact.
This is the report of an early run; the newest results are in the sections
below.

## What it shows today

Everything in this section comes from one run of the `lab` workflow:
[run 44126989299](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44126989299),
17 November 2026. Its run page shows the same answers in a longer table, and
its artifact `lab-run` holds the sensors' raw output (`sysmon.txt` and
`audit.txt`), the answers with what each rests on (`results.json`) and the full
report (`report.html`). GitHub keeps both for 90 days.

- **Target:** a GitHub-hosted `ubuntu-24.04` runner (Ubuntu 24.04.5, kernel
  7.0.0-1017-azure, runner image 20261111.370.1).
- **Tests:** 61 Linux tests from Atomic Red Team at commit `a0e3f9bc`, run
  unchanged by its executor, Invoke-AtomicRedTeam, at commit `8af478bb`. 60 of
  them ran: the runner has no `ccencrypt`, which the ccrypt test (T1486)
  needs, so the run left that test out and its report says so. Five run with
  one input argument changed; [`pinned-tests.yaml`](pinned-tests.yaml) says
  which and why.
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

All 60 tests took effect. Three of them raised an alert, meaning a match of a
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
| T1053.003 Cron - Add script to /etc/cron.d folder | telemetry only (low) | telemetry only |
| T1053.006 Create Systemd Service and Timer | telemetry only (low) | alert |
| T1543.002 Create Systemd Service | telemetry only (low) | alert |
| T1136.001 Create a user account on a Linux system | telemetry only (medium) | alert |
| T1098.004 Modify SSH Authorized Keys | telemetry only (none matched) | telemetry only |
| T1546.004 Add command to .bashrc | telemetry only (medium) | telemetry only |
| T1546.004 Add command to .bash_profile | telemetry only (medium) | telemetry only |
| T1546.004 Append commands user shell profile | telemetry only (medium) | telemetry only |
| T1037.004 rc.local | telemetry only (medium) | telemetry only |
| T1546.005 Trap EXIT | telemetry only (medium) | telemetry only |
| T1546.018 Python Startup Hook - usercustomize.py (Linux / MacOS) | telemetry only (medium) | alert |
| T1569.003 Enable systemd Service for Persistence with Auto-Restart | telemetry only (low) | alert |
| T1569.003 Create and Enable a Malicious systemd Service Unit | telemetry only (low) | alert |
| T1569.003 Masquerade Malicious Service as Legitimate System Service | telemetry only (low) | alert |
| T1569.003 Create systemd Service Unit from /tmp (Unusual Location) | telemetry only (low) | telemetry only |
| T1556.003 Malicious PAM rule | telemetry only (none matched) | telemetry only |
| T1078.003 Reactivate a locked/expired account (Linux) | telemetry only (medium) | telemetry only |
| T1552.003 Search Through Bash History | telemetry only (medium) | telemetry only |
| T1552.004 Discover Private SSH Keys | telemetry only (medium) | alert |
| T1552.004 Copy Private SSH Keys with CP | telemetry only (informational) | alert |
| T1552.004 Find TLS private key files | telemetry only (medium) | telemetry only |
| T1222.002 chmod - Change file or folder mode (numeric mode) | telemetry only (medium) | telemetry only |
| T1548.001 Set a SetUID flag on file | telemetry only (medium) | alert |
| T1548.001 Set a SetGID flag on file | telemetry only (medium) | alert |
| T1548.001 Make and modify capabilities of a binary | telemetry only (medium) | telemetry only |
| T1036.003 Masquerading as FreeBSD or Linux crond process | telemetry only (medium) | telemetry only |
| T1036.005 Execute a process from a directory masquerading as the current parent directory | telemetry only (low) | alert |
| T1564.001 Create a hidden file in a hidden directory | telemetry only (low) | telemetry only |
| T1070.006 Set a file's modification timestamp | telemetry only (medium) | telemetry only |
| T1070.003 Clear Bash history (truncate) | alert (high) | alert |
| T1070.003 Clear Bash history (echo) | no telemetry (none matched) | no telemetry |
| T1070.003 Clear Bash history (cat dev/null) | telemetry only (none matched) | telemetry only |
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

- 56 tests took effect and left telemetry besides their launcher's start, but
  no pinned rule of an alert level fired. The lab's own rules close 14 of these
  gaps; 42 stay open. How much of a technique its telemetry shows differs: for
  the preloaded library (T1574.006) it is only the `ls` that ran, because
  neither sensor records the environment variable that carries the technique,
  except as part of the test's own command line, so no rule could close the
  gap without matching the test's text.
- Of the three pinned alerts, one would also fire on ordinary work. The alert
  on emptying the history with `truncate` (T1070.003) comes from "Binary
  Padding - Linux", a rule for another technique that matches any
  `truncate -s`: it matched the baseline's three ordinary uses of `truncate`
  in the same run. The other two, the awk shell escape and turning ASLR off
  with `sysctl` (T1685), matched nothing ordinary.
- One test left no telemetry: emptying the history with the shell's own
  `echo` (T1070.003 Clear Bash history (echo)) starts no program, auditd does
  not watch history files, and Sysmon reports a write to a file that exists
  already only when the file looks newly created afterwards, which this one,
  written by the test's preparation, did not. auditd's
  watch on the shell start files records the append to `~/.bashrc` that Sysmon
  cannot see, and recording process starts as well raised two of the alerts:
  see [A sensor change that makes a gap visible](#a-sensor-change-that-makes-a-gap-visible).
- On 31 of the tests, rules of level medium or lower matched only the one shell
  process whose command line holds the whole test. The report shows them, and
  does not count them as detections.

The canary, a test the pinned rules are known to catch (T1070.003, history
removal with `rm`), raised its alert at the start and at the end of the run. A
harmless command (T1082, `hostname`) ran through the same executor and raised
none. The first run of the first 49 of these tests,
[run 44033742721](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44033742721),
before auditd recorded process starts, gave the same answers apart from the two
tests that change made alerts and one more: the in-place instruction overwrite
(T1055.009) had not taken effect, because the lab ended the process the test
writes into before that process ran what was written. The test now waits five
seconds before its check. The first run of the twelve others,
[run 44060562649](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44060562649),
reported three systemd services (T1569.003) as attempted without effect: the
tests write their unit's command line inside quotes that its own quotes cut
short, so the unit runs without the redirect to its output file, and that file,
which each check read, stayed empty although each unit ran. The checks now read
systemd's own record that the unit ran and ended without error.

## Hardening that blocks a technique

In [run 44126989299](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44126989299),
twelve tests ran once more after all the other tests, before the closing
canary, each with one of four hardening changes in place: `/tmp` mounted
`noexec` was tried on six tests, the account's `~/.bashrc` made immutable on
three, crontab limited by `/etc/cron.allow` on two. Eight of the twelve runs
were blocked: the test ran with its prerequisites met and did not take effect,
while it had taken effect without the change earlier in the same run. What
each test printed shows why:

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

Four runs were not blocked, and each shows what its change leaves open. With
`/tmp` mounted `noexec`, the password-protected ZIP payload (T1027.013) still
printed `T1027.013: Payload extracted from encrypted ZIP`: it runs its script
through `bash`, which the mount does not stop. With `/etc/cron.allow` in place,
root still wrote a job into `/etc/cron.d` (T1053.003 Cron - Add script to
/etc/cron.d folder): the file governs only the `crontab` command. With
`~/.bashrc` immutable, lines were still added to the account's other start
files (T1546.004), which the change does not cover: a command to
`~/.bash_profile`, and to `~/.profile` the comment that test appends. So `/tmp` mounted `noexec` blocked five of the six published procedures
it was tried on, `/etc/cron.allow` one of two, the immutable `~/.bashrc` one of
three and the root-owned `~/.ssh` one of one. The first four rows were first shown in
[run 44020766356](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44020766356).

What the changes leave open beyond these was not tried: keys that root adds for
the account, moving the root-owned `~/.ssh` aside, which the account can do
because it owns its home folder, and programs run from `/dev/shm` or the
account's home folder. The changes are defined in
[`pinned-tests.yaml`](pinned-tests.yaml) under `defenses`.

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
history tests run again on `~/.zsh_history`, `~/.histfile`, `~/.sh_history` and
`~/.history`, and the key search on
`id_ed25519`, but the systemd tests' variants change a unit's name and not the
folder it is written to, though two of those tests, T1053.006 and T1543.002,
allow that too. Beyond that, each
rule's description says which spellings it covers, and only the spellings the
tests use have been seen in a run.

The visibility answer stays the pinned rules' alone. A second column in the
report gives the answer with the accepted rules counted too, and a rule that is
not accepted changes no answer. In
[run 44126989299](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44126989299),
three of the 60 tests raised an alert with the pinned rules, and 17 with the
accepted rules as well:

| Rule | Alerts on | Runs with changed input arguments | Verdict |
| --- | --- | --- | --- |
| [Systemd Unit File Written By A Shell](rules/linux/file_event/file_event_lnx_systemd_unit_written_by_shell.yml) | T1053.006 Create Systemd Service and Timer, T1543.002 Create Systemd Service, T1569.003 Enable systemd Service for Persistence with Auto-Restart, T1569.003 Create and Enable a Malicious systemd Service Unit, T1569.003 Masquerade Malicious Service as Legitimate System Service | alerted on 5 of 5 | accepted |
| [System Account Created With A Login Shell](rules/linux/process_creation/proc_creation_lnx_system_account_with_login_shell.yml) | T1136.001 Create a user account on a Linux system | alerted on 1 of 1 | accepted |
| [Setuid Or Setgid Bit Set With Chmod](rules/linux/process_creation/proc_creation_lnx_chmod_setuid_setgid.yml) | T1548.001 Set a SetUID flag on file, T1548.001 Set a SetGID flag on file | alerted on 2 of 2, one for each | accepted |
| [Shell History File Emptied](rules/linux/process_creation/proc_creation_lnx_history_file_emptied.yml) | T1070.003 Clear Bash history (truncate), T1070.003 Clear Bash history (ln dev/null) | alerted on 3 of 3, on `~/.zsh_history`, `~/.histfile` and `~/.history` | accepted |
| [Python Startup Hook File Written](rules/linux/file_event/file_event_lnx_python_startup_hook_written.yml) | T1546.018 Python Startup Hook - usercustomize.py (Linux / MacOS) | alerted on 1 of 1, with `python3.12` | accepted |
| [Private Key Files Searched With Find](rules/linux/process_creation/proc_creation_lnx_find_private_keys.yml) | T1552.004 Discover Private SSH Keys, T1552.004 Copy Private SSH Keys with CP | alerted on 2 of 2: for `id_ed25519`, and with another folder to copy to | accepted |
| [Program Run From A Folder Named Like Dots](rules/linux/process_creation/proc_creation_lnx_program_in_dots_folder.yml) | T1036.005 Execute a process from a directory masquerading as the current parent directory | alerted on 1 of 1 | accepted |
| [Archive Extracted With A Password On The Command Line](rules/linux/process_creation/proc_creation_lnx_archive_extracted_with_password.yml) | T1027.013 Password-Protected ZIP Payload Extraction and Execution | alerted on 1 of 1, with another password | accepted |
| [Program Named Like A System Daemon Run From A Temporary Folder](rules/linux/process_creation/proc_creation_lnx_daemon_name_from_temp_folder.yml) | T1036.003 Masquerading as FreeBSD or Linux crond process | none: the test has no input arguments to change | not accepted |

The rule for a unit file written by a shell was written for the first two of
its procedures. It also alerts on three more added to the list later, all
T1569.003, and on each one's run with changed input arguments. The rule for a
search for private key files, written for one procedure, also alerts on a
second, keys copied with `cp` after a `find`. Two other accepted rules alert on
two published procedures each, and four cover a single procedure each so far.

Other published procedures of the same techniques show where the rules stop.
The unit rule does not alert on a unit written in `/tmp` and linked into
systemd's folder (T1569.003 Create systemd Service Unit from /tmp): the shell
writes the unit outside systemd's folders, which the rule looks at, and
`systemctl` makes the link. The key rule does not alert on
a search for TLS key files (T1552.004 Find TLS private key files), which looks
for names such as `*.key` and `*.pem` that it does not describe. The setuid
rule does not alert on a file capability set with `setcap` (T1548.001 Make and
modify capabilities of a binary), a different way to the same privilege, for
which the pinned rule "Linux Setuid Capability Set on a Binary via Setcap
Utility" is of level low. And the history rule does not alert on
`cat /dev/null > ~/.bash_history` (T1070.003 Clear Bash history (cat dev/null)):
the redirection is the shell's, so no program start names the history file,
and Sysmon reported no write to it: it reports one to a file that exists
already only when the file looks newly created afterwards (see the Limits).

In the same run the baseline left 377 events and the runner's and the lab's own
work outside the tests 8,520, much of it the lab's own driver switching
accounts and sessions. None of the lab's rules matched any of them, while 20
pinned rules did. Two of those are of level high: the canary's own rule,
"History File Deletion", matched the baseline's removal of a copy of a history
file (`rm ~/.bash_history.bak`, record 1094), and "Binary Padding - Linux" its
three uses of `truncate`. The others are medium or lower, for example "User Has
Been Deleted Via Userdel" on the baseline's `userdel`.

The baseline is a short script, not days of real administration, so a rule that
stays quiet on it can still be noisy elsewhere. One such case is known: the
rule for a unit file written by a shell also alerts when an administrator
writes a new unit by hand. A draft that could not fire with this sensor is kept
in [`rules/rejected`](rules/rejected) with the reason.

### A rule on auditd's records: a history file truncated in place

[Shell History File Truncated In Place](rules/linux/auditd/lnx_auditd_history_file_truncated_in_place.yml)
is the first of the lab's rules on auditd's records, which the lab now
evaluates beside its rules on Sysmon's. It was written for the one step the
watch on history files made visible (see
[the first change](#a-pair-of-runs-for-a-change-to-the-defense)), from the
record of T1070.003 Clear Bash history (echo) in
[run 45350480637](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45350480637):
`openat` with the flags `0x241`, `O_WRONLY|O_CREAT|O_TRUNC`, on the existing
`~/.bash_history`, by the launcher's `sh`.

- **What it is.** A file under the history watch opened, successfully, for a
  truncating write (`O_TRUNC`, by `open`, `openat` or `creat`), which empties
  it in place: what a shell's redirect does, `> file`, whatever command is in
  front of it. It names no account, no command and no shell. An open the
  kernel refused emptied nothing, and does not match.
- **Why ordinary writers mostly do not do it.** By their source code: bash
  4.4 and later (readline 7.0 and later) and busybox ash append to their
  history file with `O_APPEND` and rewrite it by writing a new file and
  renaming it over the old one; tcsh always saves by writing a new file and
  renaming it over the old one; ksh93 appends and trims with `ftruncate`; zsh
  appends, or renames a new file over the old one. Three exceptions among the
  shells are known, and the rule alerts on each: bash creating a missing
  history file, which it opens with `O_TRUNC`, once per account; bash before
  4.4, whose readline trims the file in place on exit once it is longer than
  `HISTFILESIZE`, and rewrites it in place for `history -w`; and zsh with its
  option `HIST_SAVE_BY_COPY` unset. Besides the shells, any program that
  rewrites the history file in place under its own name truncates it and
  alerts: an editor that saves in place, as nano does, or a copy onto the
  existing file, `cp backup ~/.bash_history`. The rule cannot leave out the
  creation: auditd's system call record gives the number of path items, but
  on kernels before 6.12 an `O_CREAT` open of an existing file records two
  items too, as a creation does.
- **What it rests on.** auditd's system call record holds the open's flags and
  not the file's name; its path record holds the name and not the flags; and
  the rule engine reads one record at a time. So the rule takes the file from
  the audit key of the watch, `shell-history` in
  [`sensors/audit.rules`](sensors/audit.rules). A defender with another key
  puts that key in the rule.
- **What it does not see.** The `truncate` program, which opens without
  `O_TRUNC` and then shortens the file, and `ln -sf`, which renames a new link
  over the file as bash does when it rewrites its history: the lab's
  [Shell History File Emptied](rules/linux/process_creation/proc_creation_lnx_history_file_emptied.yml)
  covers both from their program starts. Nor anything else that writes a new
  file and renames it over the history file: bash's own `history -c` followed
  by `history -w` on bash 4.4 and later, `sed -i`, and editors that save by
  rename. Nor removing the file, `openat2`, whose flags auditd does not show,
  or a history file the watch does not name.

Its text was fixed from that one record and from what the shells do, before
it was evaluated over a whole run.
[Run 45395673682](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45395673682)
is the first to evaluate it. Its recordings and job summary were written
before a recording named the pull request's head commit: they name commit
`e809f685`, the merge commit GitHub made for the run, which no clone has. A
clone has the pull request's head, `09f4c4b4`, whose files are that merge
commit's, on its base `3d8f3610`, whose rules are the before side. Of the 4
published procedures of T1070.003 on the list besides the canary, it alerted
on two, the echo test and T1070.003
Clear Bash history (cat dev/null), `cat /dev/null > ~/.bash_history`, each by
one event, and not on `truncate` and `ln dev/null`, for the reasons above, nor
on the canary's `rm`. It matched none of that run's 8,847 ordinary events. A
run's ordinary activity tests little of its price: by the records of run
45350480637, 2 of its ordinary events are of the key the rule reads (the
baseline's append that creates `~/.bash_history`, and its `chmod`), and none
saves a shell's history the way a shell does. A test on records built by hand
from the shells' and the kernel's code, and marked as built, stands in for
that part ([`tests/test_lab_rules.py`](tests/test_lab_rules.py)). A run
accepts a rule only when each procedure it alerts on also ran with changed
input arguments, so the list now runs both once more, on `~/.zsh_history` and
on `~/.sh_history`, which the watch names too. The rule alerted on both of
those runs as well, and run 45395673682 accepted it.

## What the target has

Each run starts with an inventory of the target, and chooses the tests by it.
In [run 44028032549](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44028032549)
(17 November 2026) the hosted runner had 5 accounts that can log in (`root`,
`runner`, the lab's own test account, and `packer` and `postgres`, which come
with the runner image), 26 running services before the lab started its sensors
(auditd among them, which the job installs), and 9 listening TCP and UDP addresses,
among them TCP port 22, the port SSH uses, on every address. Sysmon for Linux
and auditd were both active once started. Every program the tests then named
(`awk`, `crontab`, `systemctl`, `useradd`) was there, so no test was left out.
In [run 44126989299](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44126989299)
the list names more programs, among them `ccencrypt` for the ccrypt test
(T1486), and the runner has no `ccencrypt`: the run left that test out, and its
report and run page list it with that reason.

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
recorded as well, among them the user manager systemd starts for a login and
what that starts. The runner's agent and the system's services have none. In
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
which it did during
[run 44050159740](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44050159740),
the first with this change, so its export missed records and the run failed
its readiness control: the lab now sets auditd not to rotate, and the loss
control fails a run in which it does.

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
   belongs to the test by those rules, or was forked by one and never started a
   program Sysmon saw (a subshell, or a start the kernel refused), which leaves
   out the driver's own records in the same session. It then judges each of
   the lab's own rules on
   the tests, their variants and the ordinary activity.
4. `bluefire-lab report` writes `report.html`, one file that loads nothing from
   elsewhere when it opens (it refuses to write one that would), and the same
   table for the run page.
5. `bluefire-lab recording` writes `recording.json`: the run as one file, made
   to be replayed step by step. It holds each step in order, the events tied to
   it and the rules that matched, taken only from `run.json` and
   `results.json`, with the digest of each rule folder of the run beside them.
   Its format is [`docs/RECORDING.md`](../docs/RECORDING.md).
   The job writes it whenever the evaluation wrote `results.json`, also when a
   control failed, and it is part of the run's artifact.
6. `bluefire-lab replay` writes `replay.html` beside it: the app's single replay
   page (`bluefire/ui/replay.html` of the same checkout) with the recording put
   inside, which plays the run in a browser with nothing installed (see
   [`docs/LIVE_VIEW.md`](../docs/LIVE_VIEW.md)). The command reads the CI run
   it runs in from GitHub's own variables (`GITHUB_ACTIONS`,
   `GITHUB_SERVER_URL`, `GITHUB_REPOSITORY`, `GITHUB_RUN_ID`), and only when
   that is the very run the recording names does the page say that the lab
   workflow made it in that CI run. Written anywhere else, the page reads the
   file as imported: it says the CI run the file names was not checked. It is part of the run's
   artifact `lab-run` too. The command fills the template as the app does,
   refuses one that does not hold exactly one recording element and one origin
   element, and never replaces an existing file.
7. When a pull request changes a sensor's settings, the list runs twice, with
   the base commit's files and with the head's, and a job that runs no test
   compares the two recordings: see
   [A pair of runs for a change to the defense](#a-pair-of-runs-for-a-change-to-the-defense).
   When it changes only the lab's own rules, the list runs once, and a job that
   runs no test evaluates that run twice, with the base commit's rules and with
   the head's, and compares the two recordings: see
   [A change of the lab's rules: one run, evaluated twice](#a-change-of-the-labs-rules-one-run-evaluated-twice).
   Otherwise a separate job, which runs no test either, compares the run's
   recording with that of the latest successful run on `main`
   (`bluefire-lab compare`, see
   [Comparing two recordings](#comparing-two-recordings)), writes `delta.md` to
   the run page, and keeps `delta.json` as the artifact `lab-delta`.

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
  environments. Sysmon can miss the creation of a new file too: in
  [run 44083991612](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/44083991612)
  it reported the deletion of the `usercustomize.py` that T1546.018 wrote and
  not its creation, while it reported both for that test's run with changed
  input arguments in the same job, so in that run the lab's rule for that file
  matched no published test and was not accepted. While `/tmp` is bind-mounted
  for the `noexec` change, Sysmon names files under it with the folder twice
  (`/tmp/tmp/crond`).
- auditd watches only the shell start files and the test account's shell
  history files in
  [`sensors/audit.rules`](sensors/audit.rules), for writes and for changes of
  permissions, owner and extended attributes; `chattr`'s file flags, such as
  immutable, are not among them. It records the process starts of processes
  with a login uid, not those without one, such as the system services systemd
  starts for a test that runs as root. A start the kernel refused for a missing
  file is not counted when it was part of a search, the same process trying
  the same name in another folder, as a shell does along its search path. A
  single start of a missing file counts, such as the missing payload of the job
  T1053.003 plants, or `useradd` trying to start `nscd`, and so does a start
  refused for another reason, such as `noexec`; each is named by the file the
  kernel refused. Such a start is tied to a test only through its process: one
  of the test's, or a fork of one that left a record; a fork of a subshell that
  left none, or of a process that had already ended, is not. So many pinned
  auditd rules cannot match under it: those about other system calls, other
  files, or audit keys it does not set. Besides the watches it records what
  programs report about themselves, such as `useradd` adding an account or
  `sudo` running a command, and those records count for the test whose process
  wrote them. auditd's record of a process's command line (PROCTITLE) keeps
  the shell's, the start of the test's own text (the kernel keeps at most 128
  bytes), after the shell has become the one command it was given, and in a
  fork of the shell whose program the kernel refused; no pinned rule reads
  that record, and the report names a program start by its own arguments.
- A process that systemd starts for a test that runs as root is tied to the
  test by time, inside the test's window, and not by process ancestry. The
  runner's own timers are stopped before the tests, so that their units do not
  start inside such a window, and systemd's own steps are left out. A late
  step of systemd for an earlier test can still land in a later root test's
  window: in run 44040235251 logind's removal of the runtime folder of the
  account T1078.003 logs in as, 10 s after that test, was tied to T1548.001,
  which changed none of its answers. That removal is left out now; setting the
  folder up, when a test logs in, stays the test's. The user manager systemd
  starts for such a login gets a session of its own from it, so the time rule,
  which takes only what systemd started outside every session, ties it neither
  to that test nor to the ordinary activity.
- Outbound traffic, name lookups included, is rejected for the test account
  only, not for tests that run as root. The job checks a name lookup and a
  connection to an address it looked up itself before the tests.
- Two tests are checked more weakly than the rest. The awk shell escape
  (T1059.004) has no check of its own that could fail: awk exits with status 0
  whether or not the shell starts, so its "took effect" rests on the command
  having run. The security software discovery (T1518.001) is checked by a text
  that `ps` also prints for the test's own `grep`, so the check shows only that
  `ps` ran.
- One runner runs the whole list in sequence (the job took 13 to 16 minutes
  in the runs above), and GitHub hands out runners with different kernels
  under the same label: kernels 7.0.0-1017-azure (the run above) and
  7.0.0-1014-aws (run 44096893965, the same tests before the cron.d test's
  change) have both been seen.

## A range and its seal

A range is a small network of disposable containers, described by a spec file
under [`range/`](range). The lab brings it up with the plain Docker CLI, proves
that it is sealed, and takes it down again:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install ./lab
bluefire-lab range run lab/range/seal-check.yaml --out <new folder>
bluefire-lab range down lab/range/seal-check.yaml
```

The lab goes into a virtual environment of its own: on a current Debian or
Ubuntu the system Python refuses a plain `pip install` (it is "externally
managed"), and `python3 -m venv` needs the package `python3-venv`. The later
commands in this file assume that environment is active.

It needs Docker Engine 28 or later on a local endpoint (`unix://` or
`npipe://`). The containers of [`seal-check.yaml`](range/seal-check.yaml) run
no published test: they run nothing but the official nginx image's web server,
which gives the seal a real listener to connect to. A spec with a path, such as
range one's, runs its published tests, on a developer's machine as in CI, but only inside
the sealed range the engine created (see [range one: the path](#range-one-the-path)).

Every network is created `--internal` with the isolated gateway mode, so that
the Docker host has no address on it, and without IPv6. Every container is
created with the same few flags (a name and labels, its host name, its networks
with its host name as alias, `--dns-search .`, `net.ipv4.ip_forward=0`, a pids
and a memory limit, `--pull never`, and `--init` for a host built from the
spec) and nothing else. Every object is
addressed by the full ID Docker returned when it was created. The seal is
checked in phases, each recorded in `seal.json`:

1. **static**: on the created containers, before any of them starts.
2. **no way out**: right after the containers start, before the engine waits
   for anything in the range or runs anything there but the seal's probes.
   Everything below except the segmentation between the hosts and the
   listening ports, with a positive control that needs no service of the
   range: an answer from another range container, a connection or a refusal
   from its kernel.
3. **segmentation**: after the ready gate, once the hosts' services listen
   (for range one, after the defense is ready too, see
   [the defense of a range](#the-defense-of-a-range)): everything, the probes
   between the hosts and the listening ports included, with a connection that
   must work as the positive control.
4. **after path**: everything again, once the path of published tests has
   run.
5. **teardown**: the event watch, after the teardown.

The checks:

- **Objects:** the run's label and the spec's prefix name exactly the
  containers and networks the run created, and no other container shares a
  range container's network, pid or ipc namespace (`--network container:<id>`
  leaves no trace on the network itself).
- **Networks:** internal, bridge, no IPv6, isolated gateway mode, and once the
  containers run, exactly the spec's members.
- **Containers:** the pinned image, or the image built from the spec under the
  tag of its build context, whose layers start with those of the image its
  Dockerfile pins by digest; not privileged; no added capability; no
  published port; no device, bind mount, volume or mount of any kind; no extra
  host, DNS server or DNS option; no host namespace; no unconfined security
  option; only the spec's networks, each with the host's alias. `--init` only
  where the engine sets it: Docker then mounts its own `docker-init` program
  read-only at `/sbin/docker-init`, a mount that `docker inspect` does not list
  under `Mounts`, so the check `container: init` names it.
- **Inside each container**, with a probe script that uses only bash,
  coreutils' `timeout` and `getent`: first the positive control (so that a
  broken tool cannot pass a probe that must fail); in every phase, four
  outside addresses (public resolvers and cloud metadata endpoints) and a
  canary; and from the segmentation phase on, every pair the spec derives
  (hosts that share a network must connect on each port the target listens
  on; hosts that share none must fail). The canary: for the seal's
  duration the engine listens on a random TCP port on the Docker host, every
  container tries it at every gateway the daemon knows, and the canary must see
  no connection. A probe that must fail passes only when nothing answered
  (network unreachable, no route to host, or a timeout); a refused connection
  fails, since something routed the packet and answered it. Also, from the
  segmentation phase on: the TCP ports in LISTEN state on any address but
  loopback (read from `/proc/net/tcp` and `/proc/net/tcp6`) are exactly the
  ports the spec gives the host under `listens`, so that no port the matrix
  does not probe is open. In every phase: routes only
  to the container's own subnets, forwarding off, no Docker socket, Docker's
  resolver only, range names resolving only to shared subnets and outside names
  not resolving.
- **Events:** a watch on Docker's events runs from before the first create to
  the end of the teardown, and any event on the range that the engine did not
  cause breaks the seal, as does the create or start of any other container
  that joins a range container's namespaces. A container whose create or
  start the watch sees while the range has containers, and which is gone
  before the watch could read its `docker inspect`, breaks the seal too: it
  may have joined a range container and left. On a machine that runs other
  containers during a run, a short-lived one (a `docker run --rm` that ends at
  once, say) can therefore make the run fail or invalid although it had
  nothing to do with the range; run a range while nothing else starts
  containers. The watch is checked once more after the teardown, as the
  seal's last phase: Docker must have reported the removal of every object,
  to a watch that was still running.

The run writes `seal.json` (every check, with the command it read, the value it
observed and whether it passed), `seal.md`, `manifest.json` and
`docker-events.ndjson` on every exit path, and takes the range down on every
exit path after the first create. Its exit code is 0 when the range was sealed
and still was at the end; 1 when it refused to start, Docker failed, or the
range was not ready in time and its seal held; 3 when the seal failed before
the place of the path: in the static phase, before the ready gate (the engine
had run nothing in the range but the seal's probes), after it (the ready
gate's own commands had run), or when the range was not ready, whose seal is
judged once more before the run ends (phase "no way out, not ready", and the
event watch to the end of the teardown), so that "not ready" never hides a
seal that failed; and 4 when the run was made
invalid. `passed` at the top of `seal.json` is true only for a run that ended
sealed: a run that was stopped or made invalid after its checks had passed is
not recorded as passed. `range down` removes only containers and networks that
carry both the spec's prefix and its range label. One case leaves something for
it: Docker does not remove a network while a container from outside is still
connected to it. The run then records that its teardown was not complete, and
`range down` removes the network once that container is gone.

The job `seal` in `.github/workflows/range-one.yml` runs the passing case and
five planted breaks (`--plant` and a network connect from outside), each of
which must fail the seal for its own reason: a network that is not internal, a
network without the isolated
gateway mode (caught by the host canary as well), a published port, a bind
mount, and an extra container connected to a range network after the seal
(caught by the event watch).
[Run 45385756781](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45385756781)
shows it on a GitHub-hosted runner with Docker Engine 28.0.4, phase by phase.
The passing case was sealed: `static` 94 of 94 checks, `no way out` 149 of
149, `segmentation` 158 of 158, `after path` 158 of 158. A network that is not
internal, a published port and a bind mount each failed `static`, and no later
phase ran. The missing isolated gateway mode failed `static` and `no way out`
(148 of 155 checks), and the ready gate never ran. The connect was recorded by
the event watch after `segmentation` had passed, and that run ended invalid
(exit code 4). In the same run, range one passed `static` (201 checks),
`no way out` (357), `segmentation` (430) and `after path` (430).
[Run 45246204061](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45246204061)
showed the same six cases with an earlier engine, which made all its checks
inside the containers in one phase after the ready gate.

## Writing a spec

A spec is a YAML file; [`range/seal-check.yaml`](range/seal-check.yaml) is the
smallest and [`range/range-one.yaml`](range/range-one.yaml) uses every part.
The loader (`lab/bluefire_lab/range/spec.py` and, for `activity`,
`activity.py`) refuses anything else with a sentence that names the key and
the rule. What it asks for:

- **Top level.** Required: `range` (a name), `version: 1`, `prefix` (starting
  `bluefire-lab-`; every container and network is named with it, so two
  ranges on one machine need two prefixes), `docker: {min_engine: 28}` or
  later, `networks` and `hosts`. Optional: `base` (the image and Ubuntu
  snapshot that hosts without an `image` are built from), `defense` (Wazuh:
  how the manager and the agents are installed and what the agents watch),
  `atomic_red_team` (the repository and commit of the published files the
  hosts carry, and the lock beside the spec), `rule_sets` and `defenses`
  (below), `path`, `activity`, and `sentence` and `executor`, which other
  parts of the lab read.
- **Networks** are names with no settings: every one is created internal,
  with the isolated gateway mode and without IPv6.
- **Hosts.** Keys: `kind` (`attacker`, `internet`, `host` or `defense`),
  `role`, `networks`, `listens`, and either `image` (pinned by digest) or,
  for a host built from `base`, `packages`, `services`, `agent`, `watch` and
  what is planted: `accounts`, `keys`, `known_hosts`, `dirs`, `files`,
  `database`, `sshd`, `serve` and `atomics_src`. A `defense` host, the Wazuh
  manager, takes only `kind`, `role`, `networks` and `listens`. Nothing else
  (no ports, volumes, capabilities or network modes).
- **Services.** A built host can start `sshd` (package `openssh-server`, port
  22), `nginx` (`nginx`, 80), `php-fpm` (`php-fpm`), `mariadb`
  (`mariadb-server`, 3306), `cron` (`cron`) and `inet-server` (`python3`, 80
  and 443). Its `listens` must be exactly the ports of its services, since
  the seal checks that no other port listens.
- **Every host shares a network with a host that listens.** Each host's
  first connection that must work is the seal's positive control: a host
  with none could not show that its failed probes mean anything, so the
  loader refuses it. A one-host range is refused for the same reason.
- **Files** a host plants `from:` a path are read from the spec's folder,
  `repo:<name>` from `repos/<name>` beside it. Each must be a regular file
  inside that folder: a link, or a path through a linked folder, is refused.
- **Jobs** of `activity` (`seed`, `warmup_seconds`, `tail_seconds`, `jobs`)
  have `name`, `host`, `account`, `every` and `do`: `do: cron` with `run`
  (and `every` in whole minutes), `do: http` with `target` (a host running
  nginx) and `paths`, or `do: ssh` with `target` (`account@host`) and `run`;
  `writes` lists the files a job writes, by pattern. [Ordinary
  activity](#range-one-ordinary-activity) gives the rules that keep jobs
  apart from each other and from the path.
- **Rule sets.** `rule_sets` maps a name to a public rule set, pinned: `kind`
  (`sigma`, the one kind of rule set the lab can give a recorded run to),
  `repo` (a GitHub repository), `commit` (in full), `folders` (the folders of
  the repository to take, none inside another), `licence` (the repository's
  licence file, which is fetched and kept with the rules) and `lock` (a file
  beside the spec with the SHA-256 of every one of those files; rule sets can
  share it, and it is not the lock of `atomic_red_team`). All six are
  required. A set may select only executable rule files with `include: rules`,
  restrict discovery to source folders with `rule_paths` (where `*` is one
  whole path part), and name exact files under `exclude`. A Sigma set may also
  name exact `pipelines`: each must be a YAML pipeline made only of
  `value_placeholders` transformations. The lock records the selection, the
  number left out for each reason, and every selected file's SHA-256. A
  declared pipeline is selected even when it is outside `rule_paths`; its
  placeholder values are applied only to engine copies of the rules, never to
  the fetched files. The name is the rule set's detector in a recording, so it
  is not `pinned` or `lab`, which a recording uses already, nor `wazuh`.
- **Defenses.** `defenses` is a list of 1 to 8 named defenses, each with `id`
  (letters, digits, `-` and `_`), `name` (a few plain words), `sensors` (the
  kinds of sensor it records with; the one kind today is `wazuh-agent`, the
  agents of `defense.wazuh` on every host that has one) and `rules` (at most
  four: `wazuh`, the rules the manager runs live, or a name of `rule_sets`;
  an empty list is a defense that only records). The first is the baseline
  that a recording shows first. A defense's rules must read what one of its
  sensors records, and every rule set must be run by a defense. A spec
  without `defenses` has the one its agents and its manager's live rules
  make, and its recording has no `defenses`. A later kind of sensor or of
  rule set is one more word in the loader's lists (`SENSORS`, `RULE_KINDS`)
  and the code that reads it; the two keys keep their shape.
  ([Range one: its defenses](#range-one-its-defenses) says what a defense
  is and how one judges a run.)
- **YAML.** The loader reads only `true` and `false` as booleans, so that the
  key `off` of `defense.wazuh` stays a key. PyYAML's `safe_load` and
  `safe_dump` read `off`, `on`, `yes` and `no` as booleans: a script that
  reads or rewrites a spec should use `bluefire_lab.range.spec.read`.

`bluefire-lab range render <spec> --out <folder>` checks a spec and writes
its build files without building or starting anything.

## The defense of a range

A range's defense is Wazuh: one manager and an agent inside each host it
watches. In [range one](#range-one-its-hosts) the agents are in `web`, `db`
and `build`, and the run shows that what happens on each of them reaches the
manager. The path of published tests runs in it
([range one: the path](#range-one-the-path)), and every step is scored
([the score and the recording](#range-one-the-score-and-the-recording)).
This section is about the sensor and the manager's live rules, which the
spec's `defense` key describes. A spec can name several defenses that judge
the same run, each with its own rules
([range one: its defenses](#range-one-its-defenses)).

```bash
bluefire-lab range render lab/range/range-one.yaml --out <folder>   # optional: only writes the build files
bluefire-lab range run lab/range/range-one.yaml --out <new folder>
```

The path runs between the [ordinary activity](#range-one-ordinary-activity)'s
warm-up and its tail, so the activity lasts as long as the path, which is long
enough for cron to start each cron job at least once; CI runs it so, without
`--hold`. `--hold <seconds>` keeps the sealed range up that much longer after
the path; it is needed only when the spec has no path: without it, a cron
job may not start at all and the ordinary day is then "not scored".

- **The pieces.** The manager is the official `wazuh/wazuh-manager` 4.14.10
  image, pinned by digest, alone: no indexer and no dashboard, and its Filebeat
  is kept from starting. Its rules are the stock ruleset. The lab adds one
  decoder, which reads the fields of snoopy's lines and raises no alert. The
  agent, package 4.14.10-1 checked against the SHA-512 in the spec, is baked
  into hosts built from Ubuntu noble, pinned by digest, with every package from
  the Ubuntu snapshot archive at the moment the spec names except the
  certificate store (ca-certificates and the openssl it needs), which comes
  from the live archive of the build day so that the snapshot can be reached
  over HTTPS; its version is not recorded. On those hosts
  snoopy 2.5.1 writes a line to syslog for each program started through the C
  library's `execv` or `execve` (see the limits below), with the
  `BLUEFIRE_TAG` of the process that started it and, as `exe`, the file the
  call named (snoopy's data source `filename`),
  which the command line does not hold: a shell that finds `grep` on its
  search path starts `/usr/bin/grep` with the command line `grep ...`. The
  lab's decoder reads it, and the ECS line gives it as `process.executable`,
  with a path written relative to the working folder joined to that folder.
  rsyslog writes the lines with timestamps to the microsecond. A host starts
  its services from a plain script, without systemd.
- **Images from the spec.** `range render` writes one multi-stage Dockerfile
  and a bake file. Every image is tagged with the spec's prefix and a hash of
  the build context, so `range run` builds with `docker buildx bake --load`
  only when a tag is missing or its image is not built on the pinned image
  (the pinned image's layers are read from its registry), and starts each
  container from the image ID it found. A local image under the right tag and
  on the right base is trusted to be what the context builds: nothing checks
  the rest of it. The containers have no mount of any kind: the manager image declares
  no volume, and its configuration is baked in under `/wazuh-config-mount/`,
  which the image's own start copies into place.
- **What the agent collects.** The lab never writes an ossec.conf of its own.
  The build takes the stock file that the agent package or the manager image
  installed and makes a short list of edits, each of which must find the exact
  text it expects in the stock file. `manifest.json` holds, for the manager and
  every agent, the diff against the stock file and each change with its label:
  - *lab addition*: the agent reads `/var/log/auth.log` and
    `/var/log/snoopy.log` (the stock file reads `/var/log/dpkg.log` already;
    the loader refuses a spec whose agent does not collect auth.log and
    snoopy.log, since the engine's nonces and marks are lines in them),
    and watches `/etc`, `/home`, `/root`, `/tmp` and `/var/tmp` in real time
    with inotify; the manager writes every event it receives to
    `archives.json`, whether or not a rule matched; the snoopy decoder.
  - *removed*: on the agent, the features the spec lists under `off`: command
    monitoring (the stock `df`, `netstat` and `last` on a timer), the security
    configuration assessment, rootcheck and the system inventory. They are
    periodic scans or inventories, not live telemetry of what happens on a
    host, and the commands would fill the archive. On the manager: the same
    features and its file monitoring, since the manager's own container is not
    a defended host; vulnerability detection and the indexer connection, which
    need an indexer and the internet; the check for a newer version; Filebeat.
    The manager's API listens on 127.0.0.1 only (`api.yaml`), since the range
    uses no API and the hosts on `mgmt` must not reach it.
  - *startup*: the agent reports to `manager` by its name in the range, enrolls
    itself on port 1515 with no password (only range hosts can reach the
    port), waits 1 s after enrolling instead of 20, and does not restart itself
    when the manager first sends it the shared configuration; the manager reads
    new agent keys every second.
- **Alert level.** `defense.wazuh.alert_level` (12 in range one) is the
  level from which a Wazuh alert counts as an alert when a step is scored,
  and `manifest.json` records it. It is not the manager's `log_alert_level`,
  which keeps its stock value 3, so that `alerts.json` also holds the matches
  below it for review. It changes no image. Each step is scored against it in
  [the score and the recording](#range-one-the-score-and-the-recording).
- **Ready.** After the seal's phase "no way out" and before its segmentation
  phase, within 180 s of the start: the manager's
  ports 1514 and 1515 answer; each agent's state file says it is connected and
  its log says its real-time file monitoring started, with none of the errors
  after which a folder is not watched (inotify could not start, or its watch
  limit was reached); the manager's `agent_control` lists each agent active at
  the pinned version; and a nonce the engine sends to syslog on each agent host
  arrives in the manager's `archives.json`. The delay from the nonce to the
  archive is recorded. A range that is not ready stops with a message that
  says which part failed and which copied file to read, with exit code 1, or
  3 when its seal, judged once more, failed; tests show this on stand-in
  files, and no run has shown it yet.
- **Versions.** In each phase of the seal from the segmentation on,
  `agent_control` on the manager is run again, and the manager and every agent
  must report the pinned version.
- **Delivery.** Just before the path of published tests runs, the engine makes a
  few harmless marks on each agent host: three lines sent to syslog, a file
  created and then changed in each folder watched in real time, and one
  program start, and records when each reached the archive. After the seal is
  checked again, the engine sends an end nonce and waits until the archive has
  caught up with each watched log. For each watched log, the lines written
  between the ready nonce and the end nonce are counted in the file copied out
  of the host, and each must be the full log of an event of that agent and
  location in the copied archive; an identical line outside the window does not
  count for one inside it. `delivery_gap` in `manifest.json` is true when a
  line is missing, a mark did not reach the archive, or one of Wazuh's own
  counters of lost events is above zero (analysisd, remoted, the agent's
  logcollector, and its log's lines about a full buffer or a full inotify
  queue); `delivery_findings` says which. It is null, and the summary says "not
  counted", when a log was not copied or is shorter than its window, or a mark
  was not made. A log with no line in the window is shown as not shown, not as
  delivered. logcollector writes its counters once a minute, so the manifest
  says whether they reach the end nonce; when they do not, its last minute is
  covered by the line count only. A lost event is a result about the defense,
  so it flags the run and does not fail it.
- **What the run keeps.** While the run lasts, two commands of the engine
  follow the manager's `archives.json` and `alerts.json` into `live/`, for a
  live view; no result is computed from them. After the run, `docker cp` by ID
  copies into `raw/hosts/<host>/` the manager's archives and alerts
  (compressed), its log, its state files and both ossec.conf files, and each
  agent host's watched logs, syslog, agent log, state files and ossec.conf
  files. Only folders and regular files are written: a link is left out and
  listed under `collected` in the manifest (Wazuh's own `archives.json` and
  `alerts.json` are links to the day's file, which is kept), so that nothing a
  container planted can make the lab read a file of the machine that runs it.
  `defense.md` sums it up for the job summary.

Some limits: snoopy does not see the first program of a `docker exec` (the
engine's `bash`), nor static programs; a process without `BLUEFIRE_TAG` has
the tag `(undefined)`. snoopy 2.5.1 wraps the C library's `execv` and
`execve` only, so it does not log every program that another program
starts: in [run 45555332964](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45555332964),
`s07`'s `find ... -exec sh -c ...` left a line for `find` and one for the
`cat` that the shell started, and none for the `sh` that `find` started. It
logs an exec call when it is made, not when it succeeds, so `exe` is the file
the call named even when there is no such file. The lab's line names no
parent program. [Run 45905224820](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45905224820)
shows the program's path arriving in the manager's archive on a hosted runner:
all 1,205 snoopy process events in its ECS output have
`process.executable`, which the Sigma evaluator received as `Image`. The agent
package is for amd64 only.

The `range-one` job of the `range-one` workflow runs this on a GitHub-hosted
runner, fails unless there was no delivery gap, every agent host got its marks
and every mark arrived, snoopy's tag was decoded, every ossec.conf is the lab's
edits of the stock file and every plant check passed, and writes the build
time, the plant checks, the
ready delays, the marks, the delivery table and the seal to its summary. Each
image has a cache scope of its own in the GitHub Actions cache, and BuildKit
runs from its own image, pinned by digest.
[Run 45281159443](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45281159443)
shows it for the seven hosts on a GitHub-hosted runner with Docker Engine
28.0.4 and AppArmor: the seal passed (201 checks before the start, 430 after
it and 430 again at the end), the range was ready 35 s after its containers
started, every plant check passed, and every line of the window was delivered
from `web`, `db` and `build` (for example `auth.log` 43 of 43 and `snoopy.log`
137 of 137 on `web`). The same
defense on a smaller range, one manager and one agent host, was shown by
[run 45262448946](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45262448946)
on a GitHub-hosted runner with Docker Engine 28.0.4, from a build without a
cache: the range was sealed and ready 28 s after its containers started, the
ready nonce was in the manager's archive 0.2 s after it was logged, all 14
marks arrived, and every line of the window was delivered (`auth.log` 8 of 8,
`snoopy.log` 35 of 35). The counters of lost events that were written were at
zero (analysisd, remoted, and the agent log's lines about a full buffer or
inotify queue); the agent's logcollector had not written its counters yet and
`wazuh-agentd.state` holds none, so there the line count is the only check.

## Range one: its hosts

[`range/range-one.yaml`](range/range-one.yaml) describes a small network: a
shop's web server, its database and its build server, watched by Wazuh, with
an attacker, the shop's customers and a stand-in internet outside. Each host
is built from the spec with what the path of published tests needs
planted in it. The network has no route out: everything outside is in the
range too.

| Host | Networks | Listens on | What is planted, and why |
| --- | --- | --- | --- |
| `attacker` | edge | nothing | The `src` folder of T1110.004 (its published password lists) under `/opt/atomics`, and `sshpass`, which that test's prerequisite would fetch: the first step guesses web's SSH password from there. |
| `inet` | edge | 80, 443 | The stand-in internet: a small server of the lab's own ([`inet_server.py`](bluefire_lab/range/inet_server.py)) that serves the published `atomic.sh` of T1105, which a step downloads, stores every `POST /upload` with its SHA-256, which the last step uses to send the stolen file out, and logs each request. Its certificate is made when the image is built. |
| `client` | edge | nothing | The shop's customers and its administrator's laptop: the account `ops`, whose SSH key `web` accepts, for the [ordinary activity](#range-one-ordinary-activity). |
| `web` | edge, inside, mgmt | 22, 80 | The shop (nginx, PHP, one page that keeps a session and reads the database). The account `webadmin` with the password `webadmin`, which is on line 475 of the published list (the build checks that line). SSH with passwords, and `pam_unix` with `nodelay`, so that a failed password is answered without the usual pause of about 3 s, which over the 482 tries of the list would come to roughly 24 minutes (an estimate: not yet measured). In `webadmin`'s `~/.ssh`, a deploy key without a passphrase (`id_rsa`), which a step finds and the next uses, and a `known_hosts` entry for `build`, which a step reads and without which that `ssh` would stop. The database password in `/var/www/app/config.php`, which a step finds. `/tmp/stage`, owned by `webadmin`, where a step writes what it pulls from `build`. `ops` may run `nginx -t` with sudo. |
| `db` | inside, mgmt | 3306 | MariaDB with the shop's table, made when the image is built, and the user `shop`, allowed from any address with the password in `config.php`. |
| `build` | inside, mgmt | 22 | The account `deploy`, which accepts the deploy key, and `/etc/buildbot/signing.env`, readable by the group `deploy`: the path's goal is to get this file out to `inet`. A git repository of the shop, owned by `ci`, for the ordinary activity. |
| `manager` | mgmt | 1514, 1515 | The Wazuh manager. The agents on `web`, `db` and `build` also read nginx's logs on `web` and MariaDB's on `db`, and watch `/var/www`, PHP's sessions and `/srv/git` in real time. |

The files the spec plants from its folder are beside it: the shop's pages and
table in [`range/app`](range/app), the build server's repository in
[`range/repos/shop`](range/repos/shop). The SSH keys have no value outside
the range. They are made when the image stage that makes them is first built
and are then kept by the build cache, the GitHub Actions cache of CI
included, so ranges built from the same stage share them; `inet`'s
certificate is kept the same way.

Install the lab once, from the clone's top folder, with `pip install ./lab`
(on Ubuntu's system Python, see [A range and its seal](#a-range-and-its-seal)
for the virtual environment it needs). Then:

```bash
bluefire-lab range run lab/range/range-one.yaml --out <new folder> --engine <path to Zircolite 4.7.1>
bluefire-lab range lock lab/range/range-one.yaml   # only when the spec's published files or rule sets change
```

Without `--engine` the run is the same, and the defense whose rules run after
the run is not judged ([its defenses](#range-one-its-defenses)).

**Published files, pinned and locked.** The build fetches the technique YAML
of every step of the path, the `src` folders the hosts carry and the files
they serve, from Atomic Red Team at the spec's commit, and checks each against
its SHA-256 in [`range/range-one.lock`](range/range-one.lock). A file the lock
does not list, or lists with another hash, stops the build with its name.
`range lock` writes the lock. Atomic Red Team's licence (MIT), fetched and
locked the same way, goes with its files: to `build/atomics/LICENSE.txt` and
to `/opt/atomics/LICENSE.txt` on each host that carries or serves one. The
images carry the files as data, with the
commit in `/opt/atomics/COMMIT`, which the seal checks; no build step runs any
published text and no prerequisite is fetched: what one would install is a
package of the spec.

**What the run shows**, on top of the seal and the defense above: the seal's
matrix for seven hosts on three networks (every pair that shares a network
connects on each port the target listens on, every other pair fails); in the
ready gate, that each `known_hosts` entry is the host key of its host, and
that `web` and `client` fetch `inet`'s page over HTTP and HTTPS; and, after
the seal, a plant check for each thing the spec plants, each a single use of
it with the engine's own commands (tag `engine:plant`): each account's shell,
password (checked against its hash) and sudo rule, which the account then uses
once (`ops` runs `sudo -n nginx -t`); one SSH login with each planted password,
from `client` as `ops`, through PAM's auth stack as the first step will log
in; the SSH server's settings
and `nodelay`; the owner, group, mode and content of each planted folder and
file, and the files of the git repository; the database's user, grant and
settings, and a connection from `web` with the values in `config.php`; the
shop's page, fetched from `client`, with items from the database; one login
with each planted key, which also lists which planted files and secrets the
account may read (`deploy` may read the signing file, and not
`/etc/shadow`, `/etc/gshadow` or the host key); the served file, fetched
from `client`, with its locked SHA-256 and its line in `inet`'s log; one
upload of a few bytes, stored and indexed, and then removed so that the
path's upload is the first one; and every file of the `src` folder
`attacker` carries, with its locked SHA-256. The plant checks' pages,
uploads and password login are tried from `client`, never from a host where a
step runs, so that no check leaves a line that a step's own check looks for;
the ready gate's fetch of `inet`'s `/` from `web` is the one request from a
host of the path before the path, and no step looks for it. A plant check that
fails ends the run with exit code 1 after the seal, the marks and the
collection, unless the teardown or the event watch failed after it, which
then gives the run its result.

**Outputs**, in the run folder: `manifest.json` (with the lock, the planted
weaknesses in words, the ready gate and the plant checks with what each
command printed), `seal.json`, `seal.md`, `defense.md`, `plants.md`,
`docker-events.ndjson`, `build/` (the rendered Dockerfile, bake file and
build context), `rules/sigma/` (the public rule set, fetched by its lock
before anything is created) and `raw/hosts/<host>/`, which now also holds
`inet`'s access log and uploads.

The services (sshd, sudo, nginx, php-fpm, MariaDB) run under AppArmor's
`docker-default` profile on the hosted runner: run 45281159443's
`manifest.json` records the daemon's security options under `docker`, and
every plant check that uses them passed there.

The path of published tests runs through the range, and a CI run shows it
([the path](#range-one-the-path)), and what the defense made of each step
([the score](#range-one-the-score-and-the-recording)).
The ordinary day is scored, and shown,
[below](#range-one-what-the-defense-recorded-in-ecs-and-the-ordinary-day).

## Range one: ordinary activity

A defense that raises an alert on everything catches every step. So while the
path runs, the shop's people and machines do their ordinary work: an alert on
that work counts as a false alert, and the path's steps are not the only
things that write to the watched logs and folders. The `activity` section of
[`range/range-one.yaml`](range/range-one.yaml) lists five jobs:

| Job | Who | Where, and what | How often | What it leaves, and where | Wazuh rules expected |
| --- | --- | --- | --- | --- | --- |
| `browse` | `ops` on `client` | Fetches a page of the shop on `web` with curl, in turn `/`, `/?item=1`, `/?item=2`, `/?item=3`, `/cart` and `/missing` (the last two answer 404) | every 5 to 15 s | `web`: a line in nginx's access log; for the four PHP pages, a new PHP session file in `/var/lib/php/sessions`, watched in real time, and a query of the database on `db`. | 31101 (a 404), 554, 550 (550 not seen in run 45358678900) |
| `admin` | `ops` on `client` | Logs in to `ops@web` with its SSH key and runs `uptime; df -h /; ls -l /var/www/app; sudo -n /usr/sbin/nginx -t` | every 90 to 150 s | `web`: sshd's login, PAM's session and sudo's lines in `auth.log`; snoopy's program starts. | 5715, 5501, 5502, 5402 |
| `cache` | `www-data` on `web`, from cron | `php /var/www/app/cron.php`: writes the shop's items to `/tmp/shop-cache-<minute>.json` and removes the older files | every minute | `web`: files added and removed in `/tmp`, the folder the path writes to, watched in real time; snoopy's program starts; cron's PAM session in `auth.log`. | 554, 553 |
| `build` | `ci` on `build`, from cron | Clones `/srv/git/shop.git` into `shop` in `ci`'s home folder on its first run, then `git pull` and `make -s -B` there | every minute | `build`: files in `ci`'s home folder, watched in real time; snoopy's program starts; cron's PAM session. | 554, 550 |
| `backup` | `root` on `db`, from cron | `mariadb-dump shop > /var/backups/shop.sql` | every 5 minutes | `db`: snoopy's program starts; cron's PAM session. `/var/backups` is not watched. | none |

The expected rules are a prediction, from the stock ruleset and a run on a
developer machine, all below level 12. On a GitHub-hosted runner,
[run 45358678900](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45358678900)
(its `alerts.ecs.ndjson`, grouped by `labels.job` and `rule.id`) shows every
rule of the table on its job except 550 on `browse`: `browse` 31101 and 554,
`admin` 5715, 5501, 5502 and 5402, `cache` 554 and 553, `build` 554 and 550,
and `backup` none. That is one run of 2.44 minutes. What the stock rules
raised on the jobs is scored in
[the ordinary day](#range-one-what-the-defense-recorded-in-ecs-and-the-ordinary-day).

- **Apart from the path.** The score tells the path from ordinary activity
  by account and address, so the loader refuses a job that runs as, or logs
  in as, an account the path uses (`webadmin` on `web`, and `deploy`, which a
  step's arguments name), and a job on or toward `attacker`, the host the path
  starts from. It also refuses a job its host cannot run (an account the host
  lacks, a cron job on a host without cron, a fetch without curl, a login
  without a key the target accepts or a `known_hosts` entry for it), and a job
  that acts on a host without an agent, since a job's runs and events are
  counted from the logs of the watched host it acts on. For the same reason it
  refuses two jobs whose lines could not be told apart: two `http` jobs from
  one host to one server with a path in common, two `ssh` jobs from one host
  to one other host, a job that runs or logs in as the account an `ssh` job
  logs in as on the same host (PAM's, sudo's and cron's lines name the
  account, not the job), and two jobs on one host whose `writes` patterns can
  match the same file. Cron jobs are told apart by their tags.
- **Baked into the images.** A cron job is an entry in `/etc/cron.d` and a
  script in `/usr/local/lib/bluefire`. Cron starts the entry every minute,
  and both start with `test -e /run/bluefire/go || exit 0`: the job's script
  and its command start only after the engine writes that file. Before the
  go and after the stop, cron still opens and closes a session for the job's
  account each minute (two lines in `auth.log`), ordinary events outside the
  activity's minutes. The `http` and `ssh` jobs (`browse` and `admin`) are
  one loop script on the host they run from, `client`, since their waits are
  counted in seconds and `client` runs no cron; its start script runs the
  loop once for each job as the job's account, and the loop waits for the
  same file. Every program a job starts after the go carries
  `BLUEFIRE_TAG=job:<name>`; an `ssh` job sets it in the command it sends.
- **A schedule from the seed.** Each wait between two runs is drawn from the
  spec's `seed`, the job's name and the run's number (a SHA-256), inside the
  job's `every`, whole minutes for a cron job, for the first hour of a run;
  after that the waits start again. The same spec gives the same schedule,
  and the schedule is in `manifest.json`. A loop job runs at once when the go
  appears; cron starts a cron job at its next minute.
- **The engine.** After the seal's segmentation phase and the plant checks, the engine
  writes `/run/bluefire/go` on each host that runs a job (tag `engine:go`) and
  waits `warmup_seconds` (30). Then comes the place of the path. After it, the
  jobs run `tail_seconds` (15) more and the engine removes the file again (tag
  `engine:stop`), so the activity has an end; then the seal is checked again.
  `manifest.json` records each host's go and stop in the container's clock.
- **What was done, and what was seen.** After the collection, for each job:
  how many times it ran, from the host it acts on (for a cron job, snoopy's
  line of the run's own `/bin/bash -c <command>` with the job's tag; for
  `browse`, nginx's access log lines of its paths from `client`'s address;
  for `admin`, sshd's key logins of `ops` from `client`'s address), between
  its host's go and stop; the same runs again from those lines that reached
  the manager's archive ("archived runs"); and how many events of it reached
  the archive in that time and 5 s after, by the job's tag on snoopy's lines,
  `client`'s address on nginx's lines of the job's paths, on sshd's lines and
  on snoopy's lines of an SSH session, the target account `ops` on snoopy's
  lines of its sessions (sshd's motd scripts and what sudo starts without the
  tag) and in PAM's, sshd's and sudo's lines, the close of a sudo session the
  job opened, and the files the job writes (`writes` in the spec) for file
  integrity events. An event is placed in a job's window by the time its line
  carries, the same time as its ECS line's `@timestamp`: rsyslog's, or the
  time to the second that nginx, dpkg and MariaDB write (compared with the go
  taken down to its second, as the runs are), and the manager's own time only
  for a line without one, such as a file integrity event. The engine starts
  the go in a new second, so that a request it made before the go, a plant
  check's say, carries an earlier second and stays out of the window however
  late the manager receives it. A snoopy line with another job's tag or the engine's is
  never this job's, by address or by account. An event counts
  for one job at most, and the engine's mark files, one of which is in PHP's
  session folder, for none. Cron's session lines of a cron job's account are
  counted apart, as "cron sessions of the account": cron opens one for every
  entry of an account, so on `db` root's stock entries in `/etc/crontab` (such
  as `cron.hourly` at minute 17) give the same lines as `backup`'s entry. The
  counts go into `manifest.json` and `activity.md`, next to the minutes from
  the first go to the last stop. Each job's last output and its own state are
  copied out of `/run/bluefire` into `raw/hosts/<host>/`.

The `range-one` job runs the path between the activity's warm-up and its tail,
so that the activity lasts more than two minutes and cron starts each cron job
at least once. It shows `activity.md` in its summary and
fails unless every job ran at least once and the line of at least one of its
runs reached the archive. The delivery counts of the same run are taken with
the jobs running, so the job's check for a delivery gap also shows whether
every line still reaches the manager under that load. In
[run 45337096555](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45337096555)
on a GitHub-hosted runner, made before the path existed with the range held
90 s in its place, the range was sealed and every job ran in the 2.4
minutes from the first go to the last stop: `browse` 15 times, `admin` twice,
`cache` and `build` three times each and `backup` once. The line of every one
of those runs reached the manager's archive, and the run had no delivery gap.

## Range one: what the defense recorded, in ECS, and the ordinary day

After the collection, every run of a range with a defense writes two files
next to `manifest.json`: `events.ecs.ndjson`, one line for each event of the
manager's archive, and `alerts.ecs.ndjson`, one line for each alert, in the
[Elastic Common Schema](https://www.elastic.co/guide/en/ecs/8.17/index.html)
8.17, so that the run can be loaded into other tools. Nothing is dropped or
merged, and the raw files stay in `raw/` so that the mapping can be checked
against them. The run is invalid (exit code 4, with the reason) when a raw
line cannot be parsed, when a file has another number of ECS lines than raw
lines, or when a line would lack `@timestamp`, `event.kind` or `labels.origin`.
A rule set that is evaluated after the run writes its matches to a file of
its own beside them, `alerts.<rule set>.ecs.ndjson` (`alerts.sigma.ecs.ndjson`
in range one), in the same shape as an alert: see
[its defenses](#range-one-its-defenses).

Each ECS line keeps the manager's line whole under `wazuh.*`, less its
`full_log` and `timestamp`. The ECS fields beside it are copies where ECS has a
clear home (`lab/bluefire_lab/range/ecs.py` lists every field it can write, and
a test checks each against the field list of ECS 8.17.0):

| Wazuh field | ECS field |
| --- | --- |
| `full_log` | `event.original`; `message` on an event |
| `timestamp` (the manager's time) | `event.ingested` on an event; `@timestamp` and `event.created` on an alert |
| `agent.id`, `agent.name`, `agent.ip` | `agent.id`, `agent.name`, `host.name`, `host.ip`; `agent.type` is `wazuh` |
| `manager.name` | `observer.name`; `observer.vendor` is `Wazuh` |
| `location`, when it is a file | `log.file.path` |
| `predecoder.program_name` | `event.provider` |
| `data.srcip`, `data.srcport` | `source.ip`, `source.port` |
| `data.dstuser`, when the line has no `data.srcuser` | `user.name` |
| `data.srcuser`, `data.dstuser` (sudo, PAM) | `user.name` (who ran sudo or opened the session), `user.effective.name` when it is another account |
| snoopy's `data.command`, `data.exe`, `data.cwd`, `data.uid`, `data.euid` | `process.command_line`, `process.executable` (a path written relative to the working folder is joined to that folder), `process.working_directory`, `user.id`, `user.effective.id`; `event.category` `process`, `event.type` `start` |
| nginx's `data.protocol`, `data.url`, `data.id` | `http.request.method`, `url.original`, `http.response.status_code`; `event.category` `web`, `event.type` `access` |
| `syscheck.path`, `uname_after`, `gname_after`, `uid_after`, `gid_after`, `inode_after`, `size_after`, `md5_after`, `sha1_after`, `sha256_after` | `file.path`, `file.owner`, `file.group`, `file.uid`, `file.gid`, `file.inode`, `file.size`, `file.hash.*`; `event.category` `file`, `event.type` `creation`, `change` or `deletion` |
| `rule.id`, `rule.description`, `rule.level` | `rule.id`, `rule.description`, `event.severity`; `message` on an alert |
| `rule.groups` with `authentication_success` or `authentication_failed` | `event.category` `authentication`, `event.type` `info`, `event.outcome` |
| `rule.mitre.id`, `rule.mitre.tactic` | `threat.technique.id` (T1548), `threat.technique.subtechnique.id` (T1548.003), `threat.tactic.name`; `threat.framework` is `MITRE ATT&CK` |

`event.kind` is `event` or `alert`, `event.dataset` `wazuh.archives` or
`wazuh.alerts`, `event.module` `wazuh`. A categorization field is set only
where the line says so. `labels.*` holds keyword values only:

- `labels.time_source` says where `@timestamp` comes from: `rsyslog`, the
  microsecond time rsyslog wrote on the line (`predecoder.timestamp`);
  `log-second`, a time to the second that the program wrote at the start of
  the line (nginx, dpkg, MariaDB; a time without a zone is the container's,
  which is UTC); `manager`, the manager's own time, for lines with no time of
  their source, such as file integrity events. An alert's `@timestamp` is
  always the time the manager raised it.
- `labels.origin`, and `labels.job` for an ordinary line, by the first rule
  that holds (`lab/bluefire_lab/range/score.py`): `engine` when snoopy tagged
  the program start `engine:*` (a program start snoopy logged is decided by
  its tag alone, since a step's own command can name a mark file, as `s08`'s
  tar of `/etc` on `build` does), or another line holds the run's ID, which every
  nonce and mark of the engine and the name of every mark file it makes carry
  (what the plant checks and the seal's probes leave behind, such as a login's
  session lines or a PHP session file, carries no ID); `cleanup` when snoopy
  tagged it `cleanup:<id>`, or it is a file event inside a step's published
  cleanup for a file the cleanup's command names; `ordinary` when the
  line is a job's as the [activity's counts](#range-one-ordinary-activity)
  sort it (tag, address, the path of a request, account, the files the job
  writes, inside the job's window), or when snoopy tagged it `job:<name>`; a
  program start with a job's tag is that job's and no other's, whatever
  account it runs as, and an nginx line from `client` for a path that no job
  fetches is no job's, so it is `unattributed`; cron's session lines of a
  cron job's account inside the job's window are `ordinary` with no
  `labels.job`, since they do not tell one cron entry of the account from
  another; `step`, with `labels.step_id` and `labels.tied_by`, for a line
  tied to a step of the path (see
  [the score](#range-one-the-score-and-the-recording)); `unattributed` for
  everything else, which is counted and listed and never called ordinary. An
  alert takes the origin of its event in the archive (the same agent,
  location, line and manager time), and `labels.event_id` names that event's
  `event.id`.

Loading them into a tool, here [DuckDB](https://duckdb.org/) 1.4.1 from PyPI,
run in a run folder (on the files of the run below it lists `ordinary`,
`build`, rule 554, 26 alerts first):

```python
import duckdb

duckdb.sql("""
    SELECT labels.origin, labels.job, rule.id, any_value(rule.description), count(*) AS alerts
    FROM read_json_auto('alerts.ecs.ndjson')
    GROUP BY ALL ORDER BY alerts DESC
""").show()
```

**The ordinary day.** From the same lines the run scores what the stock rules
said about the shop's own work, into `manifest.json` (`score`) and `score.md`:
per origin, the events and the alerts by level band; the *false alerts*, the
distinct stock rules at the range's `alert_level` (12) or higher among alerts
on ordinary events, each with its description, level, count and the job it
fell on; the rules from level 7 to 11 on ordinary work, *for review*, a second
number never added to the first; and the alerts at level 12 or higher on the
engine's work and on unattributed events, listed apart, since the bench's own
noise is not the shop's. Every number stands next to its denominators: the
minutes of activity, the runs of each job (in the host's log and in the
archive) and the events of each origin; without them, or when a job has no
run in the archive, the score says "not scored" and gives no number. A run
that did not end sealed (made invalid, a seal that failed, plants not in
place) is no result either: its `score.md` is headed "not a result" with the
run's result, exit code and reason, and its numbers follow under that, or,
when the day could not be scored, the words that say why. The
engine starts the seal's probes after the stop only once every job's window
has closed, and a file whose modification time is before the go is no job's.
A file a job links rather than writes keeps its older time: the first clone
of `build` hard-links git's objects from the server's repository, so those
file events count as unattributed. The `range-one` job shows `score.md` in
its summary, keeps both ECS files in its artifact, and fails when the
conversion fails or the day was not scored. The score also lists what the
jobs do, which is all it prices: a rule that fires only on something else,
such as a password login or a failed login, is not priced by it.

[Run 45358678900](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45358678900)
of the `range-one` job on a GitHub-hosted runner, with the range held 90 s:
2.44 minutes of activity, with `browse` 15 runs, `admin` 2, `cache` 3,
`build` 3 and `backup` 1, each run also counted in the archive. Its archive
held 647 events and its alerts 128, and both ECS files had as many lines:

| Origin | Events | Alerts 0 to 3 | Alerts 4 to 6 | Alerts 7 to 11 | Alerts 12 to 14 | Alerts 15 |
| --- | --- | --- | --- | --- | --- | --- |
| engine | 283 | 0 | 18 | 18 | 0 | 0 |
| ordinary | 172 | 12 | 44 | 8 | 0 | 0 |
| unattributed | 192 | 15 | 13 | 0 | 0 | 0 |

False alerts: 0 rules at level 12 or higher. For review: 550 "Integrity
checksum changed." (level 7) 6 times, all on `build`, and 553 "File
deleted." (level 7) twice on `cache`'s files. No alert at level 12 or higher
on the engine's work or on unattributed events. The one nginx line from
`client` that is unattributed is a plant check's request, just before the go.
(In [run 45363557672](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45363557672),
of an earlier engine that placed such a line by the manager's time, the same
request reached the manager after the go and was counted as `browse`'s.)
Zero false alerts here is a result about those 2.44 minutes and that work
only.

The lines that the engine's own seal probes and plant checks leave behind
before the go and after the stop, such as a login's session lines, carry
neither the engine's tag nor the run's ID, so they count as unattributed, as
do the hosts' own start-up lines. Wazuh's stateful rules (a
first time, a frequency, a rule that follows another) have already seen the
plant checks' logins and sudo before the go, so a rule that fires only on a
first occurrence may not fire on the jobs: in this run the plant check's sudo
raised 5403 "First time user executed sudo." and `admin`'s sudo only 5402.
This section does not tie events to steps of the path:
[the score and the recording](#range-one-the-score-and-the-recording) does.

## Range one: the path

`lab/range/range-one.yaml` holds the path of range one: eleven steps, which run
ten published tests (the port scan runs twice, against two hosts). `bluefire-lab atomic argv lab/range/range-one.yaml --atomics
<atomics folder> --out argv.json` writes, for each step, the argument vectors of
its attack, its prereq checks and its cleanup, read from the pinned YAML as
Invoke-AtomicRedTeam reads it. The job `atomic-parity` in
`.github/workflows/range-one.yml` runs Invoke-AtomicRedTeam for the same steps
with stand-ins for `sh` and `bash` that record how they were started and run
nothing, and fails on any byte that differs. In
[run 45246198695](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45246198695)
every vector that exists was identical: the attack and the cleanup of all 11
steps (six of those cleanups are empty, `bash -c ""` or `sh -c ""`, because
their tests publish none) and the prereq checks of the two steps that have
one (`s01` and `s09`), 24 vectors in all. For the other nine steps the job
checked that neither side started a prereq command.

`bluefire-lab range run lab/range/range-one.yaml` runs the path inside the
sealed range (`bluefire_lab/range/path.py`): after the seal's phases
`static`, `no way out` and `segmentation` have passed and the plants are
in place, between the warm-up and the tail of the ordinary activity, and
before the seal is checked again (`after path`). The tests are the published
ones at the pinned commit, unchanged apart from their declared input
arguments, which the spec writes out.

| Step | What the published test does here | Host, account | How the engine checks its effect |
| --- | --- | --- | --- |
| s01 | Tries the published list of user and password pairs over SSH against `web` | `attacker`, root | `web`'s auth.log has `Accepted password for webadmin from` `attacker`'s address |
| s02 | Downloads a script from `inet` over HTTP and runs it | `web`, webadmin | its output has `Hello From Atomic Red Team`, and `inet`'s access log a 200 for that file from `web` |
| s03 | Writes the system's description to `/tmp/T1082.txt` | `web`, webadmin | the file holds `Linux` |
| s04 | Collects the `known_hosts` files under webadmin's home | `web`, webadmin | `/tmp/ssh_enum.txt` has a line that starts with `build ` |
| s05a | Tries every TCP port of `build` | `web`, webadmin | its output has `port 22 is open` |
| s05b | Tries every TCP port of `db` | `web`, webadmin | its output has `port 3306 is open` |
| s06 | Searches the shop's folder for passwords | `web`, webadmin | its output has the database password |
| s07 | Finds the private SSH keys under webadmin's home and copies them to `/tmp/creds.txt` | `web`, webadmin | the file holds a private key |
| s08 | Logs in to `deploy@build` with the found key and copies `/etc` of `build` back as an archive | `web`, webadmin | `/tmp/stage/etc.tar.gz` lists `buildbot/signing.env` |
| s09 | Packs `/tmp/stage` into `/tmp/loot.tar.gz` | `web`, webadmin | the archive lists `tmp/stage/etc.tar.gz` |
| s10 | Uploads `/tmp/loot.tar.gz` to `https://inet/upload` with wget | `web`, webadmin | `inet`'s first upload came from `web`'s address and has the SHA-256 of `/tmp/loot.tar.gz` |

Each step runs through `docker exec` in its container, as its account and in
its folder, with exactly the argument vector above and without `-i`. First
comes the test's published prerequisite check, where it has one. After the
test and a grace of 5 s, the engine runs the effect check as root, then the
published cleanup where the spec asks for one. What happened is one of four:

- `took effect`: the test ran and its effect check passed;
- `attempted without effect`: the test ran and the check failed;
- `not attempted`: the prerequisite check failed, or Docker could not start
  the test;
- `inconclusive`: the check itself could not run, or the run was stopped
  during the step.

The path goes on after a step that failed. After the last step, the goal
check reads files copied out of the range: `inet`'s first upload came from
`web`, holds `tmp/stage/etc.tar.gz`, and that archive holds
`buildbot/signing.env` byte for byte as it is on `build`. Three things stop
the path and make the run invalid: an event on the range that the engine did
not cause; an event watch that has stopped; and one that has not reported the
start and end of a step's own command (its prerequisite check, its test or
its cleanup) within 30 s after the command returned (the 15 s the engine
always waits for them, and 15 s more, the time the watch is given to settle),
so that nothing watched the seal. A slow daemon or runner is given
that time: in runs
[45507244968](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45507244968),
[45521926761](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45521926761)
and
[45524094071](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45524094071)
every step's test and every cleanup was timed by the daemon's events, so the
watch reported each of them within the first 15 s.
A run leaves `raw/steps/<id>/` (the command, its standard output and error,
and what the prerequisite check, the effect check and the cleanup printed),
the steps and the goal in `manifest.json`, and `path.md`.

Limits:

- A test's parent is the container runtime, not a login shell, and s02 to
  s10 are started through `docker exec`, not inside the SSH session of s01.
- Snoopy does not see the first program of an exec (the published `sh -c` or
  `bash -c`); `raw/steps/<id>/command` records it.
- A step's start and end are the Docker daemon's times of its exec, not the
  engine's; where those events were not matched, the engine's own clock is
  used and `path.md` marks it.
- A loaded daemon can stamp an exec's `exec_die` before its `exec_start`; the
  daemon's two times are used only in order, and otherwise the step is timed
  by the engine's clock and labelled so, which fails the score's clock check.
- The published port scan tries every port, so s05a and s05b may run until
  the step's timeout of 300 s. At a timeout the engine kills what the step
  started, as the step's account, and the effect check still decides what
  happened.
- Before any container exists, the loader refuses a step that names a host
  outside the spec, or one its host shares no network with, in the forms it
  recognises: the step's `to`, a URL with a scheme, `user@host`,
  `/dev/tcp/<host>` and `/dev/udp/<host>`. It refuses an address that
  Python's `ipaddress` reads. It does not recognise a bare host name, nor an
  address in a short, integer or hex form. It refuses a step on a host that
  runs a pinned image, which carries none of the published files, and a step
  with a `to` whose command reaches, in those forms, a host its `to` does not
  name, since the score ties a step's events on the hosts of its `to`. This is
  an early, plain refusal of mistakes; the seal is what keeps a step inside the
  range.
- `blocked` cannot occur: range one configures no active response.

In [run 45464907926](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45464907926),
job "range one's path, sealed and watched" on a hosted runner, the range
stayed sealed in every phase (static, no way out, segmentation, after path,
teardown), every step took effect, and the goal check passed: the first
upload `inet` stored came from `web`, and the `buildbot/signing.env` in it is
byte for byte the file on `build`. Seconds are the Docker daemon's times of
each step's exec. The two port scans ended by themselves before their timeout
of 300 s, with exit code 1, and nothing was killed. s08 exits 2 because tar
could not read every file of `/etc` on `build` as `deploy`; the archive holds
`buildbot/signing.env`, which is what the check asks.

| Step | Host | Technique | Test | Seconds | Exit code | What happened | The check |
| --- | --- | --- | --- | --- | --- | --- | --- |
| s01 | attacker | T1110.004 | SSH Credential Stuffing From Linux | 60.05 | 5 | took effect | pass |
| s02 | web | T1105 | Linux Download File and Run | 0.029 | 0 | took effect | pass |
| s03 | web | T1082 | List OS Information | 0.027 | 0 | took effect | pass |
| s04 | web | T1018 | Enumerate SSH Configuration | 0.027 | 0 | took effect | pass |
| s05a | web | T1046 | Port Scan | 242.124 | 1 | took effect | pass |
| s05b | web | T1046 | Port Scan | 262.528 | 1 | took effect | pass |
| s06 | web | T1552.001 | Extract passwords with grep | 0.024 | 0 | took effect | pass |
| s07 | web | T1552.004 | Discover Private SSH Keys | 0.026 | 0 | took effect | pass |
| s08 | web | T1048 | Exfiltration Over Alternative Protocol - SSH | 0.224 | 2 | took effect | pass |
| s09 | web | T1560.001 | Data Compressed - nix - tar Folder or File | 0.031 | 0 | took effect | pass |
| s10 | web | T1048.002 | Exfiltrate data in a file over HTTPS using wget | 0.042 | 0 | took effect | pass |

Whether the defense saw or alerted on each step is the next section, from a
later run.

## Range one: the score and the recording

After the collection, a run of a range with a path says, for every step, what
each of its defenses made of it, into `manifest.json` (`score.path` for the
manager's live rules, `score.defenses` for every defense), `score.md` and
`steps.ecs.ndjson` (one ECS line per step: its daemon times, host, account,
technique, the test's name and GUID, the exit code, what happened, the
check's result, and the outcome below), and it writes `recording.json`, the
run in the [recording format](../docs/RECORDING.md) that the app's live view
plays. A spec that names no defense has one, the agents with the manager's
stock rules, and its recording has no `defenses`.
`bluefire-lab range score <run folder> [--engine <path to Zircolite 4.7.1>]`
writes all of these again from a run folder's own files, with the spec the
run's manifest holds and the rule files in its folder, and starts nothing.

**`score.md`** opens with the path's outcome in one sentence (whether it
reached its goal, and after how long), then a table with a row for each
defense: its sensors, its rules and whether they ran live or after the run,
the steps it alerted on, saw without an alert and did not see, its first
alert in seconds after the first step and before the goal, and its false
alerts on the ordinary day beside the minutes of that day. Then the table of
steps, with one column for each defense's outcome, the detail of the
manager's live rules, the ordinary day, and a section for each rule set that
ran after the run ([its defenses](#range-one-its-defenses)).

**Ties.** Each archived event and each alert is the engine's, a cleanup's, a
job's of the ordinary activity, a step's, or unattributed, by the first rule
that holds (`lab/bluefire_lab/range/score.py`). What is neither the engine's,
a cleanup's nor a job's is a step's only on evidence the run holds, by the
first of: `session`, snoopy tagged the program start `step:<id>`; `account`,
the line names an account only the path uses on its host (`webadmin` on
`web`, `deploy` on `build`; the activity's loader refuses a job that uses
one), on a host the step ran on or reached, inside its window; `address`, the
line's own source address is an address of the host the step ran on, inside
its window (sshd's lines on `web` from `attacker` in `s01`'s), or the line is
on a host the step reached and its text names an address or the container
name of the host the step ran on (sshd's and MariaDB's lines often carry the
address only in their text); `content`, a file event for a path the step was
given, or a line that names one, on a host the step ran on or reached, inside
its window. A step's window runs from the Docker daemon's start of its
test to 5 s after the daemon's end (a second longer, from the start of its
second, for a line whose time is to the second). An event that only falls
inside a window, on a host the step ran on or reached, is coincident: it
keeps the origin `unattributed`, carries the step with `tied_by` `window`, is
counted apart and never counts for the step. An alert takes the tie of the
line it was raised on, so a correlation rule such as 40112 is tied by its own
line and not by the lines before it. The counts of each origin add up to the
raw lines.

**What the defense made of each step**, in the words of the recording format:
`alert` when an alert of the stock rules at level 12 or higher is tied to the
step, `telemetry only` when an event is, `no telemetry` otherwise, and `not
applicable` when the test did not start; the outcome follows the format's
order (`alerted`, `seen`, `unseen`, `no effect`, `inconclusive`). A step
cannot be `stopped` in range one: it configures no active response. The score
also lists, per step, which agents recorded it, the rules that matched with
their levels and first times, and the rules the spec expects of the step
(`expect`) that did not appear. Every defense gets the same words from its own
sensors' events and its own rules' alerts; the ties are the same for all.

**The race.** The time from the start of the first step to the first alert at
level 12 or higher on a step, against the time from the same start to the end
of the step after which the goal check passed. One clock: a step's times are
the Docker daemon's `exec_start` and `exec_die`, an alert's the manager's time
of it, and both read the kernel clock of the machine that runs the
containers; the engine's own clock is not used. Each run checks it: every
program start snoopy logged in a step's session, at rsyslog's time in its
container, must fall inside its step's daemon times, and every step's times
must be the daemon's, in order. When the check fails, the race is labelled
"not a result" in the score, no recording is written, and the CI job fails.
The manager's own time of a line can run seconds behind the time rsyslog
wrote on it, so an alert counts from the manager's time of it, or from its
line's time when that is later, and the score gives the spread it measured.
A rule that ran after the run counts from the time of the event it matched.
Beside the race stand the ordinary day's false alerts and their denominators
([above](#range-one-what-the-defense-recorded-in-ecs-and-the-ordinary-day)).

**The recording.** The seven hosts with their roles and addresses, a link
between every two that share a network, the three Wazuh agents as sensors,
the manager's stock rules as the detector `pinned` that ran live, each step
with its published name and one plain sentence (`plain` in the spec), its
command and output, and the events and alerts tied to it, the first 300
events of a step, shared in equal parts among the sensors that recorded them,
and every one a rule matched; a step that went to another host (`to` in the
spec) is on that host, `from` its own. An alert has the time of its line and
`raised`, the manager's time of it. Two words joined the
format's ties for this: `address` and `content`. A rule set that judged the
run after it is a detector of its own, with `when` `after the run`, the
number of rules its engine loaded and the digest of its files, and its
alerts have the time of their event and no `raised`. When the spec names its
defenses, the recording has `defenses`: for each defense that judged the run,
its sensors, its detectors, its own answer for every step, its ordinary day
and its score. The top level is the first defense's, `wazuh-stock`: its
verdicts, ordinary day and score are those of a recording of the spec without
defenses, except that the recording also keeps each event beyond a step's cut
that another defense's rules matched, and a step's `kept` counts it. The
recording's `alerts` are those of every defense, numbered together in time
order. The app's import refuses a key that its [recording
format](../docs/RECORDING.md) does not list, so it takes a recording with
`defenses` only when that format lists the key; it takes a recording of a
spec without defenses as before. A single page that plays a recording is made
so:

```bash
bluefire-lab replay <run folder>/recording.json --template bluefire/ui/replay.html --out replay.html
```

A page made so from a downloaded recording reads it as imported: it says that
the file names a CI run which was not checked, and it does not link that run.
Only the page the `range-one` job writes inside the very run the recording
names says that run made it.

The format counts an alert from level 12, so a run of a spec whose
`defense.wazuh.alert_level` is another level writes no recording (set the
level back to 12, or read the score without a recording), and nor does a run
with an alert at level 12 or higher whose archived line is not in the archive:
the manifest says why, and `bluefire-lab range score` exits 1.

The `range-one` job keeps `recording.json`, the ECS files (the rule set's
matches among them), the rule files the run fetched and `replay.html` in its
artifact, and shows `score.md` in its summary.

The app ships the recording of
[run 45555332964](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45555332964)
as `bluefire/data/recordings/lab-range-one-path.json`. The loop at the top of
the [front page](../README.md) and the single page
[`docs/live-view/attack-path.html`](../docs/live-view/attack-path.html) play it
([the run on the front page](../docs/LIVE_VIEW.md#the-run-on-the-front-page)).

**What a run shows.** In
[run 45555332964](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45555332964),
the run the app ships, on a hosted runner (its job "range one's path, sealed
and watched", and the artifact `range-one-run`), the stock rules raised their
first alert at level 12 or higher 76.367 s after the first step started: rule
40112, "Multiple authentication failures followed by a success", on `s01`. The
path reached its goal 730.488 s after that start, so the alert came 654.121 s
before the goal. Beside it, on the ordinary day of 13.21 minutes: 0 false
alerts at level 12 or higher. The clock check held: 19 program starts in the
steps' sessions, none outside its step's daemon times.

| Step | Host | Recorded | By | Tied by | First alert | Outcome |
|---|---|---|---|---|---|---|
| s01 | attacker to web | alert, 1,857 events | web | address 1,841, account 16 | 40112, level 12 | alerted |
| s02 | web | 4 events | web | account 1, session 3 | none | seen |
| s03 | web | 8 events | web | account 2, session 6 | none | seen |
| s04 | web | 3 events | web | account 1, session 2 | none | seen |
| s05a | web to build | 1 event | build | address 1 | none | seen |
| s05b | web to db | 1 event | db | address 1 | none | seen |
| s06 | web | 1 event | web | session 1 | none | seen |
| s07 | web | 3 events | web | account 1, session 2 | none | seen |
| s08 | web to build | 20 events | web 3, build 17 | account 18, session 1, address 1 | none | seen |
| s09 | web | 5 events | web | account 2, session 3 | none | seen |
| s10 | web to inet | 1 event | web | session 1 | none | seen |

One step alerted and ten were seen with no alert; none was unseen. **Each of
the two port scans is tied by one line only.** On `build` it is sshd's line
saying that a connection from `web`'s address sent a banner in an invalid
format (`banner exchange: ... invalid format`: the scan writes a bare newline
to each port). Two more lines of the same sshd process, its start and a broken
pipe, are in the archive but count only as coincident, since their text does
not name `web`. On `db` it is MariaDB's line about a connection from `web`'s
container that closed without authentication. Each is tied by the `address`
rule because its text names `web`. Where a step is tied by the `address`
rule alone, `score.md` and the recording quote its lines (up to three) in
that step's own sentence, as this run's summary does for both scans. The
range has no network sensor, so a scan of every port shows only where an open
port's service logs a broken connection.

One run is one sample. Four earlier hosted runs of the same job,
[45507244968](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45507244968),
[45521926761](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45521926761),
[45524094071](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45524094071)
and
[45546532335](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45546532335),
gave the same outcome for every step, with the first alert after 61.56 s,
77.05 s, 76.58 s and 69.46 s and the goal after 628.44 s, 731.31 s, 730.87 s
and 724.59 s. The first three were scored before a program start that snoopy
logged was counted for the engine by its tag alone, so `s08` has 19 events
there: its own archive of `/etc` was counted as the engine's. Five runs do not
say how far the times can vary.

## Range one: its defenses

A defense is a named thing in the spec (`defenses`, see
[writing a spec](#writing-a-spec)): the kinds of sensor it records with and
the rules it runs. One run is recorded with every sensor on, and each defense
judges that same run, counting only the events its own sensors recorded and
only the alerts of its own rules. For each one the score says what it made of
every step, its first alert against the goal, and its false alerts on the
ordinary day, with the denominators of the run.

| Defense | Sensors | Rules | When the rules ran |
| --- | --- | --- | --- |
| `wazuh-stock`, Wazuh with its stock rules | the Wazuh agents on `web`, `db` and `build` | the manager's stock rules, the detector `pinned` | live |
| `sigma-public`, the public Sigma rules over the same host logs | the same agents' records | SigmaHQ's rules at commit `552f3fee` (the commit `lab.yml` pins for the bench on one host), the folders `rules/linux/process_creation`, `rules/linux/file_event`, `rules/linux/builtin` and `rules/web/webserver_generic`, the detector `sigma` | after the run, by Zircolite 4.7.1 |

`wazuh-stock` is first, so a recording's top level is its view, with the
verdicts, ordinary day and score a recording had before the spec named
defenses ([the recording](#range-one-the-score-and-the-recording) says what
else differs). A third or a fourth defense is one more entry of `defenses`,
with its rule set under `rule_sets`.

**The rule set, fetched and locked.** `bluefire-lab range lock <spec>` lists
each folder of the rule set at its commit through GitHub's contents API,
fetches every file from `raw.githubusercontent.com` at that commit, and writes
their SHA-256 to [`range/range-one.rules.lock`](range/range-one.rules.lock),
with the repository's `LICENSE`. With `include: rules`, the locker fetches and
checks each candidate individually, keeps only a rule of the set's kind, and
records why every other candidate was omitted. It never clones or downloads
an archive. A run fetches the selected files by that lock into
`rules/sigma/` of its own folder, with the `LICENSE` and a file `SOURCE` that
says `SigmaHQ/sigma@<commit>`, before anything is created; a file that is
missing or has another SHA-256 stops the run with the file's name. Nothing is
cloned. `bluefire-lab range score` reads the rules from the run's folder,
checks each file against the hashes the run recorded, and fetches nothing. For
a run folder made before its spec named these defenses, `bluefire-lab range
rules <spec> --out <run folder>` fetches the rules into it the way a run does,
and `bluefire-lab range score <run folder> --engine <path to Zircolite>
--defenses <spec>` judges it by that spec's defenses; its notes then say so.
A rule set the run fetched itself stays as the run fetched it, so that the run
can still be judged by its own spec: `range rules` refuses a rule set of the
same name with another lock, which then needs a name of its own. The folder of
any other rule set it empties before it fetches, so that the folder holds the
files of the lock and no others.

**How the rules are given the run.** After the run, the engine is given the
manager's archived events, each rule folder over the events of the Sigma log
source its rules name and no others, in Sigma's field names:

- `process_creation` for Linux: the program starts snoopy logged, as `Image`
  (the file the exec call named, `process.executable` in ECS), `CommandLine`,
  `User` (the login name snoopy recorded) and `CurrentDirectory`.
- `file_event` for Linux: the files the agents' file integrity monitoring saw
  added or changed, as `TargetFilename`.
- `webserver`: nginx's access lines, as `c-ip`, `cs-method`, `cs-uri-query`
  (the request's path and query as the line holds them), `cs-uri-stem` (the
  request's path without its query), `sc-status`, `cs-user-agent` and
  `cs-referer`, with the line itself, all taken from the line. The engine names
  a column by the letters and digits of a field's name,
  so it reads a copy of each such rule with the field's name written that way;
  the fetched files stay as the lock has them.
- the keyword rules of `builtin`: a rule that names a `service` (`sshd`,
  `sudo`, `cron`, `auth`, `syslog`) is given that service's lines only, and a
  rule without one every line of every collected log file. A rule for a
  service the range has no line of, such as `vsftpd`, is given nothing.

Events of every origin are given: a step's, the ordinary activity's, the
engine's own and unattributed ones. For each folder and log source the run
records how many rules it holds, how many the engine says it loaded, and how
many events it was given and read: the engine skips a rule it cannot convert,
and a rule it did not load was not evaluated.

Atomics and Sigma v2 `event_count`, `value_count`, `temporal` and
`temporal_ordered` correlations run over one database. Every engine row
carries its source, host, time and stable archive event id, and each atomic
dependency is constrained to its own source. A correlation alert is attributed
to the latest real event that completed it; its ordered evidence event ids are
retained with the alert. Conversion failures and unsupported sources are
recorded per rule and are not described as evaluated.

**A match.** Each match is an alert of the detector `sigma`, at the time of
the event it matched and with no `raised` time, at the rule's own level; it
counts as an alert at `high` or `critical`. It is tied as the manager's alerts
are, by its event: on a step's event it is that step's; on an event of the
ordinary activity it is a match on the ordinary day, and a false alert when it
counts; on the engine's own work or on an unattributed event it is listed
apart and never counted. The matches are written to `alerts.sigma.ecs.ndjson`,
one line each, in the shape of an alert, with the rule's id, title, level,
author and address at its commit, and `labels.event_id` naming the event;
`score.md` has a section for the rule set (what each folder was given, what
the engine loaded and read, the rules that matched and where), and the
manifest has it under `score."rule sets"`.

**Without the engine.** `range run` and `range score` take the engine's path
as `--engine`. Without it the Sigma rules are not evaluated: the run still
completes, `score.md` says that `sigma-public` was not judged and why, and the
recording holds only the defenses that were judged. The `range-one` job
fetches the engine as the `lab` workflow does, at the same address and digest,
and fails unless every defense of the spec judged the run.

Limits:

- The rules ran after the run, so a match counts from the time of its event,
  while a live alert counts from when the manager raised it: the race favours
  the rules that ran after the run by the manager's delay, and no response
  could have followed their alert.
- The lab's snoopy line names no parent program, so a rule that needs
  `ParentImage`, `ParentCommandLine` or `LogonId` cannot match; the file
  integrity sensor does not know which program wrote a file, so a `file_event`
  rule that needs `Image` cannot match either. `User` is the login name, not
  always the account the program ran as.
- Only programs started through the C library's `execv` or `execve` are
  logged (see [the defense of a range](#the-defense-of-a-range)), so a rule
  cannot match a program snoopy did not see.
- A run made before snoopy's line held the program's path has no `Image`:
  most of the `process_creation` rules need one and can match nothing there,
  and the recording's notes say so. Each recording's notes say which fields
  the rules were given and which they named and were not given.
- [Run 45905224820](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45905224820)
  shows the public Sigma rules judging range one on a hosted runner: 162 of
  165 rules loaded, 6 rules matched below the alert level, all 11 path steps
  were seen and none alerted, and no false alert counted on the ordinary day.

## Not yet shown

- Tests on Windows.

## How to run it

The one-host bench's workflow runs on pull requests that change `lab/`, on a
weekly schedule, and by hand from the Actions tab. Its attack tests run on
the runner itself, so they run on GitHub-hosted runners only: `bluefire-lab
run` refuses to start unless `RUNNER_ENVIRONMENT` is `github-hosted`, which
GitHub sets on its own runners. That guards against starting it by mistake
anywhere else; it cannot stop someone who sets the variable on purpose. A
range is different: `bluefire-lab range run` runs its path of published tests
in Docker on any machine, in CI or on a developer's, but only inside the
sealed range's own containers (see [a range and its seal](#a-range-and-its-seal)).

The answers can be computed again from a run's artifact, on any machine:

```bash
python3 -m venv .venv && . .venv/bin/activate   # see "A range and its seal"
pip install ./lab
bluefire-lab evaluate <folder of the unpacked artifact> --engine <path to Zircolite 4.7.1>
bluefire-lab report <folder of the unpacked artifact>
bluefire-lab recording <folder of the unpacked artifact> [--run-url <address of the CI run>] [--tests lab/pinned-tests.yaml]
```

`--tests` supplies the plain sentence of each test for a run made before
`run.json` recorded them; the recording's notes then say so.

Two runs' recordings can be compared the same way: see the next section.

## Comparing two recordings

"Before against after" is a claim about a cause: one thing changed, the same
tests ran again, and this is what changed. `bluefire-lab compare` is where that
claim is computed, and where it is refused:

```bash
bluefire-lab compare <before>/recording.json <after>/recording.json --out <folder> [--change detectors:lab] [--two-runners | --one-run]
```

It writes `delta.json`, whose format is the section "A delta" of
[`docs/RECORDING.md`](../docs/RECORDING.md), and `delta.md`, the same for a job
summary. `--change` declares the one thing that changed between the two runs:
`detectors:lab` for the rules in [`rules/linux`](rules/linux),
`detectors:pinned` for the published rules, or `sensors:sysmon` or
`sensors:auditd` for a sensor's settings. Left out, nothing was declared.

- **What was the same.** Each recording says how it was made: `source.setup`
  holds the tests' commit, the runner's image and kernel, and the SHA-256 of
  each sensor's settings as loaded, and each detector the `digest` of its rule
  files. The comparison lists every one of these, and each tool's version,
  that differs between the two. It gives no verdict, and still lists every
  step and what differed, when anything differs other than the declared
  change (the published rules' pinned commit is part of a change of the
  published rules; a sensor's program version is not part of a change of its
  settings), when the declared change is the same in both, when the two are not
  of the same steps in the same order, or when a recording has no
  `source.setup`, as every recording made before this format had.
- **Pairing.** A step has the same id in every run of the same list (its role,
  its test, a hash of its input arguments, its hardening change, and a count
  for the canary, which runs twice), so steps pair by id. An older recording's
  steps pair by role, test and order, and each such pair says so. A step on one
  side only is listed as new or gone and never counted.
- **Like with like.** A change of the lab's rules is judged on the outcome with
  the lab's rules; the outcome by the published rules, whether a sensor
  recorded the step and whether the test took effect, which such a rule cannot
  change, are the control. A change of the published rules is judged on both
  outcomes, with whether a sensor recorded the step and whether the test took
  effect as the control. A change of a sensor's settings is judged also on
  whether a sensor recorded the step. A step whose control moved is run
  variation, not an effect, and is named as such. Each run decides anew which
  of the lab's rules it accepts, so the recording keeps, for each rule, whether
  the run accepted it and the digest of its file: a step that an unchanged rule
  matched in one run only is not credited to a change of rules, the lab's or
  the published ones. It is credited to a change of a sensor's settings, whose
  new telemetry can make an unchanged rule match.
- **The control step.** The step of role `control` must raise no alert, so an
  alert on it is worse, and named as a false alert.
- **Its price, on the same line.** A step that got better carries what the
  gain cost, and a test step also how many of the list's published procedures
  of its technique got better. For the lab's rules the cost cannot be counted
  from the recording: a rule that matched ordinary activity is not accepted,
  and its matches are left out of the recording before it is written. The line
  says that, and quotes both recordings' notes on which rules were accepted,
  rather than a count that would read as zero. On two runners that differed
  (below), each run counted its ordinary activity on its own runner, so the
  line says the price is not known and gives each run's own counts.
- **The lab's code.** Two runs from different commits of this repository may
  differ because of the code, which the comparison does not check. It does not
  refuse for that, since a pull request always differs from `main`, but every
  verdict then says so, and `delta.md` names both commits.
- **No race.** The rules ran after each run, so there is no time to a first
  alert to compare, and the comparison makes none up.
- Every verdict rests on one pair of runs, and says so.

The job "compare with the latest run on main" of the `lab` workflow runs it
with nothing declared, on every run without a pair (next section).

With `--two-runners`, as the pair gives it, `delta.json` says `runners: 2` and
`delta.md` says that the two runs were made side by side, each on a fresh
runner of its own. With `--change sensors:<id>`, a changed step also lists what
that sensor recorded of it in one run only, and a step whose outcome moved
while that sensor recorded the same for it in both runs is not credited to the
change: it is run variation. A change of Sysmon's settings is credited with no
step at all: two runs of the same settings already differ in what Sysmon
records of a step, by temporary file names, and Sysmon's events carry nothing,
as auditd's carry an audit key, that tells what new settings recorded from
that, so every step that moved is not attributable, and its verdict says why.
When two runners side by side got another image
or kernel, and nothing else differs besides the declared change, a change of
the audit rules gets a limited verdict (`limit` in `delta.json`): it is
credited only on a step it left its own mark on, every event of the step being
of an audit key whose every rule watches a path that no rule of the other run,
as written, could have recorded, while the other run holds nothing of it, and
every other step that differs is not attributable. What a run's rules watch under each key,
each recording says from the audit rules as that run loaded them
(`audit_watches` of its sensor `auditd`, each rule in one fixed form without its
key, so that a watch and the system-call rule it stands for, or a rule's two
architectures, read the same). The mark is given only where that text can
establish it: each rule of the key names one path; no rule of the other run,
under any key, names that path, a folder above it or a path under it, whatever
its permission letters, nor any other path the event names (a rename or a link
names two); and no rule of the other run without a path could record the same
kind of event. There are two kinds: program starts, and reads, writes and
changes of attributes as one, since the kernel matches `perm=r` and `perm=w`
alike on an open for reading and writing. A rule with `perm=x`, or on `execve`
or `execveat` alone, records program starts alone, so it leaves the mark
standing; one for reads alone (`perm=r`) does not, and neither does one on
`open`, `openat`, `truncate` or any other system call, or on every one. Where
the text cannot establish the mark, the step is not attributable and its
verdict says why. The text has a limit, and the verdict names it: paths are
compared as the rules and the events write them, so a second name that a link
gives a file (a symbolic or hard link, or a name under `/proc`) is not found
out. A key is only a label: a key renamed, split or merged on
rules both runs have, or one that kept an old rule beside a new one, is no
mark, nor is a key whose rules both runs have that fired on one runner only.
A credited step is counted under its result and again in
`counts.by_mark`. A recording that does not say what its rules watch, one
written by an older version, is refused on two runners that differed: write it
again with `bluefire-lab recording` from its run's folder, or run the pair
again. Every other change on two runners that differed is refused, with the
advice to run the pair again. The section "Two runners that differed" of
[`docs/RECORDING.md`](../docs/RECORDING.md) gives the rule.

**The noise floor.** The job "compare with the latest run on main" of
[run 45358678821](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45358678821),
a pull request that changed neither rules nor sensor settings, compared its
recording with that of
[run 45352666265](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45352666265)
on `main`, with nothing declared: the same tests' commit, runner image and
kernel, sensor settings, rule sets and tool versions, from two commits of this
repository (which the comparison names), and all 91 steps the same in what
happened, in whether a sensor recorded them and in both outcomes. Two runs are
one sample of the noise floor, not its measure: a pair of runs told below had
one step that took effect on one runner and not on the other.

## A pair of runs for a change to the defense

A defender who changes a rule or a sensor setting wants to see what that one
change did. A comparison with the latest run on `main` cannot show it: that run
is days old, on another runner, from other code. So when a pull request
changes what a run loads of the defense, the `lab` workflow makes a pair of
fresh runs for it, in the same workflow run, where only that thing differs. A
change of the lab's own rules alone needs no second run: see the next section.

- **When.** The job "decide how a change to the defense is shown" checks out
  the base commit's `lab/rules/` and `lab/sensors/`, and nothing else of it,
  and runs `bluefire-lab pair --base base/lab lab`. It compares the digests of
  what a run loads: [`sensors/sysmon.xml`](sensors/sysmon.xml) (`sensors:sysmon`),
  [`sensors/audit.rules`](sensors/audit.rules) (`sensors:auditd`) and the
  folder [`rules/linux`](rules/linux) (`detectors:lab`, the same digest a
  recording gives that detector). The paths a pull request touched do not
  decide: a change that leaves these files as they were runs once, as does
  every run that is not of a pull request (`pair=no`). A change of a sensor's
  settings is a pair of runs (`pair=runs`), and so is a change of a sensor's
  settings and of the lab's rules together, which is two changes and declares
  nothing. A change of the lab's rules alone is one run evaluated twice
  (`pair=rules`).
- **The two runs.** The whole list runs twice, as two jobs on two runners
  started side by side: "attack tests on this runner, with the defense of the
  base commit", which loads the base commit's rules and sensor settings, and
  "attack tests on this runner", the usual run, which loads the head's. Both
  run the head's code, list and tools, and are evaluated, reported and
  recorded the usual way; their artifacts are `lab-run-base` and `lab-run`.
- **Why two runners, not one after the other on one.** A run that the first
  run's leftovers could have changed is no before or after, and the list
  leaves some behind on purpose: it ends with tests whose changes upstream does
  not undo (the root certificate of T1553.004 and the sudo setting of
  T1548.003 stay until the runner is gone), and the effect checks of those
  tests would pass on a second run whatever the test then did. The tests'
  cleanups undo much of the rest, but nothing shows that they undo all of it.
  A fresh runner for each side is a clean state that needs no proof. What it
  costs: two runners can differ, and GitHub hands out different images and
  kernels under the same label, also to two jobs started side by side (the
  first pair, below, got two). Each recording says its runner image and
  kernel. When they are the same, what still differs between two runners is
  part of the run variation the control shows. When they differ, a change of
  the audit rules is judged only where its own mark is, and any other change
  is refused.
- **When a pair is refused for its runners.** Run the workflow again for the
  same commit (re-run all jobs of the run on its page): that gives two new
  runners, which may get the same image and kernel. Nothing in the pull
  request can choose them.
- **The comparison.** The job "the change to the defense, before against
  after" runs `bluefire-lab compare` on the two recordings with the one change
  the plan declared (`--change sensors:auditd`, for example) and
  `--two-runners`. When more than one thing changed it declares nothing, the
  comparison gives no verdict, and the job's summary says so. `delta.md` goes
  to the run page, and the artifact `lab-pair` holds both recordings
  (`before/recording.json`, `after/recording.json`), `delta.json` and
  `delta.md`. The job runs only when both runs passed their controls.
- **The comparison with `main`** runs only on a run that changes nothing of the
  defense (`pair=no`). There it is the one comparison, and it declares nothing,
  so it names what varies and credits nothing to a change. Beside a pair, or
  beside one run evaluated twice, it would be a second, weaker comparison that
  could be read as the result, so such a run has none.
- **What it says.** Under a sensor change, `delta.md` names the steps that are
  recorded now and were recorded by no sensor before, or says that there are
  none, and the tests unseen in both runs. Two runs of the same audit rules
  already differ in auditd's text, by temporary file names and a password's
  salt that are new in every run, so for `sensors:auditd` a step is credited
  only through events of an audit key that one run's events carry and the
  other's never do, with every alert that one run has on it and the other
  lacks resting on those events alone, and `delta.md` gives how many events
  of each such key the recordings hold. That is a description: on two
  runners that differed it also says whether each such key can carry the
  change's own mark, and why not.
  Each side says the commit its rules and sensor settings came from.
- **What it costs.** One more run of the whole list: in the three pairs told
  below it took 13.5 to 15.5 minutes of runner time, and each of the two short
  jobs that decide and compare under half a minute. The two runs go side by
  side, so the pull request waits about as long as for one.

**The first change: auditd watches the history files.** One test of the list
was unseen: T1070.003 Clear Bash history (echo) empties `~/.bash_history` with
the shell's own redirect, which starts no program. Both sensors recorded only
the launcher's own start, `sh -c` with the test's whole command, which the lab
never counts, since it holds the whole test, and nothing of what the test did.
The change is to a sensor: the
rules in [`sensors/audit.rules`](sensors/audit.rules) now watch the test
account's shell history files by path (`~/.bash_history`, `~/.zsh_history`,
`~/.histfile`, `~/.sh_history`, `~/.history`) for writes and changes of
attributes, as a defender would watch them, not the test's command. If the
watch works, auditd records the shell opening the file to empty it, in the
audit session of the test's attack step, and the step goes from unseen to
seen.

**The pair that shows it** is run
[45365902367](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45365902367)
of the pull request that made the change (its job "the change to the defense,
before against after", and the artifact `lab-pair`). Its recordings and job
summary were written before a recording named the pull request's head
commit: they name commit `35df6a6f`, the merge commit GitHub made for the
run, which no clone has. A clone has the pull request's head, `fc33afe0`,
whose files are that merge commit's, on its base `673169ec`, whose rules and
sensor settings are the before side. Its two runners had the
same image and kernel, so the comparison is like with like, with a verdict on
every step. Before, with the old audit rules, "Clear Bash history (echo)"
(`test:cbf506a5`) had no telemetry; after, it is seen, by one event:
`openat: /home/bluefire-lab/.bash_history` of the audit key `shell-history`,
the key of the new watches, written by the launcher's shell in the test's
attack session. The comparison calls that step better, on 1 of the 4
published procedures of T1070.003 in the list (the 3 others were seen or
alerted before too), and gives its price: 2 published rules alerted on
ordinary activity before and 2 after, with 8,902 ordinary events before and
8,841 after. The 90 other steps are the same, and what happened is the same
on all 91. One pair of runs.

Two earlier pairs of the same change got two runners that differed in image
and kernel (`ubuntu24 20261116.133.1` with `7.0.0-1014-aws`, and
`ubuntu24 20261116.376.1` with `7.0.0-1017-azure`). Both recorded the same
event on the same step, and both summaries were written by earlier versions of
`compare`: run
[45362120784](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45362120784)
gave a limited verdict that rested on the key's name alone, and run
[45350480637](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45350480637)
refused every pair on two runners that differed. Their recordings were written
before a recording said what its audit rules watch under each key (those of
run 45362120784 name the keys alone, those of run 45350480637 not even
those), so this version of `compare` refuses both: on two runners that
differed, a key's name is no mark. A limited verdict by this version's
rule, on a pair of runners that differed, is not yet shown by a CI run. In run
45350480637 one more step differed,
`test:23b91cd2` (T1518.001 Security Software Discovery - ps): on one runner
its output lacked the text its effect check looks for. That is what two
runners can differ by, and why such a step is not credited to a change. Of
these three pairs, two got runners that differed.

## A change of the lab's rules: one run, evaluated twice

On this host the rules run after the run, over the telemetry it recorded. So a
change of the lab's own rules needs no second run of the tests: the same run's
telemetry, evaluated once with the base commit's rules and once with the
head's, gives two real recordings of one run, with no difference of runners
and no run variation.

- **When.** The plan says `pair=rules` when, of what a run loads of the
  defense, only the folder [`rules/linux`](rules/linux) differs from the base
  commit's. A change of a sensor's settings still makes a pair of runs on two
  runners, since it changes what is recorded, and a change of both is two
  changes and declares nothing.
- **The run and the evaluations.** The list runs once, "attack tests on this
  runner", with the head's files, as any run. Then the job "the change to the
  lab's rules, one run evaluated twice", which runs no test, takes that run's
  artifact `lab-run` and the base commit's `lab/rules/`, and makes two copies
  of the run's folder, each with one commit's rules in `lab-rules/linux` and
  that commit in `lab-rules/SOURCE`, and without what the run's own
  evaluation wrote. It runs `bluefire-lab evaluate` and `bluefire-lab
  recording` in each, with the pinned Zircolite, and `bluefire-lab compare
  --change detectors:lab --one-run` on the two recordings. `delta.md` goes to
  the run page; the artifact `lab-rules-twice` holds both recordings and both
  `results.json`, `delta.json` and `delta.md`.
- **What the comparison checks.** That the two are one run, and that
  everything a change of the lab's rules cannot move is the same in both, not
  only alike: the run and its CI run, the steps, what happened, whether a
  sensor recorded each step, every event, the published rules' alerts and
  outcomes, and the ordinary activity. It also checks that every rule of the
  lab's own whose file is the same in both was judged the same way and matched
  the same steps. A run judges a rule on its own tests, variants and ordinary
  activity, so on one run an unchanged rule cannot flip: if one does, the two
  were not evaluations of one run, and the comparison is refused.
- **What it says.** "One run evaluated with two rule sets" on every verdict,
  never "one pair of runs". A step that got better is named with its
  procedures of the technique on the list and with its price as the lab tells
  it for its own rules: not counted, since a rule that matched ordinary activity
  is not accepted and its matches are left out of the recording, with both
  evaluations' notes on which rules were accepted. `delta.md` also lists each
  rule of the lab's own that is new, gone, changed, or the same text moved to
  another file, and how each
  evaluation judged it, so that a rule that did not change an answer, because
  the run did not accept it, says why.
- **What it costs.** One run of the list instead of two, and a job that
  evaluates the run twice: 54 s of runner time in the one run so far.

What this job shows for the rule above, in
[run 45395673682](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45395673682):
with the base commit's rules the rule is not there, and with the head's the
run accepted it. Four steps are better, each from seen to alerted with the
lab's rules and each by one alert of the new rule: T1070.003 Clear Bash
history (echo), T1070.003 Clear Bash history (cat dev/null), and the variant
of each. The 89 other steps are the same, and what the change cannot move
(what happened, whether a sensor recorded the step, the published rules'
outcome) is the same on all 93. Of the 60 tests, 17 were alerted with the
lab's rules before and 19 after; by the published rules alone it stays 3. One
run, evaluated with two rule sets.

## The defender loop so far

A step nobody saw, its telemetry, a rule drafted from it, and before against
after, each turn shown by a CI run of the `lab` workflow:

1. **The watch.** T1070.003 Clear Bash history (echo) was unseen. The audit
   rules now watch the test account's history files. The pair of runs of
   [run 45365902367](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45365902367),
   on two runners with the same image and kernel, gives the verdict: the step
   went from unseen to seen, by one audit event, `openat` of
   `~/.bash_history` under the watch's key `shell-history`, and no rule alerts
   on it. The 90 other steps are the same. An earlier pair,
   [run 45350480637](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45350480637),
   recorded the same event, but its two runners differed and the comparison
   of that day refused the pair. See
   [A pair of runs for a change to the defense](#a-pair-of-runs-for-a-change-to-the-defense).
2. **The rule.** [Shell History File Truncated In Place](#a-rule-on-auditds-records-a-history-file-truncated-in-place),
   drafted from that event as run 45350480637 recorded it, shown as one run
   evaluated twice in
   [run 45395673682](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45395673682):
   the run accepted the rule, and the step went from seen to alerted with the
   lab's rules, as did T1070.003 Clear Bash history (cat dev/null). See
   [A change of the lab's rules: one run, evaluated twice](#a-change-of-the-labs-rules-one-run-evaluated-twice).

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
