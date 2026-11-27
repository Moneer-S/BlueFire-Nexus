# Recordings

A recording is one file that holds what really happened in a run: the network
it ran on, every step of the attacker, what the sensors recorded, which rules
matched, and the score. It is made to be replayed by the live view (see
[LIVE_VIEW.md](LIVE_VIEW.md)), which plays inside the app and also opens as a
single HTML page that holds one recording and plays without the app. The app
keeps recordings: it lists them, returns one whole, imports one, plays one in
its live view, and writes the single page of one (see "In the app" below).

A recording is made from the files of a run by an engine that ran the steps for
real: today `bluefire-lab`, on one disposable host or on a range (a network of
disposable containers). Nothing in a recording is invented. A
value the engine did not measure is left out, and the reader shows it as not
known.

A recording can hold one run judged by several defenses, each with its own
sensors and rule sets: see [Defenses](#defenses).

The format is JSON, UTF-8, one object. Its `schema` is `bluefire.recording/1`.
Times are ISO 8601 in UTC with a `Z`, with up to six digits after the second
where the source has them (`2026-11-17T17:07:23.834Z`). The app and the live
view compare them to the microsecond, and the live view shows them to the
millisecond.

## Characters a text cannot hold

No text or key holds NUL or half of a character pair (a lone surrogate). A
step's `command`, `output` and `plain`, the attacker's `description` and
`goal`, and `notes` are free text: they may hold line breaks, tabs and a
terminal's escapes. Every other text and every key, an event's `text`, a
title, a host's or a sensor's name and a rule's title included, holds no
control character: no C0 or C1 control or DEL, no direction mark, embedding,
override or isolate (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to
U+2069), and no line or paragraph separator (U+2028, U+2029). Each of these can
make a name read otherwise on screen than it is written. What the app refuses
on import is under "In the app".

A sensor can still record such a character: a command line with a tab in it,
or a file name with a right-to-left override, as a test of ATT&CK T1036.002
makes one. A writer neither drops it nor replaces it with another character.
Where the format refuses a character, the writer writes `\u{`, the
character's code point in uppercase hexadecimal, and `}`: a tab is `\u{9}`, a
line break `\u{A}`, a right-to-left override `\u{202E}`, a NUL `\u{0}`. So
that this form never stands for text the source held already, a backslash that
comes right before `u{` in the source is written `\u{5C}`, in every text, free
text included: what the source held as `\u{41}` is written `\u{5C}u{41}`.
Nothing else changes. Free text keeps its line breaks and tabs, every other
backslash is the source's own, and a text that holds none of these characters
and no `\u{` is written as the source gave it. So each `\u{<hex>}` in a text
stands for one character the source recorded there, and a reader that turns
each back into its character gets the source's text. A text that is cut
(`...`) keeps such a form whole or leaves it out. `bluefire-lab recording`
does this for every text and key it writes.

## Top level

| Key | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `bluefire.recording/1` |
| `id` | string | The engine's id of the run. Letters, digits, `-` and `_`, at most 64. |
| `title` | string | A few plain words, such as "60 published tests on one Linux host". |
| `kind` | string | `test list`: independent steps, one after another. `attack path`: steps that build on each other toward a goal. |
| `source` | object | Where and when the run happened. See below. |
| `network` | object | The hosts, their links, the sensors and the detectors. See below. |
| `attacker` | object | Who drove the steps. See below. |
| `steps` | array | Every step that ran, in the order it ran. A test the engine dropped before the run, for example because the host lacks a program it needs, is not a step: `notes` names it and gives the reason. See below. |
| `events` | array | What the sensors recorded for the steps, in time order. See below. |
| `alerts` | array | Every rule match on those events, in time order. See below. |
| `ordinary` | object | Optional. What the defenses said about ordinary activity. See below. |
| `score` | object | The totals. See below. |
| `defenses` | array | Optional. The defenses that judged the run, each with its sensors, its rule sets and what it made of every step. With it, each step's verdict, `ordinary` and `score` above are the first defense's, and `events` and `alerts` hold those of every defense. See [Defenses](#defenses). |
| `notes` | array of strings | Limits a reader must know, in plain sentences. May be empty. |

## `source`

| Key | Type | Meaning |
| --- | --- | --- |
| `engine` | string | The program that ran the steps, such as `bluefire-lab`. |
| `environment` | string | Plain words: `GitHub-hosted runner` or `containers on a developer machine`. |
| `started`, `finished` | time | The run's start and end. |
| `repository`, `commit` | string | Optional. The GitHub repository, as `owner/name`, and a commit of it that stays there, for the code that ran the steps. For a run of a push to a branch, a scheduled run or one started by hand, it is the commit the run checked out: the branch's newest commit. For a run of a pull request, it is the pull request's head commit, its branch's newest commit when the run started. The pull request's own reference `refs/pull/<number>/head` points to it until the branch is pushed again, and a merge of the pull request by a merge commit keeps it in the base branch's history. GitHub runs a pull request's code as a merge of that commit into the base branch as it then was, in a merge commit that it makes anew whenever either side moves and that no branch holds, so a clone does not have it. The code that ran is this commit's changes on that base, which is this commit itself when the branch was not behind its base. A recording of a pull request's run written before the lab recorded the head commit names GitHub's merge commit here instead, and wherever else it names the head's files (`defense_commit`, the detector `lab`'s `commit`), and `lab/README.md` gives the head commit a clone has beside each run it cites with such recordings. The recording can be written later from the run's files, by newer code. |
| `defense_commit` | string | Optional. The commit of the same repository that the sensors' settings were loaded from, and the lab's own rules too unless the detector `lab` has its own `commit`: that one names where the rules came from, and wins. In the run of a pair that loads a pull request's base commit, it is that commit and not `commit`; otherwise it is the same commit as `commit`, with the same meaning for a pull request. When one run is evaluated twice, both recordings have the run's `defense_commit`, and the detector `lab` of each names its rules' commit: the base commit, and the pull request's head commit. |
| `run_url` | string | Optional. The CI run that made the recording. A reader shows it as a link only when it is the https address of a GitHub Actions run (`https://github.com/<owner>/<repository>/actions/runs/<number>`) of the recording's own `repository` when that is given, and leaves out anything else. |
| `tools` | array | Each `{ "name", "version", "role" }`: a pinned tool of the run. `role` is one of `tests`, `executor`, `sensor`, `rules`, `rule engine`. The list is always there, and empty when the run names no pinned tool. |
| `setup` | object | Optional. What a comparison of two runs needs to know was the same. See below. A recording with `setup` has stable step ids. |

`setup` holds, each optional:

| Key | Type | Meaning |
| --- | --- | --- |
| `atomic_commit` | string | The commit of Atomic Red Team the tests came from. |
| `images` | object | The image each host ran on, by host id. The lab writes the runner's image name and version, such as `ubuntu24 20261116.133.1`. |
| `kernels` | object | The kernel each host ran, by host id. GitHub hands out runners with different kernels under the same image. |
| `sensors` | object | The SHA-256 of each sensor's settings as the sensor loaded them, by sensor id: for the lab, of the Sysmon configuration and of the audit rules with the test account's home folder filled in. |

A reader treats any other key of `setup` the same way: a text, or an object of texts by id, that two
runs must share.

## `network`

| Key | Type | Meaning |
| --- | --- | --- |
| `hosts` | array | Each host of the run. |
| `links` | array | Optional. Each `{ "from", "to", "label" }` between host ids: who can reach whom. |
| `sensors` | array | Each `{ "id", "name", "host", "records" }`: a sensor, the host it runs on, and in plain words what it records. Optional on the sensor `auditd`: `audit_watches`, an object that maps each audit key of its rules (the word after `-k`, or after `key=` in `-F`) to what the rules under that key watch, read from the rules as the run loaded them (after `-D`, `-d` and `-W`; `""` for the rules without a key). Each rule is a string in one fixed form, its keys taken out: `-a <list>,<action>` sorted, then `-S` with the system calls sorted and joined by commas, then each `-F` sorted, then each `-C`. A watch `-w <path> -p <perms>` is written as the rule it stands for, `-a always,exit -F path=<path> -F perm=<perms>` (`perm=arwx` without `-p`), `dir=` as `path=`, the letters of `perm` sorted, `arch=` left out, so that a rule for `b32` and the same one for `b64` are one, and an unset login uid (`-1`, `4294967295`) written `unset`. The forms of a key are sorted and each is there once. An older recording does not have it, and may have `audit_keys` instead: the audit keys of its rules, sorted, without what they watch. Nothing reads `audit_keys` now, and on two runners that differed a comparison of `sensors:auditd` refuses a recording that has only that (see Two runners that differed). |
| `detectors` | array | Each `{ "id", "name", "rules", "when" }`, plus an optional `digest`: a rule set with its engine, the number of rules evaluated, `when` the rules ran: `live` or `after the run`, and the SHA-256 of its rule files. A detector's id is free, with two that are kept: `lab` is the id of the rules written in this repository, and a detector with the id `pinned` holds published rules only. Whether a rule is a published one or one of this repository's own is said by each alert's `rule.origin`, not by the detector's id. |

A network holds at most 12 hosts, at most 3 of them of kind `defense`, at most
16 links, at most 16 sensors with at most 4 on one host, and at most 4
detectors: the most the live view's map draws readably (see
[LIVE_VIEW.md](LIVE_VIEW.md)). A recording with defenses holds at most 8
detectors, of which each defense has at most 4: the map draws one defense's
view at a time. A link joins two different hosts, and no link is
given twice with the same `from`, `to` and `label`. The service and the replay
page both refuse a network beyond these, with a sentence that names the limit;
the limits are `MAX_HOSTS`, `MAX_DEFENSE_HOSTS`, `MAX_LINKS`, `MAX_SENSORS`,
`MAX_SENSORS_ON_A_HOST`, `MAX_DETECTORS` and `MAX_DETECTORS_WITH_DEFENSES` in
`bluefire/recordings.py` and `frontend/src/live/recording.ts`.

A packet sensor belongs to the host whose interfaces it records, not to either
remote endpoint. Its id is `packet-capture-<host>`; for example,
`packet-capture-web` records traffic on `web`'s range interfaces. Events from
that sensor therefore have `host: "web"`, while their source and destination
addresses remain in `fields`. A Suricata detector that reads the retained
capture has `when: "after the run"`.

A rule set's `digest` is the SHA-256 of what `sha256sum` prints for its files,
sorted by their path inside the rule set's folder, so it can be checked from a
run's artifact: `cd rules/linux && find . -type f -printf '%P\n' | LC_ALL=C sort
| xargs -d '\n' sha256sum | sha256sum` (and the same in `lab-rules/linux`). An
empty folder has the digest of nothing. Two runs with the same digest evaluated
the same rules; the lab digests every file of the folder, also its rules that a
run did not accept.

The lab's detector `lab` also has `verdicts`, optional: for each rule written
in this repository, `{ "rule", "title", "digest", "accepted", "reason" }`, its
id and title, the SHA-256 of the file that holds it, whether the run accepted
it, and why. A run decides that anew each time, from ordinary activity and from
the runs with changed input arguments, so an unchanged rule can be accepted in
one run and not in the next. An older recording has no `verdicts` and says the
same only in one of its `notes`, the one that starts "The run accepted"; the
app's page for fixing a step shows that note whole for such a recording.

So that a reader can show a rule beside the step it alerted on, each verdict
can also hold, optional, the rule itself: `file`, the path of its file in the
repository (such as `lab/rules/linux/auditd/<name>.yml`), and `lines`, an array
of strings, the file's text line by line, without the line breaks (no value of
the format outside a step's own text holds a line break). Joined with a line
break after each line, the lines give the file whose SHA-256 is `digest`, for a
file that ends with a line break, uses no other kind and holds no character a
text cannot hold (see above), as the lab's do. The
detector can also have `commit`, optional, the commit of this repository the
rules came from; where it is given, it and not `source.defense_commit` says
where the lab's rules came from. In the artifact `lab-rules-twice` of
[CI run 45395673682](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45395673682),
which holds one run's recording written with two sets of the lab's rules, the
text of 9 rules makes about 14 KB of a 1.2 MB recording, and that of 10 rules
about 17 KB. A recording written before these keys has none of them.

A host is `{ "id", "name", "role", "kind", "os", "addresses" }`. `kind` is one
of `host`, `attacker`, `internet`, `defense`. `role` is plain words, such as
"web application" or "Linux host under test". `os` (a string) and `addresses`
(an array of strings) are optional.

A rule written in this repository is accepted when it alerted on a test,
alerted again on every run of that test with changed input arguments, and
matched nothing in the ordinary activity. A match of a rule that was not
accepted is not in the recording, and `notes` names each such rule with the
reason.

## `attacker`

`{ "kind", "description", "goal" }`. `kind` is `scripted` or `agent`.
`description` says in plain words what drove the steps. `goal` is the end of an
attack path in plain words, or null for a test list: it is always there. An
attack path with `score.goal_seconds` has a goal, and the live view names it
where it says the goal was reached.

## A step

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | Unique in the recording. In a recording with `source.setup` it is also stable: the same test with the same input arguments in the same role has the same id in every run of the same list, so two recordings pair their steps by it. See below. An older recording has the step's `order` as text. Treat it as an opaque key. |
| `order` | number | Its position among everything the run did, from 1. Steps are sorted by it. Positions that were not steps, such as ordinary administration, are skipped, so do not use it as an index or a count: use the step's place in `steps`, and `score.steps` for the total. |
| `role` | string | One of `test`, a step that counts; `canary`, a step the defenses are known to catch; `control`, a step that must raise no alert; `hardened`, a test run again with a hardening change in place; and `variant`, a test run again with changed arguments. |
| `title` | string | The published name of the test. |
| `plain` | string | Optional. What the step does, in one plain sentence. |
| `technique` | object | `{ "id", "name", "tactic" }` from MITRE ATT&CK. `name` and `tactic` are optional. `tactic` is the tactic the published index lists the test under, in the index's lowercase spelling, and several joined with `, ` when it lists more than one. |
| `test` | object | Optional. `{ "project", "guid", "executor", "elevated" }`: the published test this step ran. `elevated` is a boolean: true when the test ran as root. |
| `host` | string | The id of the host the step ran on. |
| `from` | string | Optional. The id of the host the step came from, for a step that crosses the network. |
| `started`, `ended` | time | When the step's attack command started and ended. Left out when the engine could not measure them, as for a test whose attack did not start. `ended` is never earlier than `started`. See "Steps run forward" below. |
| `command` | string | Optional. What ran, as text. It keeps its start: when it is cut it ends in `...`. |
| `output` | string | Optional. What the step printed. It keeps its end: when it is cut it starts with `...`. |
| `happened` | object | `{ "answer", "basis" }`. `answer` is `took effect`, `attempted without effect`, `blocked`, `not attempted` (the attack did not start) or `inconclusive`. `basis` says what the answer rests on. |
| `visibility` | object | `{ "answer", "basis", "events" }`. `answer` is `alert`, `telemetry only`, `no telemetry`, `inconclusive` or `not applicable`. `answer` and `basis` count published rules only, like `outcome`; a match of a lab rule shows in `outcome_with_lab_rules` and in the step's alerts. `events` counts the sensor events tied to the step, and is left out when the engine could not tie events to it (`inconclusive` or `not applicable`). When the recording holds fewer of them than that, `kept` says how many. |
| `outcome` | string | The score word for the step, counting published rules only. See below. |
| `outcome_with_lab_rules` | string | Optional. The score word when the accepted rules written in this repository count too. Present on every step when the run evaluated such rules, and absent when it did not. |
| `first_event` | time | Optional. The first sensor event of the step. |
| `first_alert` | time | Optional. The first match of a published rule on the step that counts as an alert, at its moment: its `raised` time when its detector ran live, and its `time` when the rules ran after the run, like the score's `first_alert_seconds`. Absent when there is none. |
| `first_alert_with_lab_rules` | time | Optional. The same, when the accepted rules written in this repository count too. Written only when the run evaluated such rules and one of the two kinds alerted on the step. A step whose `outcome` is `seen` or `stopped` can carry it. |
| `compared_with` | string | Optional. For a `hardened` or `variant` step only: the id of the step it repeats, an earlier step that is itself neither `hardened` nor `variant`, never the step itself. |
| `defense` | object | Optional. For a `hardened` step: `{ "title", "why" }` of the hardening change. |

The lab makes a step's id from parts joined by `:`: its `role`; the first 8
characters of its test's GUID; when it ran with input arguments, the first 6 hex
digits of the SHA-256 of those arguments as compact JSON with sorted keys in
UTF-8 (`{"search_path":"~"}` gives `85163a`); for a `hardened` step, the name
of its hardening change; and when the same id would come more than once, as the
canary's does at the start and the end of a run, its count among them from 1.
For example `test:46959285:85163a`, `variant:46959285:5e4f5f`,
`hardened:2fc6c0ab:tmp-noexec` and `canary:a934276e:2`. An event's id does not
use it: it stays the step's `order` and the event's place among the step's
events, such as `31-4`.

`command` and `output` are at most 2,000 characters, the `...` included. Each
sensor stamps its own records, so a step's `first_event` or `first_alert` can be
a few milliseconds earlier than its `started`, and an event a little later than
its `ended`.

**Steps run forward.** Steps run one after another in their `order`: a step's
`started` is not earlier than the `started` of the step before it with one, nor
earlier than that step's `ended`, so steps do not overlap. The stretch of the
run a step holds, from its `started` or its earliest event or alert `time`,
whichever comes first, to its `ended` or its latest event or alert `time`,
whichever comes last, begins no earlier than the stretch of the step before it
ends. An event stamped a moment outside its step's start and end is kept; one
stamped inside another step's stretch is not.

**An attack path's race** counts from one moment: its first step in `order` is
of role `test` and has a `started`, and both `score.first_alert_seconds` and
`score.goal_seconds` count from that start. A check of the lab's own, such as a
canary or a control, comes after the first test or is left out. A test list has
no race.

`outcome` is the first of these that holds:

1. `stopped`: `happened.answer` is `blocked`.
2. `no effect`: `happened.answer` is `attempted without effect` or `not attempted`.
3. `alerted`: `visibility.answer` is `alert`: a published rule that counts as an alert matched an event of the step.
4. `seen`: `visibility.answer` is `telemetry only`: a sensor recorded the step, and no published rule that counts as an alert matched it.
5. `unseen`: `happened.answer` is `took effect` and `visibility.answer` is `no telemetry`.
6. `inconclusive`: anything else, for example `happened.answer` `inconclusive` with `visibility.answer` `no telemetry`, or `visibility.answer` `inconclusive`.

A step whose `happened.answer` is `inconclusive` is scored by what the sensors
saw: `alerted` or `seen`, or else `inconclusive`. It is never `unseen`, which
needs the step to have taken effect. `outcome_with_lab_rules` follows the same
rules, with an alert of an accepted lab rule counted as an alert too.

## An event

`{ "id", "time", "host", "sensor", "kind", "text", "step", "tied_by" }`, plus
optional `user`, `image` (the program), and `fields` (a small object of the
source's own field names and values, and for auditd also `paths` and `command`,
which the lab puts together from the record). `sensor` is a sensor id. `kind`
is plain words such as `process start`, `file created`, `network flow`, `HTTP
request`, `TLS handshake`, `SSH session` or `DNS query`, or the sensor's own
name for the record: a call such as auditd's `execve` or `openat`, or a record
type such as `USER_ACCT`. Packet-event text names its
observed endpoints and protocol; protocol records add the request, handshake,
session or query in plain words, and distinguish a DNS response from its
query. `text` is one line, where a line
break or a tab the sensor recorded is shown as "Characters a text cannot hold"
says (`\u{A}`, `\u{9}`): the command
line for a program start, the file for a file record, a sentence that names the
file and the kernel's answer for a start the kernel refused, the connection for
a network record, auditd's own `op=`, `cmd=`, `acct=` and `res=` words for a
record a program such as sudo writes about itself, and empty when the record
has none, as for a process end. `text` is at most 2,000
characters and each `fields` value at most 300; a cut one keeps its start and
ends in `...`. auditd's `fields.msg` is the record's id in auditd's own form,
`audit(<seconds>.<ms>:<serial>)`.

A canonical packet event keeps its stable ECS id in `fields.ecs_event_id` and
uses the packet timestamp, not the later evaluation time. Its bounded scalar
fields can include the source and destination address and port, transport and
application protocol, capture interface, and Suricata flow or transaction id.
A 64-bit Suricata id is text, so a reader cannot round it by parsing a number.

`step` is the id of the step the engine tied the event to, and `tied_by` says
how: `session` (in the test's login session), `launcher` (done by the shell
that carried the test itself, such as a file it wrote), `account` (a program
the test's account started during the step outside the lab's own sessions, such
as one cron ran),
`systemd` (started by systemd during a root test's window), `address` (the
event's own source address is an address of the host the step ran on, as
sshd's lines on web from the attacker's machine during a range's first step,
or, on a host the step reached, its text names that address or that host's
container name),
`content` (the event names a path the step was given, such as a file
integrity event for the file the step wrote) or `window` (only inside the
step's time window). `address` and `content` are a range's ties, and like
`account` they hold only inside the step's window. `systemd` and `window` are
ties by time, not by which process started which; `lab/README.md` gives the
rules. A range never writes an event tied by `window`: such an event is
coincident with a step and does not count for it. Events tied to no
step are not in the recording: the engine's own output holds them.

For a step with very many events the recording does not keep them all, and the
step's `visibility.kept` says how many it kept. It keeps every event a rule
matched. In a recording with defenses the cut is made for each sensor: the
recording keeps the first events of each sensor in time order, up to that
sensor's share, so that one busy sensor does not push out what another
recorded, and each defense's view (see [Defenses](#defenses)) keeps the start
of what its own sensors recorded. A recording without defenses may instead
keep the first events of the step in time order, whichever sensor recorded
them.

A packet recording follows the same cut. It keeps every canonical packet event
that any Suricata rule matched, including a lower-level match that does not
count as an alert. In each defense view `visibility.events` is the full count
from that defense's sensors and `visibility.kept` is the exact count retained.

## An alert

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | Unique in the recording. |
| `time` | time | When the matched activity happened. |
| `raised` | time | Optional. When the alert existed in the defender's system. Absent when the rules ran after the run. |
| `host` | string | Host id. |
| `detector` | string | Detector id. |
| `rule` | object | `{ "id", "title", "level", "origin" }`. `level` is one of Sigma's levels: `informational`, `low`, `medium`, `high`, `critical`. `origin` is `pinned` for a published rule and `lab` for an accepted rule written in this repository. |
| `counts` | boolean | True when the match counts as an alert: its level is high or critical. A lower level is a match for review. This holds for both origins: a counting match of a lab rule goes toward `outcome_with_lab_rules` and `first_alert_with_lab_rules` only, never toward `outcome` or `first_alert`. |
| `step` | string | The id of the step the matched event belongs to. |
| `events` | array of strings | The ids of the matched events, in evidence order. Usually they belong to the alert's step. For a multi-event correlation whose detector ran after the run, earlier evidence may belong to earlier steps on the same host; the last id is its terminal event, belongs to the alert's step, and has the alert's `time`. No evidence is later than that terminal event, and observed users do not disagree. A live alert's moment (`raised`) is not earlier than the earliest event; it can be earlier than a later event of its own step. |
| `launcher_only` | boolean | Optional. True when the rule matched only the one shell command that carried the whole test, not what the test did. Such a match never counts, and its `events` is empty: that command is the step's `command`, not one of its events. |

A Suricata alert is an after-run alert: `time` is the matched packet event's
time and `raised` is absent. Its one `events` entry is the canonical packet
event that the match was tied to. If the evaluator cannot link a match to one
event without guessing, that rule set is not presented as evaluated.

## `ordinary`

Optional: `{ "events", "matches" }`, both always there when `ordinary` is, and
`matches` empty when no rule matched. `events` counts the sensor events of
ordinary activity outside the attack steps: the ordinary administration the run
did at its own positions in `order`, and the host's own background work (the
runner, system services and the test driver) outside every step's window.
The observations can be present when the ordinary day could not be scored; in
that case `score.false_alerts` is absent, so an unknown result is not reported as zero.
`matches` lists `{ "rule", "level", "count" }` for the published rules that
matched any of those events, each rule once: `rule` is the rule's title, and
`count` the number of events it matched, not more than `events`. Two published
rules can share a title, so where two listed rules do, each one's `rule` is its
title followed by its id in parentheses, such as `Some Title (<id>)`, and no two
rules are listed under one `rule`. `id`, optional, is the rule's id, as an
alert's `rule.id` gives it; the lab writes it on every match, and an older
recording has none. A match at a level that counts as an alert is a false
alert.

## `score`

| Key | Type | Meaning |
| --- | --- | --- |
| `steps` | number | Steps with role `test`. |
| `took_effect` | number | Of those, how many took effect. |
| `alerted`, `seen`, `unseen` | number | Of those that took effect, how many have each outcome. |
| `alerted_with_lab_rules` | number | Optional. The same count of alerted steps when the accepted rules of this repository count too. Present when the run evaluated such rules. |
| `stopped` | number | Steps of any role with outcome `stopped`. |
| `first_alert_seconds` | number | Optional, attack path only: seconds from the `started` of the first step, which is of role `test`, to the first alert of a published rule on a step of role `test`, and zero when that alert's stamp is a moment earlier. An alert counts from its `raised` time when its detector ran live, and from its `time` when the rules ran after the run. Not written for a test list, whose steps do not build on each other: read each step's `first_alert` there. |
| `goal_seconds` | number | Optional, attack path only: seconds from the same start, the first step's `started`, to the end of the step that reached the goal. Written only with an `attacker.goal`. Not written for a test list. |
| `false_alerts` | number | Optional, and only with `ordinary`. Published rules that matched ordinary activity (see `ordinary`) at a level that counts as an alert. Each such rule is one false alert, whatever the number of events it matched. |

## Defenses

A defense is a named thing: the sensors it has and the rule sets it runs. A
run is recorded once, with every sensor on, and each defense judges that same
run, counting only what its own sensors recorded and only the alerts of its
own rule sets. A recording with the optional key `defenses` holds one run and
what each defense made of every step. A recording without it holds one
defense, which has no name: every sensor and every detector of its network.

`defenses` is an array of 1 to 8 objects, each:

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | Unique among the defenses. Letters, digits, `-` and `_`, at most 64. |
| `name` | string | A few plain words, such as "Wazuh with its stock rules". |
| `sensors` | array of strings | Ids of `network.sensors`: what this defense records with. At least one. |
| `detectors` | array of strings | Ids of `network.detectors`: the rule sets this defense runs, at most 4. May be empty, for a defense that only records. |
| `steps` | object | This defense's verdict on each step, by the step's `id`: `{ "visibility", "outcome", "first_event", "first_alert", "outcome_with_lab_rules", "first_alert_with_lab_rules" }`, each with the meaning and the rules the same key has on a step. `visibility` and `outcome` are always there, and the others as on a step. It has an entry for every step of the recording, and for no other id. |
| `ordinary` | object | Optional, as the top-level `ordinary`: the events of ordinary activity this defense's sensors recorded, and the published rules of its rule sets that matched them. |
| `score` | object | As the top-level `score`, counted from this defense's `steps` and `ordinary`. |

**A defense is a view of the recording.** The view of a defense is the
recording with:

- only the events whose `sensor` is one of the defense's sensors;
- only the alerts whose `detector` is one of the defense's detectors and whose
  `events` were all recorded by the defense's sensors;
- only those sensors and detectors in `network`;
- each step's `visibility`, `outcome`, `first_event`, `first_alert`,
  `outcome_with_lab_rules` and `first_alert_with_lab_rules` as the defense's
  `steps` gives them, a key it leaves out being left out;
- the defense's `ordinary` and `score`.

A view is itself a recording without `defenses`, and everything this document
says of a recording holds for each view. A step's `visibility.events` counts
the events of the defense's sensors tied to the step, and its `kept`, when the
recording holds fewer of them, the number the view holds. Its `first_event` is
the earliest event the view holds of the step, and its `first_alert` the
moment of the first counting alert of a published rule among the view's
alerts on the step. Its `outcome` follows from the step's `happened` and the
view's `visibility`. The score is counted from the view's steps,
`false_alerts` from the view's `ordinary`, and the race from the view's first
alert. Steps run forward among the view's own events and alerts.

**The top level holds the first defense's verdicts.** Each step's
`visibility`, `outcome`, `first_event`, `first_alert`,
`outcome_with_lab_rules` and `first_alert_with_lab_rules`, and the top-level
`ordinary` and `score`, are the same values as in the first entry of
`defenses`: the baseline, which a reader shows first. `network`, `events` and
`alerts` hold the sensors, the detectors, the events and the alerts of every
defense, and `events` and `alerts` are in time order as a whole, as in any
recording. So the top level, taken without `defenses`, is the first defense's
view only when that defense has every sensor and every detector of the
network. A reader that plays the first defense plays its view.

What a step did does not depend on who judges it: its `happened`, `started`,
`ended`, `command` and `output` are the step's own, and no defense repeats
them.

Every event is of a sensor that at least one defense has, and every alert is
in the view of at least one defense: no alert names an event that no defense
with its rule set recorded.

## A recording that is still running

A recording without `source.finished` is still running: its engine has not
finished the run. While it runs, the engine sends the recording again, whole,
each time it grows, with the same `id`, `source.engine` and `source.started`. A
reader replaces what it holds with the newer copy; it never merges two copies.
The last copy the engine sends has `source.finished`, and from then on the
recording does not change. Each copy follows every rule of this format, the
end time aside: the service's import and the app's live view check a copy of a
running recording as they check a finished one, so an attack path's first step
is already its first test, with a `started`.

## In the app

The app lists recordings, returns one whole, and imports one: the routes are in
[API.md](API.md) under "Recordings", and the commands `bluefire recordings list`
and `bluefire recordings import <file>` in [CLI.md](CLI.md).
`bluefire recordings page <id> --out <file>` writes the single replay page of
one finished recording, with the note on where it comes from
([LIVE_VIEW.md](LIVE_VIEW.md)). The Runs screen lists them, imports one from a
file and plays one in the live view; the
[user guide](USER_GUIDE.md#recorded-runs) says how. A recording with defenses
is listed with its top-level score, which is its first defense's. The live
view plays it as that defense judged the run, in the app and on the single
page, and the page for fixing a step and the page of a pair of runs read it
the same way: each takes the first defense's view. A recording shipped
with the app is one that a workflow of this repository recorded in CI; it is
kept unchanged under `bluefire/data/recordings/`. The single pages of the two
the app ships, made in CI with that command, are in `docs/live-view/`:
`attack-path.html` of the attack path, which the front page's loop shows, and
`replay.html` of the run on one Linux machine.

On import the app refuses a recording, and names each problem, unless it
follows this format and its parts agree with each other:

- The top-level keys are those of the table above. Every key that is not marked
  optional is there with its type, in the objects inside too: a tool, a host, a
  link, a sensor, a detector, a step with its technique, published test,
  `happened`, `visibility` and hardening change, an event, an alert with its
  rule, `ordinary`, and a defense with its verdict on each step, its `ordinary`
  and its `score`. Every word is one the tables allow, and every time is a
  UTC time. An optional key is left out when it is not known, never null; only
  `attacker.goal` and the values of an event's `fields` may be null. A value of
  `fields` is text, a number no further than 2^53 from zero (written as a whole
  number or with a decimal point or an exponent alike), true, false or null.
  The replay page reads every one of these keys, so a recording the app
  keeps is one the page can play once it has its end time. The events, the
  alerts with their `raised`, and each step's `started` and `ended` fall inside
  the run's `started` and `finished`. Steps are sorted by `order`, and events
  and alerts by `time`. Steps run forward, as "Steps run forward" above says:
  none ends before it starts, starts go forward in `order` with no overlap, and
  no step's events or alerts fall inside the stretch of another. `repository`
  is `owner/name`.
- Every id that a step, an event, an alert or a link names exists, and ids are
  unique. An event is on the host of its sensor. An alert's events belong to the
  alert's step and are on the alert's host, except an after-run multi-event
  correlation may name evidence from earlier steps on that host. Its last event
  is the terminal one, belongs to the alert's step and has the alert's time;
  every other event is no later, and events with observed users name the same
  user.
- An alert `counts` exactly when its rule's level is `high` or `critical` and it
  is not `launcher_only`; a `launcher_only` alert has no events, and one that
  counts has at least one. An alert of the detector `pinned` has the origin
  `pinned`, and one of the detector `lab` the origin `lab`. `raised` is not
  earlier than `time`, and is absent when the detector ran after the run. An
  alert's moment is not earlier than the earliest event it names. A
  `compared_with` is on a `hardened` or `variant` step only, and names an
  earlier step that is neither.
- A step's `visibility.answer` is `alert` exactly when an alert of a published
  rule that counts is on the step. Its `outcome` is the one the rules under
  "A step" give for its `happened.answer` and `visibility.answer`, and its
  `outcome_with_lab_rules`, when present, the one they give when a counting alert
  of a lab rule counts too. `visibility.events` is there unless the answer is
  `inconclusive` or `not applicable`; `alert` and `telemetry only` need at least
  one event and `no telemetry` none. `visibility.kept` is not more than
  `visibility.events`, and it (or `events` when there is no `kept`) is the number
  of the step's events the recording holds.
- A step's `first_event` is the time of its earliest event in the recording, and
  is there exactly when it has events. `first_alert` is the moment of its
  earliest counting alert of a published rule, and is there exactly when it has
  one: an alert's moment is its `raised` time where its detector ran live, and
  its `time` otherwise, and the earliest is the earliest by moment. A file that
  gives a live alert's `time` instead is refused with both times named.
  `first_alert_with_lab_rules` is the same over every counting alert, on a step
  with `outcome_with_lab_rules` only.
- The counts of `score` are the ones its steps give. `false_alerts` is there
  only with `ordinary`, and is the number of rules of `ordinary.matches` at a
  level that counts; each rule is listed there once, with no more events than
  `ordinary.events`. A test list has no `first_alert_seconds` or
  `goal_seconds`, and its `attacker.goal` is null. An attack path begins with a
  step of role `test` that has a `started`; its `first_alert_seconds` is the
  time its steps and alerts give from that start, to the millisecond, counted
  to the alert's `raised` time where its detector ran live (zero when the
  alert's stamp is earlier than that start), and its `goal_seconds`, written
  only with a goal, the time from that start to the end of one of the steps.
  Which step reached the goal is not checked.
- A recording with `defenses` has from 1 to 8 of them. Each has an id of its
  own, sensors and detectors that the network has, at least one sensor, at most
  4 detectors, and a verdict on every step and on no other id; the network has
  at most 8 detectors. Every event is of a sensor that some defense has, and
  every alert is in the view of some defense. Each step's verdict at the top
  level, the top-level `ordinary` and the top-level `score` are the same values
  as the first defense's. The recording's events and alerts are in time order.
  Then every other check above that reads the events, the alerts, a step's
  verdict, `ordinary` or `score` is made of each defense's view in place of the
  whole recording: a step's `visibility.kept` is the number of its events the
  view holds, steps run forward among the view's events and alerts, and each
  defense's score is the one its own verdicts give. A problem names the defense
  and the key, such as `defenses[1].steps.<step id>.outcome` or
  `defenses[1].score.seen`. What does not depend on a defense, such as an event
  outside the run, is named once.
- The file is at most 8 MiB, with at most 2,000 steps, 20,000 events and 20,000
  alerts, nested at most 8 deep. Event `fields` hold at most 64 plain values.
  Numbers are finite, keys appear once in an object, and no text or key holds a
  NUL. Only a step's `command`, `output` and `plain`, the attacker's
  `description` and `goal`, and `notes` may hold other control characters, such
  as line breaks, tabs or a terminal's escapes; every other text and every key
  holds none, an event's `text` included: no C0 or C1 control character, no
  direction mark, embedding, override or isolate (U+061C, U+200E, U+200F,
  U+202A to U+202E, U+2066 to U+2069), and no line or paragraph separator
  (U+2028, U+2029). Each of these can make a name read otherwise on screen than
  it is written. A writer shows a character the format refuses as
  "Characters a text cannot hold" says.

These checks show that a recording agrees with itself. They do not show that
its steps ran, where or when, which sensor recorded each event, or which step
reached the goal: the app says so next to every imported recording.

The app keeps a recording file as it was sent, so the SHA-256 of the kept file
is the one its engine wrote, and a delta (below) can name it. The Runs screen
and `bluefire recordings import <file>` send the file itself.

One run can be evaluated more than once: the lab evaluates one run's telemetry
with two sets of its rules and writes two recordings with the run's one `id`
(see One run evaluated twice, below). A finished file whose `id` is kept, when
the kept file is finished too and the two `source` objects are the same in every
key, is kept beside it as another evaluation of that run, under the SHA-256 of
its file. So is the same recording in other bytes, such as its original file
sent after the recording was sent as an object and kept as canonical JSON: a
delta names its recordings by the SHA-256 of their files, and can name either.
At most 8 files are kept for one `id`. Any other file under a kept `id` is
refused, and so is every other recording under the `id` of a recording shipped
with BlueFire: what was shipped stands alone, and the shipped recording sent in
other bytes is answered by the shipped file. Every import that is not refused
names, by its `sha256`, a kept file that is returned by it. The list shows the first file of each `id`, and
`GET /api/v1/recordings/<id>` returns it; every kept file, the first included,
is returned by its `id` and SHA-256 (see [API.md](API.md)). Whether two such
files really are one run, in their steps and events, is checked when a delta
of one run evaluated twice names them.

**A pair of runs in the app.** The app also keeps deltas: `bluefire recordings
import-delta <delta.json>` or `POST /api/v1/recordings/deltas` (see
[API.md](API.md)). It takes a delta only when it follows the format below in
every key the app reads and agrees with itself where the format ties its keys
together, when both recordings it names are kept, finished, as the very files it
was made from (by `sha256` and `id`), with the facts it copies from their
`source` (and `lab_rules_commit`, the `commit` of the recording's detector
`lab`), and when every step id it names is a step of its recording; otherwise
it says why, and keeps nothing. A kept recording that is finished is never
replaced, so a delta made from another file under a kept id cannot be imported
unless that file can be kept beside it, as another evaluation of the same run or
as the same recording in other bytes.
A delta is shown only while both its recordings are still those files.
The app never computes or corrects a delta. A delta whose recordings, or which
itself, was imported is labelled as imported, with the note that the app did
not make the comparison; a delta shipped with the app is a file under
`bluefire/data/recordings/deltas/`. Of a limited verdict the app also checks
that the limit, the marks and the counts agree: a `limit` only with `runners` 2,
both sides naming one CI run, a verdict, a declared change that leaves a mark
of its own, and names of a runner's image or kernel that are among the
`differences`, recorded in both with two different values and not part of the
declared change; every other difference part of the declared change; under a
limit, each key of `audit_keys` saying `mark`, with `no_mark` exactly when it
is false, and without a limit neither; a `mark` only under a limit, on a step
counted `better`, `worse` or `changed` whose verdict starts as the format says
and names each audit key of the mark, whose other run says `no telemetry`,
none of whose keys `audit_keys` lists for the other run or with `mark` false,
each it lists for its run listing that step, and, when `audit_keys` lists every
key of the mark for its run, those entries' `events` adding up to at least the
mark's `events` (a key that can carry the mark and whose name the other run's
events carry too is not listed, and then the sum is not checked), and which
carries `records` whose count for its run is the mark's `events`; under a
limit, no step credited without a mark and no price but `price not known`;
`counts.by_mark` and the limit's `credited` equal to the steps with a mark;
and, from the two kept recordings, that both say what their audit rules watch
(`audit_watches`) and that every key said to carry the mark is on a rule of its
run. A limited delta of recordings that name their audit keys alone is
refused: a key's name is no mark. The app checks the delta's structure and the
few phrases the format fixes (`one pair of runs`, a credited step's lead,
`price not known`), not the rest of the lab's sentences, which it draws as
written. Under a limit, a step that is `not attributable` says under it, for
each key of its events that `audit_keys` says gives no mark, the lab's reason.

Of a delta of one run evaluated twice (`one_run` true) the app checks what
`--one-run` promises, as hard as it checks a pair of runs. In the delta: the
`claim` is `one run evaluated with two rule sets` exactly when `one_run` is
true and `one pair of runs` otherwise; the declared change is `detectors:lab`;
there is no `runners`, `limit` or `audit_keys`; both sides name the same `id`
and the same `run_url`, and two different files; with a verdict, no step varied
in the control, none is `without cause` or `not attributable`, and `lab_rules`
is a list. `judged` and `control.fields` are the fields the format gives the
declared change, for every delta. Each row of `lab_rules` is in the evaluations
its `change` says (`new` after only, `gone` before only), and a `moved` rule's
file differs. From the two kept files: their `source` is the same; they hold the
same steps in the same order, each with the same `happened`, `recorded`,
`outcome`, `visibility.events`, `first_event`, `first_alert`, `started` and
`ended`; the same events, where an event one file holds alone must be one an
alert of the lab's rules there rests on; the same alerts of the published rules
and the same `ordinary`; both detectors `lab` have `verdicts`, and every rule
whose file has the same digest in both was judged the same and matched the same
steps; `lab_rules` lists exactly the rules that are new, gone or of another
text or file, each side as that file's `verdicts` give it (`accepted`, `reason`
and `file`); each step's `before` and `after` are its values in each file; and
every step credited to the change was matched, in one evaluation only, by a rule
`lab_rules` lists. A delta that claims one run and holds two is refused with
each reason.

The app ships two real pairs, and they tell the defender's loop as it went.
The first is the watch: the two runs of the pull request that added an audit
watch on the test account's shell history files, made side by side on two
runners of the same image and kernel, and their delta, all three from the
artifact `lab-pair` of CI run
[45365902367](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45365902367),
unchanged. Its verdict is on every step: of 91 paired steps, "Clear Bash history
(echo)" is better, unseen before and seen after by one event, with its price;
the other 90 are the same. The second is the rule drafted from that event,
"Shell History File Truncated In Place": one run evaluated with the lab's rules
of the base commit and of the head's, the two recordings and their delta from
the artifact `lab-rules-twice` of CI run
[45395673682](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45395673682),
unchanged. Of 93 paired steps, "Clear Bash history (echo)" and "Clear Bash
history (cat dev/null)", and a run of each with changed input arguments, are
better, seen before and alerted after with the lab's rules; the other 89 are
the same. Its price is not counted, in the lab's words: the lab leaves a rule
that matched ordinary activity out of the recording. The run after kept the new
rule, which it does only for a rule that alerted on no ordinary activity in that
run, so the app shows this price as "None in this run". The two recordings of that
run, about 1.2 MB each, ship as one entry of the list with a second file.

The Runs screen lists the pairs that declare a change under "Before against
after" as the turns of one loop: those shipped with BlueFire first, then the
imported ones, whatever their dates, each part in the order it happened (by
when the later of its runs started). A comparison that declares no change is
listed under them on its own, with no number, and opens as a comparison
outside the loop. Each turn has a short name (`New <sensor> settings`, the rule's
change such as "A new rule" with its title under it, or the declared change),
the marks of what moved before and after in `outcome_with_lab_rules` (an alert
of the lab's rules alone drawn in violet and said to be theirs), a small
picture of the moved path drawn from the step's `recorded` and mark, a headline
of what the change did built from the steps the delta credits and its
`counts`, the tests it moved, how the runs were made (side by side, one run
evaluated with two rule sets, or the two dates), the price as the delta words
it (the service lists each moved step with its `price`), or "None in this run"
for a new rule of the lab's own that the run after kept, and one line of the
result: how many paired steps read the same, or, for a limited or refused
comparison, the delta's counts in words. It opens one at
`#/runs/compared/<id>`. A recording that is one side of a listed pair is opened
from its pair, by its file, and not listed again on its own, so that the two
runs of one pair do not read as unrelated runs. The Overview leads with the
first run the Runs screen lists on its own (what was shipped with BlueFire
before what was imported, whatever the dates) and the turns of the loop under
it, holds their place while they load, and still offers the newest of what
the Runs screen lists among its recent outcomes.

The page of a pair draws the delta and the two recordings it names, and nothing
is compared there: the two turns of a loop are never compared with each other.
At the top, where the comparison stands among those the service keeps (a
stepper of the turns, by name, an imported turn marked as imported), the headline of what the change did, the tests
it moved, and the basis of the verdict (`claim`, and whether it is one pair of
runs side by side or one run read with two rule sets). Then the move: the marks
before and after with the declared change between them, or, when several steps
moved, a row for each, which puts that step on two stages. Each stage draws
what one recording holds of the step: the host and whether the step took
effect, each sensor with the events it recorded of it, each rule engine with
what it matched, an alert or a match below alert level; what reads the same on
both stages is drawn dim and named once under them. Each stage links to the
step in the live view, paused at its start, and the after stage offers Fix this, which opens
the step's fix page in the after run, when the step still raises no alert. Under the stages: the price (false alerts of published rules on
ordinary activity, `score.false_alerts` and `ordinary` of each recording, with
the delta's price in its words; "None in this run" when the price is not
counted for a new rule of the lab's own that the run after kept, which it does
only for a rule that alerted on no ordinary activity in that run; otherwise "Not
counted" when the price is not counted, with the rule's reason; or "Not known"
under a limit), what else moved (every
paired step before and after as a cell, the moved ones marked, with the counts
of the delta), what comes next (the next comparison of the list, or the tests
of the after recording that still raise no alert, seen or unseen, counted with
the lab's own rules too, beside what its score gives), and one line on why the
comparison is fair, which opens: the claim and how the runs were made, the
declared change highlighted with both values, each run's id, where and when,
commits, CI run (a link only for a recording shipped with the app) and the
SHA-256 of its file, what was recorded as the same and whether the lab's code
was, the control and the steps where it varied, the race only when the delta
has one with numbers, new and gone steps listed and not counted, and each step
that differs in the delta's own words: its result, verdict with price, what
changed underneath, its mark, and why a key gives no mark. A refused delta reads
"No verdict." with every reason and every difference, and its steps are listed
as not judged; under a limit, the page says at the top that the verdict is
limited, in what the two runners differed with both values and what alone is
credited, and lists the steps not attributable apart. Below come what made the
difference (for a sensor's change, the events it recorded of the step, marked
when only the after run holds them, and the audit keys only one run's events
carry; for a change of the lab's rules, the events each alert of such a rule
rests on, and each rule of `lab_rules` with its change, file, how each
evaluation judged it and its text line by line as the recording carries it),
the published tests of the step's technique that ran in the after recording,
each once, the canary's test among them, with its mark and the rules that
alerted on it, and links to play either run. The
step's whole detail from both recordings, each by its file, opens under the
stages, and the address keeps it (`?step=<id>&detail=1`).

## A delta

A delta says what differs between two recordings, a run before a change and a
run after it, and whether one declared change can explain it. "Before against
after" is a claim about a cause, so the delta is the one place where it is
computed, and where it is refused; a view only draws what a delta says. It is
not a recording. `bluefire-lab compare <before.json> <after.json> --out
<folder> [--change <what>] [--two-runners | --one-run]` writes it as `delta.json`, with `delta.md`, the same
in a few lines for a job summary (see `lab/README.md`).

The format is JSON, UTF-8, one object. Its `schema` is `bluefire.delta/1`.
`one_run` and `lab_rules` were added to it later: a delta that lacks them,
such as that of the pair of runs of run 45365902367, is read as `one_run`
false and `lab_rules` null.

| Key | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `bluefire.delta/1` |
| `claim` | string | What every verdict rests on: `one pair of runs`, or `one run evaluated with two rule sets` when `one_run` is true. |
| `before`, `after` | object | Each recording: `{ "sha256", "id" }`, the SHA-256 of its file and its `id`, from its `source` the `run_url`, `environment`, `commit`, `defense_commit` and `started` it has, and `lab_rules_commit`, the `commit` of its detector `lab`, when it has one. |
| `declared_change` | string or null | The one thing declared as changed between the runs, as a name of the setup (below): `sensors:<sensor id>` for a sensor's settings or `detectors:<detector id>` for a rule set. Null when nothing was declared. |
| `runners` | number or null | `2` when the two runs were made side by side in one CI run, each on a fresh runner of its own (`--two-runners`, as the lab's pair of runs gives it), and both recordings name the same `run_url`. Null otherwise: `--two-runners` on recordings that do not name one CI run is a refusal. |
| `one_run` | boolean | True when the two recordings were said to be one run whose telemetry was evaluated twice, with two sets of the lab's rules (`--one-run`). See One run evaluated twice. |
| `lab_rules` | array or null | Only when the declared change is `detectors:lab`: each rule of the lab's own that is new, gone, another text or the same text in another file in the after recording, `{ "rule", "title", "change", "before", "after" }`, with `change` `new`, `gone`, `changed` or `moved` (the same text, another `file`), and each side's `{ "accepted", "reason", "file" }` from its `verdicts`, null on the side without the rule. Null when the change is another, or a recording has no `verdicts`. |
| `comparable` | boolean | True when there is a verdict: `refused_because` is empty. With a `limit`, the verdict is limited. |
| `limit` | object or null | Null when the verdict is like with like. Otherwise `{ "why", "differences", "credits", "credited", "not_attributable" }`: why the verdict is limited (`the two runners differed`), the names of the setup that differed for it (such as `images:target` and `kernels:target`), on which steps the change is credited, in words, how many steps were credited by the change's mark and how many are `not attributable`. See Two runners that differed. |
| `refused_because` | array of strings | Each reason there is no verdict, in plain words. |
| `differences` | array | Each `{ "what", "before", "after" }`: a name of the setup whose values differ, with both values, null where a recording does not record it, and `"declared": true` on the declared change and on a name that is part of it (see Refusals). |
| `same_in_both` | array of strings | The names of the setup whose values are recorded and equal in both. |
| `lab_code` | object | `{ "before", "after", "same" }`: each recording's `source.commit`, null where it has none, and whether both are recorded and equal. See below. |
| `judged` | array of strings | The fields of a step the declared change can move. Empty when nothing was declared. |
| `control` | object | `{ "fields", "same", "of", "varied" }`: the fields of a step the declared change cannot move, on how many paired steps they are the same of how many, and the ids of the steps where they are not. |
| `counts` | object | `paired`, the number of steps paired, then how many of them have each `result`, every result with its number, 0 included, then `by_mark`, how many of the steps counted as `better`, `worse` or `changed` were credited by the change's own mark alone under a `limit` (0 without one), then `new` and `gone`. |
| `unexplained` | array of strings | The ids of the steps that changed although the declared change could not have changed them (`result` `without cause` or `not attributable`). |
| `steps` | array | Each paired step, in the order of the after recording. See below. |
| `new`, `gone` | array | Each `{ "id", "role", "title", "technique" }`: a step only in the after recording, or only in the before recording. Listed, never counted. |
| `race` | object | The time to the first alert of each side, `{ "before", "after" }` with each recording's `first_alert_seconds` and `goal_seconds` where it has them, only when both are attack paths with a detector that ran `live`. Otherwise `{ "why" }`: there is no race to compare, and none is made up. |
| `audit_keys` | object or null | Only when the declared change is `sensors:auditd`: `{ "only_before", "only_after" }`, each the audit keys (`fields.key` of auditd's events) that one recording's events carry and the other's never do, each `{ "events", "steps" }`, its number of events and the ids of their steps, and under a `limit` also `mark`: `true` when the key's events can carry the change's own mark, or `false` with `no_mark`, why not, in words. A key only one run's events carry is not by that the change's own: a rule both runs have may have fired on one runner only. A key that can carry the mark and whose name the other run's events carry too, on other rules, is not listed here. Null otherwise. |

**The setup.** A delta compares, by name: each key of `source.setup`, and each
member of an object there as `<key>:<id>` (such as `images:target` or
`sensors:auditd`); `sensors:<id>` for every sensor of the network, also when
`setup` does not record its settings; `detectors:<id>` with the `digest` of each
detector; and `tools:<name>` with the version of each tool of `source.tools`,
except the tests', which are `atomic_commit`: a recording whose `setup` does not
hold it has it from the version of its tool of role `tests`, and a recording
that has neither does not record it. A value that is not recorded on either
side is not known to be the same, so it is a difference, and its refusal says it
is recorded in neither rather than that it differed.

**The lab's code** is not part of the setup. Its commit differs between a pull
request and `main`, and a change of the lab's own rules is a commit too, so a
different commit refuses nothing. The comparison does not check what such a
change did: when `lab_code.same` is false, a step that changed `without cause`
or `not attributable` names run variation or a change of the lab's code, a
`better`, `worse` or `changed` step says that the lab's code is not known to be
the same, and `delta.md` says which commits differed.

**Pairing.** When both recordings have `source.setup`, steps pair by `id`.
Otherwise they pair by role, test GUID and hardening change, in the order they
ran, and each such pair says `paired_by` `role, test and order`. A step left
without a partner is new or gone.

**Refusals.** There is no verdict, and the delta still lists every step and
what differed, when a recording has no `source.setup`; when the two are not of
the same `kind`; when they are not of the same steps in the same order (a new or
a gone step included); when the declared change is not a sensor's settings or a
detector's rules of these recordings, is the same in both, or is not recorded in
both; when any name of the setup other than the declared change differs (but
see Two runners that differed, below); or when `--two-runners` says the runs
were made side by side in one CI run and the two recordings do not name the
same `run_url`. The published rules' pin, the version of the tool of role
`rules`, is the commit their files come from, so it is part of a declared
`detectors:pinned`; no other tool version is part of a declared change. The
rule engine's version is not part of either rule set, and a sensor's program
version is not its settings: a new version can record otherwise under the same
settings, so it refuses a declared `sensors:<id>`.

**A step** of a delta:

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | The step's id in the after recording. `before_id` is there too when the before recording gave it another one. |
| `role`, `title`, `technique` | string | From the after recording; `technique` is the ATT&CK id. |
| `paired_by` | string | `id`, or `role, test and order`. |
| `before`, `after` | object | `{ "happened", "recorded", "outcome", "outcome_with_lab_rules" }` of each side: `happened` is the step's `happened.answer`; `recorded` is `recorded` when `visibility.answer` is `alert` or `telemetry only`, `no telemetry` when it is that, and `not known` otherwise; and `outcome_with_lab_rules` is the `outcome` when the run evaluated no rules of the lab's own. |
| `changed` | array of strings | The fields whose value differs. |
| `underneath` | array of strings | For a changed step, what changed under it: `recorded now` or `no longer recorded` with the number of events, `matches now:` or `no longer matches:` and a rule as `<level>: <title>`. |
| `records` | object | Only on a changed step, when the declared change is `sensors:<id>`: `{ "sensor", "new", "gone" }`, where `new` is what that sensor recorded of the step in the after recording and not in the before one, and `gone` the other way, each `{ "count", "lines" }` with the first 20 lines as `<kind>: <text>` of the events (`<kind>` alone when the text is empty), in time order. Only the events a recording kept count. For `sensors:auditd`, only events of an audit key that one recording's events carry and the other's never do (`audit_keys`) count, and under a `limit` also those of a key that can carry the change's own mark. Being listed here does not make an event the change's own: the step's `result` and `mark` say whether it is. |
| `result` | string | `same`; `better` or `worse` (every judged field that moved went up, or down, in the order `unseen`, `seen`, `alerted`, `stopped`, and `recorded` from `no telemetry` to `recorded`), or `changed` (a value outside that order, or both ways); `without cause` (only the control moved); `not attributable` (the control moved too; for a change of rules, a rule of the lab's own that is the same file in both runs matched the step differently while its outcome with the lab's rules moved; for a sensor's settings, that sensor's `records` of the step are empty while the recordings hold events of the step; for `sensors:auditd`, an alert that one run has on the step and the other lacks does not rest on the events of `records` alone; for `sensors:sysmon`, any judged field moved; or, under a `limit`, the step does not carry the change's mark); or `no verdict` (the comparison is refused). A step of role `control` must raise no alert, so for it a move to `alerted` is `worse`, a move away from it `better`, and nothing else is ranked. |
| `mark` | object | Only under a `limit`, on a step credited by the change's own mark: `{ "run", "keys", "events" }`, the run whose events carry the mark (`after` or `before`), their audit keys and their number. Under a `limit`, a `not attributable` step without one says in its verdict why it carries no mark. |
| `verdict` | string | The result in plain words. A changed step's ends with the `claim`, except on a refused comparison with `one_run` true, which has not shown that it is one run. Under a `limit`, a credited step's starts with `<result> by the change's own mark, on two runners that differed` and says what it rests on, and a `not attributable` step's names the runners' difference. |
| `procedures`, `price` | object, string | On a `better` step, and in its `verdict` too: `price`, what the gain cost; and on a step of role `test` only, `procedures`, `{ "better", "of" }`, on how many of the steps of role `test` of the same technique the result is `better`. |

**Like with like.** A change of the lab's rules (`detectors:lab`) is judged on
`outcome_with_lab_rules`, and its control is `happened`, `recorded` and
`outcome`, which such a rule cannot move. A change of another rule set is judged
on `outcome` and `outcome_with_lab_rules`, and its control is `happened` and
`recorded`: rules cannot make a sensor record a step. A change of a sensor's
settings is judged on `recorded` and both outcomes, and its control is
`happened`. With nothing declared every field is control, and a step that
differs is run variation: what two runs of the same list differ by with nothing
changed is the noise floor. A run decides anew whether it accepts each of the
lab's rules, so for `detectors:lab` a step that a rule of the lab's own matched
in one run and not in the other, while that rule's file has the same digest in
both `verdicts`, is `not attributable`, and its verdict gives what each run
said of that rule. A recording without `verdicts` does not say which rules
changed, and such a step is `not attributable` too. A change of the published
rules cannot make a rule of the lab's own match at all, so for
`detectors:pinned` a step whose `outcome_with_lab_rules` moved while a rule of
the lab's own matched it in one run only is `not attributable`. A change of a
sensor's settings can make an unchanged rule of the lab's own match new
telemetry, and that is its effect, so for `sensors:<id>` it is credited, but
only through what that sensor recorded: a sensor's settings change a step only
through what that sensor records of it, so for `sensors:<id>` a step whose
judged fields moved while that sensor's events of it are the same in both
recordings is `not attributable`, and its verdict says the sensor recorded the
same. Two runs of the same audit rules already differ in auditd's text, by
temporary file names and a password's salt that are new in every run, so for
`sensors:auditd` a step that moved with no event of an audit key that one
run's events carry and the other's never do (or, under a `limit`, of a key that
can carry the change's own mark) is `not attributable`, and so is one with an
alert that one run has and the other lacks, by rule, that does not rest on
such events alone. Sysmon's events carry nothing like an audit key, so nothing
a recording holds tells what new Sysmon settings recorded from what two runs
of the same settings differ by, such as temporary file names: for
`sensors:sysmon` every step whose judged fields moved is `not attributable`,
and its verdict says why. That a key
is in one run's events only is a description, not the change's own mark (below):
a rule both runs have may have fired on one runner only. Under a sensor change,
`delta.md` also names the steps recorded now and by no sensor before, or says
there are none, the steps of role `test` unseen in both runs, and for auditd
the events of each audit key that only one run's events carry, with, under a
`limit`, whether the key can carry the change's own mark and why not.

**Two runners that differed.** The two runs of `--two-runners` run on two
fresh runners, and GitHub can hand out two images and kernels to two jobs
started side by side. When the runner's image and kernel (`images:<host>`,
`kernels:<host>`, both recorded) are all that differ besides the declared
change, and nothing else refuses, then:

- For `sensors:auditd`, when both recordings' auditd says what its rules
  watch under each audit key (`audit_watches`), the comparison is not
  refused. It is limited, and `limit` says so. The change is credited only
  on a step that carries its own mark: one run holds no event and no alert
  of the step (a rule that matched only the launcher's start left out) and
  says it was not recorded, every event the other run holds of it is
  auditd's, under an audit key whose every rule in that run watches a path
  that no rule of the other run, as written, could have recorded (below,
  with the limit of what the rules' text can tell), the step's
  `visibility.events` equals the events kept, and every alert on the step
  rests on those events alone. Without those events that run too would
  hold nothing of the step, so its move is the change's and not the
  runners'. A key is a label on a rule, and what makes a record is what the
  rule watches, so a key's name is never the mark: not a key that both runs'
  rules watch the same under, also when only one run's events carry it (it
  may have fired on one runner only), not a key renamed, split in two or
  merged with another, and not a key that gained a rule and kept one the
  other run has (its events could come from the old rule).

  What the comparison can establish from the forms of `audit_watches` and
  the paths an event names, and so what a key's rules and its events must be
  for those events to be a mark. Where the text
  cannot establish it, there is no mark, and the verdict says why.

  - Each rule of the key names one path (`path=`; a watch is one). A rule
    without a path, such as a system call rule for every program, records
    what its system calls and fields select, and its text does not tell that
    apart from what another rule records, so it gives no mark. A path must be
    absolute, with no empty, `.` or `..` part and no `/` at its end: paths are
    compared as written, part by part, so a file that a link gives a second
    name (a symbolic or hard link, or a name under `/proc`) is not found out.
    That is the limit of the mark, and every verdict that rests on it says
    "as written".
  - No rule of the other run, under any key or none, names that path, a
    folder above it or a path under it, whatever its permission letters. A
    watch on a folder records what happens to everything under it, and the
    text does not say whether a watched path is a folder, so a path under the
    key's own path counts too. Permission letters are not compared: a watch
    for writes alone (`-p w`) records the write a watch for `-p wa` records.
  - No rule of the other run without a path could record the same kind of
    event. There are two kinds: a program start, and a read, a write or a
    change of attributes, which are one kind. They are one because the kernel
    does not tell them apart for every system call: on `open`, `openat` and
    `openat2` it matches `perm` against the call's access mode, so an open
    for reading and writing matches `perm=r` and `perm=w` alike, and `link`
    and `linkat` are in its class of writes and in its class of changes of
    attributes. A rule records program starts alone when its
    `perm` is `x`, or when its system calls are all `execve` or `execveat`;
    reads, writes and changes of attributes alone when its `perm` has no `x`;
    and both kinds otherwise: any other system call, such as `open`,
    `openat`, `truncate` and their kin, a rule that names none (every system
    call), and a `perm` with letters other than `r`, `w`, `x` and `a`. A rule
    of the other run that never records (action `never`), or one of a list
    that holds no system call's records (`exclude`, `user`, `filesystem`),
    records nothing of it. A form the comparison cannot read back, in either
    run, gives no mark.
  - No event of the key names a path that a rule of the other run watches, a
    folder above it or a path under it. One system call can name two paths,
    as a rename or a link does, and a watch on either records it, so an event
    whose `fields.paths` (the paths of its `PATH` records) names a file the
    other run watches, under any key, gives no mark. Each path must be plain,
    as above: a path written relative to the working folder gives no mark,
    and so does an event that names no path, or whose `paths` ends in `...`,
    since a cut field leaves out the paths after its cut.

  On the first real pair (the `audit-rules.txt` of the artifacts `lab-run-base`
  and `lab-run` of
  [run 45350480637](https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45350480637))
  the before run's rules name no history file, no
  folder above one and no path under one, and their one rule without a path
  is the program starts' `-S execve`, which records program starts alone: so
  by these rules the after run's watches on the history files, for writes and
  changes of attributes, can carry the mark. A CI run whose comparison gives
  that verdict is not yet shown: the recordings of that run were written
  before they said what their rules watch, and the comparison refuses them.

  Such a step has `mark`, it is counted under its `result` and in
  `counts.by_mark`, and its verdict says what it rests on. Every other step
  that differs is `not attributable`, with the runners' difference as the
  reason, also one that only the control moved for, and also one with a
  marked event and other events too: those other events were recorded on
  another runner, and could have moved it as well. When a recording does not
  have `audit_watches` (one written before it was added, which may have
  `audit_keys`, the keys alone), nothing shows what only one run's rules
  watch, so the comparison is refused, and a reason says so and how to
  write the recording again from its run's folder, or to run the pair
  again.
- For any other declared change (another sensor's settings, which leave no
  mark of their own, or a rule set) the comparison is refused, and a reason
  says that the runners differed and to run the pair again, which gives two
  new runners.

Any other difference, such as a tool's version, another sensor's settings,
another rule set or the tests' commit, refuses as before, also when the
runners differed too, and without `--two-runners` a runner's difference
refuses as any other.

**One run evaluated twice.** Rules evaluated after a run read only the
telemetry it recorded, so a change of the lab's rules can be shown on one run:
its folder evaluated once with the base's rules and once with the head's, each
into a folder of its own, gives two recordings of the same run. With
`--one-run`, the declared change must be `detectors:lab`, and the comparison
is refused unless everything else is the same, not only alike: both recordings
have the same `id` and `run_url`; the same steps in the same order, each with
the same `happened`, `recorded` and `outcome`, `visibility.events`,
`first_event`, `first_alert`, `started` and `ended`; the same events, where an
event only one recording holds must be one that an alert of the lab's rules
there rests on (a recording keeps every event a rule matched beyond the first
few hundred of a step); the same alerts of the published rules; the same
`ordinary`; and every rule of the lab's own whose file has the same digest in
both judged the same way (`accepted` and `reason`) and matching the same
steps. The last holds by construction too, since a run's verdict on a rule
reads only that run's tests, variants and ordinary activity, so a difference
there means the evaluations were not of one run. There is no run variation and
no difference of runners, the `claim` is `one run evaluated with two rule sets`,
and `delta.md` says that the list ran once and what was checked.

**The price** of a gain is on the same line as the gain. For the lab's rules,
the lab leaves a rule that matched ordinary activity out of the recording before
it is written, so the delta says the price is not counted, and quotes both
recordings' notes on the rules they accepted; it never writes a number that
looks like zero. For another rule set, the published rules that alerted on ordinary
activity (`score.false_alerts`) before and after; for a sensor, those and the
ordinary events (`ordinary.events`) before and after. A number the recording
does not hold is written `not recorded`. Under a `limit`, each run counted its
ordinary activity on a runner of its own, so what differs between the two
counts is not the change's price: the price is `price not known`, and gives
both counts as each run's own.
