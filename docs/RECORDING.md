# Recordings

A recording is one file that holds what really happened in a run: the network
it ran on, every step of the attacker, what the sensors recorded, which rules
matched, and the score. It is made to be replayed by the live view (see
[LIVE_VIEW.md](LIVE_VIEW.md)), which today opens as a single HTML page that
holds one recording and plays without the app. The app keeps recordings: it
lists them, returns one whole, imports one, and writes the single page of one
(see "In the app" below).

A recording is made from the files of a run by an engine that ran the steps for
real: today `bluefire-lab` (published attack tests on one disposable host),
later a range (a network of containers). Nothing in a recording is invented. A
value the engine did not measure is left out, and the reader shows it as not
known.

The format is JSON, UTF-8, one object. Its `schema` is `bluefire.recording/1`.
Times are ISO 8601 in UTC with a `Z`, with up to six digits after the second
where the source has them (`2026-11-17T17:07:23.834Z`). The live view plays
them to the millisecond.

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
| `notes` | array of strings | Limits a reader must know, in plain sentences. May be empty. |

## `source`

| Key | Type | Meaning |
| --- | --- | --- |
| `engine` | string | The program that ran the steps, such as `bluefire-lab`. |
| `environment` | string | Plain words: `GitHub-hosted runner` or `containers on a developer machine`. |
| `started`, `finished` | time | The run's start and end. |
| `repository`, `commit` | string | Optional. The repository and commit of the code that ran the steps. The recording can be written later from the run's files, by newer code. |
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
| `sensors` | array | Each `{ "id", "name", "host", "records" }`: a sensor, the host it runs on, and in plain words what it records. |
| `detectors` | array | Each `{ "id", "name", "rules", "when" }`, plus an optional `digest`: a rule set with its engine, the number of rules evaluated, `when` the rules ran: `live` or `after the run`, and the SHA-256 of its rule files. The detector `pinned` holds the published rules, and `lab` the rules written in this repository. |

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
one run and not in the next.

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
attack path in plain words, or null for a test list: it is always there.

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
| `started`, `ended` | time | When the step's attack command started and ended. Left out when the engine could not measure them, as for a test whose attack did not start. |
| `command` | string | Optional. What ran, as text. It keeps its start: when it is cut it ends in `...`. |
| `output` | string | Optional. What the step printed. It keeps its end: when it is cut it starts with `...`. |
| `happened` | object | `{ "answer", "basis" }`. `answer` is `took effect`, `attempted without effect`, `blocked`, `not attempted` (the attack did not start) or `inconclusive`. `basis` says what the answer rests on. |
| `visibility` | object | `{ "answer", "basis", "events" }`. `answer` is `alert`, `telemetry only`, `no telemetry`, `inconclusive` or `not applicable`. `answer` and `basis` count published rules only, like `outcome`; a match of a lab rule shows in `outcome_with_lab_rules` and in the step's alerts. `events` counts the sensor events tied to the step, and is left out when the engine could not tie events to it (`inconclusive` or `not applicable`). When the recording holds fewer of them than that, `kept` says how many. |
| `outcome` | string | The score word for the step, counting published rules only. See below. |
| `outcome_with_lab_rules` | string | Optional. The score word when the accepted rules written in this repository count too. Present on every step when the run evaluated such rules, and absent when it did not. |
| `first_event` | time | Optional. The first sensor event of the step. |
| `first_alert` | time | Optional. The first match of a published rule on the step that counts as an alert, at its moment: its `raised` time when its detector ran live, and its `time` when the rules ran after the run, like the score's `first_alert_seconds`. Absent when there is none. |
| `first_alert_with_lab_rules` | time | Optional. The same, when the accepted rules written in this repository count too. Written only when the run evaluated such rules and one of the two kinds alerted on the step. A step whose `outcome` is `seen` or `stopped` can carry it. |
| `compared_with` | string | Optional. For a `hardened` or `variant` step: the id of the step it repeats. |
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
a few milliseconds earlier than its `started`.

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
is plain words such as `process start`, `file created`, `network connection`,
or the sensor's own name for the record: a call such as auditd's `execve` or
`openat`, or a record type such as `USER_ACCT`. `text` is one line: the command
line for a program start, the file for a file record, a sentence that names the
file and the kernel's answer for a start the kernel refused, the connection for
a network record, auditd's own `op=`, `cmd=`, `acct=` and `res=` words for a
record a program such as sudo writes about itself, and empty when the record
has none, as for a process end. `text` is at most 2,000
characters and each `fields` value at most 300; a cut one keeps its start and
ends in `...`. auditd's `fields.msg` is the record's id in auditd's own form,
`audit(<seconds>.<ms>:<serial>)`.

`step` is the id of the step the engine tied the event to, and `tied_by` says
how: `session` (in the test's login session), `launcher` (done by the shell
that carried the test itself, such as a file it wrote), `account` (a program
the test's account started during the step outside the lab's own sessions, such
as one cron ran),
`systemd` (started by systemd during a root test's window) or `window` (only
inside the step's time window). `systemd` and `window` are ties by time, not by
which process started which; `lab/README.md` gives the rules. Events tied to no
step are not in the recording: the engine's own output holds them. For a step
with very many events the recording keeps the first of them in time order and
every event a rule matched, and the step's `visibility.kept` says how many it
kept.

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
| `events` | array of strings | The ids of the matched events. |
| `launcher_only` | boolean | Optional. True when the rule matched only the one shell command that carried the whole test, not what the test did. Such a match never counts, and its `events` is empty: that command is the step's `command`, not one of its events. |

## `ordinary`

Optional: `{ "events", "matches" }`, both always there when `ordinary` is, and
`matches` empty when no rule matched. `events` counts the sensor events of
ordinary activity outside the attack steps: the ordinary administration the run
did at its own positions in `order`, and the host's own background work (the
runner, system services and the test driver) outside every step's window.
`matches` lists `{ "rule", "level", "count" }` for the published rules that
matched any of those events: `rule` is the rule's title, and `count` the number
of events it matched. A match at a level that counts as an alert is a false
alert.

## `score`

| Key | Type | Meaning |
| --- | --- | --- |
| `steps` | number | Steps with role `test`. |
| `took_effect` | number | Of those, how many took effect. |
| `alerted`, `seen`, `unseen` | number | Of those that took effect, how many have each outcome. |
| `alerted_with_lab_rules` | number | Optional. The same count of alerted steps when the accepted rules of this repository count too. Present when the run evaluated such rules. |
| `stopped` | number | Steps of any role with outcome `stopped`. |
| `first_alert_seconds` | number | Optional, attack path only: seconds from the start of the first step of role `test` to the first alert of a published rule on a step of role `test`. An alert counts from its `raised` time when its detector ran live, and from its `time` when the rules ran after the run. Not written for a test list, whose steps do not build on each other: read each step's `first_alert` there. |
| `goal_seconds` | number | Optional, attack path only: seconds from the start of the first step to the end of the step that reached the goal. Not written for a test list. |
| `false_alerts` | number | Optional. Published rules that matched ordinary activity (see `ordinary`) at a level that counts as an alert. Each such rule is one false alert, whatever the number of events it matched. |

## A recording that is still running

A recording without `source.finished` is still running: its engine has not
finished the run. While it runs, the engine sends the recording again, whole,
each time it grows, with the same `id`, `source.engine` and `source.started`. A
reader replaces what it holds with the newer copy; it never merges two copies.
The last copy the engine sends has `source.finished`, and from then on the
recording does not change.

## In the app

The app lists recordings, returns one whole, and imports one: the routes are in
[API.md](API.md) under "Recordings", and the commands `bluefire recordings list`
and `bluefire recordings import <file>` in [CLI.md](CLI.md).
`bluefire recordings page <id> --out <file>` writes the single replay page of
one finished recording, with the note on where it comes from
([LIVE_VIEW.md](LIVE_VIEW.md)). A recording shipped
with the app is one that this repository's lab workflow recorded in CI; it is
kept unchanged under `bluefire/data/recordings/`.

On import the app refuses a recording, and names each problem, unless it
follows this format and its parts agree with each other:

- The top-level keys are those of the table above. Every key that is not marked
  optional is there with its type, in the objects inside too: a tool, a host, a
  link, a sensor, a detector, a step with its technique, published test,
  `happened`, `visibility` and hardening change, an event, an alert with its
  rule, and `ordinary`. Every word is one the tables allow, and every time is a
  UTC time. An optional key is left out when it is not known, never null; only
  `attacker.goal` and the values of an event's `fields` may be null. A value of
  `fields` is text, a number no further than 2^53 from zero, true, false or
  null. The replay page reads every one of these keys, so a recording the app
  keeps is one the page can play once it has its end time. The events, the
  alerts with their `raised`, and each step's `started` and `ended` fall inside
  the run's `started` and `finished`. Steps are sorted by `order`, and events
  and alerts by `time`.
- Every id that a step, an event, an alert or a link names exists, and ids are
  unique. An event is on the host of its sensor. An alert's events belong to the
  alert's step.
- An alert `counts` exactly when its rule's level is `high` or `critical` and it
  is not `launcher_only`; a `launcher_only` alert has no events, and one that
  counts has at least one. An alert of the detector `pinned` has the origin
  `pinned`, and one of the detector `lab` the origin `lab`. `raised` is not
  earlier than `time`, and is absent when the detector ran after the run.
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
- The counts of `score` are the ones its steps give; `false_alerts`, when
  `ordinary` is there, is the number of `ordinary.matches` at a level that counts.
  A test list has no `first_alert_seconds` or `goal_seconds`. In an attack path,
  `first_alert_seconds` is the time its steps and alerts give, to the
  millisecond, counted to the alert's `raised` time where its detector ran live
  (zero when the alert's stamp is earlier than the first start), and `goal_seconds` the time
  from the first step's start to the end of one of the steps. Which step reached
  the goal is not checked.
- The file is at most 8 MiB, with at most 2,000 steps, 20,000 events and 20,000
  alerts, nested at most 8 deep. Event `fields` hold at most 64 plain values.
  Numbers are finite, keys appear once in an object, and no text or key holds a
  NUL. Only a step's `command`, `output` and `plain`, the attacker's
  `description` and `goal`, and `notes` may hold other control characters, such
  as line breaks, tabs or a terminal's escapes; every other text holds none,
  an event's `text` included.

These checks show that a recording agrees with itself. They do not show that
its steps ran, where or when, which sensor recorded each event, or which step
reached the goal: the app says so next to every imported recording.

## A delta

A delta says what differs between two recordings, a run before a change and a
run after it, and whether one declared change can explain it. "Before against
after" is a claim about a cause, so the delta is the one place where it is
computed, and where it is refused; a view only draws what a delta says. It is
not a recording. `bluefire-lab compare <before.json> <after.json> --out
<folder> [--change <what>]` writes it as `delta.json`, with `delta.md`, the same
in a few lines for a job summary (see `lab/README.md`).

The format is JSON, UTF-8, one object. Its `schema` is `bluefire.delta/1`.

| Key | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `bluefire.delta/1` |
| `claim` | string | `one pair of runs`: what every verdict rests on. |
| `before`, `after` | object | Each recording: `{ "sha256", "id" }`, the SHA-256 of its file and its `id`, and from its `source` the `run_url`, `environment`, `commit` and `started` it has. |
| `declared_change` | string or null | The one thing declared as changed between the runs, as a name of the setup (below): `sensors:<sensor id>` for a sensor's settings or `detectors:<detector id>` for a rule set. Null when nothing was declared. |
| `comparable` | boolean | True when there is a verdict: `refused_because` is empty. |
| `refused_because` | array of strings | Each reason there is no verdict, in plain words. |
| `differences` | array | Each `{ "what", "before", "after" }`: a name of the setup whose values differ, with both values, null where a recording does not record it, and `"declared": true` on the declared change and on a name that is part of it (see Refusals). |
| `same_in_both` | array of strings | The names of the setup whose values are recorded and equal in both. |
| `lab_code` | object | `{ "before", "after", "same" }`: each recording's `source.commit`, null where it has none, and whether both are recorded and equal. See below. |
| `judged` | array of strings | The fields of a step the declared change can move. Empty when nothing was declared. |
| `control` | object | `{ "fields", "same", "of", "varied" }`: the fields of a step the declared change cannot move, on how many paired steps they are the same of how many, and the ids of the steps where they are not. |
| `counts` | object | `paired`, the number of steps paired, then how many of them have each `result`, every result with its number, 0 included, then `new` and `gone`. |
| `unexplained` | array of strings | The ids of the steps that changed although the declared change could not have changed them (`result` `without cause` or `not attributable`). |
| `steps` | array | Each paired step, in the order of the after recording. See below. |
| `new`, `gone` | array | Each `{ "id", "role", "title", "technique" }`: a step only in the after recording, or only in the before recording. Listed, never counted. |
| `race` | object | The time to the first alert of each side, `{ "before", "after" }` with each recording's `first_alert_seconds` and `goal_seconds` where it has them, only when both are attack paths with a detector that ran `live`. Otherwise `{ "why" }`: there is no race to compare, and none is made up. |

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
both; or when any name of the setup other than the declared change differs.
The published rules' pin, the version of the tool of role `rules`, is the commit
their files come from, so it is part of a declared `detectors:pinned`; no other
tool version is part of a declared change. The rule engine's version is not
part of either rule set, and a sensor's program version is not its settings: a
new version can record otherwise under the same settings, so it refuses a
declared `sensors:<id>`.

**A step** of a delta:

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | The step's id in the after recording. `before_id` is there too when the before recording gave it another one. |
| `role`, `title`, `technique` | string | From the after recording; `technique` is the ATT&CK id. |
| `paired_by` | string | `id`, or `role, test and order`. |
| `before`, `after` | object | `{ "happened", "recorded", "outcome", "outcome_with_lab_rules" }` of each side: `happened` is the step's `happened.answer`; `recorded` is `recorded` when `visibility.answer` is `alert` or `telemetry only`, `no telemetry` when it is that, and `not known` otherwise; and `outcome_with_lab_rules` is the `outcome` when the run evaluated no rules of the lab's own. |
| `changed` | array of strings | The fields whose value differs. |
| `underneath` | array of strings | For a changed step, what changed under it: `recorded now` or `no longer recorded` with the number of events, `matches now:` or `no longer matches:` and a rule as `<level>: <title>`. |
| `result` | string | `same`; `better` or `worse` (every judged field that moved went up, or down, in the order `unseen`, `seen`, `alerted`, `stopped`, and `recorded` from `no telemetry` to `recorded`), or `changed` (a value outside that order, or both ways); `without cause` (only the control moved); `not attributable` (the control moved too, or, for a change of rules, a rule of the lab's own that is the same file in both runs matched the step differently while its outcome with the lab's rules moved); or `no verdict` (the comparison is refused). A step of role `control` must raise no alert, so for it a move to `alerted` is `worse`, a move away from it `better`, and nothing else is ranked. |
| `verdict` | string | The result in plain words. A changed step's ends with `one pair of runs`. |
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
telemetry, and that is its effect, so for `sensors:<id>` it is credited.

**The price** of a gain is on the same line as the gain. For the lab's rules,
the lab leaves a rule that matched ordinary activity out of the recording before
it is written, so the delta says the price is not counted, and quotes both
recordings' notes on the rules they accepted; it never writes a number that
looks like zero. For another rule set, the published rules that alerted on ordinary
activity (`score.false_alerts`) before and after; for a sensor, those and the
ordinary events (`ordinary.events`) before and after. A number the recording
does not hold is written `not recorded`.
