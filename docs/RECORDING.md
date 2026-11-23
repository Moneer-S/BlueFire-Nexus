# Recordings

A recording is one file that holds what really happened in a run: the network
it ran on, every step of the attacker, what the sensors recorded, which rules
matched, and the score. It is made to be replayed: by the app's live view, and
by a single HTML page that plays without the app. Neither reader is in the
repository yet.

A recording is made from the files of a run by an engine that ran the steps for
real: today `bluefire-lab` (published attack tests on one disposable host),
later a range (a network of containers). Nothing in a recording is invented. A
value the engine did not measure is left out, and the reader shows it as not
known.

The format is JSON, UTF-8, one object. Its `schema` is `bluefire.recording/1`.
Times are ISO 8601 in UTC with a `Z`, to the millisecond where the source has
it (`2026-11-17T17:07:23.834Z`).

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
| `tools` | array | Each `{ "name", "version", "role" }`: a pinned tool of the run. `role` is one of `tests`, `executor`, `sensor`, `rules`, `rule engine`. |

## `network`

| Key | Type | Meaning |
| --- | --- | --- |
| `hosts` | array | Each host of the run. |
| `links` | array | Optional. Each `{ "from", "to", "label" }` between host ids: who can reach whom. |
| `sensors` | array | Each `{ "id", "name", "host", "records" }`: a sensor, the host it runs on, and in plain words what it records. |
| `detectors` | array | Each `{ "id", "name", "rules", "when" }`: a rule set with its engine, the number of rules evaluated, and `when` the rules ran: `live` or `after the run`. The detector `pinned` holds the published rules, and `lab` the rules written in this repository. |

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
attack path in plain words, or null for a test list.

## A step

| Key | Type | Meaning |
| --- | --- | --- |
| `id` | string | Unique in the recording. The lab writes the step's `order` as text: treat it as an opaque key. |
| `order` | number | Its position among everything the run did, from 1. Steps are sorted by it. Positions that were not steps, such as ordinary administration, are skipped, so do not use it as an index or a count: use the step's place in `steps`, and `score.steps` for the total. |
| `role` | string | `test` for a step that counts. The lab also writes `canary` (a step the defenses are known to catch), `control` (a step that must raise no alert), `hardened` (a test run again with a hardening change in place) and `variant` (a test run again with changed arguments). |
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
| `first_alert` | time | Optional. The first match of a published rule on the step that counts as an alert. Absent when there is none. |
| `first_alert_with_lab_rules` | time | Optional. The same, when the accepted rules written in this repository count too. Written only when the run evaluated such rules and one of the two kinds alerted on the step. A step whose `outcome` is `seen` or `stopped` can carry it. |
| `compared_with` | string | Optional. For a `hardened` or `variant` step: the id of the step it repeats. |
| `defense` | object | Optional. For a `hardened` step: `{ "title", "why" }` of the hardening change. |

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

Optional: `{ "events", "matches" }`. `events` counts the sensor events of
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
| `first_alert_seconds` | number | Optional, attack path only: seconds from the start of the first step of role `test` to the first alert of a published rule on a step of role `test`. Not written for a test list, whose steps do not build on each other: read each step's `first_alert` there. |
| `goal_seconds` | number | Optional, attack path only: seconds from the start of the first step to the end of the step that reached the goal. Not written for a test list. |
| `false_alerts` | number | Optional. Published rules that matched ordinary activity (see `ordinary`) at a level that counts as an alert. Each such rule is one false alert, whatever the number of events it matched. |
