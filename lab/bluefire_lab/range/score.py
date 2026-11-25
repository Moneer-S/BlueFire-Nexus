"""Where each event and alert of a run came from, what the defense made of each step, and of the ordinary day.

Every archived event and every alert gets one origin, by the first rule that holds:

1. `engine`: snoopy tagged its program start `engine:*`, or the line holds the
   run's ID, which every nonce and mark of the engine carries, and so does the
   name of every mark file the engine makes. What the plant checks and the
   seal's probes leave behind (a login's session lines, a PHP session file)
   carries no ID.
2. `cleanup`: snoopy tagged its program start `cleanup:<id>`, or it is a file
   integrity event on its step's host, inside the window of a step's published
   cleanup, for a file that the cleanup's command names.
3. `ordinary`: it is a job's of the ordinary activity, sorted to the job as
   `activity.attribute` sorts it (the job's tag, its host's address, the path
   of an http job's request, the account it logs in as, the files it writes,
   inside its window); or snoopy tagged it `job:<name>`. A program start with
   another job's tag is never an ssh job's by its account or address, and an
   nginx line for a path no job fetches is no job's. `labels.job` names the
   job. Cron's session line of a cron job's account inside the job's window is
   ordinary with no `labels.job`, since it does not tell one cron entry of the
   account from another.
4. `step`: what is left is tied to a step of the path on evidence the run
   holds, by the first of these that holds (`labels.tied_by`):
   - `session`: snoopy tagged its program start `step:<id>`;
   - `account`: it names an account the path uses on its host (webadmin on
     web, deploy on build: the activity's loader refuses a job that uses one),
     inside a step's window;
   - `address`: its own source address is an address of the host the step ran
     on, inside the step's window, as sshd's lines on web from attacker's
     address in s01's; or, on a host the step reached (`to`), its text names
     an address of the step's host or that host's container name, as sshd's
     and MariaDB's lines often do when no decoder takes the address out;
   - `content`: on a host the step ran on or reached, inside its window, a file
     integrity event for a path the step was given as an argument, or under
     it, or a log line that names such a path.
   A step's window runs from the Docker daemon's start of its test to `GRACE`
   seconds after the daemon's end, and a second longer, from the start of its
   second, for a line whose own time is to the second. Where two windows hold
   a moment, the later step that had started by then has it.
5. `unattributed`: everything else. These are listed and counted, and never
   called ordinary. One that only falls inside a step's window, on a host the
   step ran on or reached, carries that step and `tied_by` `window`: it is
   coincident in time and never counts toward what the defense saw of the step.

An alert takes the origin and tie of its event in the archive (the same agent,
location, line and manager time), so that a correlation rule such as 40112 is
tied by the line it was raised on, not by the lines before it. An alert with no
such event is given one by the same rules, read on the alert itself.

What the defense made of each step (`path_score`), in the words of
docs/RECORDING.md: `alert` when an alert of the stock rules at the alert level
or higher is tied to the step, `telemetry only` when at least one event is,
`no telemetry` otherwise, and `not applicable` when the attack did not start;
ties by `window` never count. A step cannot be stopped in a range that
configures no active response. The race: the time from the start of the first
step to the first such alert, at the moment the manager raised it, against the
time from the same start to the end of the step that reached the goal, when the
goal check passed. Both are on one clock: the Docker daemon's for the steps,
the manager container's for the alerts, and the kernel's both; `clock` checks
it on each run, against the program starts snoopy logged inside each step.

The ordinary day's score: false alerts are the distinct stock rules at the
range's alert level or higher among the alerts whose origin is `ordinary`;
the rules from level 7 up to the alert level on ordinary work are a second
number, for review, never added to the first. Alerts at the alert level on the
engine's own work and on unattributed events are listed apart: the bench's own
noise is not the shop's.
"""

from __future__ import annotations

import math
import posixpath
import re
import shlex
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..recording import outcome as score_word
from . import activity, ecs, wazuh

ENGINE = "engine"
CLEANUP = "cleanup"
ORDINARY = "ordinary"
STEP = "step"
UNATTRIBUTED = "unattributed"
ORIGINS = (ENGINE, CLEANUP, ORDINARY, STEP, UNATTRIBUTED)
# How a line is tied to a step, in the order the rules are tried; a tie by window never counts.
TIES = ("session", "account", "address", "content", "window")
COUNTED = TIES[:-1]
# A step's window runs this many seconds past the end of its test, as the executor's grace does.
GRACE = 5
STEPS_FILE = "steps.ecs.ndjson"
# A path a step is given as an argument, or a cleanup's command names.
PLAIN_PATH = re.compile(r"/[A-Za-z0-9._/-]*[A-Za-z0-9._-]\Z")
WORD = re.compile(r"[^\s;|&<>()'\"`]+")
# Wazuh's levels in bands: informational, low, medium, high and critical.
BANDS = ((0, 3, "0 to 3"), (4, 6, "4 to 6"), (7, 11, "7 to 11"), (12, 14, "12 to 14"), (15, 15, "15"))
REVIEW_FROM = 7
EVENTS_FILE = "events.ecs.ndjson"
ALERTS_FILE = "alerts.ecs.ndjson"


def _tag(event: dict) -> str:
    if event.get("location") != activity.SNOOPY_LOG:
        return ""
    return str((event.get("data") or {}).get("tag") or "")


def _engine(event: dict, run_id: str) -> bool:
    path = str((event.get("syscheck") or {}).get("path") or "")
    return _tag(event).startswith("engine:") or run_id in (event.get("full_log") or "") or run_id in path


@dataclass(frozen=True)
class Stretch:
    """A step's test, or its published cleanup, as the ties read it: when it ran, where, and the paths it names.

    `started` and `ended` are the Docker daemon's times of its exec, in seconds.
    """

    step: str
    host: str
    to: tuple[str, ...]
    started: float
    ended: float
    paths: tuple[str, ...] = ()

    def holds(self, when: float, whole: bool) -> bool:
        """True for a moment inside the window; `whole` for a time to the second."""

        low = math.floor(self.started) if whole else self.started
        return low <= when <= self.ended + GRACE + (1 if whole else 0)

    def on(self, host: str | None) -> bool:
        return host == self.host or host in self.to


def argument_paths(args: object) -> tuple[str, ...]:
    """The input arguments of a step that are absolute paths."""

    values = args.values() if isinstance(args, dict) else []
    return tuple(dict.fromkeys(v for v in values if isinstance(v, str) and PLAIN_PATH.match(v)))


def cleanup_paths(text: str, workdir: str) -> tuple[str, ...]:
    """The paths a cleanup's command names, from its `cleanup.txt`, those written relative to its folder too.

    The first line of the file is `command: ` and the docker exec command line,
    whose last word is the published cleanup's command.
    """

    first = text.splitlines()[0] if text else ""
    if not first.startswith("command: "):
        return ()
    try:
        command = shlex.split(first.removeprefix("command: "))[-1]
    except (ValueError, IndexError):
        return ()
    found = []
    for word in WORD.findall(command):
        if word.startswith("-"):
            continue
        path = posixpath.normpath(word if word.startswith("/") else posixpath.join(workdir, word))
        if PLAIN_PATH.match(path):
            found.append(path)
    return tuple(dict.fromkeys(found))


def stretches(path: dict | None, out: Path) -> tuple[list[Stretch], list[Stretch]]:
    """The tests of the path that started, and the cleanups that ran, from the manifest's `path`."""

    steps, cleanups = [], []
    for record in (path or {}).get("steps") or []:
        if record.get("started_ns") is not None and record.get("ended_ns") is not None:
            steps.append(
                Stretch(
                    record["id"],
                    record["host"],
                    tuple(record.get("to") or ()),
                    record["started_ns"] / 1e9,
                    record["ended_ns"] / 1e9,
                    argument_paths(record.get("args")),
                )
            )
        run = record.get("cleanup_run") or {}
        if run.get("started_ns") is not None and run.get("ended_ns") is not None:
            notes = out / "raw" / "steps" / record["id"] / "cleanup.txt"
            text = notes.read_text(encoding="utf-8", errors="replace") if notes.is_file() else ""
            cleanups.append(
                Stretch(
                    record["id"],
                    record["host"],
                    (),
                    run["started_ns"] / 1e9,
                    run["ended_ns"] / 1e9,
                    cleanup_paths(text, record.get("workdir") or "/"),
                )
            )
    return steps, cleanups


def _cleanup(event: dict, cleanups: list[Stretch]) -> bool:
    if _tag(event).startswith("cleanup:"):
        return True
    if event.get("location") != "syscheck" or not cleanups:
        return False
    moment = activity.event_time(event)
    path = (event.get("syscheck") or {}).get("path")
    host = (event.get("agent") or {}).get("name")
    return moment is not None and any(
        c.host == host and path in c.paths and c.holds(*moment) for c in cleanups
    )


def _accounts(event: dict, uses: set[tuple[str, str]]) -> bool:
    """True when the line names an account the path uses on the line's host."""

    host = (event.get("agent") or {}).get("name")
    mine = {account for where, account in uses if where == host}
    if not mine:
        return False
    data = event.get("data") or {}
    syscheck = event.get("syscheck") or {}
    named = {
        data.get("srcuser"),
        data.get("dstuser"),
        syscheck.get("uname_after"),
        syscheck.get("uname_before"),
    }
    if event.get("location") == activity.SNOOPY_LOG:
        named.add(data.get("login"))
    if mine & named:
        return True
    log = event.get("full_log") or ""
    return event.get("location") == activity.AUTH_LOG and any(
        activity.names(account).search(log) for account in mine
    )


def _names_a_path(event: dict, paths: tuple[str, ...]) -> bool:
    if not paths:
        return False
    if event.get("location") == "syscheck":
        path = str((event.get("syscheck") or {}).get("path") or "")
        return any(path == p or path.startswith(p.rstrip("/") + "/") for p in paths)
    log = event.get("full_log") or ""
    return any(re.search(rf"(?<![A-Za-z0-9._/-]){re.escape(p)}(?![A-Za-z0-9._-])", log) for p in paths)


def _names_a_source(event: dict, sources: list[str]) -> bool:
    """True when the line's text names one of a host's addresses or its container's name, as a whole word."""

    log = event.get("full_log") or ""
    return any(
        re.search(rf"(?<![A-Za-z0-9_.-]){re.escape(source)}(?![A-Za-z0-9_-]|\.[0-9])", log)
        for source in sources
        if source
    )


def tie(
    event: dict,
    steps: list[Stretch],
    uses: set[tuple[str, str]],
    addresses: dict[str, list[str]],
    names: dict[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """The step an event of no other origin belongs to, and how it is tied, by the first rule that holds.

    `address` holds for a line whose source address, as Wazuh decoded it, is
    the step's host's, and for a line on a host the step reached whose text
    names that host's address or container name (`names`, by host): many sshd
    and MariaDB lines carry the address only in their text.
    """

    tag = _tag(event)
    if tag.startswith("step:"):
        return tag.removeprefix("step:"), "session"
    moment = activity.event_time(event)
    if moment is None:
        return None, None
    when, whole = moment
    inside = [stretch for stretch in steps if stretch.holds(when, whole)]
    if not inside:
        return None, None
    host = (event.get("agent") or {}).get("name")
    source = str((event.get("data") or {}).get("srcip") or "")
    named = _accounts(event, uses)
    rules = (
        ("account", lambda s: named and s.on(host)),
        (
            "address",
            lambda s: (
                (bool(source) and source in addresses.get(s.host, []))
                or (
                    host in s.to
                    and _names_a_source(event, [*addresses.get(s.host, []), (names or {}).get(s.host, "")])
                )
            ),
        ),
        ("content", lambda s: s.on(host) and _names_a_path(event, s.paths)),
        ("window", lambda s: s.on(host)),
    )
    for name, holds in rules:
        found = [stretch for stretch in inside if holds(stretch)]
        if found:
            started = [stretch for stretch in found if stretch.started <= when]
            return (started[-1] if started else found[0]).step, name
    return None, None


def origins(
    events: list[dict],
    run_id: str,
    jobs: activity.Activity | None = None,
    addresses: dict[str, list[str]] | None = None,
    go: dict[str, float] | None = None,
    stop: dict[str, float] | None = None,
    cleanups: list[Stretch] | None = None,
) -> list[tuple[str, str | None]]:
    """The origin of each event, and the job's name for an ordinary one, in the order given.

    An event of none of these is `unattributed` here: `ties` gives it to a step if it can.
    """

    sorted_ = activity.attribute(jobs, events, addresses or {}, go or {}, stop or {}) if jobs and go else {}
    names = {job.name for job in jobs.jobs} if jobs else set()
    found: list[tuple[str, str | None]] = []
    for index, event in enumerate(events):
        tag = _tag(event)
        if _engine(event, run_id):
            found.append((ENGINE, None))
        elif _cleanup(event, cleanups or []):
            found.append((CLEANUP, None))
        elif index in sorted_:
            name, how = sorted_[index]
            # Cron's session line of a cron job's account does not tell one entry of the account from another.
            found.append((ORDINARY, None if how == activity.CRON_SESSION_SOURCE else name))
        elif tag.startswith("job:") and tag[4:] in names:
            found.append((ORDINARY, tag[4:]))
        else:
            found.append((UNATTRIBUTED, None))
    return found


def attributed(
    lines: list[dict],
    run_id: str,
    jobs: activity.Activity | None,
    addresses: dict[str, list[str]] | None,
    go: dict[str, float],
    stop: dict[str, float],
    steps: list[Stretch],
    cleanups: list[Stretch],
    uses: set[tuple[str, str]] | None,
    names: dict[str, str] | None = None,
) -> list[tuple[str, str | None, str | None, str | None]]:
    """Each line's origin, job, step and tie: `origins`, then `tie` for what is left."""

    found = []
    for line, (origin, job) in zip(
        lines, origins(lines, run_id, jobs, addresses, go, stop, cleanups), strict=True
    ):
        step = tied_by = None
        if origin == UNATTRIBUTED and steps:
            step, tied_by = tie(line, steps, uses or set(), addresses or {}, names)
            if tied_by in COUNTED:
                origin = STEP
        found.append((origin, job, step, tied_by))
    return found


def _key(line: dict) -> tuple:
    return (
        (line.get("agent") or {}).get("name"),
        line.get("location"),
        line.get("full_log"),
        line.get("timestamp"),
    )


def matched_events(alerts: list[dict], events: list[dict]) -> list[int | None]:
    """For each alert, the place in `events` of its archived event, or None when the archive has none."""

    index: dict[tuple, int] = {}
    for number, event in enumerate(events):
        index.setdefault(_key(event), number)
    return [index.get(_key(alert)) for alert in alerts]


def alert_origins(alerts: list[dict], events: list[dict], found: list, fallback: list) -> tuple[list, int]:
    """Each alert's origin: its archived event's, else its own (`fallback`); and how many had an event."""

    places = matched_events(alerts, events)
    result = [own if place is None else found[place] for place, own in zip(places, fallback, strict=True)]
    return result, sum(place is not None for place in places)


def band(level: int) -> str:
    for low, high, name in BANDS:
        if low <= level <= high:
            return name
    return "other"


def _rules(alerts: list[dict], picked: list[tuple[str, str | None]], low: int, high: float) -> list[dict]:
    """The distinct rules among the alerts with a level in [low, high], each with its count and jobs or origins."""

    rules: dict[str, dict] = {}
    for alert, (origin, job) in zip(alerts, picked, strict=True):
        rule = alert.get("rule") or {}
        level = rule.get("level")
        if not isinstance(level, int) or not low <= level <= high:
            continue
        entry = rules.setdefault(
            str(rule.get("id")),
            {
                "rule": str(rule.get("id")),
                "description": rule.get("description"),
                "level": level,
                "alerts": 0,
            },
        )
        entry["alerts"] += 1
        where = entry.setdefault("on", {})
        name = (job or "no job named") if origin == ORDINARY else origin
        host = (alert.get("agent") or {}).get("name")
        label = f"{name} ({host})"
        where[label] = where.get(label, 0) + 1
    return sorted(rules.values(), key=lambda entry: (-entry["level"], entry["rule"]))


def not_exercised(jobs: activity.Activity | None) -> list[str]:
    """What the jobs do, which is all the score prices, and examples of what they leave out."""

    if not jobs:
        return ["the range has no ordinary activity, so no false alert can be counted"]
    done = []
    for job in jobs.jobs:
        if job.do == "http":
            done.append(
                f"{job.name}: GET requests for {', '.join(job.paths)} on {job.target}, from {job.host}"
            )
        elif job.do == "ssh":
            done.append(
                f"{job.name}: a key login of {job.target_account}@{job.target} from {job.host}, "
                f"which runs: {job.run}"
            )
        else:
            done.append(f"{job.name}: cron on {job.host}, as {job.account}, runs: {job.run}")
    return done + [
        "nothing else is exercised, for example a password login or a failed login over SSH, a request "
        "other than a GET, or any work none of the commands above does: an alert a rule raises only on "
        "such work is not priced by this score",
        "Wazuh's stateful rules (a first time, a frequency, a rule that follows another) have already "
        "seen the plant checks' logins and sudo before the go, so a rule that fires only on a first "
        "occurrence may not fire on the jobs",
    ]


def ordinary_day(
    alerts: list[dict],
    picked: list[tuple[str, str | None]],
    event_counts: dict[str, int],
    alert_level: int,
    jobs: activity.Activity | None,
    record: dict | None,
) -> dict:
    """The score of the ordinary day, with its denominators."""

    record = record or {}
    by_band = {origin: Counter() for origin in ORIGINS}
    for alert, (origin, _) in zip(alerts, picked, strict=True):
        level = (alert.get("rule") or {}).get("level")
        by_band[origin][band(level) if isinstance(level, int) else "no level"] += 1
    ordinary = [(a, p) for a, p in zip(alerts, picked, strict=True) if p[0] == ORDINARY]
    others = [(a, p) for a, p in zip(alerts, picked, strict=True) if p[0] not in (ORDINARY, STEP)]
    false_alerts = _rules([a for a, _ in ordinary], [p for _, p in ordinary], alert_level, float("inf"))
    review = _rules([a for a, _ in ordinary], [p for _, p in ordinary], REVIEW_FROM, alert_level - 1)
    elsewhere = _rules([a for a, _ in others], [p for _, p in others], alert_level, float("inf"))
    counted = record.get("jobs") or {}
    runs = {
        job.name: {
            "runs": (counted.get(job.name) or {}).get("runs"),
            "archived runs": (counted.get(job.name) or {}).get("archived runs"),
        }
        for job in (jobs.jobs if jobs else [])
    }
    missing = [
        f"{name} (runs {n['runs']}, archived runs {n['archived runs']})"
        for name, n in runs.items()
        if not (n["runs"] or 0) >= 1 or not (n["archived runs"] or 0) >= 1
    ]
    if not jobs:
        reason = not_exercised(jobs)[0]
    elif record.get("minutes") is None:
        reason = "the minutes of activity were not counted, so no number of false alerts is a result"
    elif missing:
        reason = (
            "a job had no run that reached the defense, so no number of false alerts is a result: "
            + ", ".join(missing)
        )
    else:
        reason = None
    return {
        "alert_level": alert_level,
        "for_review_from": REVIEW_FROM,
        "scored": reason is None,
        "not scored": reason,
        "denominators": {
            "minutes of activity": record.get("minutes"),
            "activity started": record.get("started"),
            "runs of each job": runs,
            "events of each origin": event_counts,
        },
        "alerts by origin and level": {origin: dict(sorted(c.items())) for origin, c in by_band.items()},
        "false alerts": len(false_alerts),
        "false alert rules": false_alerts,
        "for review": len(review),
        "for review rules": review,
        "alerts at the alert level on the engine's work and unattributed events": elsewhere,
        "what the jobs exercise": not_exercised(jobs),
    }


def _when(line: dict) -> datetime:
    return ecs.chosen_time(line)[0]


def raised_at(alert: dict) -> datetime:
    """When an alert existed: the manager's time of it, or the time on its line when that is later.

    The manager's time of a line can be seconds earlier than the time rsyslog
    wrote on the line in its container (`clock` measures by how much), and an
    alert is never raised before the line it was raised on was written.
    """

    return max(ecs.manager_time(alert), ecs.chosen_time(alert)[0])


def seconds_between(start: str, end: str) -> float:
    """From one ISO time of the run to another, in seconds, to the millisecond."""

    first, second = (datetime.fromisoformat(text.replace("Z", "+00:00")) for text in (start, end))
    return round((second - first).total_seconds(), 3)


def visibility(started: bool, events: int, alerted: bool) -> str:
    """What the defense made of a step, by the counted ties alone."""

    if not started:
        return "not applicable"
    if alerted:
        return "alert"
    return "telemetry only" if events else "no telemetry"


def race(steps: list[dict], goal: dict | None, agree: bool = True) -> dict:
    """The time to the first alert on a step, against the time to the goal, both from the first step's start.

    A step's times count only on the Docker daemon's clock (`time_source`
    `daemon`). `result` is false, and `says` begins "not a result", when the
    clock check (`agree`) did not pass.
    """

    start = steps[0].get("started") if steps else None
    if steps and steps[0].get("time_source") not in (None, "daemon"):
        return {
            "start": None,
            "result": False,
            "says": f"no race: {steps[0]['id']} has no times on the Docker daemon's clock",
        }
    if start is None:
        return {"start": None, "result": False, "says": "no race: the first step did not start"}
    alerted = [(s["first_alert"]["raised"], s) for s in steps if s.get("first_alert")]
    first = min(alerted, key=lambda pair: pair[0]) if alerted else None
    found: dict = {"start": start, "started by": steps[0]["id"], "result": agree}
    if first:
        found["first_alert_seconds"] = max(0.0, seconds_between(start, first[0]))
        found["first_alert"] = {"step": first[1]["id"], **first[1]["first_alert"]}
    after = next((s for s in steps if goal and s["id"] == goal.get("after")), None)
    end = after.get("ended") if after else None
    daemon = bool(after) and after.get("time_source") == "daemon"
    if goal and goal.get("passed") and end and daemon:
        found["goal_seconds"] = seconds_between(start, end)
        found["goal"] = goal.get("plain")
    alert, reached = found.get("first_alert_seconds"), found.get("goal_seconds")
    unreached = (
        f"the goal's step {after['id']} has no times on the Docker daemon's clock"
        if goal and goal.get("passed") and after and after.get("time_source") not in (None, "daemon")
        else "the goal was not reached"
    )
    if alert is None:
        found["says"] = "no alert" + ("" if reached is not None else f"; {unreached}")
    elif reached is None:
        found["says"] = f"first alert after {alert} s; {unreached}"
    elif alert < reached:
        found["says"] = f"alert before goal by {round(reached - alert, 3)} s"
    elif alert > reached:
        found["says"] = f"alert after goal by {round(alert - reached, 3)} s"
    else:
        found["says"] = "alert at the goal"
    if not agree:
        found["says"] = f"not a result, the clocks are not shown to agree: {found['says']}"
    return found


def clock(steps: list[Stretch], events: list[dict], found: list[tuple], records: list[dict]) -> dict:
    """Whether the steps' clock and the containers' agree: each program start snoopy logged in a step's session,
    at rsyslog's time in its container, against the Docker daemon's start and end of the step's test.

    A step that started with the engine's clock for its times (the daemon's
    exec events were not matched, or its end came before its start) makes the
    check fail.
    """

    engine_timed = [
        record["id"]
        for record in records
        if record.get("started") is not None and ecs.step_clock(record) != "daemon"
    ]
    windows = {stretch.step: stretch for stretch in steps}
    before, after, outside, counted = 0.0, 0.0, 0, 0
    lags = []
    for event, (_, _, step, tied_by) in zip(events, found, strict=True):
        moment, source = ecs.chosen_time(event)
        if source != "rsyslog":
            continue
        lags.append((ecs.manager_time(event) - moment).total_seconds())
        if tied_by != "session" or step not in windows:
            continue
        counted += 1
        when, stretch = moment.timestamp(), windows[step]
        early, late = stretch.started - when, when - stretch.ended
        before, after = max(before, early), max(after, late)
        outside += early > 0 or late > 0
    return {
        "steps": "the Docker daemon's times of each test's exec_start and exec_die",
        "alerts": "the manager's time of each alert, or the time on the line it was raised on when that is "
        "later",
        "events": "rsyslog's time in the agent host's container, else the time the program wrote, else the "
        "manager's",
        "engine": "the engine's own clock is not used for any of these",
        "program starts checked": counted,
        "outside their step": outside,
        "most seconds before a step's start": round(before, 6),
        "most seconds after a step's end": round(after, 6),
        "steps on the engine's clock": engine_timed,
        "agree": counted > 0 and outside == 0 and not engine_timed,
        "manager's time against the line's": {
            "lines": len(lags),
            "earlier than the line": sum(1 for lag in lags if lag < 0),
            "least seconds": round(min(lags), 3) if lags else None,
            "most seconds": round(max(lags), 3) if lags else None,
            "note": "the manager's time of an archived line minus rsyslog's time on it in its container; a "
            "line cannot reach the manager before it is written, so a negative value is the manager's time "
            "running behind, and an alert's time is never put before its line's",
        },
    }


def path_score(
    path: dict,
    steps: list[Stretch],
    events: list[dict],
    found: list[tuple],
    alerts: list[dict],
    picked: list[tuple],
    alert_level: int,
) -> dict:
    """What the defense made of each step of the path, the race, and how the run's clocks agree."""

    scored = []
    started = {stretch.step for stretch in steps}
    for record in path["steps"]:
        step_id = record["id"]
        mine = [
            (event, tied_by)
            for event, (_, _, step, tied_by) in zip(events, found, strict=True)
            if step == step_id
        ]
        counted = [event for event, tied_by in mine if tied_by in COUNTED]
        on_step = [
            alert
            for alert, (_, _, step, tied_by) in zip(alerts, picked, strict=True)
            if step == step_id and tied_by in COUNTED
        ]
        rules: dict[str, dict] = {}
        for alert in on_step:
            rule = alert.get("rule") or {}
            raised = ecs.iso(raised_at(alert))
            entry = rules.setdefault(
                str(rule.get("id")),
                {
                    "rule": str(rule.get("id")),
                    "description": rule.get("description"),
                    "level": rule.get("level"),
                    "alerts": 0,
                    "first raised": raised,
                },
            )
            entry["alerts"] += 1
            entry["first raised"] = min(entry["first raised"], raised)
        counting = [r for r in rules.values() if isinstance(r["level"], int) and r["level"] >= alert_level]
        first = min(counting, key=lambda r: r["first raised"]) if counting else None
        seen = visibility(step_id in started, len(counted), bool(counting))
        happened = record.get("happened")
        expected = [str(rule) for rule in record.get("expect") or []]
        source = ecs.step_clock(record)
        told = source != ecs.END_BEFORE_START
        entry = {
            "id": step_id,
            "host": record.get("host"),
            "to": record.get("to") or [],
            "started": record.get("started") if told else None,
            "ended": record.get("ended") if told else None,
            "time_source": source,
            "happened": happened,
            "why": record.get("why"),
            "visibility": seen,
            "outcome": score_word(happened, seen),
            "events": len(counted),
            "events by tie": dict(Counter(tied_by for _, tied_by in mine if tied_by in COUNTED)),
            "coincident events": sum(1 for _, tied_by in mine if tied_by == "window"),
            "agents": dict(Counter((e.get("agent") or {}).get("name") for e in counted)),
            "first_event": ecs.iso(min(_when(e) for e in counted)) if counted else None,
            "alerts": len(on_step),
            "rules": sorted(rules.values(), key=lambda r: (-(r["level"] or 0), r["rule"])),
            "first_alert": {
                "raised": first["first raised"],
                "rule": first["rule"],
                "description": first["description"],
                "level": first["level"],
            }
            if first
            else None,
            "expected rules": expected,
            "expected rules that did not appear": [rule for rule in expected if rule not in rules],
        }
        scored.append(entry)
    words = Counter(step["outcome"] for step in scored)
    checked = clock(steps, events, found, path["steps"])
    return {
        "alert_level": alert_level,
        "steps": scored,
        "outcomes": {
            word: words[word] for word in ("alerted", "seen", "unseen", "no effect", "inconclusive")
        },
        "race": race(scored, path.get("goal"), checked["agree"]),
        "clock": checked,
        "events": {
            "of each origin": {o: sum(1 for f in found if f[0] == o) for o in ORIGINS},
            "unattributed, coincident with a step": sum(1 for f in found if f[0] == UNATTRIBUTED and f[2]),
        },
        "alerts": {
            "of each origin": {o: sum(1 for p in picked if p[0] == o) for o in ORIGINS},
            "unattributed at the alert level": sum(
                1
                for alert, p in zip(alerts, picked, strict=True)
                if p[0] == UNATTRIBUTED and ((alert.get("rule") or {}).get("level") or 0) >= alert_level
            ),
        },
        "notes": [
            "Events are tied to a step by snoopy's tag of its session, the accounts only the path uses, the "
            "address or container name of the host it ran on and the paths it was given, inside its window; an "
            "event that only falls inside its window is coincident and never counts.",
            "There is no network sensor, so the scans and both exfiltrations are seen only through what they "
            "leave in the logs and files the agents watch.",
            "Snoopy misses the first program of each docker exec, the published sh -c itself, which is the "
            "step's command.",
            "The defense is the stock Wazuh rules with the lab's agent configuration (its diff is in the "
            "manifest). One run is one sample: variation between runs is not yet shown.",
        ],
    }


def record(
    out: Path,
    logs: Path,
    run_id: str,
    alert_level: int,
    jobs: activity.Activity | None = None,
    activity_record: dict | None = None,
    addresses: dict[str, list[str]] | None = None,
    path: dict | None = None,
    uses: set[tuple[str, str]] | None = None,
    names: dict[str, str] | None = None,
) -> tuple[dict, dict | None]:
    """Write events.ecs.ndjson and alerts.ecs.ndjson from the manager's copied logs, and score the run.

    `logs` is the manager's copied logs folder, `path` the manifest's record of
    the path, `uses` the (host, account) pairs the path uses and `names` each
    host's container name. With a path,
    the steps are written to steps.ecs.ndjson too, and the score has `path`,
    what the defense made of each step and the race (see `path_score`).
    Returns the manifest's `ecs` section, whose `error` says why the conversion
    failed (then the score is None), and the score.
    """

    section: dict = {
        "version": ecs.VERSION,
        "files": {},
        "error": None,
        "note": (
            "one ECS line for each line of the manager's archive and alerts as collected, in "
            f"{EVENTS_FILE} and {ALERTS_FILE}; the raw lines stay in raw/ so that the mapping can be checked"
        ),
    }
    try:
        raw = {}
        for kind in ("archives", "alerts"):
            folder = logs / kind
            paths = wazuh.daily_files(folder) if folder.is_dir() else []
            if not paths:
                raise ecs.ConversionError(f"no file of the manager's {kind} was copied out")
            raw[kind] = (paths, *ecs.read(paths))
        events, alerts = raw["archives"][1], raw["alerts"][1]
        record_ = activity_record or {}
        go, stop = record_.get("go") or {}, record_.get("stop") or {}
        steps, cleanups = stretches(path, out)
        found = attributed(events, run_id, jobs, addresses, go, stop, steps, cleanups, uses, names)
        own = attributed(alerts, run_id, jobs, addresses, go, stop, steps, cleanups, uses, names)
        picked, matched = alert_origins(alerts, events, found, own)
        places = matched_events(alerts, events)
        ids = [f"archive-{number}" for number in range(1, len(events) + 1)]
        for kind, name, lines, labels, convert, links in (
            ("archives", EVENTS_FILE, events, found, ecs.event, ids),
            (
                "alerts",
                ALERTS_FILE,
                alerts,
                picked,
                ecs.alert,
                [None if p is None else ids[p] for p in places],
            ),
        ):
            documents = []
            for line, labelled, where, link in zip(lines, labels, raw[kind][2], links, strict=True):
                try:
                    documents.append(convert(line, *labelled, event_id=link))
                except (ValueError, AttributeError, TypeError) as error:
                    raise ecs.ConversionError(f"{where}: {error}") from error
            count = ecs.write(out / name, documents)
            section["files"][name] = {
                "from": [str(p.relative_to(out)) if p.is_relative_to(out) else p.name for p in raw[kind][0]],
                "raw lines": len(lines),
                "ECS lines": count,
                "time sources": dict(Counter(d["labels"]["time_source"] for d in documents)),
                "origins": dict(Counter(d["labels"]["origin"] for d in documents)),
            }
            if count != len(lines):
                raise ecs.ConversionError(f"{name} has {count} lines for {len(lines)} raw lines")
        section["alerts with their event in the archive"] = matched
        counts = {origin: sum(1 for o, *_ in found if o == origin) for origin in ORIGINS}
        unattributed = Counter(
            f"{(e.get('agent') or {}).get('name')}: {e.get('location')}"
            for e, (o, *_) in zip(events, found, strict=True)
            if o == UNATTRIBUTED
        )
        result = ordinary_day(alerts, [p[:2] for p in picked], counts, alert_level, jobs, activity_record)
        result["unattributed events by host and source"] = dict(sorted(unattributed.items()))
        if path and path.get("steps"):
            result["path"] = path_score(path, steps, events, found, alerts, picked, alert_level)
            written = []
            for step_record in path["steps"]:
                scored = next(s for s in result["path"]["steps"] if s["id"] == step_record["id"])
                written.append(
                    ecs.step(
                        {**step_record, "visibility": scored["visibility"], "outcome": scored["outcome"]}
                    )
                )
            section["files"][STEPS_FILE] = {
                "from": ["manifest.json: path.steps"],
                # A "raw line" here is a step as the manifest records it.
                "raw lines": len(path["steps"]),
                "ECS lines": ecs.write(out / STEPS_FILE, written),
            }
        return section, result
    except ecs.ConversionError as error:
        section["error"] = str(error)
    except Exception as error:  # noqa: BLE001 - a conversion that fails for any reason fails the run
        section["error"] = f"{type(error).__name__}: {error}"[:500]
    return section, None


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def summary(manifest: dict) -> str:
    """The ordinary day's score as Markdown, for a CI job's summary."""

    section = manifest.get("ecs") or {}
    score = manifest.get("score")
    if section.get("error") or not score:
        return (
            f"### Ordinary day of {manifest.get('range')}: not scored\n\n"
            f"The conversion to ECS failed: {section.get('error')}\n"
        )
    files = section.get("files") or {}
    counts = (
        [
            "ECS files: "
            + "; ".join(
                f"{name}, {entry['ECS lines']} lines for {entry['raw lines']} raw lines"
                for name, entry in files.items()
            )
            + ".",
            "",
        ]
        if files
        else []
    )
    if not score["scored"]:
        return "\n".join(
            [f"### Ordinary day of {manifest.get('range')}: not scored: {score['not scored']}", "", *counts]
        )
    level = score["alert_level"]
    denominators = score["denominators"]
    runs = denominators["runs of each job"]
    minutes = denominators["minutes of activity"]
    title = f"{score['false alerts']} false alerts at level {level} or higher on {minutes} minutes of ordinary work"
    lines = []
    if manifest.get("result") != "sealed":
        # A run that did not end sealed has no score to headline: what it recorded is shown, labelled.
        lines += [
            f"### Ordinary day of {manifest.get('range')}: not a result, the run ended "
            f"{manifest.get('result')} (exit code {manifest.get('exit_code')})",
            "",
            f"Reason: {manifest.get('reason')}",
            "",
            f"What the run recorded, which is not a score of the range: {title}.",
            "",
        ]
    else:
        lines += [f"### Ordinary day of {manifest.get('range')}: {title}", ""]
    lines += [
        f"On an ordinary day of {minutes} minutes from {denominators['activity started']}, with "
        + ", ".join(
            f"{name} {n['runs']} {'run' if n['runs'] == 1 else 'runs'} ({n['archived runs']} in the archive)"
            for name, n in runs.items()
        )
        + ", the stock rules raised these alerts on the shop's own work. False alerts are the distinct "
        f"rules at level {level} or higher among alerts on ordinary events; rules from level "
        f"{score['for_review_from']} to {level - 1} are for review, and never added to them.",
        "",
        "| Origin | Events | " + " | ".join(f"Alerts {name}" for _, _, name in BANDS) + " |",
        "|---|---|" + "---|" * len(BANDS),
    ]
    for origin in ORIGINS:
        bands = score["alerts by origin and level"].get(origin, {})
        lines.append(
            f"| {origin} | {denominators['events of each origin'].get(origin, 0)} | "
            + " | ".join(str(bands.get(name, 0)) for _, _, name in BANDS)
            + " |"
        )
    lines.append("")
    for heading, rules in (
        (f"False alerts (level {level} or higher, ordinary)", score["false alert rules"]),
        (
            f"For review (levels {score['for_review_from']} to {level - 1}, ordinary)",
            score["for review rules"],
        ),
        (
            f"Level {level} or higher on the engine's work and on unattributed events (not the shop's)",
            score["alerts at the alert level on the engine's work and unattributed events"],
        ),
    ):
        lines += [f"{heading}: {len(rules)} rules.", ""]
        if rules:
            lines += ["| Rule | Description | Level | Alerts | On |", "|---|---|---|---|---|"]
            lines += [
                f"| {r['rule']} | {_cell(r['description'])} | {r['level']} | {r['alerts']} | "
                + _cell(", ".join(f"{k} {v}" for k, v in r["on"].items()))
                + " |"
                for r in rules
            ]
            lines.append("")
    unattributed = score.get("unattributed events by host and source") or {}
    if unattributed:
        lines += [
            "Unattributed events, neither the engine's, a cleanup's, a job's nor a step's: "
            + ", ".join(f"{k} {v}" for k, v in unattributed.items())
            + ".",
            "",
        ]
    lines += ["What the jobs exercise:", ""]
    lines += [f"- {_cell(item)}" for item in score["what the jobs exercise"]]
    lines.append("")
    return "\n".join(lines + counts)


def markdown(manifest: dict) -> str:
    """score.md: the path's score first, then the ordinary day's."""

    path = path_summary(manifest)
    return (path + "\n" if path else "") + summary(manifest)


def path_summary(manifest: dict) -> str:
    """What the defense made of each step of the path, and the race, as Markdown for a CI job's summary."""

    found = (manifest.get("score") or {}).get("path")
    if not found:
        return ""
    level = found["alert_level"]
    race_ = found["race"]
    day = manifest.get("score") or {}
    title = f"### Path of {manifest.get('range')}: {race_['says']}"
    lines = []
    if manifest.get("result") != "sealed":
        lines += [
            f"### Path of {manifest.get('range')}: not a result, the run ended {manifest.get('result')} "
            f"(exit code {manifest.get('exit_code')})",
            "",
            f"What the run recorded, which is not a score of the range: {race_['says']}.",
            "",
        ]
    else:
        lines += [title, ""]
    alert = race_.get("first_alert")
    parts = [
        f"First alert at level {level} or higher: "
        + (
            f"{race_['first_alert_seconds']} s after the first step started, rule {alert['rule']} "
            f"({_cell(alert['description'])}, level {alert['level']}) on {alert['step']}"
            if alert
            else "none"
        )
        + ".",
        "Goal: "
        + (
            f"{race_['goal_seconds']} s after the first step started ({_cell(race_['goal'])})"
            if "goal_seconds" in race_
            else "not reached"
        )
        + ".",
    ]
    if day.get("scored"):
        parts.append(
            f"Beside it, on the ordinary day: {day['false alerts']} false alerts at level {level} or higher "
            f"in {day['denominators']['minutes of activity']} minutes."
        )
    else:
        parts.append(f"Beside it, the ordinary day was not scored: {day.get('not scored')}.")
    lines += [" ".join(parts), ""]
    lines += [
        "| Step | Host | What happened | Recorded | Agents | Ties | Coincident | First alert | Outcome | "
        "Expected rules missing |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for step in found["steps"]:
        first = step.get("first_alert")
        lines.append(
            f"| {step['id']} | {step['host']}{''.join(' to ' + t for t in step['to'])} | {step['happened']} | "
            f"{step['visibility']} ({step['events']} events) | "
            + _cell(", ".join(f"{k} {v}" for k, v in step["agents"].items()) or "none")
            + " | "
            + _cell(", ".join(f"{k} {v}" for k, v in step["events by tie"].items()) or "none")
            + f" | {step['coincident events']} | "
            + (f"{first['rule']} (level {first['level']}) at {first['raised']}" if first else "none")
            + f" | {step['outcome']} | "
            + (", ".join(step["expected rules that did not appear"]) or "none")
            + " |"
        )
    lines.append("")
    check = found["clock"]
    lag = check["manager's time against the line's"]
    lines += [
        f"One clock. Steps: {check['steps']}. Alerts: {check['alerts']}. Checked: "
        f"{check['program starts checked']} program starts in the steps' sessions, at their containers' time, "
        f"{check['outside their step']} outside their step's daemon times"
        + (
            "; the daemon's times of "
            + ", ".join(check["steps on the engine's clock"])
            + " were not matched or not in order, so they are not used"
            if check["steps on the engine's clock"]
            else ""
        )
        + ("." if check["agree"] else ": the clocks are not shown to agree, so the race is not a result."),
        "",
        "The manager's own time of an archived line, against the time rsyslog wrote on it in its container: "
        f"from {lag['least seconds']} s to {lag['most seconds']} s, earlier than the line for "
        f"{lag['earlier than the line']} of {lag['lines']} lines. An alert counts from the manager's time of "
        "it, or from its line's time when the manager's is earlier.",
        "",
        "No step can be stopped: the range configures no active response. "
        "An event that only falls inside a step's window is coincident and is not counted as the step's. "
        "Unattributed: "
        f"{found['events']['of each origin'].get(UNATTRIBUTED, 0)} events "
        f"({found['events']['unattributed, coincident with a step']} coincident with a step) and "
        f"{found['alerts']['of each origin'].get(UNATTRIBUTED, 0)} alerts "
        f"({found['alerts']['unattributed at the alert level']} at level {level} or higher).",
        "",
    ]
    lines += [f"- {_cell(note)}" for note in found["notes"]]
    lines.append("")
    return "\n".join(lines)
