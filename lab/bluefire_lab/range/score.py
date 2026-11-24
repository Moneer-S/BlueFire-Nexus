"""Where each event and alert of a run came from, and what the defense said about the ordinary day.

Every archived event and every alert gets one origin, by the first rule that holds:

1. `engine`: snoopy tagged its program start `engine:*`, or the line holds the
   run's ID, which every nonce and mark of the engine carries, and so does the
   name of every mark file the engine makes. What the plant checks and the
   seal's probes leave behind (a login's session lines, a PHP session file)
   carries no ID.
2. `ordinary`: it is a job's of the ordinary activity, sorted to the job as
   `activity.attribute` sorts it (the job's tag, its host's address, the path
   of an http job's request, the account it logs in as, the files it writes,
   inside its window); or snoopy tagged it `job:<name>`. A program start with
   another job's tag is never an ssh job's by its account or address, and an
   nginx line for a path no job fetches is no job's. `labels.job` names the
   job. Cron's session line of a cron job's account inside the job's window is
   ordinary with no `labels.job`, since it does not tell one cron entry of the
   account from another.
3. `unattributed`: everything else. These are listed and counted, and never
   called ordinary. A step of the path will claim its events from among them.

An alert takes the origin of its event in the archive (the same agent,
location, line and manager time). An alert with no such event is given an
origin by the same rules, read on the alert itself.

The ordinary day's score: false alerts are the distinct stock rules at the
range's alert level or higher among the alerts whose origin is `ordinary`;
the rules from level 7 up to the alert level on ordinary work are a second
number, for review, never added to the first. Alerts at the alert level on the
engine's own work and on unattributed events are listed apart: the bench's own
noise is not the shop's.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from . import activity, ecs, wazuh

ENGINE = "engine"
ORDINARY = "ordinary"
UNATTRIBUTED = "unattributed"
ORIGINS = (ENGINE, ORDINARY, UNATTRIBUTED)
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


def origins(
    events: list[dict],
    run_id: str,
    jobs: activity.Activity | None = None,
    addresses: dict[str, list[str]] | None = None,
    go: dict[str, float] | None = None,
    stop: dict[str, float] | None = None,
) -> list[tuple[str, str | None]]:
    """The origin of each event, and the job's name for an ordinary one, in the order given."""

    sorted_ = activity.attribute(jobs, events, addresses or {}, go or {}, stop or {}) if jobs and go else {}
    names = {job.name for job in jobs.jobs} if jobs else set()
    found: list[tuple[str, str | None]] = []
    for index, event in enumerate(events):
        tag = _tag(event)
        if _engine(event, run_id):
            found.append((ENGINE, None))
        elif index in sorted_:
            name, how = sorted_[index]
            # Cron's session line of a cron job's account does not tell one entry of the account from another.
            found.append((ORDINARY, None if how == activity.CRON_SESSION_SOURCE else name))
        elif tag.startswith("job:") and tag[4:] in names:
            found.append((ORDINARY, tag[4:]))
        else:
            found.append((UNATTRIBUTED, None))
    return found


def _key(line: dict) -> tuple:
    return (
        (line.get("agent") or {}).get("name"),
        line.get("location"),
        line.get("full_log"),
        line.get("timestamp"),
    )


def alert_origins(
    alerts: list[dict], events: list[dict], found: list[tuple[str, str | None]], fallback: list
) -> tuple[list[tuple[str, str | None]], int]:
    """Each alert's origin: its archived event's, else its own (`fallback`); and how many had an event."""

    index: dict[tuple, tuple[str, str | None]] = {}
    for event, origin in zip(events, found, strict=True):
        index.setdefault(_key(event), origin)
    result, matched = [], 0
    for alert, own in zip(alerts, fallback, strict=True):
        origin = index.get(_key(alert))
        matched += origin is not None
        result.append(origin or own)
    return result, matched


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
    others = [(a, p) for a, p in zip(alerts, picked, strict=True) if p[0] != ORDINARY]
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


def record(
    out: Path,
    logs: Path,
    run_id: str,
    alert_level: int,
    jobs: activity.Activity | None = None,
    activity_record: dict | None = None,
    addresses: dict[str, list[str]] | None = None,
) -> tuple[dict, dict | None]:
    """Write events.ecs.ndjson and alerts.ecs.ndjson from the manager's copied logs, and score the ordinary day.

    `logs` is the manager's copied logs folder. Returns the manifest's `ecs`
    section, whose `error` says why the conversion failed (then the score is
    None), and the score.
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
        found = origins(events, run_id, jobs, addresses, go, stop)
        own = origins(alerts, run_id, jobs, addresses, go, stop)
        picked, matched = alert_origins(alerts, events, found, own)
        for kind, name, lines, labels, convert in (
            ("archives", EVENTS_FILE, events, found, ecs.event),
            ("alerts", ALERTS_FILE, alerts, picked, ecs.alert),
        ):
            documents = []
            for line, (origin, job), where in zip(lines, labels, raw[kind][2], strict=True):
                try:
                    documents.append(convert(line, origin, job))
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
        counts = {origin: sum(1 for o, _ in found if o == origin) for origin in ORIGINS}
        unattributed = Counter(
            f"{(e.get('agent') or {}).get('name')}: {e.get('location')}"
            for e, (o, _) in zip(events, found, strict=True)
            if o == UNATTRIBUTED
        )
        result = ordinary_day(alerts, picked, counts, alert_level, jobs, activity_record)
        result["unattributed events by host and source"] = dict(sorted(unattributed.items()))
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
    lines = [f"### Ordinary day of {manifest.get('range')}: {title}", ""]
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
            "Unattributed events, neither the engine's nor a job's: "
            + ", ".join(f"{k} {v}" for k, v in unattributed.items())
            + ".",
            "",
        ]
    lines += ["What the jobs exercise:", ""]
    lines += [f"- {_cell(item)}" for item in score["what the jobs exercise"]]
    lines.append("")
    return "\n".join(lines + counts)
