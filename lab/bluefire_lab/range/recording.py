"""Write recording.json for a run of a range: its path, what the defense made of it, in the format the app plays.

The format is docs/RECORDING.md, the same one the single-host lab writes
(`bluefire_lab.recording`), whose helpers this module uses to show and cut
texts, to name a step's outcome and to list the rules of ordinary activity.
Every value comes from the run folder: `manifest.json` (the spec the run
used, the hosts, the path and the score), the ECS lines of the events and
alerts with their ties (`score`), what each step printed (`raw/steps/`), the
Docker events the engine watched (the run's start and end) and the manager's
log (how many rules it loaded).

The network is the spec's hosts and the links between those that share a
network; the sensors are the Wazuh agents; the detector `pinned` is the
manager's stock rules, which ran live, so an alert has the time of its event
and the time the manager raised it. A step's events are the archived events
tied to it by its session, an account only the path uses, the address of the
host it ran on or a path it was given (`score`); one that only falls inside
its window is not the step's, and is not in the recording. A step that went to
another host (`to` in the spec) is on that host, and comes `from` its own.
A run whose race the score's clock check does not back as a result has no
recording, and neither has one the app's check would refuse: a counting alert
whose archived line is not in the archive, or a spec whose alert level is not
the level the format's words count from.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from .. import recording as lab
from . import ecs, score
from . import path as range_path
from .spec import read

FILE = "recording.json"
# Wazuh's levels in the words of the format: informational, low, medium, high and critical.
WORDS = ((0, 3, "informational"), (4, 6, "low"), (7, 11, "medium"), (12, 14, "high"), (15, 15, "critical"))
COUNTING = ("high", "critical")
# The level the format's counting words start at: a score at another level cannot be written in them.
FORMAT_LEVEL = min(low for low, _, word in WORDS if word in COUNTING)
RULES_LOADED = re.compile(r"Total rules enabled: '([0-9]+)'")
KINDS = {"creation": "file created", "change": "file changed", "deletion": "file deleted"}
DATABASE_LINE = "database error log line"


def level_word(level: object) -> str:
    for low, high, word in WORDS:
        if isinstance(level, int) and low <= level <= high:
            return word
    return "informational"


def lines(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def nanoseconds(value: int) -> str:
    return range_path.iso(value) or ""


def run_times(folder: Path) -> tuple[str, str]:
    """The run's start and end: the Docker daemon's times of the first and the last event the engine watched."""

    times = [
        int(event["timeNano"])
        for event in lines(folder / "docker-events.ndjson")
        if isinstance(event.get("timeNano"), int)
    ]
    if not times:
        raise ValueError("docker-events.ndjson holds no event, so the run's start and end are not known")
    return nanoseconds(min(times)), nanoseconds(max(times))


def rules_loaded(folder: Path, manager: str) -> int:
    log = folder / "raw" / "hosts" / manager / "var" / "ossec" / "logs" / "ossec.log"
    found = RULES_LOADED.findall(log.read_text(encoding="utf-8", errors="replace")) if log.is_file() else []
    if not found:
        raise ValueError("the manager's ossec.log does not say how many rules it loaded")
    return int(found[-1])


def installed(folder: Path, hosts: list[str], package: str) -> str | None:
    """The version of a package as dpkg.log of an agent host, copied out of the range, says it was installed."""

    found = re.compile(rf" install {re.escape(package)}:\S+ \S+ (\S+)")
    for host in hosts:
        log = folder / "raw" / "hosts" / host / "var" / "log" / "dpkg.log"
        versions = found.findall(log.read_text(encoding="utf-8", errors="replace")) if log.is_file() else []
        if versions:
            return versions[-1]
    return None


def records(spec: dict, host: str) -> str:
    """What the agent on a host collects, in plain words, from the spec."""

    defense = spec.get("defense") or {}
    own = (spec["hosts"][host].get("watch") or {}) if isinstance(spec["hosts"][host], dict) else {}
    watch = defense.get("watch") or {}
    logs = [entry["path"] for entry in (watch.get("logs") or []) + (own.get("logs") or [])]
    folders = list(watch.get("fim_realtime") or []) + list(own.get("fim_realtime") or [])
    return (
        f"the lines of {', '.join(logs)}, snoopy's program starts among them, and every change to a file "
        f"under {', '.join(folders)}, as it happens; the manager reads them"
    )


def network(manifest: dict, spec: dict, rules: int) -> dict:
    hosts = []
    for name, settings in spec["hosts"].items():
        container = (manifest.get("containers") or {}).get(name) or {}
        image = (manifest.get("images") or {}).get(name) or {}
        built_on = str(image.get("built_on") or "").partition("@")[0]
        hosts.append(
            lab.known(
                id=name,
                name=name,
                role=settings.get("role"),
                kind=settings.get("kind"),
                os=f"built on {built_on}" if built_on else None,
                addresses=list((container.get("addresses") or {}).values()) or None,
            )
        )
    names = list(spec["hosts"])
    links = []
    for number, first in enumerate(names):
        for second in names[number + 1 :]:
            shared = [n for n in spec["hosts"][first]["networks"] if n in spec["hosts"][second]["networks"]]
            if shared:
                links.append({"from": first, "to": second, "label": ", ".join(shared)})
    defense = manifest.get("defense") or {}
    version = defense.get("wazuh_version")
    return {
        "hosts": hosts,
        "links": links,
        "sensors": [
            {
                "id": sensor_id(agent),
                "name": lab.named("Wazuh agent", version),
                "host": agent,
                "records": records(spec, agent),
            }
            for agent in defense.get("agents") or []
        ],
        "detectors": [
            {
                "id": "pinned",
                "name": lab.named("Wazuh", version)
                + " stock rules with the lab's decoder for snoopy, on "
                + str(defense.get("manager")),
                "rules": rules,
                "when": "live",
            }
        ],
    }


def sensor_id(host: str) -> str:
    return f"wazuh-agent-{host}"


def error_logs(spec: dict) -> set[str]:
    """The error logs of the spec's databases (`database.log_error`)."""

    found = set()
    for settings in spec["hosts"].values():
        database = (settings.get("database") or {}) if isinstance(settings, dict) else {}
        if isinstance(database, dict) and database.get("log_error"):
            found.add(str(database["log_error"]))
    return found


def kind_of(document: dict, database_logs: set[str] = frozenset()) -> str:
    """An event's kind in plain words, from its ECS categorization, or the log it comes from."""

    event = document.get("event") or {}
    categories, types = event.get("category") or [], event.get("type") or []
    if "process" in categories:
        return "process start"
    if "file" in categories:
        return KINDS.get(types[0] if types else "", "file event")
    if "authentication" in categories:
        return "login succeeded" if event.get("outcome") == "success" else "login failed"
    if "web" in categories:
        return "web request"
    # The decoder Wazuh picks for a database's line differs from run to run: the log names it.
    if (document.get("wazuh") or {}).get("location") in database_logs:
        return DATABASE_LINE
    decoder = ((document.get("wazuh") or {}).get("decoder") or {}).get("name")
    return f"{decoder} line" if decoder else "log line"


def text_of(document: dict) -> str:
    process = (document.get("process") or {}).get("command_line")
    if process:
        return process
    path = (document.get("file") or {}).get("path")
    if path:
        return path
    return str((document.get("event") or {}).get("original") or "")


def event_of(document: dict, step: str, number: int, database_logs: set[str] = frozenset()) -> dict:
    wazuh = document.get("wazuh") or {}
    host = (document.get("host") or {}).get("name")
    return {
        "id": f"{step}-{number}",
        "time": document["@timestamp"],
        "host": host,
        "sensor": sensor_id(host),
        "kind": kind_of(document, database_logs),
        "text": text_of(document),
        "step": step,
        "tied_by": document["labels"]["tied_by"],
        **lab.known(user=(document.get("user") or {}).get("name")),
        "fields": lab.known(
            location=wazuh.get("location"),
            decoder=(wazuh.get("decoder") or {}).get("name"),
            srcip=(document.get("source") or {}).get("ip"),
            ecs_event_id=(document.get("event") or {}).get("id"),
        ),
    }


def output(folder: Path, step: str) -> str | None:
    found = []
    for name in ("stdout", "stderr"):
        file = folder / "raw" / "steps" / step / name
        if file.is_file():
            found.append(file.read_text(encoding="utf-8", errors="replace"))
    text = "".join(found).strip()
    return text or None


def basis(entry: dict, alert_level: int) -> str:
    """What a step's visibility rests on, in a sentence."""

    if entry["visibility"] == "not applicable":
        return "the test did not start, so nothing could be tied to it"
    ties = ", ".join(f"{n} by {how}" for how, n in entry["events by tie"].items())
    said = lab.count(entry["events"], "archived event") + " tied to the step" + (f" ({ties})" if ties else "")
    shown = entry.get("lines tied by address alone") or []
    if shown:
        said += (
            f", only because {'the line' if entry['events'] == 1 else 'each line'} names {entry['host']}'s address or container name, or comes from its "
            "address: " + "; ".join(shown)
        )
    first = entry.get("first_alert")
    if first:
        said += (
            f"; rule {first['rule']} at level {first['level']}, an alert at level {alert_level} or higher, "
            f"raised at {first['raised']}"
        )
    elif entry["alerts"]:
        said += f"; {lab.count(entry['alerts'], 'rule match', 'rule matches')} below level {alert_level}"
    if entry["coincident events"]:
        said += (
            f"; {entry['coincident events']} more fell only inside the step's time span, from its start to "
            f"{score.GRACE} s after its end, on a host it ran on or reached, not counted"
        )
    return said


def build(folder: Path) -> dict:
    """The recording of a range run's folder, after `score` has written its ECS lines and score."""

    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    spec = read(manifest["spec"]["text"])
    path = manifest.get("path") or {}
    scored = ((manifest.get("score") or {}).get("path")) or {}
    if not scored.get("steps"):
        raise ValueError("the run has no score of its path, so there is nothing to record")
    race = scored.get("race") or {}
    if race.get("start") is None:
        # The format's race, and the app's check, count from the first step's start on the steps' clock.
        raise ValueError(
            f"an attack path's recording needs its first step's daemon start: {race.get('says')}"
        )
    if not race.get("result"):
        # A step on the engine's clock, or a program start outside its step: the times are not shown to agree.
        raise ValueError(f"the run's race is not a result, so no recording is written: {race.get('says')}")
    alert_level = scored["alert_level"]
    if alert_level != FORMAT_LEVEL:
        raise ValueError(
            f"the spec's defense.wazuh.alert_level is {alert_level}, but the recording format counts an alert "
            f"from level {FORMAT_LEVEL} (its words high and critical), so no recording is written: set the level "
            f"back to {FORMAT_LEVEL}, or read the score without a recording"
        )
    defense = manifest.get("defense") or {}
    started, finished = run_times(folder)
    sensors = set(defense.get("agents") or [])

    events = lines(folder / score.EVENTS_FILE)
    alerts = lines(folder / score.ALERTS_FILE)
    of_step: dict[str, list[dict]] = defaultdict(list)
    for document in events:
        labels = document.get("labels") or {}
        if labels.get("origin") == score.STEP and (document.get("host") or {}).get("name") in sensors:
            of_step[labels["step_id"]].append(document)
    on_step: dict[str, list[dict]] = defaultdict(list)
    for document in alerts:
        labels = document.get("labels") or {}
        if labels.get("origin") == score.STEP:
            on_step[labels["step_id"]].append(document)

    plain = {
        step.get("id"): step.get("plain")
        for step in ((spec.get("path") or {}).get("steps") or [])
        if isinstance(step, dict)
    }
    scores = {entry["id"]: entry for entry in scored["steps"]}
    databases = error_logs(spec)
    steps, kept_events, kept_alerts, cut, late_cut = [], [], [], 0, 0
    for order, record in enumerate(path.get("steps") or [], start=1):
        step_id, entry = record["id"], scores[record["id"]]
        mine = sorted(of_step.get(step_id, []), key=lambda d: d["@timestamp"])
        named = {(d.get("labels") or {}).get("event_id") for d in on_step.get(step_id, [])}
        placed: dict[str, dict] = {}
        for number, document in enumerate(mine, start=1):
            if number <= lab.KEPT_EVENTS or (document.get("event") or {}).get("id") in named:
                placed[(document.get("event") or {}).get("id")] = event_of(
                    document, step_id, number, databases
                )
        kept_events += placed.values()
        held_alerts = []
        for document in on_step.get(step_id, []):
            rule = document.get("rule") or {}
            level = level_word((((document.get("wazuh") or {}).get("rule")) or {}).get("level"))
            event_id = (document.get("labels") or {}).get("event_id")
            linked = placed.get(event_id)
            if level in COUNTING and not linked:
                # The format needs a counting alert to name the event it was raised on.
                where = (
                    " is not in the archive (a delivery gap)"
                    if event_id is None
                    else f", {event_id}, is not among the step's events"
                )
                raise ValueError(
                    f"the alert of rule {rule.get('id')} at {document['@timestamp']} on {step_id} counts, but the "
                    f"archived line it was raised on{where}, so no recording is written"
                )
            host = (document.get("host") or {}).get("name")
            time = linked["time"] if linked else document["@timestamp"]
            # The manager's time can run behind the line's (see score.clock): raised is then left out, and
            # the alert counts from its line's time, as score.raised_at does.
            late = document["@timestamp"] >= time
            late_cut += not late
            held_alerts.append(
                {
                    "time": time,
                    **({"raised": document["@timestamp"]} if late else {}),
                    "host": host,
                    "detector": "pinned",
                    "rule": {
                        "id": str(rule.get("id")),
                        "title": rule.get("description") or str(rule.get("id")),
                        "level": level,
                        "origin": "pinned",
                    },
                    "counts": level in COUNTING,
                    "step": step_id,
                    "events": [linked["id"]] if linked else [],
                }
            )
        kept_alerts += held_alerts
        to = record.get("to") or []
        daemon = ecs.step_clock(record) == "daemon"
        counting = [a.get("raised", a["time"]) for a in held_alerts if a["counts"]]
        held = len(placed)
        cut += held < entry["events"]
        argv = record.get("argv") or []
        steps.append(
            lab.known(
                id=step_id,
                order=order,
                role="test",
                title=record.get("name"),
                plain=record.get("plain") or plain.get(step_id),
                technique={"id": record.get("technique")},
                test={
                    "project": "Atomic Red Team",
                    "guid": record.get("guid"),
                    "executor": argv[0] if argv else "sh",
                    "elevated": record.get("account") == "root",
                },
                host=to[0] if to else record.get("host"),
                **({"from": record.get("host")} if to else {}),
                started=record.get("started") if daemon else None,
                ended=record.get("ended") if daemon else None,
                command=argv[-1] if argv else None,
                output=output(folder, step_id),
                happened={"answer": record.get("happened"), "basis": record.get("why")},
                visibility=lab.known(
                    answer=entry["visibility"],
                    basis=basis(entry, alert_level),
                    events=None if entry["visibility"] == "not applicable" else entry["events"],
                    kept=held if held < entry["events"] else None,
                ),
                outcome=entry["outcome"],
                first_event=min((e["time"] for e in placed.values()), default=None),
                first_alert=min(counting, default=None),
            )
        )
    kept_events.sort(key=lambda found: found["time"])
    kept_alerts.sort(key=lambda found: found["time"])
    kept_alerts = [{"id": f"alert-{number}", **found} for number, found in enumerate(kept_alerts, start=1)]

    ordinary_rules: dict[str, dict] = {}
    for document in alerts:
        if (document.get("labels") or {}).get("origin") != score.ORDINARY:
            continue
        rule = document.get("rule") or {}
        level = (((document.get("wazuh") or {}).get("rule")) or {}).get("level")
        entry = ordinary_rules.setdefault(
            str(rule.get("id")),
            {
                "id": str(rule.get("id")),
                "title": rule.get("description") or str(rule.get("id")),
                "level": level_word(level),
                "events": 0,
            },
        )
        entry["events"] += 1
    origins = (scored.get("events") or {}).get("of each origin") or {}
    ordinary = {
        "events": origins.get(score.ORDINARY, 0),
        "matches": lab.ordinary_matches(list(ordinary_rules.values())),
    }

    tests = [step for step in steps if step["role"] == "test"]
    # A published test that runs twice, as the port scan does against two hosts, is one test of two steps.
    distinct = {step["test"]["guid"] for step in tests}
    took = [step for step in tests if step["happened"]["answer"] == "took effect"]
    words = Counter(step["outcome"] for step in took)
    totals: dict = {"steps": len(tests), "took_effect": len(took)}
    totals.update({word: words[word] for word in ("alerted", "seen", "unseen")})
    totals["stopped"] = sum(1 for step in steps if step["outcome"] == "stopped")
    goal = path.get("goal") or {}
    first = steps[0] if steps else {}
    if "started" in first:
        alerted = [step["first_alert"] for step in tests if "first_alert" in step]
        if alerted:
            totals["first_alert_seconds"] = max(0.0, score.seconds_between(first["started"], min(alerted)))
        end = next((s.get("ended") for s in steps if s["id"] == goal.get("after")), None)
        if goal.get("passed") and end:
            totals["goal_seconds"] = score.seconds_between(first["started"], end)
    totals["false_alerts"] = sum(1 for match in ordinary["matches"] if match["level"] in COUNTING)

    environment = manifest.get("environment") or "containers on a developer machine"
    atomic = manifest.get("atomic_red_team") or {}
    made = lab.known(
        schema="bluefire.recording/1",
        id=manifest["run_id"],
        # What a person reads first on a card: what this is, in a stranger's words. The range's own
        # name and the count of published tests are in the description below.
        title=f"An attack path of {lab.count(len(tests), 'step')} through a network of "
        f"{lab.count(len(spec['hosts']), 'host')}",
        kind="attack path",
        source=lab.known(
            engine="bluefire-lab",
            environment=environment,
            started=started,
            finished=finished,
            run_url=manifest.get("run_url"),
            # A tool whose version the run does not hold is left out.
            tools=[
                {"name": name, "version": version, "role": role}
                for name, version, role in (
                    ("Atomic Red Team", atomic.get("commit"), "tests"),
                    ("Wazuh agent", defense.get("wazuh_version"), "sensor"),
                    ("snoopy", installed(folder, defense.get("agents") or [], "snoopy"), "sensor"),
                    ("Wazuh ruleset", defense.get("wazuh_version"), "rules"),
                    ("Wazuh manager", defense.get("wazuh_version"), "rule engine"),
                )
                if version
            ],
            setup=lab.known(
                atomic_commit=atomic.get("commit"),
                images={host: str(image.get("id")) for host, image in (manifest.get("images") or {}).items()}
                or None,
            ),
        ),
        network=network(manifest, spec, rules_loaded(folder, defense.get("manager") or "manager")),
        attacker={
            "kind": "scripted",
            "description": " ".join(
                part
                for part in (
                    str(spec.get("sentence") or "").strip(),
                    f"The engine ran the path's {lab.count(len(tests), 'step')} in turn inside the sealed "
                    f"range {manifest.get('range')}, through docker exec as the step's account. The steps ran "
                    f"{lab.count(len(distinct), 'published test')}."
                    if manifest.get("result") == "sealed"
                    else f"The engine started {lab.count(len(tests), 'step')} of the path's "
                    f"{len(path.get('planned') or tests)} in turn, through docker exec as the step's account; "
                    f"then the run ended {manifest.get('result')}: {manifest.get('reason')}.",
                )
                if part
            ),
            "goal": goal.get("plain"),
        },
        steps=steps,
        events=kept_events,
        alerts=kept_alerts,
        ordinary=ordinary,
        score=totals,
        notes=notes(manifest, scored, path, spec, cut, late_cut),
    )
    return lab.visible(made)


def notes(manifest: dict, scored: dict, path: dict, spec: dict, cut: int, behind: int) -> list[str]:
    said = []
    if manifest.get("result") != "sealed":
        said.append(
            f"The run ended {manifest.get('result')} (exit code {manifest.get('exit_code')}): "
            f"{manifest.get('reason')}. What it recorded is shown, and is not a result about the range."
        )
    hand_off = (spec.get("path") or {}).get("hand_off")
    if hand_off:
        said.append(f"Hand-off: {hand_off}.")
    reference = (spec.get("executor") or {}).get("commit")
    if reference:
        # The engine runs the steps itself; Invoke-AtomicRedTeam is only what its reading is checked against.
        said.append(
            "The engine's own executor ran each step, reading the test as Invoke-AtomicRedTeam "
            f"{reference} does; the atomic-parity job of the range one workflow checks that."
        )
    said += list(path.get("notes") or [])
    said += list(scored.get("notes") or [])
    check = scored.get("clock") or {}
    said.append(
        "The steps' times are the Docker daemon's and the alerts' the manager container's: "
        f"{check.get('program starts checked')} program starts snoopy logged in the steps' sessions, at their "
        "containers' time, all fall inside their step's "
        "daemon times."
    )
    said.append(
        "An alert's time is the time of the event it was raised on, and raised is the manager's time of it: "
        "the race counts to raised."
    )
    if behind:
        said.append(
            f"By the manager's own time, {lab.count(behind, 'alert')} on the steps would come before the line "
            "it was raised on, a time rsyslog wrote in the line's container: the manager's time runs behind at "
            "times (manifest.json, score.path.clock, says by how much). These alerts have no raised, and count "
            "from their line's time."
        )
    coincident = (scored.get("events") or {}).get("unattributed, coincident with a step")
    if coincident:
        said.append(
            f"{lab.count(coincident, 'archived event')} fell only inside a step's time span, from its start to "
            f"{score.GRACE} s after its end, on a host it ran on or reached: coincident in time, not counted as "
            "the step's and not in the recording; events.ecs.ndjson holds them with the step and tied_by window."
        )
    if cut:
        said.append(
            f"{lab.count(cut, 'step')} had more than {lab.KEPT_EVENTS} events. The recording keeps the first "
            f"{lab.KEPT_EVENTS} of each and every event an alert was raised on; events.ecs.ndjson holds them all."
        )
    weaknesses = manifest.get("weaknesses") or []
    if weaknesses:
        said.append(
            "The range has planted weaknesses, listed in the manifest: "
            + "; ".join(str(w.get("what") if isinstance(w, dict) else w) for w in weaknesses)
            + "."
        )
    if (manifest.get("defense") or {}).get("delivery_gap"):
        said.append("Not every line of a watched log reached the manager: see delivery in the manifest.")
    return said


def write(folder: Path) -> dict:
    """Write recording.json into a run folder; returns how many steps, events and alerts it holds."""

    made = build(folder)
    (folder / FILE).write_text(json.dumps(made, indent=1) + "\n", encoding="utf-8")
    return {"steps": len(made["steps"]), "events": len(made["events"]), "alerts": len(made["alerts"])}
