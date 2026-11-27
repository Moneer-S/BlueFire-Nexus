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
and the time the manager raised it. A rule set that was evaluated after the
run is a detector of its own, named after the set: its alerts have the time of
their event and no time of being raised. When the spec names its defenses, the
recording has `defenses`: for each one that judged the run, its sensors, its
detectors and its own answer for every step, its ordinary day and its score,
which is the recording as that defense alone sees it. The top level is the
first defense's. A step's events are the archived events
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
from . import ecs, score, sigma
from . import path as range_path
from .spec import WAZUH_AGENT, read

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


def detectors(folder: Path, manifest: dict, judged: list[dict]) -> list[dict]:
    """The detectors of the defenses that judged the run: the manager's stock rules, which ran live, and each
    rule set that was evaluated after the run, with the rules its engine loaded and the digest of its files."""

    defense = manifest.get("defense") or {}
    sets = (manifest.get("score") or {}).get("rule sets") or {}
    found = []
    for identifier in dict.fromkeys(name for entry in judged for name in entry["detectors"]):
        if identifier == score.PINNED:
            found.append(
                {
                    "id": identifier,
                    "name": lab.named("Wazuh", defense.get("wazuh_version"))
                    + " stock rules with the lab's decoder for snoopy, on "
                    + str(defense.get("manager")),
                    "rules": rules_loaded(folder, defense.get("manager") or "manager"),
                    "when": score.LIVE,
                }
            )
            continue
        entry = sets[identifier]
        repo, _, commit = entry["source"].partition("@")
        engine = entry["engine"]
        found.append(
            {
                "id": identifier,
                "name": f"Published Sigma rules ({repo} at {commit[:12]}) with "
                + lab.named(engine["name"], engine.get("version")),
                "rules": entry["loaded"],
                "when": score.AFTER,
                "digest": entry["digest"],
            }
        )
    return found


def network(manifest: dict, spec: dict, rules: list[dict]) -> dict:
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
        "detectors": rules,
    }


def sensor_id(host: str) -> str:
    return score.sensor_id(WAZUH_AGENT, host)


def sensor_of(document: dict) -> str:
    """The sensor that recorded an ECS line: the Wazuh agent on its host, the one kind of sensor so far."""

    return sensor_id((document.get("host") or {}).get("name"))


def rule_of(document: dict) -> dict:
    """The rule of an alert line in the format's words: its id, its title and its level.

    A rule that was evaluated after the run carries its own level and title;
    the manager's rule has a number for a level, and its description for a title.
    """

    rule, labels = document.get("rule") or {}, document.get("labels") or {}
    if "level" in labels:
        level = labels["level"] if labels["level"] in sigma.LEVELS else sigma.LEVELS[0]
        return {"id": str(rule.get("id")), "title": rule.get("name") or str(rule.get("id")), "level": level}
    level = level_word((((document.get("wazuh") or {}).get("rule")) or {}).get("level"))
    return {
        "id": str(rule.get("id")),
        "title": rule.get("description") or str(rule.get("id")),
        "level": level,
    }


def shares(counts: dict[str, int], room: int) -> dict[str, int]:
    """How many events of each sensor a step keeps, of `room` in all: an equal share each, and what a sensor
    with fewer events leaves of its share goes to the others in equal parts again."""

    kept = dict.fromkeys(counts, 0)
    while room > 0 and any(counts[sensor] > kept[sensor] for sensor in counts):
        short = sorted(sensor for sensor in counts if counts[sensor] > kept[sensor])
        part = max(room // len(short), 1)
        for sensor in short:
            more = min(part, counts[sensor] - kept[sensor], room)
            kept[sensor] += more
            room -= more
    return kept


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
        "sensor": sensor_of(document),
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


def basis(entry: dict, alert_level: int, live: bool = True) -> str:
    """What a step's visibility rests on, in a sentence.

    `live` is false when the step's first alert is of rules that were
    evaluated after the run: it was never raised, and its level is the rule's
    own word. `alerts` counts the matches of live rules below the alert level,
    and `matches after the run` those of rules evaluated after the run, below
    the level whose word counts.
    """

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
    if first and live:
        said += (
            f"; rule {first['rule']} at level {first['level']}, an alert at level {alert_level} or higher, "
            f"raised at {first['raised']}"
        )
    elif first:
        said += (
            f"; the rule {first['title']} at level {first['level']}, which counts as an alert, matched an "
            f"event of {first['raised']}, when the rules were evaluated after the run"
        )
    else:
        for matches, level in (
            (entry["alerts"], alert_level),
            (entry.get("matches after the run"), sigma.ALERT_LEVELS[0]),
        ):
            if matches:
                said += f"; {lab.count(matches, 'rule match', 'rule matches')} below level {level}"
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
    # The defenses that judged the run, the first of which the top level shows, and their detectors:
    # the manager's live rules, and each rule set whose matches were written beside its alerts.
    judged = [entry for entry in (manifest.get("score") or {}).get("defenses") or [] if entry.get("judged")]
    if not judged:
        raise ValueError("no defense judged the run, so there is nothing to record")
    found = detectors(folder, manifest, judged)
    live = {entry["id"] for entry in found if entry["when"] == score.LIVE}

    events = lines(folder / score.EVENTS_FILE)
    of_step: dict[str, list[dict]] = defaultdict(list)
    for document in events:
        labels = document.get("labels") or {}
        if labels.get("origin") == score.STEP and (document.get("host") or {}).get("name") in sensors:
            of_step[labels["step_id"]].append(document)
    # Each detector's alert lines, in the order: the manager's, then each rule set's matches.
    alerts = {
        entry["id"]: lines(
            folder / (score.ALERTS_FILE if entry["id"] in live else score.MATCHES_FILE.format(entry["id"]))
        )
        for entry in found
    }
    on_step: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for detector, documents in alerts.items():
        for document in documents:
            labels = document.get("labels") or {}
            if labels.get("origin") == score.STEP:
                on_step[labels["step_id"]].append((detector, document))

    named_evidence = {
        event_id
        for documents in on_step.values()
        for _, document in documents
        for event_id in ecs.evidence_ids(document)
    }
    plain = {
        step.get("id"): step.get("plain")
        for step in ((spec.get("path") or {}).get("steps") or [])
        if isinstance(step, dict)
    }
    databases = error_logs(spec)
    steps, kept_events, kept_alerts, cut, late_cut = [], [], [], 0, 0
    placed_all: dict[str, dict] = {}
    for order, record in enumerate(path.get("steps") or [], start=1):
        step_id = record["id"]
        mine = sorted(of_step.get(step_id, []), key=lambda d: d["@timestamp"])
        # The cut of a step with very many events is made for each sensor, so that no defense's sensors
        # are cut out by another's: the first of each sensor's events up to its share, and every event
        # a rule matched.
        room = shares(Counter(sensor_of(d) for d in mine), lab.KEPT_EVENTS)
        placed: dict[str, dict] = {}
        for number, document in enumerate(mine, start=1):
            sensor = sensor_of(document)
            if room[sensor] > 0 or (document.get("event") or {}).get("id") in named_evidence:
                placed[(document.get("event") or {}).get("id")] = event_of(
                    document, step_id, number, databases
                )
            room[sensor] -= 1
        kept_events += placed.values()
        placed_all.update(placed)
        cut += len(placed) < len(mine)
        for detector, document in on_step.get(step_id, []):
            rule = rule_of(document)
            event_id = (document.get("labels") or {}).get("event_id")
            linked = placed.get(event_id)
            evidence_ids = ecs.evidence_ids(document)
            linked_evidence = [placed_all.get(value) for value in evidence_ids]
            missing_evidence = [
                value
                for value, evidence in zip(evidence_ids, linked_evidence, strict=True)
                if evidence is None
            ]
            if linked and missing_evidence:
                raise ValueError(
                    f"the alert of rule {rule['id']} at {document['@timestamp']} on {step_id} names "
                    f"evidence outside the path events kept in the recording: {', '.join(missing_evidence)}"
                )
            if rule["level"] in COUNTING and not linked:
                # The format needs a counting alert to name the event it was raised on.
                where = (
                    " is not in the archive (a delivery gap)"
                    if event_id is None
                    else f", {event_id}, is not among the step's events"
                )
                raise ValueError(
                    f"the alert of rule {rule['id']} at {document['@timestamp']} on {step_id} counts, but the "
                    f"archived line it was raised on{where}, so no recording is written"
                )
            time = linked["time"] if linked else document["@timestamp"]
            # The manager's time can run behind the line's (see score.clock): raised is then left out, and
            # the alert counts from its line's time, as score.raised_at does. A rule that was evaluated
            # after the run was never raised.
            late = detector in live and document["@timestamp"] >= time
            late_cut += detector in live and not late
            kept_alerts.append(
                {
                    "time": time,
                    **({"raised": document["@timestamp"]} if late else {}),
                    "host": (document.get("host") or {}).get("name"),
                    "detector": detector,
                    "rule": {**rule, "origin": "pinned"},
                    "counts": rule["level"] in COUNTING,
                    "step": step_id,
                    "events": [evidence["id"] for evidence in linked_evidence if evidence] if linked else [],
                }
            )
        to = record.get("to") or []
        daemon = ecs.step_clock(record) == "daemon"
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
            )
        )
    kept_events.sort(key=lambda found: found["time"])
    kept_alerts.sort(key=lambda found: found["time"])
    kept_alerts = [{"id": f"alert-{number}", **found} for number, found in enumerate(kept_alerts, start=1)]

    goal = path.get("goal") or {}
    on_host = {sensor_id(agent): agent for agent in defense.get("agents") or []}
    when = {entry["id"]: entry["when"] for entry in found}
    views = [
        view(entry, steps, path, kept_events, kept_alerts, alerts, when, on_host, alert_level)
        for entry in judged
    ]
    # The top level is the recording as its first defense sees it.
    first = views[0]
    steps = [{**step, **first["steps"][step["id"]]} for step in steps]
    tests = [step for step in steps if step["role"] == "test"]
    # A published test that runs twice, as the port scan does against two hosts, is one test of two steps.
    distinct = {step["test"]["guid"] for step in tests}
    environment = manifest.get("environment") or "containers on a developer machine"
    atomic = manifest.get("atomic_red_team") or {}
    # Source names what made the run, so it stays byte-for-byte stable when the same telemetry is
    # judged again by another defense. Post-run rules and their engine belong to detector metadata
    # and notes; the live Wazuh components stay here even when a selected defense does not use them.
    tools = [
        ("Atomic Red Team", atomic.get("commit"), "tests"),
        ("Wazuh agent", defense.get("wazuh_version"), "sensor"),
        ("snoopy", installed(folder, defense.get("agents") or [], "snoopy"), "sensor"),
        ("Wazuh ruleset", defense.get("wazuh_version"), "rules"),
        ("Wazuh manager", defense.get("wazuh_version"), "rule engine"),
    ]
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
            # A tool whose version the run does not hold is left out, and one is named once.
            tools=[
                {"name": name, "version": version, "role": role}
                for name, version, role in dict.fromkeys(tools)
                if version
            ],
            setup=lab.known(
                atomic_commit=atomic.get("commit"),
                images={host: str(image.get("id")) for host, image in (manifest.get("images") or {}).items()}
                or None,
            ),
        ),
        network=network(manifest, spec, found),
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
        ordinary=first["ordinary"],
        score=first["score"],
        # Only a spec that names its defenses gets them in its recording: one that names none is as before.
        defenses=views if (manifest.get("score") or {}).get("defenses named") else None,
        notes=notes(manifest, scored, path, spec, cut, late_cut),
    )
    return lab.visible(made)


def view(
    judged: dict,
    steps: list[dict],
    path: dict,
    events: list[dict],
    alerts: list[dict],
    lines_of: dict[str, list[dict]],
    when: dict[str, str],
    on_host: dict[str, str],
    alert_level: int,
) -> dict:
    """One defense's part of a recording: for every step its own visibility, outcome, first event and first
    alert, then its ordinary day and its score.

    It is the recording as that defense alone sees it: only the events of its
    sensors, only the alerts of its detectors, and every number counted from
    those. `judged` is the defense as the score judged it, `events` and
    `alerts` what the recording holds, `lines_of` each detector's alert lines,
    `when` whether each detector ran live or after the run, and `on_host` the
    host of each sensor.
    """

    sensors, mine = set(judged["sensors"]), set(judged["detectors"])
    watched = {on_host[sensor] for sensor in sensors if sensor in on_host}
    seen = {entry["id"]: entry for entry in judged["steps"]}
    hosts = {
        step["id"]: record.get("host") for step, record in zip(steps, path.get("steps") or [], strict=True)
    }
    answers = {}
    for step in steps:
        entry = seen[step["id"]]
        held = [event for event in events if event["step"] == step["id"] and event["sensor"] in sensors]
        counting = [
            alert.get("raised", alert["time"])
            for alert in alerts
            if alert["step"] == step["id"] and alert["detector"] in mine and alert["counts"]
        ]
        first = entry.get("first_alert")
        # A defense can run live rules and rules evaluated after the run: its first alert is told as its
        # own rules ran, and its matches below the alert level are counted apart for each kind of rules.
        below: Counter = Counter()
        for rule in entry["rules"]:
            below[when[rule["detector"]]] += rule["matches"]
        said = basis(
            {
                **entry,
                "host": hosts[step["id"]],
                "alerts": below[score.LIVE],
                "matches after the run": below[score.AFTER],
                "first_alert": {**first, "raised": first["moment"]} if first else None,
            },
            alert_level,
            when[first["detector"]] == score.LIVE if first else True,
        )
        answers[step["id"]] = lab.known(
            visibility=lab.known(
                answer=entry["visibility"],
                basis=said,
                events=None if entry["visibility"] == "not applicable" else entry["events"],
                kept=len(held) if len(held) < entry["events"] else None,
            ),
            outcome=entry["outcome"],
            first_event=min((event["time"] for event in held), default=None),
            first_alert=min(counting, default=None),
        )

    rules: dict[tuple[str, str], dict] = {}
    for detector in judged["detectors"]:
        for document in lines_of[detector]:
            if (document.get("labels") or {}).get("origin") != score.ORDINARY:
                continue
            if (document.get("host") or {}).get("name") not in watched:
                continue
            rule = rule_of(document)
            rules.setdefault((detector, rule["id"]), {**rule, "events": 0})["events"] += 1
    repeated = Counter(rule["id"] for rule in rules.values())
    ordinary_rules = [
        {
            **rule,
            "id": f"{detector}:{rule['id']}" if repeated[rule["id"]] > 1 else rule["id"],
        }
        for (detector, _), rule in rules.items()
    ]
    ordinary = {"events": judged["ordinary"]["events"], "matches": lab.ordinary_matches(ordinary_rules)}

    tests = [step for step in steps if step["role"] == "test"]
    took = [step for step in tests if step["happened"]["answer"] == "took effect"]
    words = Counter(answers[step["id"]]["outcome"] for step in took)
    totals: dict = {"steps": len(tests), "took_effect": len(took)}
    totals.update({word: words[word] for word in ("alerted", "seen", "unseen")})
    totals["stopped"] = sum(1 for step in steps if answers[step["id"]]["outcome"] == "stopped")
    goal = path.get("goal") or {}
    start = steps[0].get("started") if steps else None
    if start:
        alerted = [
            answers[step["id"]]["first_alert"] for step in tests if "first_alert" in answers[step["id"]]
        ]
        if alerted:
            totals["first_alert_seconds"] = max(0.0, score.seconds_between(start, min(alerted)))
        end = next((step.get("ended") for step in steps if step["id"] == goal.get("after")), None)
        if goal.get("passed") and end:
            totals["goal_seconds"] = score.seconds_between(start, end)
    totals["false_alerts"] = sum(1 for match in ordinary["matches"] if match["level"] in COUNTING)
    return {
        "id": judged["id"],
        "name": judged["name"],
        "sensors": judged["sensors"],
        "detectors": judged["detectors"],
        "steps": answers,
        "ordinary": ordinary,
        "score": totals,
    }


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
            f"{lab.KEPT_EVENTS} of each, shared in equal parts among the sensors that recorded them, and every "
            "event a rule matched; events.ecs.ndjson holds them all."
        )
    said += defense_notes(manifest)
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


def matched_rule_notes(name: str, matched: list[dict]) -> list[str]:
    """Name every matched rule and its author in notes the recording format can import."""

    opening = f"The rules of {name} that matched in this run, each with its author as the rule gives it: "
    continuation = f"The matched rules of {name}, continued: "
    notes, current = [], opening
    for rule in matched:
        attribution = f"{rule['title']} ({rule['rule']}), by {rule.get('author') or 'no author named'}"
        separator = "" if current in (opening, continuation) else "; "
        candidate = current + separator + attribution + "."
        if len(candidate) <= lab.KEPT_TEXT:
            current += separator + attribution
            continue
        if current not in (opening, continuation):
            notes.append(current + ".")
            current, separator = continuation, ""
        # Public rules fit as one attribution. Still preserve an unusually long author instead of
        # silently cutting its credit: carry the exact text into as many bounded notes as it needs.
        while len(current + attribution + ".") > lab.KEPT_TEXT:
            suffix = " [continued]"
            room = lab.KEPT_TEXT - len(current) - len(suffix)
            notes.append(current + attribution[:room] + suffix)
            attribution = attribution[room:]
            current = continuation
        current += attribution
    if current not in (opening, continuation):
        notes.append(current + ".")
    return notes


def defense_notes(manifest: dict) -> list[str]:
    """What a reader must know of the named defenses: which judged the run, and for each rule set that was
    evaluated after the run what its rules were given and what they were not."""

    result = manifest.get("score") or {}
    judged, sets = result.get("defenses") or [], result.get("rule sets") or {}
    said = []
    if not result.get("defenses named"):
        return said
    held = [entry for entry in judged if entry["judged"]]
    said.append(
        f"{lab.count(len(held), 'defense')} judged this one run, each counting only the events of its own "
        "sensors and the alerts of its own detectors: "
        + "; ".join(f"{entry['name']} ({entry['id']})" for entry in held)
        + f". The top level of the recording is the first, {held[0]['id']}. Every event that a rule of any "
        "of them matched is kept, so a step's kept, in each defense's view, also counts the events beyond the "
        "step's cut that the rules of another defense matched."
    )
    said += [
        f"The defense {entry['id']} of the spec is not in this recording: it was not judged, since "
        f"{entry['not judged']}."
        for entry in judged
        if not entry["judged"]
    ]
    source = manifest.get("judged_by")
    if source:
        said.append(
            f"The defenses are those of the spec {source['file']} (SHA-256 {source['sha256']}), given when the "
            "run was scored again, and not those of the spec the run ran."
        )
    used = {name for entry in held for name in entry["detectors"]}
    for name, entry in sets.items():
        if not entry.get("evaluated") or name not in used:
            continue
        repo, _, commit = entry["source"].partition("@")
        engine = lab.named(entry["engine"]["name"], entry["engine"].get("version"))
        said.append(
            f"The detector {name} is the public rule set {repo} at commit {commit}, evaluated after the run by "
            f"{engine} over the events the sensors recorded. Its alerts have the time of their event and no "
            f"raised time, and count from that time. Of its {entry['rules']} rules the engine loaded "
            f"{entry['loaded']}; a rule it did not load was not evaluated."
        )
        matched = entry.get("rules that matched") or []
        if matched:
            # The rule set's licence asks that what is said of a match keeps the rule's author.
            said += matched_rule_notes(name, matched)
        groups = [group for group in entry["groups"] if not group.get("not evaluated")]
        given = "; ".join(
            f"{group['log source']}: {', '.join(group['fields given']) or 'the line itself'}, of "
            f"{group['given']} {group['events']}"
            for group in groups
        )
        missing = []
        for group in groups:
            fields = group.get("fields the rules name that are not given") or {}
            if fields:
                missing.append(
                    f"{group['log source']}: "
                    + ", ".join(
                        f"{field} ({lab.count(rules, 'rule names', 'rules name')} it)"
                        for field, rules in fields.items()
                    )
                )
        said.append(
            f"The rules of {name} were given, by Sigma log source: {given}. "
            + (
                "Fields not given for any event of a log source, although that source's rules name them: "
                + "; ".join(missing)
                + ". A rule cannot match on a field it was not given."
                if missing
                else "Every field they name was given."
            )
        )
        starts = next((group for group in groups if group["log source"] == sigma.PROCESS.name), None)
        if starts and "User" in starts["fields given"]:
            said.append(
                "A program start's User is the login name snoopy recorded, which is not always the account "
                "the program ran as."
            )
        if starts and "Image" not in starts["fields given"]:
            said.append(
                "The run's snoopy lines do not hold the path of the program they log, as in a run made before "
                f"the hosts' sensor recorded it: its program starts have no Image, and the rules of {name} that "
                "need one could match nothing."
            )
        skipped = [group for group in entry["groups"] if group.get("not evaluated")]
        if skipped:
            said.append(
                f"Not evaluated, of {name}: "
                + "; ".join(
                    f"{lab.count(group['rules'], 'rule')} of {group['folder']} ({group['not evaluated']})"
                    for group in skipped
                )
                + "."
            )
        said.append(
            "The file integrity sensor does not know which program wrote a file, and the lab's snoopy line "
            "names no parent program: a rule that needs either cannot match here."
        )
    return said


def write(folder: Path) -> dict:
    """Write recording.json into a run folder; returns how many steps, events and alerts it holds."""

    made = build(folder)
    (folder / FILE).write_text(json.dumps(made, indent=1) + "\n", encoding="utf-8")
    return {"steps": len(made["steps"]), "events": len(made["events"]), "alerts": len(made["alerts"])}
