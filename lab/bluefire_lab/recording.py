"""Write recording.json: what really happened in a run, in one file that can be replayed.

The format is docs/RECORDING.md. Every value comes from run.json and
results.json, and the digests of the rule sets from the rule files in the run's
folder; one the run did not measure is left out. The rules were evaluated after
the run, so an alert carries the time of the event it matched.
"""

from __future__ import annotations

import collections
import hashlib
import json
from datetime import datetime
from pathlib import Path

import yaml

from .evaluate import step_of
from .report import count

HOST = "target"
# A step keeps this many of its events, the first in time order, and every later one a rule matched.
KEPT_EVENTS = 300
# The longest command, output and event text, and the longest value of a field, in characters.
KEPT_TEXT, KEPT_FIELD = 2000, 300
# The fields of a record that go with its event, under the sensors' own names: Sysmon's, then auditd's.
FIELDS = (
    "EventRecordID", "ProcessId", "ParentProcessId", "ParentImage", "ParentCommandLine", "TargetFilename",
    "pid", "ppid", "success", "exit", "key", "paths", "command",
)  # fmt: skip
# What each sensor records under the configuration in lab/sensors.
RECORDS = {
    "sysmon": "process starts and ends, network connections, and files created and deleted",
    "auditd": "program starts with their arguments, changes to the files its rules watch, and what programs "
    "such as sudo and useradd report about themselves",
}


def utc(text: str) -> str:
    """A sensor's time, "2026-11-17 17:07:23.834" in UTC, as a recording writes it."""

    moment = datetime.fromisoformat(text)
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{moment.microsecond // 1000:03d}Z"


def seconds(start: str, end: str) -> float:
    """From one of a recording's sensor times to another."""

    first, second = (datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ") for text in (start, end))
    return (second - first).total_seconds()


def cut(text: str, limit: int) -> str:
    """The text, or its start and three dots when it is longer than the limit."""

    return text if len(text) <= limit else text[: limit - 3] + "..."


def known(**values: object) -> dict:
    """The values by name, without those the run did not measure."""

    return {name: value for name, value in values.items() if value not in (None, "")}


def named(name: str, version: str | None) -> str:
    return f"{name} {version}" if version else name


def digest(folder: Path) -> str | None:
    """The SHA-256 of a rule set: of the lines sha256sum prints for its files, sorted by their path
    inside the folder. None when the folder is not there; an empty folder has the digest of nothing."""

    if not folder.is_dir():
        return None
    files = sorted(
        (path.relative_to(folder).as_posix(), path) for path in folder.rglob("*") if path.is_file()
    )
    listing = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}\n" for name, path in files)
    return hashlib.sha256(listing.encode("utf-8")).hexdigest()


def step_ids(tests: list[dict]) -> dict[int, str]:
    """The id of each test of the run, by its order: the same in every run of the same list.
    Its role and the first 8 characters of its GUID, then the first 6 hex digits of the SHA-256 of
    its input arguments when it has any, then the name of its hardening change when it has one, and
    when the same id comes more than once, as the canary's does, its count among them."""

    names = []
    for test in tests:
        parts = [test["role"], test["guid"][:8]]
        if test.get("args"):
            text = json.dumps(test["args"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            parts.append(hashlib.sha256(text.encode("utf-8")).hexdigest()[:6])
        if test.get("defense"):
            parts.append(test["defense"]["name"])
        names.append(":".join(parts))
    repeated, counted = collections.Counter(names), collections.Counter()
    ids = {}
    for test, name in zip(tests, names, strict=True):
        if repeated[name] > 1:
            counted[name] += 1
            name = f"{name}:{counted[name]}"
        ids[test["order"]] = name
    return ids


def plain_words(document: dict) -> dict[str, str]:
    """The plain sentence of each test on the list of pinned tests, by the test's GUID."""

    specs = [document.get("canary"), document.get("control"), *document.get("tests", [])]
    return {spec["guid"]: spec["plain"] for spec in specs if spec and "plain" in spec}


def outcome(happened: str, seen: str) -> str:
    """The score word of a step: the first that holds, in the order the format gives."""

    if happened == "blocked":
        return "stopped"
    if happened in ("attempted without effect", "not attempted"):
        return "no effect"
    if seen == "alert":
        return "alerted"
    if seen == "telemetry only":
        return "seen"
    if happened == "took effect" and seen == "no telemetry":
        return "unseen"
    return "inconclusive"


def event(found: dict, step: str, number: int, order: int | None = None) -> dict:
    """One event of a step as a recording holds it: a few fields of its record, never all of it.
    Its id is the step's order (or else its id) and its place among the step's events, whether
    or not all are kept."""

    audit = isinstance(found["record"], str)  # "audit <seconds>.<ms>:<serial>"; Sysmon numbers its records
    fields = {
        name: cut(str(value), KEPT_FIELD)
        for name, value in found["fields"].items()
        if name in FIELDS and value not in ("", None)
    }
    kind, text = found["kind"].removesuffix(" (auditd)"), found["detail"]
    if audit:
        fields["msg"] = f"audit({found['record'].removeprefix('audit ')})"  # as auditd's log names the event
        # auditd's detail names every path of the record and then the command: keep the one a reader needs.
        if kind in ("execve", "execveat") and found["fields"].get("command"):
            text = found["fields"]["command"]
        elif kind == "openat" and found["fields"].get("paths"):
            text = found["fields"]["paths"].split(", ")[0]
    return {
        "id": f"{step if order is None else order}-{number}",
        "time": utc(found["time"]),
        "host": HOST,
        "sensor": "auditd" if audit else "sysmon",
        "kind": kind,
        "text": cut(" ".join(text.splitlines()), KEPT_TEXT),
        "step": step,
        "tied_by": found["why"],
        # Sysmon writes "-" for a user it does not know.
        **known(user=None if found["user"] == "-" else found["user"], image=found["image"]),
        "fields": fields,
    }


def rule_matches(seen: dict, accepted: set[str]) -> list[tuple[dict, bool]]:
    """The rule matches of a step that a recording holds, each with whether the rule matched
    only the launcher: those of the pinned rules, and of the lab's own rules the run accepted."""

    matches = [(rule, False) for rule in seen.get("rules", [])]
    matches += [(rule, False) for rule in seen.get("with_lab_rules", {}).get("rules", [])]
    matches += [(rule, True) for rule in seen.get("launcher_only_rules", [])]
    return [(rule, only) for rule, only in matches if rule.get("origin") != "lab" or rule["id"] in accepted]


def network(results: dict, digests: dict[str, str | None]) -> dict:
    """The one host the tests ran on, its sensors, and the rule sets that read their records,
    each with the digest of its files when the run's folder holds them."""

    target, rules = results["run"]["target"], results["rules"]
    system = [target.get("os")] + [
        f"{label} {target[key]}"
        for key, label in (("kernel", "kernel"), ("runner_image", "runner image"))
        if target.get(key)
    ]
    sensors = {"sysmon": results["sensor"]}
    if results.get("audit"):
        sensors["auditd"] = results["audit"]
    engine = named(results["engine"]["name"], results["engine"].get("version"))
    detectors = [
        known(
            id="pinned",
            name=f"Published Sigma rules ({rules['source'].partition('@')[0]}) with {engine}",
            rules=sum(number or 0 for number in rules["evaluated"].values()),
            when="after the run",
            digest=digests.get("pinned"),
        )
    ]
    if results.get("lab_rules"):
        detectors.append(
            known(
                id="lab",
                name=f"Rules written in this repository with {engine}",
                rules=rules.get("lab", len(results["lab_rules"])),
                when="after the run",
                digest=digests.get("lab"),
                # Whether the run accepted each rule, and the digest of the file that holds it.
                verdicts=[
                    known(
                        rule=rule["id"],
                        title=rule["title"],
                        digest=hashlib.sha256(rule["text"].encode("utf-8")).hexdigest()
                        if "text" in rule
                        else None,
                        accepted=rule["accepted"],
                        reason=rule.get("reason"),
                    )
                    for rule in results["lab_rules"]
                ],
            )
        )
    return {
        "hosts": [
            known(
                id=HOST,
                name="GitHub-hosted runner",
                role="Linux host under test",
                kind="host",
                os=", ".join(part for part in system if part),
            )
        ],
        "sensors": [
            {
                "id": sensor_id,
                "name": named(sensor["name"], sensor.get("version")),
                "host": HOST,
                "records": RECORDS[sensor_id],
            }
            for sensor_id, sensor in sensors.items()
        ],
        "detectors": detectors,
    }


def source(results: dict, run_url: str | None) -> dict:
    """Where and when the run happened, and the pinned tools it used."""

    run, pins, audit = results["run"], results["run"]["tools"], results.get("audit")
    repository, _, commit = (pins.get("lab") or "").partition("@")
    defense_commit = (pins.get("lab-defense") or "").partition("@")[2]
    rules, _, rules_commit = results["rules"]["source"].partition("@")
    tools = [
        ("Atomic Red Team", pins.get("atomic-red-team"), "tests"),
        ("Invoke-AtomicRedTeam", pins.get("invoke-atomicredteam"), "executor"),
        (results["sensor"]["name"], results["sensor"].get("version"), "sensor"),
        *([(audit["name"], audit.get("version"), "sensor")] if audit else []),
        (rules, rules_commit, "rules"),
        (results["engine"]["name"], results["engine"].get("version"), "rule engine"),
    ]
    return known(
        engine="bluefire-lab",
        environment="GitHub-hosted runner",
        started=run["started"],
        finished=run.get("finished"),
        repository=repository if commit else None,
        commit=commit if repository else None,
        # The commit the lab's own rules and the sensors' settings came from, when the run says.
        defense_commit=defense_commit or None,
        run_url=run_url,
        tools=[known(name=name, version=version, role=role) for name, version, role in tools],
        setup=setup(results),
    )


def setup(results: dict) -> dict | None:
    """What two runs must share for a comparison of them to say what one change did: the tests'
    commit, the runner's image and kernel, and the digest of each sensor's settings as loaded."""

    target, audit = results["run"]["target"], results.get("audit") or {}
    sensors = known(sysmon=results["sensor"].get("configuration_sha256"), auditd=audit.get("rules_sha256"))
    return (
        known(
            atomic_commit=results["run"]["tools"].get("atomic-red-team"),
            images=known(**{HOST: target.get("runner_image")}) or None,
            kernels=known(**{HOST: target.get("kernel")}) or None,
            sensors=sensors or None,
        )
        or None
    )


def score(steps: list[dict], ordinary: dict | None, results: dict) -> dict:
    """The totals: the steps of role "test" by outcome, what was stopped, and the false alerts. A test
    list has no time to the first alert, since its steps do not build on each other: each step has its own."""

    tests = [step for step in steps if step["role"] == "test"]
    took = [step for step in tests if step["happened"]["answer"] == "took effect"]
    first = collections.Counter(step["outcome"] for step in took)
    second = collections.Counter(step.get("outcome_with_lab_rules", step["outcome"]) for step in took)
    totals = {"steps": len(tests), "took_effect": len(took)}
    totals.update({word: first[word] for word in ("alerted", "seen", "unseen")})
    if results.get("lab_rules"):
        totals["alerted_with_lab_rules"] = second["alerted"]
    totals["stopped"] = sum(1 for step in steps if step["outcome"] == "stopped")
    if ordinary:
        # One rule that matched ordinary activity is one false alert, as one rule on one step is one alert.
        levels = results["rules"]["alert_levels"]
        totals["false_alerts"] = sum(1 for match in ordinary["matches"] if match["level"] in levels)
    return totals


def notes(run: dict, results: dict, steps: list[dict], events: list[dict], listed: int = 0) -> list[str]:
    """The limits a reader must know, in plain sentences. listed counts the steps whose plain
    sentence came from the list of tests given to the converter, not from the run."""

    said = [
        "The rules were evaluated after the run ended, so an alert's time is the time of the event it matched.",
        "A step starts when Sysmon records the shell that carries the test, and ends at a marker the lab runs "
        "after it. For a test that schedules something, the marker comes after the wait the list of tests sets.",
    ]
    starts = {step["id"]: step["started"] for step in steps if "started" in step}
    early = [
        seconds(found["time"], starts[found["step"]])
        for found in events
        if found["time"] < starts.get(found["step"], "")
    ]
    if early:
        said.append(
            "Each sensor stamps its own records, so an event can be earlier than the start of its step, here "
            f"by up to {round(max(early) * 1000)} ms ({count(len(early), 'event')})."
        )
    failed = [check["detail"] for check in results.get("controls", []) if not check["passed"]]
    if failed:
        said.append(
            f"{count(len(failed), 'control')} of the run failed, so this run does not support its results: "
            + "; ".join(failed)
            + "."
        )
    if results["run"].get("aborted"):
        said.append(f"The run stopped early: {results['run']['aborted']}.")
    ordinary = [str(test["order"]) for test in run["tests"] if test["role"] == "baseline"]
    if ordinary:
        said.append(
            f"Position {' and '.join(ordinary)} of the run was ordinary administration, not an attack step: "
            "what the rules said about it is under ordinary."
        )
    dropped = results.get("dropped", [])
    if dropped:
        named_ = "; ".join(f"{test['technique']} {test['name']} ({test['reason']})" for test in dropped)
        said.append(f"{count(len(dropped), 'test')} on the list did not run: {named_}.")
    verdicts = results.get("lab_rules", [])
    if verdicts:
        refused = [rule for rule in verdicts if not rule["accepted"]]
        said.append(
            f"The run accepted {len(verdicts) - len(refused)} of the {count(len(verdicts), 'rule')} written "
            "in this repository. A match of a rule it did not accept is not in the recording."
            + (
                " Not accepted: " + "; ".join(f"{rule['title']} ({rule['reason']})" for rule in refused) + "."
                if refused
                else ""
            )
        )
    cut_short = sum(1 for step in steps if "kept" in step["visibility"])
    if cut_short:
        said.append(
            f"{count(cut_short, 'step')} left more than {KEPT_EVENTS} events. The recording keeps the first "
            f"{KEPT_EVENTS} of each and every event a rule matched, and the run's results.json holds them all."
        )
    if listed:
        said.append(
            f"The plain sentence of {count(listed, 'step')} comes from the list of tests given to the "
            "converter, not from the run."
        )
    return said


def build(
    run: dict,
    results: dict,
    run_url: str | None = None,
    plain: dict[str, str] | None = None,
    digests: dict[str, str | None] | None = None,
) -> dict:
    """The recording of a run. plain gives the plain sentence of a test by its GUID, for a run
    made before the run itself recorded those, and digests the digest of each rule set by its
    detector's id."""

    plain, lab_rules, listed = plain or {}, bool(results.get("lab_rules")), 0
    ids = step_ids(results["tests"])
    accepted = {rule["id"] for rule in results.get("lab_rules", []) if rule["accepted"]}
    printed = {}
    for test in run["tests"]:
        attack = step_of(test, "attack")
        if attack:
            # The end of what a test printed says how it went: a cut output keeps its end and starts with "...".
            text = (attack["output"] + attack["error"]).strip()
            printed[test["order"]] = text if len(text) <= KEPT_TEXT else "..." + text[-(KEPT_TEXT - 3) :]

    steps, events, alerts = [], [], []
    for test in results["tests"]:
        done, seen, step_id = test["execution"], test["visibility"], ids[test["order"]]
        launcher, window, change = seen.get("launcher"), seen.get("window"), test.get("defense")
        matches = rule_matches(seen, accepted)
        cited = {record for rule, only in matches if not only for record in rule["records"]}
        placed = {
            found["record"]: event(found, step_id, number, test["order"])
            for number, found in enumerate(test["events"], start=1)
            if number <= KEPT_EVENTS or found["record"] in cited
        }
        events += placed.values()
        raised = []
        for rule, only in matches:
            # The launcher's start is the step's command, not one of its events.
            matched = [] if only else [placed[record] for record in rule["records"]]
            origin = rule.get("origin", "pinned")
            raised.append(
                {
                    "time": utc(launcher["time"]) if only else min(found["time"] for found in matched),
                    "host": HOST,
                    "detector": origin,
                    "rule": {
                        "id": rule["id"],
                        "title": rule["title"],
                        "level": rule["level"],
                        "origin": origin,
                    },
                    "counts": rule["alert"] and not only,
                    "step": step_id,
                    "events": [found["id"] for found in matched],
                    **({"launcher_only": True} if only else {}),
                }
            )
        alerts += raised
        first = outcome(done["answer"], seen["answer"])
        second = outcome(done["answer"], seen.get("with_lab_rules", {}).get("answer", seen["answer"]))
        # Like outcome, first_alert counts the published rules only; the second time counts the lab's too.
        published = [alert["time"] for alert in raised if alert["counts"] and alert["detector"] == "pinned"]
        every = [alert["time"] for alert in raised if alert["counts"]]
        timed = bool(launcher and window)
        listed += not test.get("plain") and test["guid"] in plain
        steps.append(
            known(
                id=step_id,
                order=test["order"],
                role=test["role"],
                title=test["name"],
                plain=test.get("plain") or plain.get(test["guid"]),
                technique=known(
                    id=test["technique"], name=test.get("technique_name"), tactic=test.get("tactic")
                ),
                test={
                    "project": "Atomic Red Team",
                    "guid": test["guid"],
                    "executor": test["executor"],
                    "elevated": test["elevated"],
                },
                host=HOST,
                started=utc(launcher["time"]) if timed else None,
                ended=utc(window[1]) if timed else None,
                command=cut(launcher["detail"], KEPT_TEXT) if launcher else None,
                output=printed.get(test["order"]),
                happened={"answer": done["answer"], "basis": done["basis"]},
                visibility=known(
                    answer=seen["answer"],
                    basis=seen["basis"],
                    # Left out when the engine could not tie events to the step.
                    events=seen.get("events"),
                    kept=len(placed) if len(placed) < len(test["events"]) else None,
                ),
                outcome=first,
                outcome_with_lab_rules=second if lab_rules else None,
                first_event=utc(test["events"][0]["time"]) if test["events"] else None,
                first_alert=min(published, default=None),
                first_alert_with_lab_rules=min(every) if lab_rules and every else None,
                compared_with=ids.get(test["compared_with"]) if "compared_with" in test else None,
                defense={"title": change["title"], "why": change["why"]} if change else None,
            )
        )
    events.sort(key=lambda found: found["time"])
    alerts.sort(key=lambda alert: alert["time"])
    alerts = [{"id": f"alert-{number}", **alert} for number, alert in enumerate(alerts, start=1)]

    ordinary = None
    if results.get("ordinary_activity"):
        activity = results["ordinary_activity"]
        ordinary = {
            "events": activity["baseline_events"] + activity["system_events"],
            "matches": [
                {"rule": rule["title"], "level": rule["level"], "count": rule["events"]}
                for rule in activity["pinned_rules"]
            ],
        }
    account = results["run"].get("account")
    return known(
        schema="bluefire.recording/1",
        id=results["run"]["id"],
        title=f"{count(sum(1 for step in steps if step['role'] == 'test'), 'published test')} on one Linux host",
        kind="test list",
        source=source(results, run_url),
        network=network(results, digests or {}),
        attacker={
            "kind": "scripted",
            "description": "Invoke-AtomicRedTeam ran each published test in turn, as "
            + (f"the account {account}" if account else "an unprivileged account")
            + ", or as root where the test needs it.",
            "goal": None,
        },
        steps=steps,
        events=events,
        alerts=alerts,
        ordinary=ordinary,
        score=score(steps, ordinary, results),
        notes=notes(run, results, steps, events, listed),
    )


def main(folder: Path, run_url: str | None = None, tests: Path | None = None) -> int:
    run, results = (
        json.loads((folder / name).read_text(encoding="utf-8")) for name in ("run.json", "results.json")
    )
    plain = plain_words(yaml.safe_load(tests.read_text(encoding="utf-8"))) if tests else {}
    # The rules the run used travel with its results: the published ones, and the lab's own apart.
    digests = {"pinned": digest(folder / "rules" / "linux"), "lab": digest(folder / "lab-rules" / "linux")}
    made = build(run, results, run_url, plain, digests)
    (folder / "recording.json").write_text(json.dumps(made, indent=1) + "\n", encoding="utf-8")
    print(
        f"recording.json: {count(len(made['steps']), 'step')}, {count(len(made['events']), 'event')}, "
        f"{count(len(made['alerts']), 'alert')}"
    )
    return 0
