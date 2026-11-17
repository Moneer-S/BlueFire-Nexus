"""Compute the two answers for every test from the files a run leaves behind.

Input, all in the run folder: run.json (what the driver did), sysmon.txt (what
the sensor wrote, untouched) and rules/ (the pinned Sigma rules). The rule
engine is a separate program. Output: results.json.

Every test gets two answers.

Execution: "not attempted" when a prerequisite was missing, "took effect" or
"attempted without effect" by the test's effect check: a command run after the
test, a text only the effect prints, or failing both the test's exit status.
"blocked" is reserved for a run that compares against a baseline.

Visibility: "alert" when a rule of an alert level matched an event of the test,
"telemetry only" when the test left events but no such match, "no telemetry"
when it left none. "inconclusive" when the measurement cannot be trusted.

The executor starts a test as one shell process whose command line is the whole
test. That process start is not counted as telemetry of the test, and a rule
that matches nothing else is reported apart.
"""

from __future__ import annotations

import collections
import hashlib
import json
import re
import subprocess
from pathlib import Path

import yaml

from . import sysmon

# The Sigma specification says a match of a "high" rule should trigger an alert
# and a "critical" one indicates an incident. Lower levels are for review.
ALERT_LEVELS = ("high", "critical")

# systemd 255 starts a unit's command through this helper, which then becomes
# the command. Its start is systemd's own step, not part of what a test did.
SYSTEMD_HELPER = "/systemd-executor"

# The programs a launcher can be, by the executor a test declares. On Ubuntu sh is dash.
SHELLS = {"sh": ("/sh", "/dash"), "bash": ("/bash",)}

# Sigma log source category -> the Sysmon event it describes.
CATEGORIES = {
    "process_creation": sysmon.PROCESS_START,
    "file_event": sysmon.FILE_CREATED,
    "network_connection": sysmon.NETWORK,
}

# What the rule engine writes in its log about the rules it loaded and the events it read.
_LOADED = re.compile(r"(\d[\d,]*) rules loaded")
_READ = re.compile(r"Total events processed: (?:\[\w+\])?(\d[\d,]*)")


def rule_index(rules: Path) -> dict[str, dict]:
    """The pinned rules by id, with what a report has to say about a rule that matched."""

    index = {}
    for path in sorted(rules.rglob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for rule in yaml.safe_load_all(text):
            if isinstance(rule, dict) and "id" in rule and "detection" in rule:
                index[str(rule["id"])] = {
                    "id": str(rule["id"]),
                    "title": rule.get("title", ""),
                    "level": rule.get("level", "informational"),
                    "author": rule.get("author", ""),
                    "file": path.relative_to(rules.parent).as_posix(),
                    "text": text,
                }
    return index


def engine_counts(log: str) -> tuple[int | None, int | None]:
    """How many rules the engine loaded and how many events it read, from its own log."""

    def number(found: re.Match | None) -> int | None:
        return int(found.group(1).replace(",", "")) if found else None

    return number(_LOADED.search(log)), number(_READ.search(log))


def run_engine(
    engine: Path, run_dir: Path, events: list[dict], raw: list[str]
) -> tuple[dict[str, list[str]], dict[str, dict]]:
    """Have the rule engine evaluate each folder of rules over the events it describes.

    Returns, for each event record, the ids of the rules that matched it, and for
    each category what the engine said it loaded and read, beside what it was given.
    The engine skips a rule it cannot convert and still succeeds, so its own
    counts are the ones that say what was evaluated.
    """

    matched: dict[str, list[str]] = collections.defaultdict(list)
    counts: dict[str, dict] = {}
    work = run_dir / "engine"
    work.mkdir(exist_ok=True)
    for category, event_id in CATEGORIES.items():
        rules = run_dir / "rules" / "linux" / category
        lines = [line for event, line in zip(events, raw, strict=True) if event["EventID"] == event_id]
        output = work / f"{category}.json"
        output.unlink(missing_ok=True)
        # The engine adds to an existing log, and its counts are read from the log.
        (work / f"{category}-engine.txt").unlink(missing_ok=True)
        counts[category] = {"given": len(lines), "loaded": 0, "read": 0}
        if not lines or not rules.is_dir():
            continue
        text = "".join(sysmon.one_line(line) + "\n" for line in lines)
        (work / f"{category}.txt").write_text(text, encoding="utf-8")
        subprocess.run(
            [
                str(engine.resolve()),
                "--events", f"{category}.txt",
                "--sysmon-linux-input",
                "--logs-encoding", "utf-8",
                "--ruleset", str(rules.resolve()),
                "--outfile", output.name,
                "--logfile", f"{category}-engine.txt",
            ],
            cwd=work,
            check=True,
            capture_output=True,
            timeout=900,
        )  # fmt: skip
        log = (work / f"{category}-engine.txt").read_text(encoding="utf-8", errors="replace")
        counts[category]["loaded"], counts[category]["read"] = engine_counts(log)
        for rule in json.loads(output.read_text(encoding="utf-8")) if output.exists() else []:
            for match in rule["matches"]:
                matched[str(match["EventRecordID"])].append(str(rule["id"]))
    return matched, counts


def when(event: dict) -> tuple[str, int]:
    return event["UtcTime"], int(event["EventRecordID"] or 0)


def step_of(test: dict, label: str) -> dict | None:
    found = [step for step in test["steps"] if step["label"] == label]
    return found[-1] if found else None


def marker_time(starts: list[dict], run_id: str, order: int, edge: str) -> str | None:
    line = f"/usr/bin/true bluefire-lab-marker {run_id} {order} {edge}"
    return next((event["UtcTime"] for event in starts if event["CommandLine"] == line), None)


def system_commands(starts: list[dict], windows: list[tuple[str, str]]) -> set[tuple[str, str]]:
    """The commands systemd started outside every test's window: the system's own work."""

    return {
        (event["Image"], event["CommandLine"])
        for event in starts
        if started_by_systemd(event) and not any(start <= event["UtcTime"] <= end for start, end in windows)
    }


def started_by_systemd(event: dict) -> bool:
    return event["TerminalSessionId"] == sysmon.NO_SESSION and event["ParentProcessId"] == "1"


def attribute(
    test: dict, starts: list[dict], window: tuple[str, str], context: dict
) -> tuple[dict | None, dict[str, str]]:
    """Find the test's launcher and the processes that belong to its attack step.

    The launcher is the process the executor names in its own log, and it must be
    the shell the test declares, in the attack step's session. A process
    belongs to the test when it is in the audit session of the attack step,
    started no earlier than the launcher, and is not one of the commands the
    executor runs for itself: those are the launcher's siblings, which have
    the launcher's parent. Sysmon for Linux 1.6.0 reports that parent as a
    thread id without a GUID (microsoft/Sysmon-Linux issue 253), and the
    comparison holds either way.

    What a test schedules runs outside its session, so two more rules apply
    inside the test's window, between its markers:
    - a test run as the test account owns what that account started outside
      every session of the driver: what cron starts on the account's behalf;
    - a test run as root owns what systemd started, unless the same command
      also ran outside every test's window. systemd's own helper, which then
      becomes the unit's command, is left out.

    Returns the launcher's start event and, for each process, why it belongs.
    """

    attack = step_of(test, "attack")
    session = attack["session"] if attack else ""
    members = sorted(
        (event for event in starts if session and event["TerminalSessionId"] == session), key=when
    )
    shell = SHELLS.get(test.get("executor", ""), ())
    launcher = next(
        (
            event
            for event in members
            if event["ProcessId"] == str(test.get("launcher_pid")) and event["Image"].endswith(shell)
        ),
        None,
    )
    if launcher is None:
        return None, {}
    owned = {}
    for event in members:
        executors_own = (
            event["ParentProcessGuid"] == launcher["ParentProcessGuid"]
            and event["ParentProcessId"] == launcher["ParentProcessId"]
            and event["ProcessId"] != launcher["ProcessId"]
        )
        if event is not launcher and event["UtcTime"] >= launcher["UtcTime"] and not executors_own:
            owned[event["ProcessGuid"]] = "session"
    for event in starts:
        if not window[0] <= event["UtcTime"] <= window[1]:
            continue
        if test["user"] == context["account"] == event["User"]:
            if event["TerminalSessionId"] not in context["known_sessions"]:
                owned.setdefault(event["ProcessGuid"], "account")
        elif test["user"] == "root" and started_by_systemd(event):
            system = (event["Image"], event["CommandLine"]) in context["system_commands"]
            if not system and not event["Image"].endswith(SYSTEMD_HELPER):
                owned.setdefault(event["ProcessGuid"], "systemd")
    return launcher, owned


def describe(event: dict, why: str) -> dict:
    detail = event.get("CommandLine") or event.get("TargetFilename") or ""
    if event["EventID"] == sysmon.NETWORK:
        detail = "{Protocol} {SourceIp}:{SourcePort} to {DestinationIp}:{DestinationPort}".format_map(
            collections.defaultdict(str, event)
        )
    return {
        "record": int(event["EventRecordID"]),
        "time": event.get("UtcTime", ""),
        "kind": sysmon.KINDS.get(event["EventID"], f"event {event['EventID']}"),
        "process_id": event.get("ProcessId", ""),
        "user": event.get("User", ""),
        "image": event.get("Image", ""),
        "detail": detail,
        "why": why,
        "fields": {name: value for name, value in event.items() if value not in ("", "-")},
    }


def execution(test: dict) -> dict:
    """Did the technique take effect?"""

    answer = {"prerequisites": test["prerequisites"], "exit_code": test.get("exit_code")}
    attack, effect = step_of(test, "attack"), step_of(test, "effect")
    answer["timed_out"] = bool(attack and attack["timed_out"])
    if test["prerequisites"] == "not met":
        answer.update(answer="not attempted", basis="a prerequisite of the test was not met")
    elif "launcher_pid" not in test:
        answer.update(answer="inconclusive", basis="the executor left no record of starting the test")
    elif effect:
        took = effect["exit_status"] == 0
        answer.update(
            answer="took effect" if took else "attempted without effect",
            basis=f"the effect check exited with status {effect['exit_status']}",
            effect_check={"command": test["effect"], "exit_status": effect["exit_status"],
                          "output": (effect["output"] + effect["error"]).strip()},
        )  # fmt: skip
    elif "output" in test:
        took = bool(attack) and test["output"] in attack["output"]
        answer.update(
            answer="took effect" if took else "attempted without effect",
            basis=f"the test {'printed' if took else 'did not print'} the text {test['output']!r}, "
            "which only its effect produces",
        )
    else:
        took = test.get("exit_code") == 0
        answer.update(
            answer="took effect" if took else "attempted without effect",
            basis=f"the test has no separate effect check; its command exited with status {test.get('exit_code')}",
        )
    return answer


def visibility(
    test: dict,
    events: list[dict],
    starts: list[dict],
    matched: dict[str, list[str]],
    rules: dict[str, dict],
    context: dict,
) -> tuple[dict, list[dict]]:
    """What did the defense see? Returns the answer and the test's events."""

    start, end = context["windows"].get(test["order"], (None, None))
    if start is None or end is None:
        return {"answer": "inconclusive", "basis": "a marker command is missing from the telemetry"}, []
    launcher, owned = attribute(test, starts, (start, end), context)
    if launcher is None:
        basis = "the shell the executor started for the test is missing from the telemetry of the attack step"
        return {"answer": "inconclusive", "basis": basis, "window": [start, end]}, []

    mine = []
    for event in events:
        guid = event.get("ProcessGuid", "")
        if guid in owned:
            mine.append(describe(event, owned[guid]))
        elif guid == launcher["ProcessGuid"] and event["EventID"] not in (
            sysmon.PROCESS_START,
            sysmon.PROCESS_END,
        ):
            mine.append(describe(event, "launcher"))
    mine.sort(key=lambda event: (event["time"], event["record"]))

    fired: dict[str, list[int]] = collections.defaultdict(list)
    for event in mine:
        for rule_id in matched.get(str(event["record"]), []):
            fired[rule_id].append(event["record"])
    launcher_only = [
        rule_id for rule_id in matched.get(launcher["EventRecordID"], []) if rule_id not in fired
    ]

    def cite(rule_id: str, records: list[int]) -> dict:
        rule = rules[rule_id]
        return {**rule, "records": records, "alert": rule["level"] in ALERT_LEVELS}

    cited = sorted((cite(rule_id, records) for rule_id, records in fired.items()), key=rule_order)
    if any(rule["alert"] for rule in cited):
        answer, basis = "alert", "a rule of an alert level matched an event of the test"
    elif mine:
        answer, basis = "telemetry only", "the test left events, and no rule of an alert level matched one"
    else:
        answer, basis = "no telemetry", "the sensor recorded nothing of the test besides its launcher"
    result = {
        "answer": answer,
        "basis": basis,
        "window": [start, end],
        "events": len(mine),
        "events_by_kind": dict(collections.Counter(event["kind"] for event in mine)),
        "rules": cited,
        "launcher": describe(launcher, "launcher"),
        "launcher_only_rules": sorted(
            (cite(rule_id, [int(launcher["EventRecordID"])]) for rule_id in launcher_only), key=rule_order
        ),
    }
    return result, mine


def rule_order(rule: dict) -> tuple[int, str]:
    levels = ("critical", "high", "medium", "low", "informational")
    return levels.index(rule["level"]) if rule["level"] in levels else len(levels), rule["title"]


def check_controls(
    run: dict, tests: list[dict], starts: list[dict], lost: dict, engine: dict[str, dict]
) -> list[dict]:
    """The checks that keep a broken measurement from looking like a finding."""

    def control(name: str, passed: bool, detail: str) -> dict:
        return {"name": name, "passed": bool(passed), "detail": detail}

    ready = run["sensor"].get("ready_after_seconds")
    probe = f"/usr/bin/true bluefire-lab-probe {run['id']}"
    seen = [event["UtcTime"] for event in starts if event["CommandLine"] == probe]
    first = min(
        (test["visibility"]["window"][0] for test in tests if test["visibility"].get("window")), default=None
    )
    in_time = bool(seen) and (first is None or min(seen) < first)
    if ready is None or not seen:
        detail = "the sensor did not report the probe command"
    elif not in_time:
        detail = "the sensor reported the probe command only after the first test began"
    else:
        detail = f"the sensor reported a probe command {ready} s after it was started, before the first test"
    checks = [control("readiness", ready is not None and in_time, detail)]

    attempted = [test for test in tests if test["execution"]["answer"] != "not attempted"]
    unmeasured = [test for test in attempted if test["visibility"]["answer"] == "inconclusive"]
    checks.append(
        control(
            "markers",
            bool(attempted) and not unmeasured,
            f"both marker commands and the launcher of all {len(attempted)} tests are in the telemetry"
            if attempted and not unmeasured
            else f"{len(unmeasured)} of {len(attempted)} tests could not be measured: "
            + "; ".join(
                f"{test.get('name', '')}: {test['visibility'].get('basis', '')}" for test in unmeasured
            ),
        )
    )

    clean = lost["sensor_reported"] and lost["lost_events"] == 0 and lost["bad_events"] == 0
    whole = not lost["missing_records"] and not lost["repeated_records"]
    if lost["sensor_starts"] != 1:
        detail = f"the sensor started {lost['sensor_starts']} times during the run, not once"
    elif not lost["sensor_reported"]:
        detail = "the sensor did not report its counts of lost and bad events once each"
    else:
        detail = (
            f"the sensor reported {lost['lost_events']} lost and {lost['bad_events']} bad events, "
            f"{lost['missing_records']} of its {lost['records'] + lost['missing_records']} records are missing "
            f"from the export, and {lost['repeated_records']} appear more than once"
        )
    checks.append(control("loss", clean and whole and lost["sensor_starts"] == 1, detail))

    problems = []
    for category, counts in engine.items():
        kind = sysmon.KINDS[CATEGORIES[category]]
        if counts["rules"] and not counts["given"]:
            problems.append(
                f"the sensor recorded no {kind} event, so the {category} rules were not evaluated"
            )
        elif counts["loaded"] != counts["rules"]:
            problems.append(f"the engine loaded {counts['loaded']} of the {counts['rules']} {category} rules")
        elif counts["read"] != counts["given"]:
            problems.append(f"the engine read {counts['read']} of the {counts['given']} {kind} events")
    rules, given = (sum(counts[key] for counts in engine.values()) for key in ("rules", "given"))
    checks.append(
        control(
            "engine",
            not problems,
            "; ".join(problems)
            or f"the rule engine loaded all {rules} rules and read all {given} events it was given, "
            "and the sensor recorded every kind of event the rules describe",
        )
    )

    canaries = [test for test in tests if test["role"] == "canary"]
    caught = [
        test
        for test in canaries
        if test["execution"]["answer"] == "took effect"
        and any(rule["id"] == test["rule"] and rule["alert"] for rule in test["visibility"].get("rules", []))
    ]
    checks.append(
        control(
            "canary",
            len(canaries) == 2 and len(caught) == 2,
            f"the known-detected test took effect and raised its alert in {len(caught)} of {len(canaries)} runs, "
            "at the start and at the end",
        )
    )

    quiet = [test for test in tests if test["role"] == "control"]
    noisy = [
        test
        for test in quiet
        if test["visibility"]["answer"] not in ("telemetry only", "no telemetry")
        or any(rule["alert"] for rule in test["visibility"].get("launcher_only_rules", []))
    ]
    if len(quiet) != 1 or noisy:
        detail = "the harmless command raised an alert or could not be measured"
    elif quiet[0]["execution"]["answer"] != "took effect":
        detail = f"the harmless command did not take effect: {quiet[0]['execution'].get('basis', '')}"
    else:
        detail = "the harmless command ran through the same executor and raised no alert"
    passed = len(quiet) == 1 and not noisy and quiet[0]["execution"]["answer"] == "took effect"
    checks.append(control("control", passed, detail))
    return checks


def main(run_dir: Path, engine: Path) -> int:
    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    events, raw, other = sysmon.read(run_dir / "sysmon.txt")
    starts = [event for event in events if event["EventID"] == sysmon.PROCESS_START]
    rules = rule_index(run_dir / "rules" / "linux")
    matched, counts = run_engine(engine, run_dir, events, raw)
    for category in counts:
        counts[category]["rules"] = sum(
            1 for rule in rules.values() if rule["file"].startswith(f"linux/{category}/")
        )

    known_sessions = {step["session"] for test in run["tests"] for step in test["steps"]}
    known_sessions |= {step["session"] for step in run.get("probes", [])}
    windows = {
        test["order"]: (
            marker_time(starts, run["id"], test["order"], "start"),
            marker_time(starts, run["id"], test["order"], "end"),
        )
        for test in run["tests"]
    }
    complete = [window for window in windows.values() if None not in window]
    context = {
        "account": run["account"],
        "known_sessions": known_sessions,
        "windows": windows,
        "system_commands": system_commands(starts, complete),
    }
    tests = []
    for test in run["tests"]:
        result = {
            key: test[key]
            for key in ("order", "role", "technique", "guid", "name", "executor", "elevated", "user")
        }
        result.update({key: test[key] for key in ("rule", "args") if key in test})
        result["execution"] = execution(test)
        if result["execution"]["answer"] == "not attempted":
            seen, mine = {"answer": "not applicable", "basis": "the test did not run"}, []
        else:
            seen, mine = visibility(test, events, starts, matched, rules, context)
        result.update(visibility=seen, events=mine)
        tests.append(result)

    version = subprocess.run(
        [str(engine.resolve()), "--version"], capture_output=True, text=True, check=False
    )
    found = re.search(r"v(\d+\.\d+\.\d+)", version.stdout + version.stderr)
    measured = [test for test in tests if test["role"] == "test"]
    took = [test for test in measured if test["execution"]["answer"] == "took effect"]
    results = {
        "schema": "bluefire-lab/results/1",
        "run": {
            key: run.get(key)
            for key in ("id", "started", "finished", "account", "target", "tools", "aborted")
        },
        "sensor": {
            **run["sensor"],
            "version": next((e["Version"] for e in events if e["EventID"] == "4" and "Version" in e), None),
            "configuration_sha256": hashlib.sha256((run_dir / "sensor-config.xml").read_bytes()).hexdigest(),
            "configuration_text": (run_dir / "sensor-config.xml").read_text(encoding="utf-8"),
            "events": len(events),
        },
        "rules": {
            "source": (run_dir / "rules" / "SOURCE").read_text(encoding="utf-8").strip(),
            "license": "Detection Rule License 1.1, https://github.com/SigmaHQ/Detection-Rule-License",
            # What the engine says it loaded: a rule it could not convert was not evaluated.
            "evaluated": {category: counts[category]["loaded"] for category in CATEGORIES},
            "alert_levels": list(ALERT_LEVELS),
        },
        "engine": {"name": "Zircolite", "version": found.group(1) if found else None, "counts": counts},
        "controls": check_controls(run, tests, starts, sysmon.loss(events, other), counts),
        "summary": {
            "tests": len(measured),
            "took_effect": len(took),
            **{
                key: sum(1 for test in took if test["visibility"]["answer"] == answer)
                for key, answer in (
                    ("alert", "alert"),
                    ("telemetry_only", "telemetry only"),
                    ("no_telemetry", "no telemetry"),
                    ("inconclusive", "inconclusive"),
                )
            },
        },
        "tests": tests,
        "dropped": run.get("dropped", []),
    }
    (run_dir / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    failed = [check for check in results["controls"] if not check["passed"]]
    for check in results["controls"]:
        print(("ok      " if check["passed"] else "FAILED  ") + f"{check['name']}: {check['detail']}")
    return 1 if failed else 0
