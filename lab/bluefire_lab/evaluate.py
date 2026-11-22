"""Compute the two answers for every test from the files a run leaves behind.

Input, all in the run folder: run.json (what the driver did), sysmon.txt (what
the sensor wrote, untouched) and rules/ (the pinned Sigma rules). The rule
engine is a separate program. Output: results.json.

Every test gets two answers.

Execution: "not attempted" when a prerequisite was missing, "took effect" or
"attempted without effect" by the test's effect check: a command run after the
test, a text only the effect prints, or failing both the test's exit status.
"blocked" when the test ran again with a hardening change in place and did
not take effect, while it took effect without the change.

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
import shutil
import subprocess
from pathlib import Path

import yaml

from . import auditd, sysmon

# The Sigma specification says a match of a "high" rule should trigger an alert
# and a "critical" one indicates an incident. Lower levels are for review.
ALERT_LEVELS = ("high", "critical")
# A rule of another rule set that gives no level: a match of it counts as an alert in that
# rule set's column, and the report says so.
NO_LEVEL = "no level"


def systemds_own(event: dict) -> bool:
    """systemd's own steps, not part of what a test did: systemd 255 starts a unit's command
    through systemd-executor, which then becomes the command; and logind removes an account's
    runtime folder 10 s after the account's last session ends, which can fall in a later
    test's window. Setting the folder up, when a test logs in, stays the test's."""

    image, command = event["Image"], f" {event.get('CommandLine', '')} "
    return image.endswith("/systemd-executor") or (
        image.endswith("/systemd-user-runtime-dir") and " stop " in command
    )


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


def rule_index(rules: Path, origin: str = "pinned") -> dict[str, dict]:
    """The rules under a folder by id, with what a report has to say about a rule that
    matched. The pinned rules are SigmaHQ's; the lab's own rules have the origin "lab"; the
    rules of a rule set given as an input have the origin "other", and are kept under names
    of their own, because such a set may hold a rule with an id the pinned rules use too."""

    index = {}
    for path in sorted(rules.rglob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for rule in yaml.safe_load_all(text):
            if isinstance(rule, dict) and "id" in rule and "detection" in rule:
                name = f"other:{rule['id']}" if origin == "other" else str(rule["id"])
                index[name] = {
                    "id": str(rule["id"]),
                    "title": rule.get("title", ""),
                    "level": rule.get("level") or ("informational" if origin != "other" else NO_LEVEL),
                    "author": rule.get("author", ""),
                    "file": path.relative_to(rules.parent).as_posix(),
                    "text": text,
                    "origin": origin,
                }
    return index


def sort_rule_set(run_dir: Path) -> dict:
    """Sort the Sigma rules of a rule set given as an input by the kind of event each describes,
    into folders the rule engine takes one at a time, and say which rules are left out and why.

    A rule is evaluated when it is one Sigma rule with an id, for Linux, and for a kind of
    event the lab's sensors record: a process start, a file creation or a network connection
    (the Sigma categories process_creation, file_event and network_connection), or auditd's
    records (the service auditd). Returns what the report says about the set.
    """

    source = run_dir / "rule-set"
    target = run_dir / "engine" / "rule-set" / "linux"
    shutil.rmtree(target.parent, ignore_errors=True)
    left_out: collections.Counter[str] = collections.Counter()
    paths, no_level = {}, 0
    files = sorted(path for path in (source / "files").rglob("*") if path.suffix in (".yml", ".yaml"))
    for path in files:
        try:
            documents = [found for found in yaml.safe_load_all(path.read_text(encoding="utf-8")) if found]
        except (yaml.YAMLError, UnicodeDecodeError):
            left_out["not readable as YAML"] += 1
            continue
        rule = documents[0] if len(documents) == 1 else None
        if (
            not isinstance(rule, dict)
            or "detection" not in rule
            or not isinstance(rule.get("logsource"), dict)
        ):
            left_out["not one Sigma rule with a log source and a detection"] += 1
            continue
        logsource = {key: str(value).lower() for key, value in rule["logsource"].items()}
        category = logsource.get("category") if logsource.get("category") in CATEGORIES else None
        category = category or ("auditd" if logsource.get("service") == "auditd" else None)
        if "id" not in rule:
            left_out["no id, by which the rule engine names a rule that matched"] += 1
        elif logsource.get("product") != "linux":
            left_out[f"for the product {logsource.get('product', 'that the rule does not name')}"] += 1
        elif category is None:
            named = logsource.get("category") or logsource.get("service") or "that the rule does not name"
            left_out[f"for a Linux log source the lab's sensors do not provide: {named}"] += 1
        else:
            copy = target / category / f"{len(paths) + 1:04d}.yml"
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, copy)
            paths[copy.relative_to(target.parent).as_posix()] = path.relative_to(source / "files").as_posix()
            no_level += "level" not in rule
    return {
        "source": (source / "SOURCE").read_text(encoding="utf-8").strip(),
        "license_files": sorted(
            path.name for path in source.iterdir() if path.is_file() and path.name != "SOURCE"
        ),
        "files": len(files),
        "sorted": len(paths),
        "no_level": no_level,
        "left_out": [{"reason": reason, "rules": number} for reason, number in left_out.most_common()],
        "paths": paths,
    }


def engine_counts(log: str) -> tuple[int | None, int | None]:
    """How many rules the engine loaded and how many events it read, from its own log."""

    def number(found: re.Match | None) -> int | None:
        return int(found.group(1).replace(",", "")) if found else None

    return number(_LOADED.search(log)), number(_READ.search(log))


def run_engine(
    engine: Path, run_dir: Path, events: list[dict], raw: list[str], root: str = "rules"
) -> tuple[dict[str, list[str]], dict[str, dict]]:
    """Have the rule engine evaluate each folder of rules under root over the events it describes.

    Returns, for each event record, the ids of the rules that matched it, and for
    each category what the engine said it loaded and read, beside what it was given.
    The engine skips a rule it cannot convert and still succeeds, so its own
    counts are the ones that say what was evaluated. The pinned rules and the
    lab's own run apart, so that each count says what it is about.
    """

    matched: dict[str, list[str]] = collections.defaultdict(list)
    counts: dict[str, dict] = {}
    work = run_dir / "engine"
    work.mkdir(exist_ok=True)
    prefix = "" if root == "rules" else f"{Path(root).name}-"
    for category, event_id in CATEGORIES.items():
        rules = run_dir / root / "linux" / category
        lines = [line for event, line in zip(events, raw, strict=True) if event["EventID"] == event_id]
        output = work / f"{prefix}{category}.json"
        output.unlink(missing_ok=True)
        # The engine adds to an existing log, and its counts are read from the log.
        (work / f"{prefix}{category}-engine.txt").unlink(missing_ok=True)
        counts[category] = {"kind": sysmon.KINDS[event_id], "given": len(lines), "loaded": 0, "read": 0}
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
                "--logfile", f"{prefix}{category}-engine.txt",
            ],
            cwd=work,
            check=True,
            capture_output=True,
            timeout=900,
        )  # fmt: skip
        log = (work / f"{prefix}{category}-engine.txt").read_text(encoding="utf-8", errors="replace")
        counts[category]["loaded"], counts[category]["read"] = engine_counts(log)
        for rule in json.loads(output.read_text(encoding="utf-8")) if output.exists() else []:
            for match in rule["matches"]:
                matched[str(match["EventRecordID"])].append(str(rule["id"]))
    return matched, counts


def run_audit_engine(
    engine: Path, run_dir: Path, records: list[dict], root: str = "rules"
) -> tuple[dict[str, list[str]], dict]:
    """Have the rule engine evaluate the auditd rules under root over auditd's records.

    The engine gets one record per line and names a match by its line, so a match is
    tied back to its record, and through the record's serial to the event. Returns,
    for each event ("audit <serial>"), the ids of the rules that matched one of its
    records, and what the engine said it loaded and read.
    """

    matched: dict[str, list[str]] = collections.defaultdict(list)
    counts = {"category": "auditd", "origin": "pinned", "kind": "auditd", "given": len(records)}
    counts.update(loaded=0, read=0)
    rules, work = run_dir / root / "linux" / "auditd", run_dir / "engine"
    work.mkdir(exist_ok=True)
    prefix = "" if root == "rules" else f"{Path(root).name}-"
    output, log = work / f"{prefix}auditd.json", work / f"{prefix}auditd-engine.txt"
    output.unlink(missing_ok=True)
    log.unlink(missing_ok=True)
    if not records or not rules.is_dir():
        return matched, counts
    (work / "auditd.txt").write_text("".join(record["line"] + "\n" for record in records), encoding="utf-8")
    subprocess.run(
        [
            str(engine.resolve()),
            "--events", "auditd.txt",
            "--auditd-input",
            "--logs-encoding", "utf-8",
            "--ruleset", str(rules.resolve()),
            "--outfile", output.name,
            "--logfile", log.name,
        ],
        cwd=work,
        check=True,
        capture_output=True,
        timeout=900,
    )  # fmt: skip
    counts["loaded"], counts["read"] = engine_counts(log.read_text(errors="replace"))
    for rule in json.loads(output.read_text(encoding="utf-8")) if output.exists() else []:
        for match in rule["matches"]:
            record = records[int(match["row_id"]) - 1]
            if match.get("type") != record["type"]:
                raise SystemExit(f"the engine's line {match['row_id']} is not the record it was given there")
            matched[f"audit {record['event']}"].append(str(rule["id"]))
    return matched, counts


def audit_facts(audit: dict, audit_events: list[dict]) -> dict:
    """What the controls need from auditd's side of a run: when it recorded the probe write,
    its own count of lost records before and after the tests, and any files it rotated its
    log into."""

    def number(value: object) -> int | None:
        return int(value) if str(value).isdigit() else None

    probes = [event["time"] for event in audit_events if audit.get("probe") in event["paths"]]
    return {
        "probe_time": min(probes, default=None),
        "lost_before": number(audit.get("before", {}).get("lost")),
        "lost_after": number(audit.get("after", {}).get("lost")),
        "rotated": audit.get("rotated", []),
    }


def lookups(audit_events: list[dict]) -> set[str]:
    """The program starts the kernel refused because no such file existed and that were part
    of a search: the same process also tried a file of that name in another folder, as a shell
    does with each folder of its search path. Those are lookups, not actions. A single start of
    a missing file, such as a scheduled job's missing payload, is an action and counts, and so
    does a start refused for another reason, such as a folder mounted noexec."""

    def program(event: dict) -> tuple[str, str] | None:
        if event["names"].get("SYSCALL") not in ("execve", "execveat") or not event["paths"]:
            return None
        return event["call"].get("pid", ""), event["paths"][0].rsplit("/", 1)[-1]

    tried: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
    for event in audit_events:
        if key := program(event):
            tried[key].add(event["paths"][0])
    return {
        event["event"]
        for event in audit_events
        if (key := program(event))
        and event["call"].get("success") == "no"
        and event["call"].get("exit") == "-2"
        and len(tried[key]) > 1
    }


def describe_audit(event: dict, why: str) -> dict:
    """An auditd event in the shape of the Sysmon events the report shows."""

    call, names = event["call"], event["names"]
    action = names.get("SYSCALL") or event["types"][0]  # a record a program wrote itself has no call
    told = {**call, "cmd": auditd.command_line(call["cmd"])} if call.get("cmd") else call  # sudo's is hex
    said = " ".join(f"{name}={told[name]}" for name in ("op", "cmd", "acct", "res") if told.get(name))
    command = event["command"]
    detail = ", ".join(event["paths"]) + (f" by {command}" if command else "")
    if action in ("execve", "execveat") and call.get("success") == "no":
        # No program started, so the process's command line is still that of the shell that
        # forked it, the test's own text: name the start by the file the kernel refused.
        command = ""
        detail = f"the kernel refused to start {', '.join(event['paths'])} (exit {call.get('exit')})"
    return {
        "record": f"audit {event['event']}",
        "time": event["time"],
        "kind": f"{action} (auditd)",
        "process_id": call.get("pid", ""),
        "user": names.get("UID", call.get("uid", "")),
        "image": call.get("exe", ""),
        "detail": detail or said,
        "why": why,
        "fields": {
            "records": " ".join(event["types"]),
            **{name: value for name, value in call.items() if value not in ("", "(none)")},
            "paths": ", ".join(event["paths"]),
            "command": command,
        },
    }


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
      also ran outside every test's window. systemd's own steps (systemds_own)
      are left out.

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
            if not system and not systemds_own(event):
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


def execution(test: dict, without_change: dict | None = None) -> dict:
    """Did the technique take effect?

    A test run again with a hardening change in place is "blocked" when it ran
    with its prerequisites met and did not take effect, while the same test
    took effect without the change, earlier in the same run.
    """

    answer = {"prerequisites": test["prerequisites"], "exit_code": test.get("exit_code")}
    attack, effect = step_of(test, "attack"), step_of(test, "effect")
    answer["timed_out"] = bool(attack and attack["timed_out"])
    change = test.get("defense")
    if test["prerequisites"] == "not met":
        answer.update(answer="not attempted", basis="a prerequisite of the test was not met")
    elif change is not None and not change.get("applied"):
        answer.update(answer="inconclusive", basis="the hardening change could not be put in place")
    elif "launcher_pid" not in test:
        answer.update(answer="inconclusive", basis="the executor left no record of starting the test")
    elif (before := step_of(test, "effect-before")) and before["exit_status"] == 0:
        basis = "the effect check found the effect before the test ran, so the test did not cause it"
        answer.update(answer="inconclusive", basis=basis)
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
    if change is not None and answer["timed_out"] and answer["answer"] != "inconclusive":
        answer.update(
            answer="inconclusive",
            basis="the test ran out of time with the change in place, so what stopped it is not known",
        )
    if change is not None and answer["answer"] == "attempted without effect" and without_change is not None:
        if without_change["answer"] == "took effect":
            answer.update(
                answer="blocked",
                basis=f"with the change in place {answer['basis']}, and without it the same test took effect",
            )
    return answer


def cleanup(test: dict) -> dict | None:
    """Did the test's cleanup undo what the test did? None for a test that did not run, and
    for the record of a run from before the lab looked.

    After the cleanup one command runs as root: the one the list names for what the test
    leaves, or else the test's effect check. "held" when it no longer finds anything, "left
    behind" when it still does. A test for which the list names neither has "nothing to
    check". "not checked" when the cleanup did not finish or the command did not run.
    """

    done, check = step_of(test, "cleanup"), step_of(test, "leftover")
    if done is None or "upstream_cleanup" not in test:
        return None
    upstream = "" if test["upstream_cleanup"] else "; the test has no cleanup command upstream"
    if done["timed_out"]:
        return {"answer": "not checked", "basis": "the cleanup ran out of time"}
    if "leftover" not in test:
        basis = "the list names nothing this test leaves on the target"
        return {"answer": "nothing to check", "basis": basis + upstream}
    if check is None or check["exit_status"] is None:
        return {"answer": "not checked", "basis": "the check after the cleanup did not run to its end"}
    left = check["exit_status"] == 0
    return {
        "answer": "left behind" if left else "held",
        "basis": f"after the cleanup the check exited with status {check['exit_status']}" + upstream,
        "check": {"command": test["leftover"], "exit_status": check["exit_status"],
                  "output": (check["output"] + check["error"]).strip()},
    }  # fmt: skip


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
    # An auditd event is the test's when its process is one of the test's: the launcher or a
    # process tied to the test above. That leaves out the driver's own records in the attack
    # session (the change of login uid that starts it, sudo's records) as the executor's are.
    attack = step_of(test, "attack")
    pids = {launcher["ProcessId"]} | {event["ProcessId"] for event in starts if event["ProcessGuid"] in owned}
    # So is a process forked from one of those that never started a program Sysmon saw: a
    # subshell, or a fork whose program the kernel refused to start (noexec). auditd names its
    # parent.
    started = {event["ProcessId"] for event in starts}
    forks: dict[str, set[str]] = collections.defaultdict(set)
    for event in context.get("audit_events", []):
        pid, parent = event["call"].get("pid"), event["call"].get("ppid")
        if pid and parent and pid not in started:
            forks[parent].add(pid)
    unseen = list(pids)
    while unseen:
        for pid in forks.pop(unseen.pop(), set()) - pids:
            pids.add(pid)
            unseen.append(pid)
    # The launcher's start, as each sensor recorded it. Its command line is the whole test, so a
    # rule that matches only these is reported as that, not as a detection. For auditd it is the
    # first program start of the launcher's process: a shell given one command can become that
    # command in the same process (bash -c "sysctl ..."), and that later start is the test's.
    audit_events = [
        event
        for event in context.get("audit_events", [])
        if event["call"].get("pid") in pids
        and (
            (attack and attack["session"] and event["call"].get("ses") == attack["session"])
            or start <= event["time"] <= end
        )
        and event["event"] not in context.get("lookups", ())
    ]
    launcher_exec = min(
        (
            (event["time"], int(event["serial"]), event["event"])
            for event in audit_events
            if event["call"].get("pid") == launcher["ProcessId"] and "EXECVE" in event["types"]
        ),
        default=(None, None, None),
    )[2]
    launched = [launcher["EventRecordID"]]
    for event in audit_events:
        if event["event"] == launcher_exec:
            launched.append(f"audit {event['event']}")
            continue
        in_step = attack and attack["session"] and event["call"].get("ses") == attack["session"]
        mine.append(describe_audit(event, "session" if in_step else "window"))
    mine.sort(key=lambda event: (event["time"], str(event["record"])))

    fired: dict[str, list[int]] = collections.defaultdict(list)
    for event in mine:
        for rule_id in matched.get(str(event["record"]), []):
            fired[rule_id].append(event["record"])
    launcher_only: dict[str, list] = collections.defaultdict(list)
    for record in launched:
        for rule_id in matched.get(record, []):
            if rule_id not in fired:
                launcher_only[rule_id].append(int(record) if record.isdigit() else record)

    def cite(rule_id: str, records: list[int]) -> dict:
        rule = rules[rule_id]
        return {**rule, "records": records, "alert": rule["level"] in (*ALERT_LEVELS, NO_LEVEL)}

    # The answer comes from the pinned rules alone; the lab's own rules give a second one, and
    # a rule set given as an input a column of its own.
    cited = sorted((cite(rule_id, records) for rule_id, records in fired.items()), key=rule_order)
    only_launcher = sorted(
        (cite(rule_id, records) for rule_id, records in launcher_only.items()), key=rule_order
    )
    pinned = [rule for rule in cited if rule["origin"] == "pinned"]
    ours = [rule for rule in cited if rule["origin"] == "lab"]
    others = [rule for rule in cited if rule["origin"] == "other"]
    if any(rule["alert"] for rule in pinned):
        answer, basis = "alert", "a rule of an alert level matched an event of the test"
    elif mine:
        answer, basis = "telemetry only", "the test left events, and no rule of an alert level matched one"
    else:
        answer, basis = "no telemetry", "nothing of the test was recorded besides its launcher's start"
    result = {
        "answer": answer,
        "basis": basis,
        "window": [start, end],
        "events": len(mine),
        "events_by_kind": dict(collections.Counter(event["kind"] for event in mine)),
        "rules": pinned,
        "launcher": describe(launcher, "launcher"),
        "launcher_only_rules": [rule for rule in only_launcher if rule["origin"] != "other"],
        # Until the lab's rules are judged, the second answer is the first; see second_answers.
        "with_lab_rules": {"answer": answer, "rules": ours},
    }
    if context.get("rule_set"):
        without = "telemetry only" if mine else "no telemetry"
        result["other_rules"] = {
            "answer": "alert" if any(rule["alert"] for rule in others) else without,
            "rules": others,
            "launcher_only_rules": [rule for rule in only_launcher if rule["origin"] == "other"],
        }
    return result, mine


def ordinary_activity(
    run: dict,
    events: list[dict],
    starts: list[dict],
    matched: dict,
    rules: dict,
    windows: list,
    audit_events: list[dict] = (),
) -> dict:
    """What the lab's own rules must stay quiet on: the events of the baseline steps, and
    the events outside every test's window of processes in no audit session (the runner,
    the system's own services and the driver), from both sensors."""

    baseline_sessions = {
        step["session"]
        for test in run["tests"]
        if test["role"] == "baseline"
        for step in test["steps"]
        if step["label"].startswith("baseline-")
    }
    session_of = {event["ProcessGuid"]: event["TerminalSessionId"] for event in starts}
    parts = [dict(part, events=0) for test in run["tests"] for part in test.get("parts", [])]
    part_of = {part["session"]: part for part in parts}
    counts: collections.Counter[str] = collections.Counter()
    hits: dict[str, list[int]] = collections.defaultdict(list)
    for event in events:
        session = session_of.get(event.get("ProcessGuid", ""))
        if session in baseline_sessions:
            kind = "baseline_events"
        elif session in (None, sysmon.NO_SESSION) and not any(
            start <= event.get("UtcTime", "") <= end for start, end in windows
        ):
            kind = "system_events"
        else:
            continue
        counts[kind] += 1
        if session in part_of:
            part_of[session]["events"] += 1
        for rule_id in matched.get(event["EventRecordID"], []):
            hits[rule_id].append(int(event["EventRecordID"]))
    searched = lookups(list(audit_events))
    for event in audit_events:
        if "LOGIN" in event["types"] or event["event"] in searched:
            continue  # the driver's change of login uid that starts a step's session; a lookup
        session = event["call"].get("ses")
        if session in baseline_sessions:
            kind = "baseline_events"
        elif session in (None, sysmon.NO_SESSION) and not any(
            start <= event["time"] <= end for start, end in windows
        ):
            kind = "system_events"
        else:
            continue
        counts[kind] += 1
        if session in part_of:
            part_of[session]["events"] += 1
        for rule_id in matched.get(f"audit {event['event']}", []):
            hits[rule_id].append(f"audit {event['event']}")
    pinned = [
        {**{key: rules[rule_id][key] for key in ("id", "title", "level")}, "events": len(records)}
        for rule_id, records in hits.items()
        if rules[rule_id]["origin"] == "pinned"
    ]
    return {
        "baseline_events": counts["baseline_events"],
        "system_events": counts["system_events"],
        "rules": dict(hits),
        "pinned_rules": sorted(pinned, key=rule_order),
        # Each part of the baseline: who wrote what it ran, whether it ran to its end, its events.
        "parts": [{key: value for key, value in part.items() if key != "session"} for part in parts],
    }


def judge_lab_rules(lab_rules: dict, tests: list[dict], ordinary: dict) -> list[dict]:
    """Whether each of the lab's rules is accepted: it alerts on a test, every published
    procedure it alerts on ran again with changed input arguments and it alerted on each
    of those runs, and it stays quiet on ordinary activity, every part of which ran to its
    end: a rule is not judged quiet on activity that did not happen.

    Changed input arguments show that a rule does not depend on the values they set. They
    cannot show that it does not depend on what a test fixes in its command."""

    def alerted(test: dict, rule_id: str) -> bool:
        return any(
            rule["id"] == rule_id and rule["alert"]
            for rule in test["visibility"].get("with_lab_rules", {}).get("rules", [])
        )

    verdicts = []
    for rule in sorted(lab_rules.values(), key=lambda rule: rule["title"]):
        fires = [test for test in tests if test["role"] == "test" and alerted(test, rule["id"])]
        orders = {test["order"] for test in fires}
        variants = [
            test for test in tests if test["role"] == "variant" and test.get("compared_with") in orders
        ]
        took = [variant for variant in variants if variant["execution"]["answer"] == "took effect"]
        missed = [variant for variant in took if not alerted(variant, rule["id"])]
        untried = [test for test in fires if not any(v["compared_with"] == test["order"] for v in took)]
        noise = ordinary["rules"].get(rule["id"], [])
        unfinished = [part for part in ordinary.get("parts", []) if part["exit_status"] != 0]
        if not fires:
            reason = "it matched no event of a test"
        elif unfinished:
            reason = (
                "a part of the ordinary activity did not run to its end, so the rule was not judged on it: "
                + ("; ".join(f"{part['name']} (exit status {part['exit_status']})" for part in unfinished))
            )
        elif noise:
            reason = f"it matched {len(noise)} event{'' if len(noise) == 1 else 's'} of ordinary activity"
        elif untried:
            reason = (
                "not every procedure it alerts on ran again with changed input arguments and took effect: "
                + ("; ".join(f"{test['technique']} {test['name'].rstrip('.')}" for test in untried))
            )
        elif missed:
            reason = f"it missed {len(missed)} of {len(took)} runs with changed input arguments"
        else:
            reason = None
        verdicts.append(
            {
                **{key: rule[key] for key in ("id", "title", "level", "file", "author", "text")},
                "accepted": reason is None,
                "reason": reason
                or "it alerted on every run with changed input arguments and on no ordinary activity",
                "fires_on": [
                    {key: test[key] for key in ("order", "technique", "guid", "name")} for test in fires
                ],
                "variants": [
                    {
                        **{key: variant[key] for key in ("order", "technique", "name", "compared_with")},
                        "args": variant.get("args", {}),
                        "took_effect": variant["execution"]["answer"] == "took effect",
                        "alerted": alerted(variant, rule["id"]),
                    }
                    for variant in variants
                ],
                "ordinary_matches": noise,
                "procedures": len({test["guid"] for test in fires}),
            }
        )
    return verdicts


def second_answers(tests: list[dict], verdicts: list[dict]) -> None:
    """The visibility answer with the lab's accepted rules as well. A rule that is not
    accepted is still listed where it matched, and changes no answer."""

    accepted = {verdict["id"] for verdict in verdicts if verdict["accepted"]}
    for test in tests:
        lab = test["visibility"].get("with_lab_rules")
        if lab is None:
            continue
        for rule in lab["rules"]:
            rule["accepted"] = rule["id"] in accepted
        closed = any(rule["alert"] and rule["accepted"] for rule in lab["rules"])
        lab["answer"] = "alert" if closed else test["visibility"]["answer"]


def rule_order(rule: dict) -> tuple[int, str]:
    levels = ("critical", "high", "medium", "low", "informational")
    return levels.index(rule["level"]) if rule["level"] in levels else len(levels), rule["title"]


def check_controls(
    run: dict,
    tests: list[dict],
    starts: list[dict],
    lost: dict,
    engine: list[dict],
    audit: dict | None = None,
) -> list[dict]:
    """The checks that keep a broken measurement from looking like a finding.

    audit, when the run had auditd record too, says when auditd recorded the driver's
    probe write and how many records auditd counted as lost before and after the tests.
    """

    def control(name: str, passed: bool, detail: str) -> dict:
        return {"name": name, "passed": bool(passed), "detail": detail}

    ready = run["sensor"].get("ready_after_seconds")
    probe = f"/usr/bin/true bluefire-lab-probe {run['id']}"
    seen = [event["UtcTime"] for event in starts if event["CommandLine"] == probe]
    first = min(
        (test["visibility"]["window"][0] for test in tests if test["visibility"].get("window")), default=None
    )
    in_time = bool(seen) and (first is None or min(seen) < first)
    audit_in_time = audit is None or (
        audit["probe_time"] is not None and (first is None or audit["probe_time"] < first)
    )
    if ready is None or not seen:
        detail = "the sensor did not report the probe command"
    elif not in_time:
        detail = "the sensor reported the probe command only after the first test began"
    elif not audit_in_time:
        detail = "auditd did not record the probe write before the first test began"
    else:
        detail = f"the sensor reported a probe command {ready} s after it was started, before the first test"
        detail += ", and auditd recorded the probe write before it too" if audit else ""
    checks = [control("readiness", ready is not None and in_time and audit_in_time, detail)]

    attempted = [test for test in tests if test["execution"]["answer"] != "not attempted"]
    unmeasured = [
        (test, answer)
        for test in attempted
        for answer in (test["execution"], test["visibility"])
        if answer["answer"] == "inconclusive"
    ]
    checks.append(
        control(
            "markers",
            bool(attempted) and not unmeasured,
            f"both marker commands and the launcher of all {len(attempted)} tests are in the telemetry"
            if attempted and not unmeasured
            else f"{len(unmeasured)} answers could not be given: "
            + "; ".join(f"{test.get('name', '')}: {answer.get('basis', '')}" for test, answer in unmeasured),
        )
    )

    hardened = [test for test in tests if test.get("defense")]
    left = [
        test for test in hardened if test["defense"].get("applied") and not test["defense"].get("reverted")
    ]
    checks.append(
        control(
            "changes",
            not left,
            f"each of the {len(hardened)} hardening changes was removed again after its test"
            if not left
            else "a hardening change stayed in place after its test, so the runs after it cannot be trusted: "
            + "; ".join(f"{test['defense']['title']} ({test.get('name', '')})" for test in left),
        )
    )

    cleaned = [test["cleanup"]["answer"] for test in tests if "cleanup" in test]
    behind = [
        f"{test['technique']} {test['name']}"
        for test in tests
        if test.get("cleanup", {}).get("answer") == "left behind"
    ]
    checks.append(
        control(
            "cleanup",
            bool(cleaned) and "not checked" not in cleaned,
            "the run recorded no check of any test's cleanup"
            if not cleaned
            else f"the cleanup of {cleaned.count('not checked')} of {len(cleaned)} runs of a test could not be checked"
            if "not checked" in cleaned
            else f"the cleanup of all {len(cleaned)} runs of a test ran and was checked: {cleaned.count('held')} "
            f"held, {cleaned.count('nothing to check')} leave nothing the list names, and {len(behind)} left "
            "what they did behind" + (": " + "; ".join(sorted(set(behind))) if behind else ""),
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
    audit_whole = audit is None or (
        audit["lost_before"] is not None
        and audit["lost_before"] == audit["lost_after"]
        and not audit.get("rotated")
    )
    if audit is not None:
        detail += (
            f"; auditd counted {audit['lost_before']} lost records before the tests and "
            f"{audit['lost_after']} after"
        )
        if audit.get("rotated"):
            detail += (
                f", but it rotated its log during the run into {len(audit['rotated'])} more "
                f"file{'' if len(audit['rotated']) == 1 else 's'}, so records may be missing from the export"
            )
    checks.append(control("loss", clean and whole and audit_whole and lost["sensor_starts"] == 1, detail))

    # A rule set given as an input is not the lab's: what the engine made of it is reported with
    # it, and does not fail the run.
    engine = [counts for counts in engine if counts["origin"] != "other"]
    problems = []
    for counts in engine:
        what = f"{counts['category']} rules" + (" of the lab's own" if counts["origin"] == "lab" else "")
        if counts["rules"] and not counts["given"]:
            problems.append(
                f"the sensor recorded no {counts['kind']} event, so the {what} were not evaluated"
            )
        elif counts["loaded"] != counts["rules"]:
            problems.append(f"the engine loaded {counts['loaded']} of the {counts['rules']} {what}")
        elif counts["rules"] and counts["read"] != counts["given"]:
            problems.append(f"for the {what} the engine read {counts['read']} of {counts['given']} events")
    rules = sum(counts["rules"] for counts in engine)
    given = sum(counts["given"] for counts in engine if counts["origin"] == "pinned")
    # That a category had events does not mean every rule in it could match: an auditd rule
    # needs records of the system calls, files or keys it names, which the configuration decides.
    checks.append(
        control(
            "engine",
            not problems,
            "; ".join(problems)
            or f"the rule engine loaded all {rules} rules and read all {given} events it was given, "
            "and every category of rules had events to evaluate",
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


def summarize(tests: list[dict]) -> dict:
    """The totals of a run. An answer that is unstable, or could not be given, is in none of
    the totals of answers: a test counts as an alert only when its execution answer is
    "took effect" and its visibility answer is "alert"."""

    measured = [test for test in tests if test["role"] == "test"]
    took = [test for test in measured if test["execution"]["answer"] == "took effect"]
    hardened = [test for test in tests if test["role"] == "hardened"]

    def seen(answer: str) -> int:
        return sum(1 for test in took if test["visibility"]["answer"] == answer)

    # Telemetry without an alert is a gap a rule could close only where the list says, by hand,
    # that the test's telemetry shows the technique itself.
    quiet = [test.get("shows_technique") for test in took if test["visibility"]["answer"] == "telemetry only"]
    return {
        "tests": len(measured),
        "took_effect": len(took),
        "alert": seen("alert"),
        "telemetry_only": seen("telemetry only"),
        "gaps_a_rule_could_close": quiet.count(True),
        "telemetry_beside_the_technique": quiet.count(False),
        "telemetry_not_judged": quiet.count(None),
        "no_telemetry": seen("no telemetry"),
        "inconclusive": seen("inconclusive"),
        "hardened": len(hardened),
        "blocked": sum(1 for test in hardened if test["execution"]["answer"] == "blocked"),
        "alert_with_lab_rules": sum(
            1 for test in took if test["visibility"].get("with_lab_rules", {}).get("answer") == "alert"
        ),
        "alert_with_rule_set": sum(
            1 for test in took if test["visibility"].get("other_rules", {}).get("answer") == "alert"
        ),
        "unstable": sum(1 for test in measured if test.get("unstable")),
    }


def main(run_dir: Path, engine: Path) -> int:
    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    events, raw, other = sysmon.read(run_dir / "sysmon.txt")
    starts = [event for event in events if event["EventID"] == sysmon.PROCESS_START]
    rules = rule_index(run_dir / "rules" / "linux")
    lab_rules = rule_index(run_dir / "lab-rules" / "linux", "lab")
    matched, counts = run_engine(engine, run_dir, events, raw)
    lab_matched, lab_counts = run_engine(engine, run_dir, events, raw, "lab-rules")
    for record, ids in lab_matched.items():
        matched[record].extend(ids)
    # When the run had auditd record beside Sysmon: its records, its events, and the rules that matched.
    audit = run.get("audit")
    records = auditd.read(run_dir / "audit.txt") if audit else []
    audit_events = auditd.events(records)
    audit_matched, audit_counts = run_audit_engine(engine, run_dir, records) if audit else ({}, None)
    for record, ids in audit_matched.items():
        matched[record].extend(ids)
    for index, by_category in ((rules, counts), (lab_rules, lab_counts)):
        for category in by_category:
            by_category[category]["rules"] = sum(
                1 for rule in index.values() if rule["file"].startswith(f"linux/{category}/")
            )
    tally = [
        {"category": category, "origin": origin, **entry}
        for origin, by_category in (("pinned", counts), ("lab", lab_counts))
        for category, entry in by_category.items()
    ]
    if audit_counts is not None:
        audit_counts["rules"] = sum(1 for rule in rules.values() if rule["file"].startswith("linux/auditd/"))
        tally.append(audit_counts)
    rules.update(lab_rules)
    # A rule set given as an input, evaluated apart, as a column of its own.
    rule_set = sort_rule_set(run_dir) if (run_dir / "rule-set" / "SOURCE").is_file() else None
    if rule_set:
        other_rules = rule_index(run_dir / "engine" / "rule-set" / "linux", "other")
        for rule in other_rules.values():
            rule["file"] = rule_set["paths"][rule["file"]]
        other_matched, other_counts = run_engine(engine, run_dir, events, raw, "engine/rule-set")
        audit_other, audit_other_counts = run_audit_engine(engine, run_dir, records, "engine/rule-set")
        for found in (other_matched, audit_other):
            for record, ids in found.items():
                matched[record].extend(f"other:{rule_id}" for rule_id in ids)
        other_counts["auditd"] = audit_other_counts
        for category, entry in other_counts.items():
            entry["rules"] = sum(1 for path in rule_set["paths"] if path.startswith(f"linux/{category}/"))
            tally.append({**entry, "category": category, "origin": "other"})
        rule_set["evaluated"] = {category: entry["loaded"] or 0 for category, entry in other_counts.items()}
        rule_set["sorted_by_kind"] = {category: entry["rules"] for category, entry in other_counts.items()}
        del rule_set["paths"]
        rules.update(other_rules)

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
        "audit_events": audit_events,
        "lookups": lookups(audit_events),
        "rule_set": rule_set,
    }
    tests, by_order = [], {}
    for test in run["tests"]:
        if test["role"] == "baseline":
            continue
        result = {
            key: test[key]
            for key in ("order", "role", "technique", "guid", "name", "executor", "elevated", "user")
        }
        kept = ("rule", "args", "defense", "compared_with", "shows_technique")
        result.update({key: test[key] for key in kept if key in test})
        if "defense" in test:
            attack = step_of(test, "attack")
            result["output"] = ((attack["output"] + attack["error"]).strip() if attack else "")[-2000:]
        without_change = by_order.get(test.get("compared_with"), {}).get("execution")
        result["execution"] = execution(test, without_change)
        if (undone := cleanup(test)) is not None:
            result["cleanup"] = undone
        by_order[test["order"]] = result
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
    # What systemd ran during the baseline is ordinary work too: only the tests' windows are left out.
    baseline = {test["order"] for test in run["tests"] if test["role"] == "baseline"}
    test_windows = [
        window for order, window in windows.items() if order not in baseline and None not in window
    ]
    ordinary = ordinary_activity(run, events, starts, matched, rules, test_windows, audit_events)
    verdicts = judge_lab_rules(lab_rules, tests, ordinary)
    second_answers(tests, verdicts)
    audit_control = audit_facts(audit, audit_events) if audit else None
    results = {
        "schema": "bluefire-lab/results/1",
        "run": {
            key: run.get(key)
            for key in ("id", "started", "finished", "account", "target", "tools", "inventory", "aborted")
        },
        "sensor": {
            **run["sensor"],
            "version": next((e["Version"] for e in events if e["EventID"] == "4" and "Version" in e), None),
            "configuration_sha256": hashlib.sha256((run_dir / "sensor-config.xml").read_bytes()).hexdigest(),
            "configuration_text": (run_dir / "sensor-config.xml").read_text(encoding="utf-8"),
            "events": len(events),
        },
        "audit": {
            "name": "auditd",
            "version": audit.get("version"),
            "rules_sha256": hashlib.sha256((run_dir / audit["rules"]).read_bytes()).hexdigest(),
            "rules_text": (run_dir / audit["rules"]).read_text(encoding="utf-8"),
            "records": len(records),
            "events": len(audit_events),
        }
        if audit
        else None,
        "rules": {
            "source": (run_dir / "rules" / "SOURCE").read_text(encoding="utf-8").strip(),
            "license": "Detection Rule License 1.1, https://github.com/SigmaHQ/Detection-Rule-License",
            # What the engine says it loaded: a rule it could not convert was not evaluated.
            "evaluated": {
                **{category: counts[category]["loaded"] for category in CATEGORIES},
                **({"auditd": audit_counts["loaded"]} if audit_counts else {}),
            },
            "alert_levels": list(ALERT_LEVELS),
            "lab": sum(lab_counts[category]["loaded"] or 0 for category in CATEGORIES),
        },
        "lab_rules": verdicts,
        "rule_set": rule_set,
        "ordinary_activity": {
            key: ordinary[key] for key in ("baseline_events", "system_events", "pinned_rules", "parts")
        },
        "engine": {"name": "Zircolite", "version": found.group(1) if found else None, "counts": tally},
        "controls": check_controls(run, tests, starts, sysmon.loss(events, other), tally, audit_control),
        "summary": summarize(tests),
        "tests": tests,
        "dropped": run.get("dropped", []),
    }
    (run_dir / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    failed = [check for check in results["controls"] if not check["passed"]]
    for check in results["controls"]:
        print(("ok      " if check["passed"] else "FAILED  ") + f"{check['name']}: {check['detail']}")
    return 1 if failed else 0
