"""Say what differs between two recordings, and whether one declared change can explain it.

Takes the recording.json of a run before a change and of a run after it, and
writes delta.json (the format is the section "A delta" of docs/RECORDING.md)
and delta.md for a job summary. Steps pair by their id. A recording without
source.setup has no stable ids, so its steps pair by role, test and order, and
each such pair says so. A step on one side only is listed, never counted.

The comparison judges like with like: a change of the lab's rules on the
outcome with the lab's rules, a change of the published rules on both outcomes,
and a change of a sensor's settings also on whether a sensor recorded the step.
What the declared change cannot move is the control, and a difference there is
run variation, not an effect. A lab rule that is the same file in both runs and
matched a step differently is run variation too, unless a sensor's settings are
the declared change. So is a step whose outcome moved under a sensor change
while that sensor recorded the same for it in both runs (for auditd: nothing
under an audit key that only one run has). A changed step lists what the
declared sensor recorded of it in one run only. It refuses a verdict, and still
lists what differed, when the two are not of the same steps, when a recording
lacks source.setup, when anything other than the declared change differs in the
setup, in the detectors' digests or in the tools' versions (the published rules'
pin is part of a change of the published rules), and when two runs said to be
made side by side do not name one CI run.

Two runs side by side get two runners, and GitHub can hand out two images and
kernels. When the runner's image and kernel are all that differ besides a
change of the audit rules, the verdict is limited instead of refused: it
credits the change only on a step that carries the change's own mark, events of
an audit key that only one run's rules define and nothing else of the step, and
every other step that differs is not attributable. Which keys a run's rules
define is what its recording's auditd sensor says, and a pair whose recordings
do not both say it is refused. Any other change on two
runners that differed is refused, with the advice to run the pair again. The
lab's own code is not part of the setup: when its commit differs, every verdict
says so.
"""

from __future__ import annotations

import collections
import hashlib
import json
from pathlib import Path

SCHEMA = "bluefire.delta/1"
CLAIM = "one pair of runs"
FIELDS = ("happened", "recorded", "outcome", "outcome_with_lab_rules")
SAID = {
    "happened": "what happened",
    "recorded": "by the sensors",
    "outcome": "by the published rules",
    "outcome_with_lab_rules": "with the lab's rules",
}
# Each field as the control sentence names it.
CONTROL = {
    "happened": "what happened",
    "recorded": "whether a sensor recorded the step",
    "outcome": "the outcome by the published rules",
    "outcome_with_lab_rules": "the outcome with the lab's rules",
}
# Better for the defender, in this order. The other values are not ranked.
RANK = {"unseen": 0, "seen": 1, "alerted": 2, "stopped": 3}
RECORDED_RANK = {"no telemetry": 0, "recorded": 1}
RESULTS = ("same", "better", "worse", "changed", "not attributable", "without cause", "no verdict")
WORDS = {
    "atomic_commit": "the tests' commit",
    "images": "the image of host",
    "kernels": "the kernel of host",
    "sensors": "the settings of sensor",
    "detectors": "the rules of detector",
    "tools": "the version of",
}
NOT_RECORDED = "not recorded"
# The names of the setup that say which runner a run had, not how its defense was set up.
RUNNER = ("images:", "kernels:")
# The declared changes that leave a mark of their own on what they record, and what that mark is.
MARKS = {
    "sensors:auditd": "every event the recordings hold of it is of an audit key that only one run's audit "
    "rules define, and the other run holds nothing of it",
}
# A changed step lists at most this many of the records its declared sensor added, and as many it lost.
KEPT_LINES = 20


def plural(number: int, noun: str) -> str:
    return f"{number} {noun}" + ("" if number == 1 else "s")


def named(item: str) -> str:
    """A setup item's name in plain words, such as "the settings of sensor `auditd`"."""

    group, _, member = item.partition(":")
    return f"{WORDS.get(group, group)} `{member}`" if member else WORDS.get(group, f"`{group}`")


def items(recording: dict) -> dict[str, object]:
    """Everything a comparison checks of how a recording was made, by name: each value of
    source.setup, each sensor's settings, each detector's digest and each tool's version.
    A sensor or detector of the network without a digest is there with None."""

    source, network = recording["source"], recording["network"]
    found: dict[str, object] = {}
    for key, value in (source.get("setup") or {}).items():
        if isinstance(value, dict):
            found.update({f"{key}:{member}": part for member, part in value.items()})
        else:
            found[key] = value
    for sensor in network["sensors"]:
        found.setdefault(f"sensors:{sensor['id']}", None)
    for detector in network["detectors"]:
        found[f"detectors:{detector['id']}"] = detector.get("digest")
    for tool in source.get("tools", []):
        if tool["role"] == "tests":
            # The tests' commit is the setup's atomic_commit, and an older recording has it here only.
            found.setdefault("atomic_commit", tool.get("version"))
        else:
            found[f"tools:{tool['name']}"] = tool.get("version")
    # Every comparison needs the tests' commit: recorded nowhere, it is not known to be the same.
    found.setdefault("atomic_commit", None)
    return found


def parts(declared: str | None, recordings: tuple[dict, dict]) -> set[str]:
    """The names of the setup that are the declared change itself. The published rules' pin, the
    version of the tool of role rules, is the commit their files come from, so the digest of the
    detector pinned already covers it: they are one change. No tool version is part of any other
    declared change. The lab's rules are files of this repository, and a sensor's program is not its
    settings: a new version of it can record otherwise under the same settings, a second change."""

    if declared != "detectors:pinned":
        return {declared} if declared else set()
    return {declared} | {
        f"tools:{tool['name']}"
        for recording in recordings
        for tool in recording["source"].get("tools", [])
        if tool["role"] == "rules"
    }


def value(step: dict, field: str) -> str:
    if field == "happened":
        return step["happened"]["answer"]
    if field == "recorded":
        answer = step["visibility"]["answer"]
        if answer == "no telemetry":
            return answer
        return "recorded" if answer in ("alert", "telemetry only") else "not known"
    # A run that evaluated no rules of the lab's own has the published rules' outcome with them too.
    return step.get(field, step["outcome"])


def key_of(step: dict, by_id: bool) -> object:
    if by_id:
        return step["id"]
    return (
        step["role"],
        (step.get("test") or {}).get("guid", step["title"]),
        (step.get("defense") or {}).get("title"),
    )


def matches(recording: dict) -> dict[str, set[str]]:
    """The rules that matched each step, as "level: title", launcher-only matches left out."""

    found: dict[str, set[str]] = collections.defaultdict(set)
    for alert in recording["alerts"]:
        if not alert.get("launcher_only"):
            found[alert["step"]].add(f"{alert['rule']['level']}: {alert['rule']['title']}")
    return found


def lab_matches(recording: dict) -> dict[str, set[str]]:
    """The ids of the lab's own rules that matched each step, launcher-only matches left out."""

    found: dict[str, set[str]] = collections.defaultdict(set)
    for alert in recording["alerts"]:
        if alert["rule"].get("origin") == "lab" and not alert.get("launcher_only"):
            found[alert["step"]].add(alert["rule"]["id"])
    return found


def lab_verdicts(recording: dict) -> dict[str, dict] | None:
    """Whether the run accepted each of the lab's rules, by rule id, or None when it does not say."""

    lab = next((detector for detector in recording["network"]["detectors"] if detector["id"] == "lab"), {})
    return {verdict["rule"]: verdict for verdict in lab["verdicts"]} if "verdicts" in lab else None


def unmoved_rules(
    touched: set[str], before: dict[str, dict] | None, after: dict[str, dict] | None
) -> list[str]:
    """Why lab rules that matched a step differently cannot be the declared change: each is the same
    file in both runs, and its acceptance or its matches moved by themselves. Empty when every one
    of them is new or changed."""

    if before is None or after is None:
        return ["the recordings do not say which of the lab's rules changed"]

    def said(verdict: dict) -> str:
        return ("accepted" if verdict["accepted"] else "not accepted") + (
            f": {verdict['reason']}" if verdict.get("reason") else ""
        )

    return [
        f"the lab's rule `{after[rule]['title']}` is the same in both runs (before {said(before[rule])}; "
        f"after {said(after[rule])})"
        for rule in sorted(touched)
        if rule in before
        and rule in after
        and before[rule].get("digest") is not None
        and before[rule].get("digest") == after[rule].get("digest")
    ]


def audit_keys(recording: dict) -> dict[str, list[dict]]:
    """auditd's events by their audit key, the key of the rule that wrote the record, in time order."""

    found: dict[str, list[dict]] = collections.defaultdict(list)
    for event in recording["events"]:
        if event["sensor"] == "auditd" and (event.get("fields") or {}).get("key"):
            found[event["fields"]["key"]].append(event)
    return found


def defined_keys(recording: dict) -> set[str] | None:
    """The audit keys that the run's audit rules define, as its auditd sensor says, or None when it
    does not say: an older recording, or one without auditd."""

    sensor = next((sensor for sensor in recording["network"]["sensors"] if sensor["id"] == "auditd"), {})
    return set(sensor["audit_keys"]) if "audit_keys" in sensor else None


def sensor_lines(recording: dict, sensor: str, keys: set[str] | None = None) -> dict[str, list[str]]:
    """The events one sensor recorded for each step, as "<kind>: <text>" lines in time order, only
    those of these audit keys when keys are given. A recording keeps at most a few hundred events of
    a step: these are the ones it kept."""

    found: dict[str, list[str]] = collections.defaultdict(list)
    for event in recording["events"]:
        if event["sensor"] == sensor and (keys is None or (event.get("fields") or {}).get("key") in keys):
            found[event["step"]].append(
                f"{event['kind']}: {event['text']}" if event["text"] else event["kind"]
            )
    return found


def only_in(lines: list[str], other: list[str]) -> list[str]:
    """The lines of one side that the other side does not have as often, in their order."""

    left, found = collections.Counter(other), []
    for line in lines:
        if left[line]:
            left[line] -= 1
        else:
            found.append(line)
    return found


def records_of(sensor: str, before: list[str], after: list[str]) -> dict:
    """What one sensor recorded for a step in one run and not in the other, the first KEPT_LINES of each."""

    new, gone = only_in(after, before), only_in(before, after)
    return {
        "sensor": sensor,
        "new": {"count": len(new), "lines": new[:KEPT_LINES]},
        "gone": {"count": len(gone), "lines": gone[:KEPT_LINES]},
    }


def by_step(recording: dict, part: str) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = collections.defaultdict(list)
    for item in recording[part]:
        found[item["step"]].append(item)
    return found


def mark_of(sides: tuple[tuple[dict, list[dict], list[dict], set[str]], ...]) -> dict | str:
    """Whether a change of the audit rules left its own mark on a step: one run holds nothing of the
    step, and every event the other holds of it is of an audit key that only that run's rules define,
    every one it recorded kept, with every alert on the step resting on those events alone. Then the
    step's move is carried by those events: without them that run too would hold nothing of it.
    sides is (step, its events, its alerts, the audit keys that its run's rules define and the other
    run's do not) of the before and the after run. The mark as {"run", "keys", "events"}, or why
    the step does not carry one."""

    holding = [number for number, (_, events, alerts, _) in enumerate(sides) if events or alerts]
    if len(holding) != 1:
        return "both runs hold events of it" if holding else "neither run holds an event of it"
    step, events, alerts, only = sides[holding[0]]
    if sides[1 - holding[0]][0]["visibility"]["answer"] != "no telemetry":
        return "the other run does not say that no sensor recorded it"
    if not all(
        event["sensor"] == "auditd" and (event.get("fields") or {}).get("key") in only for event in events
    ):
        return "not every event of it is auditd's under an audit key that only that run's audit rules define"
    if step["visibility"].get("events") != len(events):
        return "the recording did not keep every event of it"
    ids = {event["id"] for event in events}
    if not all(alert.get("events") and set(alert["events"]) <= ids for alert in alerts):
        return "an alert on it does not rest on those events alone"
    return {
        "run": ("before", "after")[holding[0]],
        "keys": sorted({event["fields"]["key"] for event in events}),
        "events": len(events),
    }


def underneath(old: dict, new: dict, before: set[str], after: set[str]) -> list[str]:
    """What changed under a step's answers: whether a sensor recorded it, and which rules matched."""

    lines = []
    for step, words in ((new, "recorded now"), (old, "no longer recorded")):
        other = old if step is new else new
        if other["visibility"]["answer"] == "no telemetry" != step["visibility"]["answer"]:
            lines.append(f"{words}: {plural(step['visibility'].get('events', 0), 'event')}")
    lines += [f"matches now: {rule}" for rule in sorted(after - before)]
    lines += [f"no longer matches: {rule}" for rule in sorted(before - after)]
    return lines


def judged_fields(declared: str | None) -> tuple[str, ...]:
    """The fields a declared change can move. The other fields are its control."""

    if declared is None:
        return ()
    if declared == "detectors:lab":
        return ("outcome_with_lab_rules",)
    if declared.startswith("detectors:"):
        # Rules cannot make a sensor record a step: whether one did is the control.
        return ("outcome", "outcome_with_lab_rules")
    return ("recorded", "outcome", "outcome_with_lab_rules")


def direction(role: str, changes: list[tuple[str, str, str]]) -> str:
    """better, worse, or changed when the values are not ranked or move both ways. A step of role
    control must raise no alert, so for it an alert is worse and nothing else is ranked."""

    def rank(field: str, word: str) -> int | None:
        if field == "recorded":
            return None if role == "control" else RECORDED_RANK.get(word)
        if role == "control":
            return (0 if word == "alerted" else 1) if word in RANK else None
        return RANK.get(word)

    ways = set()
    for field, old, new in changes:
        first, second = rank(field, old), rank(field, new)
        ways.add(None if first is None or second is None or first == second else second > first)
    return {frozenset({True}): "better", frozenset({False}): "worse"}.get(frozenset(ways), "changed")


def price(before: dict, after: dict, declared: str, limited: bool = False) -> str:
    """What a gain cost, in the recording's own numbers, or why it holds none. Under a limit each run
    counted on a runner of its own, so the two numbers are each run's and their difference is not
    the change's price."""

    if declared == "detectors:lab":
        said = (
            "price not counted: the lab's rules that matched ordinary activity are left out of the "
            "recording before it is written"
        )
        notes = [
            f"{label}: {note.rstrip('.')}"
            for label, recording in (("before", before), ("after", after))
            for note in recording["notes"]
            if note.startswith("The run accepted")
        ]
        return said + (f" ({'; '.join(notes)})" if notes else "")

    def count(recording: dict, key: str, inside: str) -> str:
        holder = recording.get(inside) or {}
        return str(holder[key]) if key in holder else NOT_RECORDED

    alerts = f"published rules that alerted on ordinary activity: {count(before, 'false_alerts', 'score')} before, {count(after, 'false_alerts', 'score')} after"
    counted = alerts
    if declared.startswith("sensors:"):
        events = f"ordinary events: {count(before, 'events', 'ordinary')} before, {count(after, 'events', 'ordinary')} after"
        counted = f"{alerts}; {events}"
    if limited:
        return (
            "price not known: each run counted its ordinary activity on its own runner, and the two runners "
            f"differed, so what differs between the counts is not the change's price (each run's own, {counted})"
        )
    return f"price: {counted}"


def race(before: dict, after: dict) -> dict:
    """The time to the first alert on each side, only where some rules ran live on an attack path."""

    live = all(
        recording["kind"] == "attack path"
        and any(detector["when"] == "live" for detector in recording["network"]["detectors"])
        for recording in (before, after)
    )
    if not live:
        return {"why": "the rules ran after each run, so there is no race to compare"}
    return {
        side: {
            key: recording["score"][key]
            for key in ("first_alert_seconds", "goal_seconds")
            if key in recording["score"]
        }
        for side, recording in (("before", before), ("after", after))
    }


def side(recording: dict, sha: str) -> dict:
    source = recording["source"]
    return {
        "sha256": sha,
        "id": recording["id"],
        **{
            key: source[key]
            for key in ("run_url", "environment", "commit", "defense_commit", "started")
            if key in source
        },
    }


def compare(
    before: dict,
    after: dict,
    shas: tuple[str, str] = ("", ""),
    declared: str | None = None,
    two_runners: bool = False,
) -> dict:
    """The delta of two recordings, as delta.json holds it. two_runners says that the two runs were
    made side by side, each on a fresh runner of its own, rather than one after the other on one."""

    refusals = []
    for label, recording in (("before", before), ("after", after)):
        if "setup" not in recording["source"]:
            refusals.append(
                f"the {label} recording has no source.setup, so what it was made with is not known"
            )
    by_id = not refusals
    if before["kind"] != after["kind"]:
        refusals.append(
            f"the before recording is a {before['kind']} and the after recording a {after['kind']}"
        )

    first, second = items(before), items(after)
    # A value not recorded on either side is not known to be the same: it differs.
    same = sorted(
        name
        for name in set(first) | set(second)
        if first.get(name) is not None and first.get(name) == second.get(name)
    )
    declared_parts = parts(declared, (before, after))
    differences = [
        {
            "what": name,
            "before": first.get(name),
            "after": second.get(name),
            **({"declared": True} if name in declared_parts else {}),
        }
        for name in sorted(set(first) | set(second))
        if name not in same
    ]
    if declared is not None:
        if not declared.startswith(("sensors:", "detectors:")) or declared not in set(first) | set(second):
            refusals.append(
                f"the declared change `{declared}` is not a sensor's settings or a detector's rules of these recordings"
            )
        elif declared not in {difference["what"] for difference in differences}:
            refusals.append(f"the declared change, {named(declared)}, is the same in both recordings")
        elif first.get(declared) is None or second.get(declared) is None:
            refusals.append(
                f"the declared change, {named(declared)}, is not recorded in both recordings, "
                "so it is not known to have changed"
            )
    for difference in differences:
        if difference.get("declared"):
            continue
        if difference["before"] is None and difference["after"] is None:
            refusals.append(
                f"not recorded in either recording: {named(difference['what'])}, so not known to be the same"
            )
            continue
        shown = [
            NOT_RECORDED if part is None else part for part in (difference["before"], difference["after"])
        ]
        refusals.append(f"also differed: {named(difference['what'])} ({shown[0]} before, {shown[1]} after)")
    # Two runs side by side in one CI run name that one run: anything else is not such a pair.
    urls = (before["source"].get("run_url"), after["source"].get("run_url"))
    if two_runners and not (urls[0] and urls[0] == urls[1]):
        refusals.append(
            "the two runs were said to be made side by side in one CI run, but the recordings "
            + ("name different CI runs" if all(urls) else "do not both name the CI run that made them")
        )
    # The lab's own code is not part of the setup: it differs between a pull request and main, and
    # a rule of the lab's own changes it too. It refuses nothing, and every verdict says it differed.
    code = {
        label: recording["source"].get("commit")
        for label, recording in (("before", before), ("after", after))
    }
    code["same"] = code["before"] is not None and code["before"] == code["after"]
    variation = "run variation" if code["same"] else "run variation or a change of the lab's code"

    earlier: dict[object, list[dict]] = collections.defaultdict(list)
    for step in before["steps"]:
        earlier[key_of(step, by_id)].append(step)
    pairs, new = [], []
    for step in after["steps"]:
        waiting = earlier.get(key_of(step, by_id))
        if waiting:
            pairs.append((waiting.pop(0), step))
        else:
            new.append(step)
    gone = [step for steps in earlier.values() for step in steps]
    in_order = [old["id"] for old, _ in pairs] == [old["id"] for old in before["steps"]]
    if new or gone:
        refusals.append(
            f"the two recordings are not of the same steps: {len(new)} only in the after recording, "
            f"{len(gone)} only in the before recording"
        )
    elif not in_order:
        refusals.append("the steps of the two recordings ran in another order")

    # Two runners of one CI run can get two images and kernels, and a pull request cannot choose them.
    # When those are all that refuse, a change that leaves a mark of its own is judged by that mark
    # alone, and any other change is refused with what to do about it.
    runner_rows = [
        difference
        for difference in differences
        if difference["what"].startswith(RUNNER)
        and not difference.get("declared")
        and difference["before"] is not None
        and difference["after"] is not None
    ]
    runner_reasons = [
        f"also differed: {named(row['what'])} ({row['before']} before, {row['after']} after)"
        for row in runner_rows
    ]
    runners_only = bool(runner_rows) and two_runners and sorted(refusals) == sorted(runner_reasons)
    runners_said = ", ".join(named(row["what"]) for row in runner_rows)
    # The mark is a key that one run's audit rules define and the other's do not: a key that only one
    # run's events carry may be one both rule sets define that fired on one runner only.
    defined = (defined_keys(before), defined_keys(after))
    unsaid = [label for label, keys_ in zip(("before", "after"), defined, strict=True) if keys_ is None]
    limit = None
    if runners_only and declared in MARKS and unsaid:
        refusals.append(
            f"the two runners differed ({runners_said}), and "
            + (
                f"the {unsaid[0]} recording does not say which audit keys its"
                if len(unsaid) == 1
                else "neither recording says which audit keys its run's"
            )
            + " audit rules define, so no step can be shown to carry the change's "
            "own mark: write the recordings again with `bluefire-lab recording` from each run's folder, "
            "which holds the audit rules as they were loaded, or run the pair again"
        )
    elif runners_only and declared in MARKS:
        refusals = []
        limit = {
            "why": "the two runners differed",
            "differences": [row["what"] for row in runner_rows],
            "credits": f"only a step that carries the change's own mark: {MARKS[declared]}",
        }
    elif runners_only and declared:
        refusals.append(
            f"the two runners differed ({runners_said}), and a change of "
            f"{named(declared)} leaves no mark of its own on a step that tells its effect from theirs: run the "
            "pair again, which gives two new runners"
        )

    comparable = not refusals
    judged = judged_fields(declared)
    control = tuple(field for field in FIELDS if field not in judged)
    gain_price = price(before, after, declared, limit is not None) if comparable and declared else None
    rules_before, rules_after = matches(before), matches(after)
    lab_before, lab_after = lab_matches(before), lab_matches(after)
    lab_titles = {
        alert["rule"]["id"]: alert["rule"]["title"]
        for recording in (before, after)
        for alert in recording["alerts"]
        if alert["rule"].get("origin") == "lab"
    }
    verdicts = (lab_verdicts(before), lab_verdicts(after))
    # A sensor's settings can change a step only through what that sensor recorded of it.
    sensor = declared.partition(":")[2] if declared and declared.startswith("sensors:") else None
    kept = ({event["step"] for event in before["events"]}, {event["step"] for event in after["events"]})
    keys = (audit_keys(before), audit_keys(after))
    only = (set(keys[0]) - set(keys[1]), set(keys[1]) - set(keys[0]))
    if sensor == "auditd":
        # Two runs of the same audit rules differ in text that is new in every run, such as temporary
        # file names and a password's salt. Only the records of a rule that one run has and the other
        # lacks, told by its audit key, can be the change's.
        lines = (sensor_lines(before, sensor, only[0]), sensor_lines(after, sensor, only[1]))
        unchanged = f"sensor `{sensor}` recorded nothing of this step under an audit key that only one of the runs has"
    else:
        lines = (sensor_lines(before, sensor), sensor_lines(after, sensor)) if sensor else ({}, {})
        unchanged = f"sensor `{sensor}` recorded the same for this step in both runs"
    events = (by_step(before, "events"), by_step(after, "events"))
    # A rule that matched only the launcher's start moves no outcome, and the mark leaves it out.
    alerts = tuple(
        by_step(
            {"alerts": [alert for alert in recording["alerts"] if not alert.get("launcher_only")]}, "alerts"
        )
        for recording in (before, after)
    )
    marking = (defined[0] - defined[1], defined[1] - defined[0]) if limit is not None else (set(), set())
    rows = []
    for old, step in pairs:
        changed = [
            (field, value(old, field), value(step, field))
            for field in FIELDS
            if value(old, field) != value(step, field)
        ]
        moved = [change for change in changed if change[0] in judged]
        varied = [change for change in changed if change[0] in control]
        touched = lab_before[old["id"]] ^ lab_after[step["id"]]
        # A lab rule that matched the step in one run only. A change of a sensor's settings can make an
        # unchanged lab rule match new telemetry, and that is its effect. A change of the lab's rules is
        # credited only with the rules whose file changed. A change of the published rules cannot make
        # any lab rule match, so every such rule moved by itself, and the outcome with the lab's rules
        # that moved with it is not the change's.
        if not touched or not declared or declared.startswith("sensors:"):
            unmoved = []
        elif declared == "detectors:lab":
            unmoved = unmoved_rules(touched, *verdicts) if moved else []
        elif any(field == "outcome_with_lab_rules" for field, _, _ in moved):
            unmoved = [
                f"the lab's rule `{lab_titles.get(rule, rule)}` matched it in one run only, and a change of "
                "the published rules cannot make a rule of the lab's own match"
                for rule in sorted(touched)
            ]
        else:
            unmoved = []
        records = (
            records_of(sensor, lines[0].get(old["id"], []), lines[1].get(step["id"], []))
            if sensor and changed
            else None
        )
        # A sensor's settings move a step only through what that sensor recorded of it: when the
        # recordings hold the step's events and none of the declared sensor's is the change's, the
        # credit an unchanged lab rule got above does not hold either.
        if records and moved and not records["new"]["count"] and not records["gone"]["count"]:
            if old["id"] in kept[0] or step["id"] in kept[1]:
                unmoved = [unchanged]
        mark = (
            mark_of(
                tuple(
                    (
                        part,
                        events[number].get(part["id"], []),
                        alerts[number].get(part["id"], []),
                        marking[number],
                    )
                    for number, part in enumerate((old, step))
                )
            )
            if limit is not None and changed
            else None
        )
        if not changed:
            result, words = "same", "no change"
        elif not comparable:
            result, words = "no verdict", "no verdict: the comparison is refused"
        elif limit is not None and (varied or isinstance(mark, str)):
            # On two runners that differed, a step without the change's mark may have moved with them.
            said = (["the control changed too"] if varied else []) + (
                [f"the step does not carry the change's own mark ({mark})"] if isinstance(mark, str) else []
            )
            result, words = (
                "not attributable",
                f"not attributable: the two runners differed ({runners_said}), "
                + (", and ".join(said))
                + f", so this is {variation} or the runners' difference",
            )
        elif varied and moved:
            result, words = (
                "not attributable",
                f"not attributable: the control changed too, which is {variation}",
            )
        elif varied:
            result, words = "without cause", f"changed without a cause: {variation}, not an effect"
        elif unmoved:
            result, words = (
                "not attributable",
                f"not attributable: {'; '.join(unmoved)}, so this is {variation}",
            )
        else:
            result = direction(step["role"], moved)
            words = (
                f"{result} by the change's own mark, on two runners that differed: "
                if isinstance(mark, dict)
                else f"{result}: "
            ) + "; ".join(f"{old_} to {new_} {SAID[field]}" for field, old_, new_ in moved)
            if step["role"] == "control" and any(new_ == "alerted" for _, _, new_ in moved):
                words += " (a false alert: a step of role control must raise none)"
        rows.append(
            {
                "id": step["id"],
                **({"before_id": old["id"]} if old["id"] != step["id"] else {}),
                "role": step["role"],
                "title": step["title"],
                "technique": step["technique"]["id"],
                "paired_by": "id" if by_id else "role, test and order",
                "before": {field: value(old, field) for field in FIELDS},
                "after": {field: value(step, field) for field in FIELDS},
                "changed": [field for field, _, _ in changed],
                "underneath": underneath(old, step, rules_before[old["id"]], rules_after[step["id"]])
                if changed
                else [],
                **({"records": records} if records else {}),
                **({"mark": mark} if isinstance(mark, dict) and result != "not attributable" else {}),
                "result": result,
                "verdict": words,
            }
        )
    tests = collections.Counter(row["technique"] for row in rows if row["role"] == "test")
    better = collections.Counter(
        row["technique"] for row in rows if row["role"] == "test" and row["result"] == "better"
    )
    for row in rows:
        if row["result"] == "better":
            row["price"] = gain_price
            if row["role"] == "test":
                procedures = {"better": better[row["technique"]], "of": tests[row["technique"]]}
                row["procedures"] = procedures
                row["verdict"] += (
                    f", on {procedures['better']} of the {plural(procedures['of'], 'published procedure')} of "
                    f"{row['technique']} in the list"
                )
            row["verdict"] += f"; {gain_price}"
        if row["result"] in ("better", "worse", "changed") and not code["same"]:
            row["verdict"] += (
                "; the lab's code is not known to be the same, and the comparison does not check it"
            )
        if "mark" in row:
            keys_said = ", ".join(f"`{key}`" for key in row["mark"]["keys"])
            row["verdict"] += (
                f"; it rests on {plural(row['mark']['events'], 'event')} of the audit "
                f"{'key' if len(row['mark']['keys']) == 1 else 'keys'} {keys_said}, which only "
                f"the {row['mark']['run']} run's audit rules define, the only events either run holds of the "
                f"step, on two runners that differed ({runners_said})"
            )
        if row["result"] != "same":
            row["verdict"] += f"; {CLAIM}"
    if limit is not None:
        limit["credited"] = sum(1 for row in rows if "mark" in row)
        limit["not_attributable"] = sum(1 for row in rows if row["result"] == "not attributable")

    def listed(steps: list[dict]) -> list[dict]:
        return [
            {
                "id": step["id"],
                "role": step["role"],
                "title": step["title"],
                "technique": step["technique"]["id"],
            }
            for step in steps
        ]

    return {
        "schema": SCHEMA,
        "claim": CLAIM,
        "before": side(before, shas[0]),
        "after": side(after, shas[1]),
        "declared_change": declared,
        "runners": 2 if two_runners and urls[0] and urls[0] == urls[1] else None,
        "comparable": comparable,
        "limit": limit,
        "refused_because": refusals,
        "differences": differences,
        "same_in_both": same,
        "lab_code": code,
        "judged": list(judged),
        "control": {
            "fields": list(control),
            "same": sum(1 for row in rows if not set(row["changed"]) & set(control)),
            "of": len(rows),
            "varied": [row["id"] for row in rows if set(row["changed"]) & set(control)],
        },
        "counts": {
            "paired": len(rows),
            **{result: sum(1 for row in rows if row["result"] == result) for result in RESULTS},
            # Of the steps counted above as better, worse or changed, those credited by the change's own
            # mark alone on two runners that differed: a limited verdict, beside the counts it is part of.
            "by_mark": sum(1 for row in rows if "mark" in row),
            "new": len(new),
            "gone": len(gone),
        },
        "unexplained": [row["id"] for row in rows if row["result"] in ("without cause", "not attributable")],
        "steps": rows,
        "new": listed(new),
        "gone": listed(gone),
        "race": race(before, after),
        "audit_keys": {
            label: {
                key: {"events": len(events), "steps": sorted({event["step"] for event in events})}
                for key, events in sorted(found.items())
                if key in keys_of
            }
            for label, found, keys_of in (("only_before", keys[0], only[0]), ("only_after", keys[1], only[1]))
        }
        if sensor == "auditd"
        else None,
    }


def markdown(delta: dict) -> str:
    """delta.json in a few lines and one table, for a job summary."""

    def cell(text: object) -> str:
        return str(text).replace("|", "\\|").replace("\n", " ")

    def run(facts: dict) -> str:
        address = facts.get("run_url")
        label = address.rstrip("/").rpartition("/")[2] if address else facts["id"]
        made = f", commit `{facts['commit'][:8]}`" if "commit" in facts else ""
        defense = facts.get("defense_commit")
        if defense:
            made += (
                f", its rules and sensor settings from commit `{defense[:8]}`"
                if defense != facts.get("commit")
                else ", its rules and sensor settings from that commit"
            )
        return (
            f"[{label}]({address})" if address else f"`{label}`"
        ) + f", {facts.get('environment', '')}{made}"

    declared, runners = delta["declared_change"], delta.get("runners")
    lines = [
        "## A pair of runs, before and after the change"
        if runners == 2
        else "## Compared with an earlier recording",
        "",
        f"Before: {run(delta['before'])}. After: {run(delta['after'])}.",
        "",
        f"Declared change: {named(declared) if declared else 'none'}.",
        "",
    ]
    limit = delta.get("limit")
    runner_rows = [
        row
        for row in delta["differences"]
        if row["what"].startswith(RUNNER) and row["before"] is not None and row["after"] is not None
    ]
    if runners == 2:
        lines += [
            "The two runs were made side by side in one CI run, each on a fresh runner of its own, not one "
            "after the other on one runner. So nothing the first run left behind could change the second"
            + (
                ", but the two runners differed: "
                + ", ".join(
                    f"{named(row['what'])} ({row['before']} before, {row['after']} after)"
                    for row in runner_rows
                )
                + "."
                if runner_rows
                else ", and what differs between two runners of the same image and kernel is part of the run "
                "variation."
            ),
            "",
        ]
    code = delta["lab_code"]
    if limit:
        lines += [
            "**A limited verdict, not like with like.** The two runners differed, and nothing else differed "
            "besides the declared change. So the change is credited only on a step that carries its own mark: "
            f"{MARKS.get(declared, 'its own mark')}. Every other step that differs is not attributable, since "
            "the runners' difference could have moved it. "
            f"{plural(limit['credited'], 'step')} credited by the mark, {limit['not_attributable']} not "
            "attributable. Run the pair again, which gives two new runners, for a verdict on every step.",
        ]
    elif delta["comparable"]:
        lines.append(
            "**Comparable.** The same steps, made with the same setup"
            + (" apart from the declared change" if declared else "")
            + ("." if code["same"] else "; the lab's code is not known to be the same.")
        )
        if not declared:
            lines.append(
                "Nothing was declared as changed, so a step that differs is not an effect: it is run "
                "variation, the noise floor"
                + ("." if code["same"] else ", or it comes from a change of the lab's code.")
            )
    else:
        lines += ["**No verdict.** The comparison is refused, and still lists what differed:", ""]
        others = [reason for reason in delta["refused_because"] if reason.startswith("also differed")]
        lines += [f"- {reason}" for reason in delta["refused_because"] if reason not in others]
        if others:
            lines.append(
                f"- {plural(len(others), 'thing')} other than the declared change differed: see the table"
            )
    lines.append("")
    if not code["same"]:
        commits = [
            f"`{commit[:8]}`" if commit else NOT_RECORDED for commit in (code["before"], code["after"])
        ]
        said = (
            f"The lab's code differed ({commits[0]} before, {commits[1]} after)"
            if code["before"] or code["after"]
            else "Neither recording says which commit of the lab's code made it"
        )
        lines += [
            f"{said}. The setup does not include the lab's code and the comparison does not check what a "
            "change of it did, so a step that differs may also come from it.",
            "",
        ]

    def shown(text: object) -> str:
        # A digest is shown by its start: delta.json holds it whole.
        text = NOT_RECORDED if text is None else str(text)
        return text[:12] if len(text) == 64 and all(digit in "0123456789abcdef" for digit in text) else text

    # A value recorded on neither side is not known to differ, only not known to be the same: a refusal says so.
    known_rows = [
        row for row in delta["differences"] if row["before"] is not None or row["after"] is not None
    ]

    def mark(row: dict) -> str:
        if limit and row["what"] in limit["differences"]:
            return " (the runners)"
        if not row.get("declared"):
            return ""
        return " (declared)" if row["what"] == declared else " (part of the declared change)"

    if known_rows:
        lines += ["| What differed | Before | After |", "|---|---|---|"]
        lines += [
            f"| {cell(named(row['what']))}{mark(row)} | "
            f"{cell(shown(row['before']))} | {cell(shown(row['after']))} |"
            for row in known_rows
        ]
        lines.append("")
    if delta["same_in_both"]:
        lines += ["Same in both: " + ", ".join(named(name) for name in delta["same_in_both"]) + ".", ""]

    counts, control = delta["counts"], delta["control"]
    by = {row["paired_by"] for row in delta["steps"]} or {"id"}
    marked = collections.Counter(row["result"] for row in delta["steps"] if "mark" in row)
    tally = ", ".join(
        f"{counts[result]} {result}"
        + (
            f" ({marked[result]} of them by the change's own mark alone, on two runners that differed)"
            if marked[result]
            else ""
        )
        for result in RESULTS
        if counts.get(result)
    )
    lines += [
        f"{plural(counts['paired'], 'step')} paired by {' and '.join(sorted(by))}"
        + (f": {tally}" if tally else "")
        + f". {counts['new']} new and {counts['gone']} gone, listed and not counted.",
        "",
    ]
    if "role, test and order" in by:
        lines += [
            "A recording has no stable step ids, so each pair rests on its role, its test and its order.",
            "",
        ]
    said = [CONTROL[field] for field in control["fields"]]
    fields = ", ".join(said[:-1]) + (" and " if len(said) > 1 else "") + said[-1]
    why = "which the declared change cannot change" if declared else "all of them, since nothing was declared"
    variation = "run variation" if code["same"] else "run variation or a change of the lab's code"
    if limit:
        variation += " or the runners' difference"
    lines += [
        f"The control, {fields}, {why}: the same on {control['same']} of {plural(control['of'], 'paired step')}."
        + (f" A difference there is {variation}, not an effect." if control["varied"] else ""),
        "",
    ]
    differing = [row for row in delta["steps"] if row["result"] != "same"]
    if differing:
        lines += [
            "| Step | Test | What happened | Recorded | By the published rules | With the lab's rules | Verdict |",
            "|---|---|---|---|---|---|---|",
        ]
        for row in differing:
            moves = [
                row["before"][field]
                if row["before"][field] == row["after"][field]
                else f"{row['before'][field]} to {row['after'][field]}"
                for field in FIELDS
            ]
            why = row["verdict"] + (f" ({'; '.join(row['underneath'])})" if row["underneath"] else "")
            paired = "" if row["paired_by"] == "id" else " (paired by role, test and order)"
            lines.append(
                f"| `{cell(row['id'])}`{paired} | {cell(row['technique'] + ' ' + row['title'])} | "
                + " | ".join(cell(move) for move in moves)
                + f" | {cell(why)} |"
            )
        lines.append("")
    recorded = [row for row in differing if "records" in row]
    if recorded:
        sensor = recorded[0]["records"]["sensor"]

        def listed(part: dict) -> str:
            shown = ["`" + cell(line).replace("`", "'") + "`" for line in part["lines"]]
            more = part["count"] - len(part["lines"])
            return (", ".join(shown) + (f", and {more} more" if more else "")) if shown else "none"

        lines += [f"What sensor `{sensor}` recorded of each step above in one run only:", ""]
        lines += [
            f"- `{cell(row['id'])}` {cell(row['technique'] + ' ' + row['title'])}: only after, "
            f"{listed(row['records']['new'])}; only before, {listed(row['records']['gone'])}."
            for row in recorded
        ]
        lines.append("")
    if declared and declared.startswith("sensors:"):
        # What a sensor change did to the steps nobody saw, said also when it did nothing.
        def steps_of(rows: list[dict]) -> str:
            return "; ".join(
                f"`{cell(row['id'])}` {cell(row['technique'] + ' ' + row['title'])}" for row in rows
            )

        now = [
            row
            for row in delta["steps"]
            if row["before"]["recorded"] == "no telemetry" and row["after"]["recorded"] == "recorded"
        ]
        still = [
            row
            for row in delta["steps"]
            if row["role"] == "test" and row["before"]["outcome"] == row["after"]["outcome"] == "unseen"
        ]
        lines.append(
            f"Recorded now, and by no sensor before: {steps_of(now)}."
            if now
            else "No step that no sensor recorded before is recorded now."
        )
        if still:
            lines.append(f"Unseen in both runs: {steps_of(still)}.")
        keys = delta.get("audit_keys")
        if keys is not None:
            for label, words in (
                ("only_after", "only the after run has"),
                ("only_before", "only the before run has"),
            ):
                found = keys[label]
                lines.append(
                    f"Events of an audit key that {words}: "
                    + "; ".join(
                        f"`{cell(key)}`, {plural(part['events'], 'event')} of {plural(len(part['steps']), 'step')}"
                        for key, part in found.items()
                    )
                    + "."
                    if found
                    else f"No event of an audit key that {words}."
                )
            lines.append(
                "A recording holds only the records tied to a step; the whole audit log of each run is "
                "`audit.txt` in its artifact."
            )
        lines.append("")
    for label in ("new", "gone"):
        if delta[label]:
            names = "; ".join(f"`{step['id']}` {step['technique']} {step['title']}" for step in delta[label])
            lines += [f"{label.capitalize()}: {cell(names)}.", ""]
    if "why" in delta["race"]:
        lines += [f"No race: {delta['race']['why']}.", ""]
    else:
        times = [
            f"{label}: "
            + (", ".join(f"{key} {seconds}" for key, seconds in delta["race"][label].items()) or NOT_RECORDED)
            for label in ("before", "after")
        ]
        lines += ["Race, in seconds from the first step: " + "; ".join(times) + ".", ""]
    lines += [f"All of this rests on {CLAIM}.", ""]
    return "\n".join(lines)


def main(before: Path, after: Path, out: Path, declared: str | None = None, two_runners: bool = False) -> int:
    texts = [path.read_bytes() for path in (before, after)]
    recordings = [json.loads(text) for text in texts]
    delta = compare(
        *recordings, tuple(hashlib.sha256(text).hexdigest() for text in texts), declared, two_runners
    )
    out.mkdir(parents=True, exist_ok=True)
    (out / "delta.json").write_text(json.dumps(delta, indent=1) + "\n", encoding="utf-8")
    text = markdown(delta)
    (out / "delta.md").write_text(text, encoding="utf-8")
    print(text)
    return 0
