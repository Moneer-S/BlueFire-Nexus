"""Recordings of runs made by an engine outside the app: format checks and storage.

A recording (``bluefire.recording/1``, defined in ``docs/RECORDING.md``) is one JSON
document in which an engine says which attack steps it ran, what its sensors
recorded and which rules matched. BlueFire checks that a recording follows the
format and that its parts agree with each other: the score with the steps, each
step's outcome with what the step says happened and with its events and alerts,
times inside the run, and references that exist. It cannot check that the steps
ran, where, or which sensor produced an event, and every entry says so.

Two kinds of recording are listed. A recording shipped with BlueFire is a file
under ``bluefire/data/recordings/`` that this repository's lab workflow recorded;
it is read-only. A recording a user imported is a file under
``<runs-dir>/recordings/``, and the import route is its only writer. A recording
without ``source.finished`` is still running: its engine sends it again, whole,
as it grows, and each import replaces the stored file in one step, so a reader
never sees half a file. Once a recording has its end time it can no longer be
replaced.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import threading
import time
from collections import Counter
from contextlib import contextmanager
from datetime import datetime
from http import HTTPStatus
from importlib import resources
from pathlib import Path
from typing import Any, Iterator, Mapping

from .application_errors import APIError
from .local_lock import (
    LocalLockError,
    owner_private_database_lock,
    prepare_owner_private_database_file,
)
from .util import canonical_json_bytes, content_hash

RECORDING_SCHEMA = "bluefire.recording/1"
MAX_RECORDING_BYTES = 8 * 1024 * 1024
MAX_STEPS = 2_000
MAX_EVENTS = 20_000
MAX_ALERTS = 20_000
MAX_LISTED = 200
# The routes of the comparisons of two recordings live under /recordings/deltas.
DELTAS_ADDRESS = "deltas"
IMPORTED_NOTE = (
    "Imported. BlueFire checked that this file follows the recording format and that "
    "its score, step outcomes, events, alerts and times agree with each other. It "
    "cannot confirm that the steps ran, where or when they ran, which sensor recorded "
    "each event, which step reached the goal, or the engine, commit and CI run the "
    "file names."
)
SHIPPED_NOTE = (
    "Shipped with BlueFire. This repository's lab workflow recorded it in the CI run "
    "at {run_url}. BlueFire checked that it follows the recording format and that its "
    "parts agree with each other."
)

_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# Half of a character pair on its own: JSON can escape it, UTF-8 cannot write it.
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")
_TOP_LEVEL = {
    "schema", "id", "title", "kind", "source", "network", "attacker",
    "steps", "events", "alerts", "ordinary", "score", "notes",
}  # fmt: skip
_OUTCOMES = ("stopped", "no effect", "alerted", "seen", "unseen", "inconclusive")
_HAPPENED = ("took effect", "attempted without effect", "blocked", "not attempted", "inconclusive")
_VISIBILITY = ("alert", "telemetry only", "no telemetry", "inconclusive", "not applicable")
_LEVELS = ("informational", "low", "medium", "high", "critical")
_COUNTING_LEVELS = ("high", "critical")
_TOOL_ROLES = ("tests", "executor", "sensor", "rules", "rule engine")
_STEP_ROLES = ("test", "canary", "control", "hardened", "variant")
_TIES = ("session", "launcher", "account", "systemd", "window")
# The largest whole number a browser's JSON reader holds exactly; past it a field's value
# would be read as another number, and past about 10**308 as infinity, which it refuses.
_MAX_FIELD_NUMBER = 2**53
_MAX_LINE = 2_000
_MAX_NAME = 200
_MAX_FIELD = 300
_MAX_FIELDS = 64
_MAX_COUNT = 1_000_000_000
_MAX_DEPTH = 8
_MAX_PROBLEMS = 20
# Every import takes this file's lock; it is not a recording, so the list skips it.
_IMPORT_LOCK = ".import.lock"
_LOCK_SECONDS = 5
# The only texts that may hold control characters (other than NUL): what a step ran
# and printed, and sentences.
_FREE_TEXT = re.compile(
    r"notes\[\d+\]|attacker\.(?:description|goal)|steps\[\d+\]\.(?:command|output|plain)"
)


class RecordingError(ValueError):
    """A recording does not follow the format; ``problems`` says where, in plain words."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__(problems[0] if problems else "The recording is not valid.")
        self.problems = problems


def _walk(value: Mapping[str, Any], check: _Checker, what: str = "A recording") -> None:
    """Visit every value once, without recursion: depth, numbers and characters.

    Raises at once when the value (``what``) nests deeper than the format allows.
    """

    stack: list[tuple[Any, str, int]] = [(value, "", 1)]
    while stack:
        item, where, depth = stack.pop()
        if isinstance(item, (Mapping, list)) and depth > _MAX_DEPTH:
            raise RecordingError([f"{what} nests objects and lists at most {_MAX_DEPTH} deep."])
        if isinstance(item, Mapping):
            if any(_CONTROL.search(key) for key in item):
                check.fail(where or "recording", "has a key that holds control characters.")
            if any(_LONE_SURROGATE.search(key) for key in item):
                check.fail(where or "recording", "has a key that holds half of a character pair.")
            children = [(child, f"{where}.{key}" if where else key) for key, child in item.items()]
            stack.extend((child, path, depth + 1) for child, path in reversed(children))
        elif isinstance(item, list):
            stack.extend(
                (item[index], f"{where}[{index}]", depth + 1)
                for index in reversed(range(len(item)))
            )
        elif isinstance(item, float) and not math.isfinite(item):
            check.fail(where, "is not a finite number.")
        elif isinstance(item, str):
            if "\x00" in item:
                check.fail(where, "must not hold a NUL character.")
            elif _LONE_SURROGATE.search(item):
                check.fail(where, "must not hold half of a character pair (a lone surrogate).")
            elif not _FREE_TEXT.fullmatch(where) and _CONTROL.search(item):
                check.fail(where, "must not hold control characters.")


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class _Checker:
    def __init__(self) -> None:
        self.problems: list[str] = []

    def fail(self, where: str, message: str) -> None:
        if len(self.problems) < _MAX_PROBLEMS:
            self.problems.append(f"{where} {message}")

    def obj(self, value: Any, where: str) -> Mapping[str, Any]:
        if isinstance(value, Mapping):
            return value
        self.fail(where, "must be an object.")
        return {}

    def items(self, value: Any, where: str, limit: int) -> list[Mapping[str, Any]]:
        if not isinstance(value, list):
            self.fail(where, "must be a list.")
            return []
        if len(value) > limit:
            self.fail(where, f"has {len(value)} entries; at most {limit} are allowed.")
            return []
        return [self.obj(item, f"{where}[{index}]") for index, item in enumerate(value)]

    def present(
        self, parent: Mapping[str, Any], key: str, where: str, *, required: bool, null: bool = False
    ) -> bool:
        """Whether ``key`` holds a value to check.

        A value that is not known is left out, so an optional key given as null is
        refused rather than read as absent: the agreement checks test which keys
        are there.
        """

        if parent.get(key) is not None:
            return True
        if required:
            self.fail(f"{where}.{key}", "is missing.")
        elif key in parent and not null:
            self.fail(f"{where}.{key}", "is null; a value that is not known is left out.")
        return False

    def text(
        self,
        parent: Mapping[str, Any],
        key: str,
        where: str,
        *,
        required: bool = True,
        limit: int = _MAX_NAME,
        choices: tuple[str, ...] | None = None,
        empty: bool = False,
        null: bool = False,
    ) -> str | None:
        """Check one text value; ``_walk`` checks the characters of every text."""

        if not self.present(parent, key, where, required=required, null=null):
            return None
        value = parent[key]
        if not isinstance(value, str) or (not empty and not value.strip()):
            self.fail(f"{where}.{key}", "must be text." if empty else "must be non-empty text.")
            return None
        if len(value) > limit:
            self.fail(f"{where}.{key}", f"is longer than {limit} characters.")
            return None
        if choices is not None and value not in choices:
            self.fail(f"{where}.{key}", "must be one of: " + ", ".join(choices) + ".")
            return None
        return value

    def time(
        self, parent: Mapping[str, Any], key: str, where: str, *, required: bool
    ) -> datetime | None:
        if not self.present(parent, key, where, required=required):
            return None
        value = parent[key]
        try:
            if isinstance(value, str) and _TIME.fullmatch(value):
                return _time(value)
        except ValueError:
            pass
        self.fail(f"{where}.{key}", "must be a UTC time such as 2026-11-17T17:07:23.834Z.")
        return None

    def count(self, parent: Mapping[str, Any], key: str, where: str, *, required: bool) -> None:
        if not self.present(parent, key, where, required=required):
            return
        value = parent[key]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_COUNT:
            self.fail(f"{where}.{key}", f"must be a whole number from 0 to {_MAX_COUNT}.")

    def seconds(self, parent: Mapping[str, Any], key: str, where: str) -> None:
        if not self.present(parent, key, where, required=False):
            return
        value = parent[key]
        # The bounds also refuse NaN and infinity, and they compare a whole number of any size
        # without turning it into a float first.
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 <= value <= _MAX_COUNT
        ):
            self.fail(f"{where}.{key}", "must be a number of seconds, zero or more.")

    def texts(self, parent: Mapping[str, Any], key: str, where: str) -> None:
        """An optional list of short texts, such as a host's addresses."""

        if not self.present(parent, key, where, required=False):
            return
        value = parent[key]
        if (
            not isinstance(value, list)
            or len(value) > 100
            or any(not isinstance(item, str) or len(item) > _MAX_NAME for item in value)
        ):
            self.fail(
                f"{where}.{key}",
                f"must be a list of at most 100 texts of at most {_MAX_NAME} characters.",
            )

    def part(self, parent: Mapping[str, Any], key: str, where: str) -> Mapping[str, Any] | None:
        """An optional object: None when it is left out, after refusing a null or a non-object."""

        if not self.present(parent, key, where, required=False):
            return None
        value = parent[key]
        if isinstance(value, Mapping):
            return value
        self.fail(f"{where}.{key}", "must be an object.")
        return None

    def flag(self, parent: Mapping[str, Any], key: str, where: str, *, required: bool) -> None:
        if self.present(parent, key, where, required=required) and not isinstance(
            parent[key], bool
        ):
            self.fail(f"{where}.{key}", "must be true or false.")

    def ref(self, value: Any, known: set[str], where: str, what: str) -> None:
        if not isinstance(value, str) or value not in known:
            shown = repr(value) if isinstance(value, str) else "a value"
            self.fail(where, f"names {what} {shown[:80]} that the recording does not have.")

    def unique_ids(self, rows: list[Mapping[str, Any]], where: str) -> set[str]:
        seen: set[str] = set()
        for index, row in enumerate(rows):
            value = self.text(row, "id", f"{where}[{index}]")
            if value is not None and value in seen:
                self.fail(f"{where}[{index}].id", f"repeats the id {value!r}.")
            elif value is not None:
                seen.add(value)
        return seen


def validate_recording(value: Any) -> Mapping[str, Any]:
    """Return the recording unchanged, or raise ``RecordingError`` naming each problem."""

    check = _Checker()
    if not isinstance(value, Mapping):
        raise RecordingError(["A recording must be one JSON object."])
    if value.get("schema") != RECORDING_SCHEMA:
        raise RecordingError([f"schema must be {RECORDING_SCHEMA!r}."])
    _walk(value, check)
    for key in sorted(set(value) - _TOP_LEVEL):
        check.fail(key, "is not a key of the recording format.")
    for key in sorted(_TOP_LEVEL - {"ordinary"} - set(value)):
        check.fail(key, "is missing.")
    if not isinstance(value.get("id"), str) or not _ID.fullmatch(value["id"]):
        check.fail("id", "must be 1 to 64 letters, digits, '-' or '_'.")
    check.text(value, "title", "recording")
    check.text(value, "kind", "recording", choices=("test list", "attack path"))

    source = check.obj(value.get("source"), "source")
    check.text(source, "engine", "source")
    check.text(source, "environment", "source")
    started = check.time(source, "started", "source", required=True)
    finished = check.time(source, "finished", "source", required=False)
    if started is not None and finished is not None and finished < started:
        check.fail("source.finished", "is earlier than source.started.")
    for key in ("repository", "commit", "run_url"):
        check.text(source, key, "source", required=False, limit=_MAX_LINE)
    if check.present(source, "tools", "source", required=True):
        for index, tool in enumerate(check.items(source["tools"], "source.tools", 100)):
            check.text(tool, "name", f"source.tools[{index}]")
            check.text(tool, "version", f"source.tools[{index}]")
            check.text(tool, "role", f"source.tools[{index}]", choices=_TOOL_ROLES)

    network = check.obj(value.get("network"), "network")
    hosts = check.items(network.get("hosts"), "network.hosts", 200)
    host_ids = check.unique_ids(hosts, "network.hosts")
    for index, host in enumerate(hosts):
        where = f"network.hosts[{index}]"
        check.text(host, "name", where)
        check.text(host, "role", where)
        check.text(host, "kind", where, choices=("host", "attacker", "internet", "defense"))
        check.text(host, "os", where, required=False, limit=_MAX_LINE)
        check.texts(host, "addresses", where)
    for index, link in enumerate(check.items(network.get("links", []), "network.links", 1_000)):
        check.ref(link.get("from"), host_ids, f"network.links[{index}].from", "host")
        check.ref(link.get("to"), host_ids, f"network.links[{index}].to", "host")
        check.text(link, "label", f"network.links[{index}]")
    sensors = check.items(network.get("sensors"), "network.sensors", 100)
    sensor_ids = check.unique_ids(sensors, "network.sensors")
    for index, sensor in enumerate(sensors):
        check.text(sensor, "name", f"network.sensors[{index}]")
        check.ref(sensor.get("host"), host_ids, f"network.sensors[{index}].host", "host")
        check.text(sensor, "records", f"network.sensors[{index}]", limit=_MAX_LINE)
    detectors = check.items(network.get("detectors"), "network.detectors", 100)
    detector_ids = check.unique_ids(detectors, "network.detectors")
    for index, detector in enumerate(detectors):
        where = f"network.detectors[{index}]"
        check.text(detector, "name", where)
        check.count(detector, "rules", where, required=True)
        check.text(detector, "when", where, choices=("live", "after the run"))

    attacker = check.obj(value.get("attacker"), "attacker")
    check.text(attacker, "kind", "attacker", choices=("scripted", "agent"))
    check.text(attacker, "description", "attacker", limit=_MAX_LINE)
    # The goal is always there: null for a test list, which has none.
    if isinstance(value.get("attacker"), Mapping) and "goal" not in attacker:
        check.fail("attacker.goal", "is missing; it is null when the run has no goal.")
    check.text(attacker, "goal", "attacker", required=False, limit=_MAX_LINE, null=True)

    steps = check.items(value.get("steps"), "steps", MAX_STEPS)
    step_ids = check.unique_ids(steps, "steps")
    for index, step in enumerate(steps):
        where = f"steps[{index}]"
        check.count(step, "order", where, required=True)
        check.text(step, "role", where, choices=_STEP_ROLES)
        check.text(step, "title", where, limit=500)
        technique = check.obj(step.get("technique"), f"{where}.technique")
        check.text(technique, "id", f"{where}.technique", limit=100)
        check.text(technique, "name", f"{where}.technique", required=False, limit=500)
        check.text(technique, "tactic", f"{where}.technique", required=False, limit=500)
        test = check.part(step, "test", where)
        if test is not None:
            for key in ("project", "guid", "executor"):
                check.text(test, key, f"{where}.test")
            check.flag(test, "elevated", f"{where}.test", required=True)
        defense = check.part(step, "defense", where)
        if defense is not None:
            check.text(defense, "title", f"{where}.defense", limit=500)
            check.text(defense, "why", f"{where}.defense", limit=_MAX_LINE)
        check.ref(step.get("host"), host_ids, f"{where}.host", "host")
        if "from" in step:
            check.ref(step.get("from"), host_ids, f"{where}.from", "host")
        for key in ("started", "ended", "first_event", "first_alert", "first_alert_with_lab_rules"):
            check.time(step, key, where, required=False)
        for key in ("command", "output", "plain"):
            check.text(step, key, where, required=False, limit=_MAX_LINE, empty=True)
        happened = check.obj(step.get("happened"), f"{where}.happened")
        check.text(happened, "answer", f"{where}.happened", choices=_HAPPENED)
        check.text(happened, "basis", f"{where}.happened", limit=_MAX_LINE)
        visibility = check.obj(step.get("visibility"), f"{where}.visibility")
        check.text(visibility, "answer", f"{where}.visibility", choices=_VISIBILITY)
        check.text(visibility, "basis", f"{where}.visibility", limit=_MAX_LINE)
        check.count(visibility, "events", f"{where}.visibility", required=False)
        check.count(visibility, "kept", f"{where}.visibility", required=False)
        check.text(step, "outcome", where, choices=_OUTCOMES)
        check.text(step, "outcome_with_lab_rules", where, required=False, choices=_OUTCOMES)
        if "compared_with" in step:
            check.ref(step.get("compared_with"), step_ids, f"{where}.compared_with", "step")

    events = check.items(value.get("events"), "events", MAX_EVENTS)
    event_ids = check.unique_ids(events, "events")
    for index, event in enumerate(events):
        where = f"events[{index}]"
        check.time(event, "time", where, required=True)
        check.ref(event.get("host"), host_ids, f"{where}.host", "host")
        check.ref(event.get("sensor"), sensor_ids, f"{where}.sensor", "sensor")
        check.ref(event.get("step"), step_ids, f"{where}.step", "step")
        check.text(event, "kind", where)
        check.text(event, "text", where, limit=_MAX_LINE, empty=True)
        check.text(event, "tied_by", where, choices=_TIES)
        check.text(event, "user", where, required=False, empty=True)
        check.text(event, "image", where, required=False, limit=_MAX_LINE, empty=True)
        fields = check.obj(event.get("fields", {}), f"{where}.fields")
        if len(fields) > _MAX_FIELDS or any(
            not isinstance(item, (str, int, float, bool, type(None)))
            or (isinstance(item, str) and len(item) > _MAX_FIELD)
            or (isinstance(item, int) and abs(item) > _MAX_FIELD_NUMBER)
            for item in fields.values()
        ):
            check.fail(
                f"{where}.fields",
                f"must hold at most {_MAX_FIELDS} plain values: text of at most {_MAX_FIELD} "
                f"characters, a number no further than {_MAX_FIELD_NUMBER} from zero, true, "
                "false or null.",
            )

    alerts = check.items(value.get("alerts"), "alerts", MAX_ALERTS)
    check.unique_ids(alerts, "alerts")
    for index, alert in enumerate(alerts):
        where = f"alerts[{index}]"
        check.time(alert, "time", where, required=True)
        check.time(alert, "raised", where, required=False)
        check.ref(alert.get("host"), host_ids, f"{where}.host", "host")
        check.ref(alert.get("detector"), detector_ids, f"{where}.detector", "detector")
        check.ref(alert.get("step"), step_ids, f"{where}.step", "step")
        rule = check.obj(alert.get("rule"), f"{where}.rule")
        check.text(rule, "id", f"{where}.rule", limit=500)
        check.text(rule, "title", f"{where}.rule", limit=500)
        check.text(rule, "level", f"{where}.rule", choices=_LEVELS)
        check.text(rule, "origin", f"{where}.rule", choices=("pinned", "lab"))
        check.flag(alert, "counts", where, required=True)
        check.flag(alert, "launcher_only", where, required=False)
        matched = alert.get("events")
        if not isinstance(matched, list):
            check.fail(f"{where}.events", "must be a list of event ids.")
        else:
            for event_id in matched:
                check.ref(event_id, event_ids, f"{where}.events", "event")

    if "ordinary" in value:
        ordinary = check.obj(value.get("ordinary"), "ordinary")
        check.count(ordinary, "events", "ordinary", required=True)
        if check.present(ordinary, "matches", "ordinary", required=True):
            for index, match in enumerate(
                check.items(ordinary["matches"], "ordinary.matches", 1_000)
            ):
                check.text(match, "rule", f"ordinary.matches[{index}]", limit=500)
                check.text(match, "level", f"ordinary.matches[{index}]", choices=_LEVELS)
                check.count(match, "count", f"ordinary.matches[{index}]", required=True)

    score = check.obj(value.get("score"), "score")
    for key in ("steps", "took_effect", "alerted", "seen", "unseen", "stopped"):
        check.count(score, key, "score", required=True)
    for key in ("alerted_with_lab_rules", "false_alerts"):
        check.count(score, key, "score", required=False)
    for key in ("first_alert_seconds", "goal_seconds"):
        check.seconds(score, key, "score")

    notes = value.get("notes")
    if not isinstance(notes, list) or any(
        not isinstance(note, str) or len(note) > _MAX_LINE for note in notes
    ):
        check.fail("notes", "must be a list of plain sentences.")
    if not check.problems and started is not None:
        _check_agreement(value, started, finished, check)
    if check.problems:
        raise RecordingError(check.problems)
    return value


def _outcome(happened: str, visibility: str) -> str:
    """The score word that docs/RECORDING.md gives a step: the first rule that holds."""

    if happened == "blocked":
        return "stopped"
    if happened in ("attempted without effect", "not attempted"):
        return "no effect"
    if visibility == "alert":
        return "alerted"
    if visibility == "telemetry only":
        return "seen"
    if happened == "took effect" and visibility == "no telemetry":
        return "unseen"
    return "inconclusive"


def _check_agreement(
    value: Mapping[str, Any], started: datetime, finished: datetime | None, check: _Checker
) -> None:
    """Check that the score, outcomes, events, alerts and times of a well-formed recording agree."""

    steps, events, alerts = value["steps"], value["events"], value["alerts"]
    sensor_hosts = {sensor["id"]: sensor["host"] for sensor in value["network"]["sensors"]}
    detector_when = {item["id"]: item["when"] for item in value["network"]["detectors"]}
    event_steps = {event["id"]: event["step"] for event in events}
    held = Counter(event["step"] for event in events)
    # The earliest time of each kind on each step, as (time, the recording's own text).
    # An alert counts from its moment: when it was raised, for a live detector, and
    # otherwise the time of its activity. The step's first alert and the race agree.
    first_event: dict[str, tuple[datetime, str]] = {}
    first_pinned: dict[str, tuple[datetime, str]] = {}
    first_counting: dict[str, tuple[datetime, str]] = {}
    # The same two by the alerts' activity time, only to name that mistake plainly.
    by_activity: dict[str, dict[str, tuple[datetime, str]]] = {
        "first_alert": {},
        "first_alert_with_lab_rules": {},
    }

    def earliest(table: dict[str, tuple[datetime, str]], step_id: str, text: str) -> None:
        moment = (_time(text), text)
        if step_id not in table or moment[0] < table[step_id][0]:
            table[step_id] = moment

    def inside(where: str, moment: str | None) -> None:
        if moment is not None and (
            _time(moment) < started or (finished is not None and _time(moment) > finished)
        ):
            check.fail(where, "falls outside the run's start and end.")

    def in_order(where: str, keys: list[Any], by: str) -> None:
        if any(later < earlier for earlier, later in zip(keys, keys[1:], strict=False)):
            check.fail(where, f"must be sorted by {by}.")

    in_order("steps", [step["order"] for step in steps], "order")
    in_order("events", [_time(event["time"]) for event in events], "time")
    in_order("alerts", [_time(alert["time"]) for alert in alerts], "time")
    for index, event in enumerate(events):
        inside(f"events[{index}].time", event["time"])
        earliest(first_event, event["step"], event["time"])
        if event["host"] != sensor_hosts[event["sensor"]]:
            check.fail(f"events[{index}].host", "is not the host its sensor runs on.")
    for index, alert in enumerate(alerts):
        where = f"alerts[{index}]"
        inside(f"{where}.time", alert["time"])
        origin, detector = alert["rule"]["origin"], alert["detector"]
        if detector in ("pinned", "lab") and origin != detector:
            check.fail(
                f"{where}.rule.origin", f"is {origin}, but the alert's detector is {detector}."
            )
        if "raised" in alert:
            if detector_when[detector] == "after the run":
                check.fail(f"{where}.raised", "is set, but the detector's rules ran after the run.")
            elif _time(alert["raised"]) < _time(alert["time"]):
                check.fail(f"{where}.raised", "is earlier than the alert's time.")
            inside(f"{where}.raised", alert["raised"])
        launcher_only = alert.get("launcher_only", False)
        if alert["counts"] != (alert["rule"]["level"] in _COUNTING_LEVELS and not launcher_only):
            check.fail(
                f"{where}.counts",
                "must be true exactly when the rule's level is high or critical and the "
                "match is not launcher_only.",
            )
        if launcher_only and alert["events"]:
            check.fail(f"{where}.events", "must be empty for a launcher_only match.")
        if alert["counts"] and not alert["events"]:
            check.fail(f"{where}.events", "is empty, but an alert that counts matched an event.")
        if any(event_steps[event_id] != alert["step"] for event_id in alert["events"]):
            check.fail(f"{where}.events", "names an event of another step.")
        if alert["counts"]:
            live = detector_when.get(detector) == "live" and "raised" in alert
            moment = alert["raised"] if live else alert["time"]
            earliest(first_counting, alert["step"], moment)
            earliest(by_activity["first_alert_with_lab_rules"], alert["step"], alert["time"])
            if origin == "pinned":
                earliest(first_pinned, alert["step"], moment)
                earliest(by_activity["first_alert"], alert["step"], alert["time"])

    def first_time(
        step: Mapping[str, Any],
        where: str,
        key: str,
        expected: tuple[datetime, str] | None,
        what: str,
    ) -> None:
        given = step.get(key)
        if given is None and expected is not None:
            check.fail(f"{where}.{key}", f"is missing, but the step has a {what}.")
        elif given is not None and expected is None:
            check.fail(f"{where}.{key}", f"is set, but the step has no {what}.")
        elif given is not None and expected is not None and _time(given) != expected[0]:
            activity = by_activity.get(key, {}).get(step["id"])
            if activity is not None and _time(given) == activity[0]:
                check.fail(
                    f"{where}.{key}",
                    f"is {given}, the time of the alert's activity, but a step's first "
                    f"alert counts from when a live detector raised it: {expected[1]}.",
                )
            else:
                check.fail(
                    f"{where}.{key}",
                    f"is {given}, but the step's first {what} is at {expected[1]}.",
                )

    for index, step in enumerate(steps):
        where = f"steps[{index}]"
        step_id = step["id"]
        inside(f"{where}.started", step.get("started"))
        inside(f"{where}.ended", step.get("ended"))
        first_time(step, where, "first_event", first_event.get(step_id), "sensor event")
        first_time(
            step, where, "first_alert", first_pinned.get(step_id),
            "counting alert of a published rule",
        )  # fmt: skip
        if "outcome_with_lab_rules" in step:
            first_time(
                step, where, "first_alert_with_lab_rules", first_counting.get(step_id),
                "counting alert",
            )  # fmt: skip
        elif "first_alert_with_lab_rules" in step:
            check.fail(
                f"{where}.first_alert_with_lab_rules",
                "is set, but the step has no outcome_with_lab_rules.",
            )
        happened, answer = step["happened"]["answer"], step["visibility"]["answer"]
        if (answer == "alert") != (step_id in first_pinned):
            check.fail(
                f"{where}.visibility.answer",
                "is alert, but no published rule's alert counts for the step."
                if answer == "alert"
                else "must be alert: a published rule's alert counts for the step.",
            )
        expected = _outcome(happened, answer)
        if step["outcome"] != expected:
            check.fail(
                f"{where}.outcome",
                f"is {step['outcome']}, but happened {happened!r} and visibility "
                f"{answer!r} give {expected}.",
            )
        if "outcome_with_lab_rules" in step:
            with_lab = _outcome(happened, "alert" if step_id in first_counting else answer)
            if step["outcome_with_lab_rules"] != with_lab:
                check.fail(
                    f"{where}.outcome_with_lab_rules",
                    f"is {step['outcome_with_lab_rules']}, but the step and its alerts give "
                    f"{with_lab}.",
                )
        tied, kept = step["visibility"].get("events"), step["visibility"].get("kept")
        if tied is None:
            if answer not in ("inconclusive", "not applicable"):
                check.fail(
                    f"{where}.visibility.events",
                    "is missing; only inconclusive and not applicable may leave it out.",
                )
            if kept is not None:
                check.fail(f"{where}.visibility.kept", "is set, but visibility.events is not.")
            continue
        if (answer in ("alert", "telemetry only") and not tied) or (
            answer == "no telemetry" and tied
        ):
            check.fail(f"{where}.visibility.events", f"is {tied}, which {answer!r} does not allow.")
        if kept is not None and kept > tied:
            check.fail(f"{where}.visibility.kept", f"is more than visibility.events ({tied}).")
        if (tied if kept is None else kept) != held[step_id]:
            check.fail(
                f"{where}.visibility",
                f"counts events the recording does not hold ({held[step_id]}).",
            )
    tests = [step for step in steps if step["role"] == "test"]
    took = [step for step in tests if step["happened"]["answer"] == "took effect"]
    expected_score = {
        "steps": len(tests),
        "took_effect": len(took),
        **{
            word: sum(step["outcome"] == word for step in took)
            for word in ("alerted", "seen", "unseen")
        },
        "stopped": sum(step["outcome"] == "stopped" for step in steps),
    }
    score = value["score"]
    if "alerted_with_lab_rules" in score:
        expected_score["alerted_with_lab_rules"] = sum(
            step.get("outcome_with_lab_rules", step["outcome"]) == "alerted" for step in took
        )
    if "false_alerts" in score and "ordinary" in value:
        expected_score["false_alerts"] = sum(
            match["level"] in _COUNTING_LEVELS for match in value["ordinary"]["matches"]
        )
    for key, number in expected_score.items():
        if score[key] != number:
            check.fail(f"score.{key}", f"is {score[key]}, but the steps give {number}.")
    _check_race(value, first_pinned, check)


def _check_race(
    value: Mapping[str, Any], first_raised: Mapping[str, tuple[datetime, str]], check: _Checker
) -> None:
    """Check the two times of an attack path's race against what its steps give.

    ``first_raised`` holds the earliest moment of a counting published alert on each
    step, the step's ``first_alert``: its ``raised`` time for a live detector, else its
    ``time``. ``goal_seconds`` must end at the end of one of the steps; the format does
    not say which step reached the goal, so that is not checked.
    """

    score, steps = value["score"], value["steps"]
    if value["kind"] == "test list":
        for key in ("first_alert_seconds", "goal_seconds"):
            if key in score:
                check.fail(f"score.{key}", "is written only for an attack path.")
        return
    starts = [_time(step["started"]) for step in steps if "started" in step]
    test_starts = [
        _time(step["started"]) for step in steps if step["role"] == "test" and "started" in step
    ]
    test_alerts = [
        first_raised[step["id"]][0]
        for step in steps
        if step["role"] == "test" and step["id"] in first_raised
    ]
    if "first_alert_seconds" in score:
        if not test_starts or not test_alerts:
            check.fail(
                "score.first_alert_seconds",
                "is set, but no step of role test has a start and a counting alert of a "
                "published rule.",
            )
        else:
            # A sensor can stamp the alert a few milliseconds before the step's start.
            expected = max(0.0, (min(test_alerts) - min(test_starts)).total_seconds())
            if abs(score["first_alert_seconds"] - expected) > 0.001:
                check.fail(
                    "score.first_alert_seconds",
                    f"is {score['first_alert_seconds']}, but the steps give {expected:.3f}.",
                )
    if "goal_seconds" in score:
        ends = [
            (_time(step["ended"]) - min(starts)).total_seconds()
            for step in steps
            if starts and "ended" in step
        ]
        if not any(abs(score["goal_seconds"] - end) <= 0.001 for end in ends):
            check.fail(
                "score.goal_seconds",
                f"is {score['goal_seconds']}, but no step ends that long after the first "
                "step started.",
            )


# The replay page's template holds its recording, and where the recording comes from,
# each in one element of its own, as JSON.
_PAGE_ELEMENTS = ("bluefire-recording", "bluefire-origin")


def replay_template() -> str:
    """The packaged replay page, ``bluefire/ui/replay.html``, which holds no recording."""

    page = resources.files("bluefire").joinpath("ui").joinpath("replay.html")
    return page.read_text(encoding="utf-8")


def replay_page(
    recording: Mapping[str, Any], origin: Mapping[str, Any], template: str | None = None
) -> str:
    """The single replay page for one recording: the template with the recording inside.

    The recording's JSON replaces the content of the template's one
    ``bluefire-recording`` element, and ``origin`` (the ``origin`` of the
    recording's list entry: its kind and note) that of the one ``bluefire-origin``
    element; the page shows the note under the title. Every ``<`` in them is
    written as ``\\u003c``, which JSON reads back as the same character, so no
    text can end the element, open a comment or start another element. A
    template that does not hold exactly one of each element is refused.
    """

    page = replay_template() if template is None else template
    for name, value in zip(_PAGE_ELEMENTS, (recording, origin), strict=True):
        exact = re.compile(
            rf'(<script id="{name}" type="application/json">)(.*?)(</script>)', re.DOTALL
        )
        # Any script element that names the id, however its attributes are written.
        loose = re.compile(rf"<script\b[^>]*\bid\s*=\s*[\"']?{name}[\"'\s/>]", re.IGNORECASE)
        found = list(exact.finditer(page))
        if len(found) != 1 or len(loose.findall(page)) != 1:
            raise ValueError(
                "The replay page template must hold exactly one "
                f'<script id="{name}" type="application/json"> element.'
            )
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        data = data.replace("<", "\\u003c")
        element = found[0]
        page = page[: element.start(2)] + data + page[element.end(2) :]
    return page


def invalid_recording(exc: RecordingError) -> APIError:
    return APIError(
        HTTPStatus.UNPROCESSABLE_ENTITY,
        "recording_invalid",
        f"The recording is not valid: {exc}",
        {"problems": exc.problems},
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError(f"the key {key!r} appears twice in one object")
        result[key] = item
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"{value} is not a JSON number")


def parse_recording_bytes(payload: bytes) -> Mapping[str, Any]:
    """Parse and check one recording file's bytes."""

    if len(payload) > MAX_RECORDING_BYTES:
        raise RecordingError([f"A recording file is limited to {MAX_RECORDING_BYTES} bytes."])
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RecordingError([f"The file is not UTF-8 JSON: {exc}"]) from None
    return validate_recording(value)


def summarize(recording: Mapping[str, Any], origin: Mapping[str, Any]) -> dict[str, Any]:
    """The list entry of one checked recording."""

    source = recording["source"]
    return {
        "id": recording["id"],
        "title": recording["title"],
        "kind": recording["kind"],
        "source": {
            key: source[key]
            for key in ("engine", "environment", "started", "finished", "run_url", "commit")
            if key in source
        },
        "score": dict(recording["score"]),
        "counts": {
            "steps": len(recording["steps"]),
            "events": len(recording["events"]),
            "alerts": len(recording["alerts"]),
        },
        "origin": dict(origin),
        # A recording without an end time is still being written by its engine.
        "running": "finished" not in source,
        "digest": content_hash(recording),
    }


def _imported_origin() -> dict[str, Any]:
    return {"kind": "imported", "note": IMPORTED_NOTE}


def _shipped(payload: bytes) -> tuple[Mapping[str, Any], dict[str, Any]]:
    recording = parse_recording_bytes(payload)
    run_url = recording["source"].get("run_url")
    if run_url is None or "finished" not in recording["source"]:
        raise RecordingError(["A shipped recording names its finished CI run."])
    origin = {
        "kind": "shipped",
        "run_url": run_url,
        "note": SHIPPED_NOTE.format(run_url=run_url),
    }
    return recording, summarize(recording, origin)


class RecordingLibrary:
    """The recordings shipped with BlueFire, and those imported under ``root``."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._summaries: dict[Path, tuple[tuple[int, int, int], dict[str, Any] | None]] = {}
        self._shipped_entries: dict[str, tuple[Mapping[str, Any], dict[str, Any]]] | None = None
        self._shipped_files: dict[str, str] = {}
        self._file_digests: dict[Path, tuple[tuple[int, int, int], str]] = {}

    def _shipped_recordings(self) -> dict[str, tuple[Mapping[str, Any], dict[str, Any]]]:
        """Read the packaged recordings once; they do not change while the app runs."""

        if self._shipped_entries is None:
            folder = resources.files("bluefire.data").joinpath("recordings")
            entries: dict[str, tuple[Mapping[str, Any], dict[str, Any]]] = {}
            names = sorted(item.name for item in folder.iterdir()) if folder.is_dir() else []
            for name in names:
                if name.endswith(".json"):
                    payload = folder.joinpath(name).read_bytes()
                    recording, summary = _shipped(payload)
                    entries[recording["id"]] = (recording, summary)
                    self._shipped_files[recording["id"]] = hashlib.sha256(payload).hexdigest()
            self._shipped_entries = entries
        return self._shipped_entries

    def kept_file(self, recording_id: str) -> tuple[str, dict[str, Any]]:
        """The SHA-256 of the file kept for a recording, as it was shipped or imported, and
        its list entry. A recording imported as an object is kept as canonical JSON."""

        shipped = self._shipped_recordings().get(recording_id)
        if shipped is not None:
            return self._shipped_files[recording_id], shipped[1]
        _, summary = self.get(recording_id)
        path = self._path(recording_id)
        try:
            status = path.stat()
            key = (status.st_ino, status.st_mtime_ns, status.st_size)
            cached = self._file_digests.get(path)
            if cached is not None and cached[0] == key:
                return cached[1], summary
            with path.open("rb") as handle:
                digest = hashlib.sha256(handle.read(MAX_RECORDING_BYTES + 1)).hexdigest()
            self._file_digests[path] = (key, digest)
        except OSError as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "recording_unreadable",
                "The stored recording could not be read or no longer follows the format.",
            ) from exc
        return digest, summary

    @contextmanager
    def import_lock(self) -> Iterator[None]:
        """The store's import lock, for another kind of import that reads the recordings."""

        with self._import_lock():
            yield

    def _path(self, recording_id: Any) -> Path:
        if not isinstance(recording_id, str) or not _ID.fullmatch(recording_id):
            raise APIError(
                HTTPStatus.BAD_REQUEST, "invalid_recording_id", "Recording identifier is invalid."
            )
        return self.root / f"{recording_id}.json"

    @staticmethod
    def _read(path: Path) -> Mapping[str, Any]:
        with path.open("rb") as handle:
            payload = handle.read(MAX_RECORDING_BYTES + 1)
        recording = parse_recording_bytes(payload)
        if recording["id"] != path.stem:
            raise RecordingError(["The recording's id does not match its file name."])
        return recording

    def _summary(self, path: Path) -> dict[str, Any] | None:
        """A file's list entry, or None when it is unreadable; read again only once replaced."""

        try:
            status = path.stat()
        except OSError:
            return None
        key = (status.st_ino, status.st_mtime_ns, status.st_size)
        cached = self._summaries.get(path)
        if cached is not None and cached[0] == key:
            return cached[1]
        try:
            summary: dict[str, Any] | None = summarize(self._read(path), _imported_origin())
        except (OSError, RecordingError):
            summary = None
        self._summaries[path] = (key, summary)
        return summary

    def list(self) -> Mapping[str, Any]:
        shipped = self._shipped_recordings()
        entries = [summary for _, summary in shipped.values()]
        paths = [
            path
            for path in (sorted(self.root.glob("*.json")) if self.root.is_dir() else [])
            if _ID.fullmatch(path.stem)
            and path.stem not in shipped
            and not path.is_symlink()
            and path.is_file()
        ]
        unreadable = 0
        for path in paths[:MAX_LISTED]:
            summary = self._summary(path)
            if summary is None:
                unreadable += 1
            else:
                entries.append(summary)
        return {
            "schema_version": "bluefire.recording-list.v1",
            "recordings": entries,
            "unreadable_count": unreadable,
            "omitted_count": max(0, len(paths) - MAX_LISTED),
        }

    def get(self, recording_id: str) -> tuple[Mapping[str, Any], dict[str, Any]]:
        path = self._path(recording_id)
        shipped = self._shipped_recordings().get(recording_id)
        if shipped is not None:
            return shipped
        if not path.is_file() or path.is_symlink():
            raise APIError(HTTPStatus.NOT_FOUND, "recording_not_found", "Recording was not found.")
        try:
            recording = self._read(path)
        except (OSError, RecordingError) as exc:
            raise APIError(
                HTTPStatus.CONFLICT,
                "recording_unreadable",
                "The stored recording could not be read or no longer follows the format.",
            ) from exc
        return recording, summarize(recording, _imported_origin())

    def detail(self, recording_id: str) -> Mapping[str, Any]:
        recording, summary = self.get(recording_id)
        return {
            "schema_version": "bluefire.recording-entry.v1",
            "summary": summary,
            "recording": recording,
        }

    @contextmanager
    def _import_lock(self) -> Iterator[None]:
        """Hold the store's import lock, which every process and thread that imports shares.

        An import reads the stored file, decides, and writes; the server and the
        command line can share one store, so the whole step runs under a lock
        between processes. Without it an older running copy could overwrite a
        finished one that another process stored in between.
        """

        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            path, identity = prepare_owner_private_database_file(self.root / _IMPORT_LOCK)
            with owner_private_database_lock(
                path, expected=identity, deadline=time.monotonic() + _LOCK_SECONDS
            ):
                yield
        except LocalLockError as exc:
            raise APIError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "recordings_busy",
                "The recording store could not be locked for the import. Send it again.",
            ) from exc

    def import_recording(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Store a new recording, or the grown version of one that is still running.

        ``recording_file`` holds the file's bytes in base64, and the file is kept as
        it was sent, so its SHA-256 stays the one its engine wrote: a comparison of
        two runs names its recordings by it. ``recording`` holds the recording as an
        object, which is kept as canonical JSON.
        """

        if set(request) not in ({"recording"}, {"recording_file"}):
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "recording_import_invalid",
                'Send exactly one field: "recording_file", the recording file\'s bytes in '
                'base64, or "recording", the recording object.',
            )
        try:
            if "recording_file" in request:
                payload = _file_bytes(request["recording_file"])
                recording = parse_recording_bytes(payload)
            else:
                recording = validate_recording(request["recording"])
                try:
                    payload = canonical_json_bytes(recording) + b"\n"
                except ValueError as exc:
                    raise RecordingError(
                        [f"The recording cannot be written as JSON: {exc}"]
                    ) from None
            if len(payload) > MAX_RECORDING_BYTES:
                raise RecordingError(
                    [f"A recording file is limited to {MAX_RECORDING_BYTES} bytes."]
                )
            if recording["id"] == DELTAS_ADDRESS:
                raise RecordingError(
                    [f"id {DELTAS_ADDRESS!r} is the address of the comparisons; give the "
                     "recording another id."]
                )  # fmt: skip
        except RecordingError as exc:
            raise invalid_recording(exc) from None
        recording_id = recording["id"]
        replaced = False
        with self._import_lock():
            target = self._path(recording_id)
            if target.exists() or recording_id in self._shipped_recordings():
                existing, summary = self.get(recording_id)
                if content_hash(existing) == content_hash(recording):
                    return {"created": False, "replaced": False, "summary": summary}
                same_run = all(
                    existing["source"].get(key) == recording["source"].get(key)
                    for key in ("engine", "started")
                )
                if (
                    summary["origin"]["kind"] != "imported"
                    or not summary["running"]
                    or not same_run
                ):
                    raise _id_taken(recording_id)
                replaced = True
            try:
                _write_atomically(self.root, target, payload, replace=replaced)
            except FileExistsError:
                # A writer that does not take the import lock created it first.
                raise _id_taken(recording_id) from None
        return {
            "created": not replaced,
            "replaced": replaced,
            "summary": summarize(recording, _imported_origin()),
        }


def _file_bytes(value: Any) -> bytes:
    """The bytes of a file sent in base64."""

    limit = 4 * -(-MAX_RECORDING_BYTES // 3)
    if not isinstance(value, str) or len(value) > limit:
        raise RecordingError(
            [f"recording_file must be the file's bytes in base64, at most {MAX_RECORDING_BYTES} "
             "bytes."]
        )  # fmt: skip
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise RecordingError(["recording_file is not base64."]) from None


def _id_taken(recording_id: str) -> APIError:
    return APIError(
        HTTPStatus.CONFLICT,
        "recording_id_taken",
        f"A different recording with the id {recording_id!r} is already kept. Only a "
        "recording that is still running can be sent again, with the same engine and "
        "start time.",
    )


def _write_atomically(directory: Path, target: Path, payload: bytes, *, replace: bool) -> None:
    """Publish ``payload`` at ``target`` in one step; a new file never overwrites one."""

    temporary = directory / f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, target)
        else:
            os.link(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
