from __future__ import annotations

import copy
import json
import threading
from pathlib import Path
from typing import Any, Iterator

import pytest

from bluefire import cli, recordings
from bluefire.api import generate_browser_bootstrap_capability
from bluefire.application_errors import APIError
from bluefire.service import BlueFireService
from tests_platform.test_api import json_body, request, running_server

ROOT = Path(__file__).resolve().parents[1]
SHIPPED = ROOT / "bluefire" / "data" / "recordings" / "lab-linux-host.json"
SHIPPED_RUN = "https://github.com/Moneer-S/BlueFire-Nexus/actions/runs/45227119895"


def small_recording(recording_id: str = "rec-small") -> dict[str, Any]:
    """Two steps of a test list, in the shape the lab writes them: one alerted, one seen."""

    def step(step_id: str, title: str, answer: str, events: int, outcome: str) -> dict[str, Any]:
        return {
            "id": step_id,
            "order": int(step_id),
            "role": "test",
            "title": title,
            "technique": {"id": "T1070.003"},
            "host": "target",
            "started": f"2026-11-17T17:07:2{step_id}.000Z",
            "ended": f"2026-11-17T17:07:2{step_id}.500Z",
            "happened": {"answer": "took effect", "basis": "the effect check exited with 0"},
            "visibility": {
                "answer": answer,
                "basis": "what the sensors and rules said",
                "events": events,
            },
            "outcome": outcome,
            "first_event": f"2026-11-17T17:07:2{step_id}.100Z",
            **({"first_alert": f"2026-11-17T17:07:2{step_id}.100Z"} if answer == "alert" else {}),
        }

    def event(
        event_id: str, step_id: str, time: str, kind: str, text: str, **extra: Any
    ) -> dict[str, Any]:
        return {
            "id": event_id,
            "time": time,
            "host": "target",
            "sensor": "sysmon",
            "kind": kind,
            "text": text,
            "step": step_id,
            "tied_by": "session",
            **extra,
        }

    return {
        "schema": "bluefire.recording/1",
        "id": recording_id,
        "title": "Two published tests on one Linux host",
        "kind": "test list",
        "source": {
            "engine": "bluefire-lab",
            "environment": "GitHub-hosted runner",
            "started": "2026-11-17T17:07:20Z",
            "finished": "2026-11-17T17:08:14Z",
            "tools": [{"name": "Sysmon for Linux", "version": "1.6.0", "role": "sensor"}],
        },
        "network": {
            "hosts": [{"id": "target", "name": "runner", "role": "Linux host under test", "kind": "host"}],
            "sensors": [{"id": "sysmon", "name": "Sysmon for Linux 1.6.0", "host": "target", "records": "process starts"}],
            "detectors": [{"id": "pinned", "name": "Published Sigma rules", "rules": 1, "when": "after the run"}],
        },
        "attacker": {"kind": "scripted", "description": "A list of published tests.", "goal": None},
        "steps": [
            step("1", "Clear Bash history (rm)", "alert", 2, "alerted"),
            step("2", "List running processes", "telemetry only", 1, "seen"),
        ],
        "events": [
            event("1-1", "1", "2026-11-17T17:07:21.100Z", "process start", "rm /tmp/lab/.bash_history",
                  user="lab", image="/usr/bin/rm", fields={"ProcessId": "41"}),
            event("1-2", "1", "2026-11-17T17:07:21.102Z", "file deleted", "/tmp/lab/.bash_history"),
            event("2-1", "2", "2026-11-17T17:07:22.100Z", "process start", "ps aux", image="/usr/bin/ps"),
        ],
        "alerts": [
            {"id": "alert-1", "time": "2026-11-17T17:07:21.100Z", "host": "target", "detector": "pinned",
             "rule": {"id": "rule-1", "title": "History File Deletion", "level": "high", "origin": "pinned"},
             "counts": True, "step": "1", "events": ["1-1"]},
        ],
        "score": {"steps": 2, "took_effect": 2, "alerted": 1, "seen": 1, "unseen": 0, "stopped": 0},
        "notes": [],
    }  # fmt: skip


def attack_path(recording_id: str = "rec-path") -> dict[str, Any]:
    """The same two tests as an attack path toward a goal: its race counts from test 1's start."""

    value = small_recording(recording_id)
    value["kind"] = "attack path"
    value["attacker"]["goal"] = "Read the history file of another account."
    return value


@pytest.fixture
def service(tmp_path: Path) -> Iterator[BlueFireService]:
    instance = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", product_db_path=tmp_path / "product.sqlite3"
    )
    try:
        yield instance
    finally:
        instance.close()


def imported(service: BlueFireService) -> list[dict[str, Any]]:
    entries = service.recordings()["recordings"]
    return [entry for entry in entries if entry["origin"]["kind"] == "imported"]


def refusal(service: BlueFireService, recording: dict[str, Any]) -> tuple[str, list[str]]:
    """The message and the problems of a refused import; nothing is stored."""

    with pytest.raises(APIError) as refused:
        service.import_recording({"recording": recording})
    assert refused.value.status == 422
    assert refused.value.code == "recording_invalid"
    assert imported(service) == []
    assert isinstance(refused.value.details, dict)
    return refused.value.message, list(refused.value.details["problems"])


def test_the_shipped_lab_recording_is_listed_with_its_origin_and_read_back_whole(
    service: BlueFireService,
) -> None:
    listed = service.recordings()

    assert listed["unreadable_count"] == 0
    [entry] = listed["recordings"]
    assert entry["origin"] == {
        "kind": "shipped",
        "run_url": SHIPPED_RUN,
        "note": "Shipped with BlueFire. This repository's lab workflow recorded it in the CI "
        f"run at {SHIPPED_RUN}. BlueFire checked that it follows the recording format and "
        "that its parts agree with each other.",
    }
    assert entry["running"] is False
    assert entry["counts"]["steps"] == 91
    assert {key: entry["score"][key] for key in ("steps", "alerted", "seen", "unseen")} == {
        "steps": 60,
        "alerted": 3,
        "seen": 56,
        "unseen": 1,
    }
    detail = service.recording(entry["id"])
    assert detail["summary"] == entry
    assert detail["recording"] == json.loads(SHIPPED.read_bytes())

    shipped = json.loads(SHIPPED.read_bytes())
    again = service.import_recording({"recording": shipped})
    shipped["title"] = "Something else"
    with pytest.raises(APIError) as refused:
        service.import_recording({"recording": shipped})
    assert again["created"] is False and again["summary"]["origin"]["kind"] == "shipped"
    assert refused.value.code == "recording_id_taken"
    assert imported(service) == []


def test_a_recording_is_imported_listed_and_read_back_whole(
    service: BlueFireService, monkeypatch: pytest.MonkeyPatch
) -> None:
    recording = small_recording()

    first = service.import_recording({"recording": recording})
    again = service.import_recording({"recording": copy.deepcopy(recording)})
    service.import_recording({"recording": small_recording("rec-other")})
    entries = imported(service)
    detail = service.recording("rec-small")
    monkeypatch.setattr(recordings, "MAX_LISTED", 1)
    bounded = service.recordings()

    assert first["created"] is True and again["created"] is False
    assert [entry["id"] for entry in entries] == ["rec-other", "rec-small"]
    # Past the bound the list says how many imported files it left out.
    assert [entry["id"] for entry in bounded["recordings"]][1:] == ["rec-other"]
    assert bounded["omitted_count"] == 1 and bounded["unreadable_count"] == 0
    entry = entries[1]
    assert entry["counts"] == {"steps": 2, "events": 3, "alerts": 1}
    assert entry["score"] == recording["score"]
    assert entry["running"] is False
    assert "cannot confirm that the steps ran" in entry["origin"]["note"]
    assert detail["recording"] == recording


def test_a_running_recording_grows_by_import_and_is_frozen_once_finished(
    service: BlueFireService,
) -> None:
    recording = small_recording("rec-live")
    del recording["source"]["finished"]
    service.import_recording({"recording": recording})
    running = service.recording("rec-live")["summary"]["running"]

    growing = copy.deepcopy(recording)
    growing["notes"] = ["Two steps have run."]
    still_running = service.import_recording({"recording": growing})
    other_run = copy.deepcopy(growing)
    other_run["source"]["started"] = "2026-11-17T17:07:19Z"
    with pytest.raises(APIError) as other_refused:
        service.import_recording({"recording": other_run})

    grown = small_recording("rec-live")
    grown["notes"] = ["The run has ended."]
    replaced = service.import_recording({"recording": grown})
    changed = small_recording("rec-live")
    changed["title"] = "Something else"
    with pytest.raises(APIError) as refused:
        service.import_recording({"recording": changed})

    assert running is True
    assert still_running["replaced"] is True and still_running["summary"]["running"] is True
    assert other_refused.value.status == 409
    assert other_refused.value.code == "recording_id_taken"
    assert replaced["replaced"] is True and replaced["summary"]["running"] is False
    assert refused.value.status == 409 and refused.value.code == "recording_id_taken"
    assert service.recording("rec-live")["recording"] == grown


def test_a_malformed_recording_is_refused_with_a_plain_message(service: BlueFireService) -> None:
    recording = small_recording()
    recording["network"]["detectors"][0]["rules"] = 10**1000
    recording["steps"][0]["title"] = "Clear\x07history"
    recording["steps"][0]["extra"] = float("inf")
    recording["steps"][1]["outcome"] = "maybe"
    recording["steps"][1]["test"] = {
        "project": "Atomic Red Team",
        "guid": "a\x00b",
        "executor": "sh",
        "elevated": False,
    }
    recording["events"][0]["step"] = "9"
    recording["events"][1]["host"] = ["target"]
    recording["events"][2]["time"] = "2026-99-99T99:99:99Z"
    deep = small_recording()
    nested: dict[str, Any] = {}
    deep["steps"][0]["extra"] = nested
    for _ in range(1000):
        nested["a"] = {}
        nested = nested["a"]
    huge = attack_path()
    huge["score"].update(first_alert_seconds=0.1, goal_seconds=10**1000)

    message, problems = refusal(service, recording)
    _, deep_problems = refusal(service, deep)
    _, huge_problems = refusal(service, huge)
    halved = small_recording("rec-halved")
    halved["notes"] = ["half of a pair: \ud83d"]
    _, halved_problems = refusal(service, halved)

    assert message == (
        "The recording is not valid: steps[0].title must not hold control characters."
    )
    assert problems == [
        "steps[0].title must not hold control characters.",
        "steps[0].extra is not a finite number.",
        "steps[1].test.guid must not hold a NUL character.",
        "network.detectors[0].rules must be a whole number from 0 to 1000000000.",
        "steps[1].outcome must be one of: stopped, no effect, alerted, seen, unseen, inconclusive.",
        "events[0].step names step '9' that the recording does not have.",
        "events[1].host names host a value that the recording does not have.",
        "events[2].time must be a UTC time such as 2026-11-17T17:07:23.834Z.",
    ]
    assert deep_problems == ["A recording nests objects and lists at most 8 deep."]
    assert huge_problems == ["score.goal_seconds must be a number of seconds, zero or more."]
    assert halved_problems == [
        "notes[0] must not hold half of a character pair (a lone surrogate)."
    ]


def test_a_recording_whose_parts_disagree_is_refused(service: BlueFireService) -> None:
    claims = small_recording()
    claims["score"].update(steps=50, alerted=50)
    claims["steps"][1]["outcome"] = "unseen"
    claims["steps"][1]["visibility"]["events"] = 999
    claims["steps"][0]["visibility"]["kept"] = 3
    claims["steps"][1]["first_alert"] = "2026-11-17T17:07:22.100Z"
    claims["events"][0]["time"] = "1999-01-01T00:00:00Z"
    claims["score"]["first_alert_seconds"] = 0.5
    race = attack_path()
    race["score"].update(first_alert_seconds=0.001, goal_seconds=999999)

    message, problems = refusal(service, claims)
    _, race_problems = refusal(service, race)
    race["score"].update(first_alert_seconds=0.1, goal_seconds=1.5)
    accepted = service.import_recording({"recording": race})

    assert message == (
        "The recording is not valid: events[0].time falls outside the run's start and end."
    )
    assert problems == [
        "events[0].time falls outside the run's start and end.",
        "steps[0].first_event is 2026-11-17T17:07:21.100Z, but the step's first sensor event is at "
        "1999-01-01T00:00:00Z.",
        "steps[0].visibility.kept is more than visibility.events (2).",
        "steps[0].visibility counts events the recording does not hold (2).",
        "steps[1].first_alert is set, but the step has no counting alert of a published rule.",
        "steps[1].outcome is unseen, but happened 'took effect' and visibility 'telemetry only' "
        "give seen.",
        "steps[1].visibility counts events the recording does not hold (1).",
        "score.steps is 50, but the steps give 2.",
        "score.alerted is 50, but the steps give 1.",
        "score.seen is 1, but the steps give 0.",
        "score.unseen is 0, but the steps give 1.",
        "score.first_alert_seconds is written only for an attack path.",
    ]
    assert race_problems == [
        "score.first_alert_seconds is 0.001, but the steps give 0.100.",
        "score.goal_seconds is 999999, but no step ends that long after the first step started.",
    ]
    assert accepted["created"] is True


def test_the_race_counts_a_live_alert_from_when_it_was_raised(service: BlueFireService) -> None:
    def path(recording_id: str, when: str, first_alert_seconds: float) -> dict[str, Any]:
        race = attack_path(recording_id)
        race["network"]["detectors"][0]["when"] = when
        if when == "live":
            # The first test starts at 21.000 s and its event is at 21.100 s; the alert is
            # raised at 36.000 s, which is also the step's first alert.
            race["alerts"][0]["raised"] = "2026-11-17T17:07:36.000Z"
            race["steps"][0]["first_alert"] = "2026-11-17T17:07:36.000Z"
        race["score"]["first_alert_seconds"] = first_alert_seconds
        return race

    _, from_the_event = refusal(service, path("rec-event", "live", 0.1))
    live = service.import_recording({"recording": path("rec-raised", "live", 15.0)})
    after = service.import_recording({"recording": path("rec-after", "after the run", 0.1)})

    assert from_the_event == ["score.first_alert_seconds is 0.1, but the steps give 15.000."]
    assert live["created"] is True
    assert after["created"] is True


def test_a_steps_first_alert_counts_a_live_alert_from_when_it_was_raised(
    service: BlueFireService,
) -> None:
    def listing(recording_id: str, when: str, first: str, first_with_lab: str) -> dict[str, Any]:
        value = small_recording(recording_id)
        value["network"]["detectors"] = [
            {"id": "pinned", "name": "Published Sigma rules", "rules": 2, "when": when},
            {"id": "lab", "name": "Lab rules", "rules": 1, "when": when},
        ]
        # Test 1 has two counting alerts of published rules, raised out of the order of
        # their events: rule 1 matches at 21.100 s and is raised at 36.000 s, rule 2
        # matches at 21.102 s and is raised at 22.000 s. Test 2, seen, has a counting
        # alert of a lab rule at 22.100 s, raised at 23.000 s.
        value["alerts"] = [
            {**value["alerts"][0], "raised": "2026-11-17T17:07:36.000Z"},
            {"id": "alert-2", "time": "2026-11-17T17:07:21.102Z", "raised": "2026-11-17T17:07:22.000Z",
             "host": "target", "detector": "pinned",
             "rule": {"id": "rule-2", "title": "History File Removed", "level": "high", "origin": "pinned"},
             "counts": True, "step": "1", "events": ["1-2"]},
            {"id": "alert-3", "time": "2026-11-17T17:07:22.100Z", "raised": "2026-11-17T17:07:23.000Z",
             "host": "target", "detector": "lab",
             "rule": {"id": "rule-3", "title": "Process Listing", "level": "high", "origin": "lab"},
             "counts": True, "step": "2", "events": ["2-1"]},
        ]  # fmt: skip
        if when == "after the run":
            for alert in value["alerts"]:
                del alert["raised"]
        one, two = value["steps"]
        one.update(
            first_alert=first, outcome_with_lab_rules="alerted", first_alert_with_lab_rules=first
        )
        two.update(outcome_with_lab_rules="alerted", first_alert_with_lab_rules=first_with_lab)
        return value

    raised = listing("rec-raised", "live", "2026-11-17T17:07:22.000Z", "2026-11-17T17:07:23.000Z")
    _, from_the_events = refusal(
        service,
        listing("rec-events", "live", "2026-11-17T17:07:21.100Z", "2026-11-17T17:07:22.100Z"),
    )
    _, from_the_latest = refusal(
        service,
        listing("rec-latest", "live", "2026-11-17T17:07:36.000Z", "2026-11-17T17:07:23.000Z"),
    )
    after = listing(
        "rec-after", "after the run", "2026-11-17T17:07:21.100Z", "2026-11-17T17:07:22.100Z"
    )

    assert service.import_recording({"recording": raised})["created"] is True
    assert service.import_recording({"recording": after})["created"] is True
    assert from_the_events == [
        "steps[0].first_alert is 2026-11-17T17:07:21.100Z, the time of the alert's activity, but a "
        "step's first alert counts from when a live detector raised it: 2026-11-17T17:07:22.000Z.",
        "steps[0].first_alert_with_lab_rules is 2026-11-17T17:07:21.100Z, the time of the alert's "
        "activity, but a step's first alert counts from when a live detector raised it: "
        "2026-11-17T17:07:22.000Z.",
        "steps[1].first_alert_with_lab_rules is 2026-11-17T17:07:22.100Z, the time of the alert's "
        "activity, but a step's first alert counts from when a live detector raised it: "
        "2026-11-17T17:07:23.000Z.",
    ]
    # The alert whose event came first is not the step's first alert: the one raised first is.
    assert from_the_latest == [
        "steps[0].first_alert is 2026-11-17T17:07:36.000Z, but the step's first counting alert of "
        "a published rule is at 2026-11-17T17:07:22.000Z.",
        "steps[0].first_alert_with_lab_rules is 2026-11-17T17:07:36.000Z, but the step's first "
        "counting alert is at 2026-11-17T17:07:22.000Z.",
    ]


def test_a_null_in_place_of_a_left_out_value_is_refused(service: BlueFireService) -> None:
    race = attack_path()
    race["score"].update(first_alert_seconds=None, goal_seconds=1.5)
    live = small_recording("rec-live")
    live["network"]["detectors"][0]["when"] = "live"
    live["alerts"][0]["raised"] = None
    live["steps"][0]["started"] = None
    live["source"]["finished"] = None

    _, race_problems = refusal(service, race)
    _, live_problems = refusal(service, live)

    assert race_problems == [
        "score.first_alert_seconds is null; a value that is not known is left out."
    ]
    assert live_problems == [
        "source.finished is null; a value that is not known is left out.",
        "steps[0].started is null; a value that is not known is left out.",
        "alerts[0].raised is null; a value that is not known is left out.",
    ]


_LEFT_OUT = object()


@pytest.mark.parametrize(
    ("path", "value", "problem"),
    [
        (("source", "tools"), _LEFT_OUT, "source.tools is missing."),
        (("source", "tools", 0, "role"), "camera",
         "source.tools[0].role must be one of: tests, executor, sensor, rules, rule engine."),
        (("network", "hosts", 0, "addresses"), "10.0.0.1",
         "network.hosts[0].addresses must be a list of at most 100 texts of at most 200 "
         "characters."),
        (("network", "links"), [{"from": "target", "to": "target"}],
         "network.links[0].label is missing."),
        (("network", "sensors", 0, "records"), _LEFT_OUT,
         "network.sensors[0].records is missing."),
        (("attacker", "goal"), _LEFT_OUT,
         "attacker.goal is missing; it is null when the run has no goal."),
        (("steps", 0, "technique", "name"), 5,
         "steps[0].technique.name must be non-empty text."),
        (("steps", 0, "test"), {"project": "Atomic Red Team", "guid": "g", "executor": "sh",
                                "elevated": "yes"},
         "steps[0].test.elevated must be true or false."),
        (("steps", 0, "test"), "Atomic Red Team", "steps[0].test must be an object."),
        (("steps", 0, "happened", "basis"), _LEFT_OUT, "steps[0].happened.basis is missing."),
        (("steps", 0, "visibility", "basis"), 3,
         "steps[0].visibility.basis must be non-empty text."),
        (("steps", 0, "defense"), {"title": "Mount /tmp noexec"},
         "steps[0].defense.why is missing."),
        (("events", 0, "tied_by"), _LEFT_OUT, "events[0].tied_by is missing."),
        (("events", 0, "tied_by"), "guess",
         "events[0].tied_by must be one of: session, launcher, account, systemd, window."),
        (("events", 0, "fields"), {"inode": 10**400},
         "events[0].fields must hold at most 64 plain values: text of at most 300 characters, "
         "a number no further than 9007199254740992 from zero, true, false or null."),
        (("alerts", 0, "rule", "id"), _LEFT_OUT, "alerts[0].rule.id is missing."),
        (("ordinary",), {"events": 3}, "ordinary.matches is missing."),
    ],
)  # fmt: skip
def test_a_value_the_replay_page_cannot_show_is_refused_on_import(
    service: BlueFireService, path: tuple[Any, ...], value: Any, problem: str
) -> None:
    """Each of these was once kept by the import and then refused by the replay page."""

    recording = small_recording()
    holder: Any = recording
    for key in path[:-1]:
        holder = holder[key]
    if value is _LEFT_OUT:
        del holder[path[-1]]
    else:
        holder[path[-1]] = value

    _, problems = refusal(service, recording)

    assert problems == [problem]


def test_a_step_role_the_format_does_not_name_is_refused(service: BlueFireService) -> None:
    recording = small_recording()
    recording["steps"][1]["role"] = "baseline"
    recording["score"].update(steps=1, took_effect=1, seen=0)

    _, problems = refusal(service, recording)

    assert problems == ["steps[1].role must be one of: test, canary, control, hardened, variant."]


def _set(value: dict[str, Any], path: tuple[Any, ...], item: Any) -> None:
    holder: Any = value
    for key in path[:-1]:
        holder = holder[key]
    if item is _LEFT_OUT:
        del holder[path[-1]]
    else:
        holder[path[-1]] = item


_T = "2026-11-17T17:07:"
_SUDO = {"rule": "Sudo Use", "level": "high", "count": 1}


@pytest.mark.parametrize(
    ("kind", "changes", "problem"),
    [
        ("test list", [(("steps", 0, "ended"), f"{_T}20.900Z")],
         f"steps[0].ended is {_T}20.900Z, earlier than the step's started, {_T}21.000Z."),
        ("test list", [(("steps", 1, "started"), f"{_T}20.500Z")],
         f"steps[1].started is {_T}20.500Z, earlier than the start of steps[0], the step before "
         "it: steps run forward in their order."),
        ("test list", [(("steps", 1, "started"), f"{_T}21.400Z")],
         f"steps[1].started is {_T}21.400Z, earlier than the end of steps[0], the step before "
         "it: steps do not overlap."),
        ("test list", [(("events", 1, "time"), f"{_T}22.050Z")],
         f"steps[1] begins at {_T}22.000Z, before steps[0] ends at {_T}22.050Z: a step's events "
         "and alerts come after those of the step before it."),
        ("test list", [(("alerts", 0, "time"), f"{_T}21.050Z"), (("steps", 0, "first_alert"), f"{_T}21.050Z")],
         f"alerts[0].time is {_T}21.050Z, earlier than the earliest event the alert matched, at "
         f"{_T}21.100Z: an alert comes after the first event it names."),
        ("test list", [(("score", "false_alerts"), 7)],
         "score.false_alerts is set, but the recording has no ordinary activity to count it from."),
        ("test list", [(("ordinary",), {"events": 100, "matches": [_SUDO, _SUDO]}), (("score", "false_alerts"), 1)],
         "ordinary.matches[1].rule names 'Sudo Use' again; each rule is listed once."),
        ("test list", [(("ordinary",), {"events": 0, "matches": [{**_SUDO, "count": 1000000}]}), (("score", "false_alerts"), 1)],
         "ordinary.matches[0].count is 1000000, more than the 0 events of ordinary activity."),
        ("test list", [(("attacker", "goal"), "Read the history file.")],
         "attacker.goal is set, but a test list has no goal: it is null."),
        ("test list", [(("steps", 1, "role"), "hardened"), (("steps", 1, "compared_with"), "2"),
                       (("score", "steps"), 1), (("score", "took_effect"), 1), (("score", "seen"), 0)],
         "steps[1].compared_with names the step itself; a rerun is compared with the step it repeats."),
        ("test list", [(("steps", 0, "role"), "variant"), (("steps", 0, "compared_with"), "2"),
                       (("score", "steps"), 1), (("score", "took_effect"), 1), (("score", "alerted"), 0)],
         "steps[0].compared_with names '2', a later step; a rerun repeats a step run before it."),
        ("test list", [(("steps", 1, "compared_with"), "1")],
         "steps[1].compared_with is set on a step of role test; only a hardened or variant step "
         "repeats another."),
        ("test list", [(("source", "repository"), "example")],
         "source.repository must be a GitHub repository as owner/name, such as example/lab."),
        ("test list", [(("steps", 0, "title"), "Clear\x85history")],
         "steps[0].title must not hold control characters."),
        ("test list", [(("network", "hosts", 0, "name"), "runner\u202e")],
         "network.hosts[0].name must not hold control characters."),
        ("test list", [(("events", 0, "text"), "rm\u2028history")],
         "events[0].text must not hold control characters."),
        ("attack path", [(("steps", 0, "role"), "canary"),
                         (("score", "steps"), 1), (("score", "took_effect"), 1), (("score", "alerted"), 0)],
         "steps[0].role is canary, but an attack path begins with a step of role test: its race "
         "counts from that step's start."),
        ("attack path", [(("steps", 0, "started"), _LEFT_OUT)],
         "steps[0].started is missing, but an attack path's race counts from its first step's "
         "start."),
        ("attack path", [(("attacker", "goal"), None), (("score", "goal_seconds"), 1.5)],
         "score.goal_seconds is set, but the attacker has no goal."),
        ("attack path", [(("steps",), []), (("events",), []), (("alerts",), []),
                         (("score",), {"steps": 0, "took_effect": 0, "alerted": 0, "seen": 0,
                                       "unseen": 0, "stopped": 0, "goal_seconds": 5})],
         "score.goal_seconds is 5, but no step ends that long after the first step started."),
        ("test list", [(("steps", 0, "command"), "rm\x00x")],
         "steps[0].command must not hold a NUL character."),
    ],
)  # fmt: skip
def test_what_the_replay_page_could_not_show_truthfully_is_refused_with_the_field_named(
    service: BlueFireService, kind: str, changes: list[tuple[tuple[Any, ...], Any]], problem: str
) -> None:
    """The page's reader refuses each of these too (frontend/tests/live-recording.test.ts)."""

    recording = attack_path() if kind == "attack path" else small_recording()
    for path, item in changes:
        _set(recording, path, item)

    _, problems = refusal(service, recording)

    assert problems == [problem]


def test_what_every_real_recording_holds_is_kept(service: BlueFireService) -> None:
    """Sensors stamp their own records, and a match can name events after its moment."""

    recording = attack_path()
    # An event stamped a moment before its step's start, another after its end, and a
    # live alert raised after its first event but before the second one it names.
    recording["network"]["detectors"][0]["when"] = "live"
    recording["events"][0]["time"] = f"{_T}20.995Z"
    recording["events"][1]["time"] = f"{_T}21.700Z"
    recording["steps"][0].update(first_event=f"{_T}20.995Z", first_alert=f"{_T}21.200Z")
    recording["alerts"][0].update(time=f"{_T}20.995Z", raised=f"{_T}21.200Z", events=["1-1", "1-2"])
    recording["steps"][0]["command"] = "sh -c 'rm history'\n\x1b[0m\u2028"
    recording["source"].update(
        repository="example/lab", run_url="https://github.com/example/lab/actions/runs/1"
    )
    recording["ordinary"] = {"events": 40, "matches": [{**_SUDO, "count": 3}]}
    recording["score"].update(false_alerts=1, first_alert_seconds=0.2, goal_seconds=1.5)

    assert service.import_recording({"recording": recording})["created"] is True


def test_a_finished_recording_is_not_overwritten_by_an_older_import_from_another_library(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two libraries on one store, as the server and the command line are, import in turn."""

    root = tmp_path / "recordings"
    server, command_line = recordings.RecordingLibrary(root), recordings.RecordingLibrary(root)
    running = small_recording("rec-live")
    del running["source"]["finished"]
    server.import_recording({"recording": running})
    older = copy.deepcopy(running)
    older["notes"] = ["One step has run."]
    finished = small_recording("rec-live")

    write = recordings._write_atomically
    checked, go_on = threading.Event(), threading.Event()

    def slow_write(*args: Any, **kwargs: Any) -> None:
        if threading.current_thread().name == "older":
            checked.set()
            go_on.wait(5)
        write(*args, **kwargs)

    monkeypatch.setattr(recordings, "_write_atomically", slow_write)
    results: dict[str, Any] = {}

    def send(name: str, library: recordings.RecordingLibrary, recording: dict[str, Any]) -> None:
        try:
            results[name] = library.import_recording({"recording": recording})
        except APIError as exc:
            results[name] = exc.code

    first = threading.Thread(target=send, args=("older", server, older), name="older")
    first.start()
    assert checked.wait(5)
    second = threading.Thread(target=send, args=("finished", command_line, finished))
    second.start()
    second.join(0.5)
    go_on.set()
    first.join(10)
    second.join(10)

    assert results["older"]["replaced"] is True
    assert results["finished"]["replaced"] is True
    assert server.get("rec-live")[0] == finished
    assert [path.name for path in root.glob("*.json")] == ["rec-live.json"]


def test_a_recording_id_cannot_reach_outside_the_store(
    service: BlueFireService, tmp_path: Path
) -> None:
    escaping = small_recording("../../outside")
    _, problems = refusal(service, escaping)
    with pytest.raises(APIError) as read_refused:
        service.recording("../product")

    assert problems == ["id must be 1 to 64 letters, digits, '-' or '_'."]
    assert read_refused.value.status == 400 and read_refused.value.code == "invalid_recording_id"
    assert not (tmp_path / "runs" / "recordings").exists()
    assert [path for path in tmp_path.rglob("outside*")] == []


def test_recordings_are_imported_and_read_through_the_http_server(
    service: BlueFireService,
) -> None:
    recording = small_recording()
    shipped = json.loads(SHIPPED.read_bytes())
    capability = generate_browser_bootstrap_capability()
    with running_server(
        service,  # type: ignore[arg-type]
        max_request_body=1024,
        bootstrap_capability=capability,
    ) as (server, _):
        created = request(server, "POST", "/api/v1/recordings", body={"recording": recording})
        listed = request(server, "GET", "/api/v1/recordings")
        detail = request(server, "GET", "/api/v1/recordings/rec-small")
        whole = request(server, "GET", f"/api/v1/recordings/{shipped['id']}")
        large = request(server, "POST", "/api/v1/recordings", body={"recording": shipped})
        missing = request(server, "GET", "/api/v1/recordings/rec-none")
        outside = request(server, "GET", "/api/v1/recordings/..%2F..%2Fproduct")
        invalid = request(
            server, "POST", "/api/v1/recordings", body={"recording": {"schema": "other"}}
        )
        other_route = request(server, "POST", "/api/v1/runs/preflight", body={"x": "y" * 2048})
        unauthenticated = request(server, "GET", "/api/v1/recordings", authenticated=False)
        server.max_recording_body = 2048
        too_large = request(
            server, "POST", "/api/v1/recordings", body={"recording": small_recording("rec-big")}
        )

    assert created[0] == 201, created[2]
    assert json_body(created[2])["summary"]["id"] == "rec-small"
    assert [item["id"] for item in json_body(listed[2])["recordings"]] == [
        shipped["id"],
        "rec-small",
    ]
    assert json_body(detail[2])["recording"] == recording
    assert json_body(whole[2])["recording"] == shipped
    # Only the import route reads a body as large as a recording.
    assert large[0] == 201 and json_body(large[2])["created"] is False
    assert other_route[0] == 413
    assert too_large[0] == 413
    assert missing[0] == 404
    assert json_body(missing[2])["error"]["code"] == "recording_not_found"
    assert outside[0] == 400
    assert invalid[0] == 422
    assert json_body(invalid[2])["error"]["message"] == (
        "The recording is not valid: schema must be 'bluefire.recording/1'."
    )
    assert unauthenticated[0] in {401, 403}


PAGE_ELEMENT = '<script id="bluefire-recording" type="application/json">'
ORIGIN_ELEMENT = '<script id="bluefire-origin" type="application/json">'


def page_recording(page: str, element: str = PAGE_ELEMENT) -> Any:
    """Read a replay page's recording back the way a browser does: up to the first end tag."""

    assert page.count(element) == 1
    start = page.index(element) + len(element)
    return json.loads(page[start : page.index("</script>", start)])


def test_the_command_line_writes_the_replay_page_of_the_shipped_recording(
    service: BlueFireService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    shipped = json.loads(SHIPPED.read_bytes())
    out = tmp_path / "replay.html"
    template = (ROOT / "bluefire" / "ui" / "replay.html").read_text(encoding="utf-8")

    written = cli.main(["recordings", "page", shipped["id"], "--out", str(out)])
    written_output = json.loads(capsys.readouterr().out)
    page = out.read_text(encoding="utf-8")
    again = cli.main(["recordings", "page", shipped["id"], "--out", str(out)])
    again_output = json.loads(capsys.readouterr().out)
    missing = cli.main(["recordings", "page", "rec-none", "--out", str(tmp_path / "none.html")])
    missing_output = json.loads(capsys.readouterr().out)

    assert written == 0
    assert written_output["recording_id"] == shipped["id"]
    assert written_output["bytes"] == len(page.encode("utf-8"))
    assert page_recording(template) is None
    assert page_recording(template, ORIGIN_ELEMENT) is None
    assert page_recording(page) == shipped
    # The page says where its recording comes from: the service's origin, with the CI run.
    assert (
        page_recording(page, ORIGIN_ELEMENT)
        == service.recording(shipped["id"])["summary"]["origin"]
    )
    assert page_recording(page, ORIGIN_ELEMENT)["run_url"] == SHIPPED_RUN
    # Only the elements' content changed: the page is the packaged one.
    start = page.index(PAGE_ELEMENT)
    assert page[:start] == template[: template.index(PAGE_ELEMENT)]
    assert page.endswith(template[template.index(ORIGIN_ELEMENT) + len(ORIGIN_ELEMENT) + 4 :])
    # An existing file is never replaced.
    assert again == 2
    assert "already exists" in again_output["error"]["message"]
    assert out.read_text(encoding="utf-8") == page
    assert missing == 2 and missing_output["error"]["code"] == "recording_not_found"
    assert not (tmp_path / "none.html").exists()


def test_the_page_of_an_imported_recording_says_what_was_not_confirmed_and_a_running_one_has_none(
    service: BlueFireService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    service.import_recording({"recording": small_recording()})
    running = small_recording("rec-live")
    del running["source"]["finished"]
    service.import_recording({"recording": running})
    out = tmp_path / "imported.html"
    running_out = tmp_path / "running.html"

    written = cli.main(["recordings", "page", "rec-small", "--out", str(out)])
    capsys.readouterr()
    refused = cli.main(["recordings", "page", "rec-live", "--out", str(running_out)])
    refused_output = json.loads(capsys.readouterr().out)

    assert written == 0
    assert page_recording(out.read_text(encoding="utf-8"), ORIGIN_ELEMENT) == {
        "kind": "imported",
        "note": recordings.IMPORTED_NOTE,
    }
    assert refused == 2
    assert refused_output["error"]["code"] == "recording_running"
    assert "still running" in refused_output["error"]["message"]
    assert not running_out.exists()


def test_a_recording_whose_texts_hold_markup_comes_back_whole_from_its_page() -> None:
    recording = small_recording()
    recording["title"] = "</script><script>alert(1)</script>"
    recording["steps"][0]["title"] = "<!-- </SCRIPT > <script"
    recording["steps"][0]["plain"] = "Ends </script\n><!--<script>"
    recording["events"][0]["text"] = "<img src=http://example.invalid/x.png>"
    recording["notes"] = ["</ScRiPt>", "<!--", "-->", "<script>"]
    origin = {"kind": "imported", "note": "</script><!--<script>"}
    template = recordings.replay_template()

    page = recordings.replay_page(recording, origin)

    assert page_recording(page) == recording
    assert page_recording(page, ORIGIN_ELEMENT) == origin
    # The recording and its origin add no markup: no "<" of their own, so each element
    # is ended once.
    for element in (PAGE_ELEMENT, ORIGIN_ELEMENT):
        start = page.index(element) + len(element)
        assert "<" not in page[start : page.index("</script>", start)]
    assert page.lower().count("<script") == template.lower().count("<script")
    for broken in (
        template.replace(PAGE_ELEMENT, "<script>"),
        template.replace("</body>", f"{PAGE_ELEMENT}null</script></body>"),
        template.replace("</body>", '<script id="bluefire-recording">null</script></body>'),
        template.replace(ORIGIN_ELEMENT, "<script>"),
        template.replace("</body>", '<script id="bluefire-origin">null</script></body>'),
    ):
        with pytest.raises(ValueError, match="exactly one"):
            recordings.replay_page(recording, origin, broken)


def test_the_command_line_imports_and_lists_a_recording_file(
    service: BlueFireService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    path = tmp_path / "recording.json"
    path.write_text(json.dumps(small_recording()), encoding="utf-8")
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps({**small_recording(), "kind": "story"}), encoding="utf-8")
    not_a_number = tmp_path / "nan.json"
    with_nan = small_recording("rec-nan")
    with_nan["score"]["first_alert_seconds"] = float("nan")
    not_a_number.write_text(json.dumps(with_nan), encoding="utf-8")

    imported_status = cli.main(["recordings", "import", str(path)])
    imported_output = json.loads(capsys.readouterr().out)
    refused = cli.main(["recordings", "import", str(broken)])
    refused_output = json.loads(capsys.readouterr().out)
    nan_refused = cli.main(["recordings", "import", str(not_a_number)])
    nan_output = json.loads(capsys.readouterr().out)
    listed = cli.main(["recordings", "list"])
    listed_output = json.loads(capsys.readouterr().out)

    assert imported_status == 0 and imported_output["created"] is True
    assert refused == 2
    assert refused_output["error"]["message"] == (
        "The recording is not valid: recording.kind must be one of: test list, attack path."
    )
    assert nan_refused == 2
    assert nan_output["error"]["message"] == (
        "The recording is not valid: The file is not UTF-8 JSON: NaN is not a JSON number"
    )
    assert listed == 0
    assert [item["origin"]["kind"] for item in listed_output["recordings"]] == [
        "shipped",
        "imported",
    ]
    assert listed_output["recordings"][1]["id"] == "rec-small"
