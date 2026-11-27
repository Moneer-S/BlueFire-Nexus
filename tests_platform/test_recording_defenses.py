"""One run judged by several defenses: what the import keeps, and what it refuses.

Each recording here is built from the first defense's plain view of the path through
range one that the app ships. The interface's reader is given the same recordings
(frontend/tests/live-defenses.test.ts). Whether a verdict follows from the events and
alerts of its view is checked here alone, as it is for a recording without defenses.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest

from bluefire import recordings
from bluefire.application_errors import APIError
from bluefire.service import BlueFireService

ROOT = Path(__file__).resolve().parents[1]
SHIPPED_PATH = ROOT / "bluefire" / "data" / "recordings" / "lab-range-one-path.json"
VERDICT = (
    "visibility",
    "outcome",
    "outcome_with_lab_rules",
    "first_event",
    "first_alert",
    "first_alert_with_lab_rules",
)
TOP_IS_FIRST = "the top level of a recording with defenses holds the verdicts of its first defense."


def plain_shipped() -> dict[str, Any]:
    """The shipped path as one plain view, whether it already holds defenses or not."""

    whole: dict[str, Any] = json.loads(SHIPPED_PATH.read_bytes())
    defenses = whole.pop("defenses", None)
    if not defenses:
        return whole

    first = defenses[0]
    sensors, detectors = set(first["sensors"]), set(first["detectors"])
    whole["network"]["sensors"] = [
        sensor for sensor in whole["network"]["sensors"] if sensor["id"] in sensors
    ]
    whole["network"]["detectors"] = [
        detector for detector in whole["network"]["detectors"] if detector["id"] in detectors
    ]
    whole["events"] = [event for event in whole["events"] if event["sensor"] in sensors]
    held = {event["id"] for event in whole["events"]}
    whole["alerts"] = [
        alert
        for alert in whole["alerts"]
        if alert["detector"] in detectors and held.issuperset(alert["events"])
    ]
    whole["steps"] = [
        {
            **{key: item for key, item in step.items() if key not in VERDICT},
            **{
                key: item
                for key, item in first["steps"][step["id"]].items()
                if key in VERDICT
            },
        }
        for step in whole["steps"]
    ]
    if "ordinary" in first:
        whole["ordinary"] = copy.deepcopy(first["ordinary"])
    else:
        whole.pop("ordinary", None)
    whole["score"] = copy.deepcopy(first["score"])
    return whole


def judged_twice() -> dict[str, Any]:
    """The shipped path as one run judged by two defenses.

    The first is everything the recording holds, so the top level is its view. The second
    records with the same three agents and runs no rule set: the step that alerted is only
    seen there, with no first alert, and its score follows.
    """

    whole = plain_shipped()
    whole["id"] = "range-one-judged-twice"
    stock = {
        "id": "wazuh-stock",
        "name": "Wazuh with its stock rules",
        "sensors": [sensor["id"] for sensor in whole["network"]["sensors"]],
        "detectors": ["pinned"],
        "steps": {
            step["id"]: {key: step[key] for key in VERDICT if key in step}
            for step in whole["steps"]
        },
        "ordinary": whole["ordinary"],
        "score": whole["score"],
    }
    alone = copy.deepcopy(stock)
    alone.update(id="agents-alone", name="The three agents with no rule set", detectors=[])
    for verdict in alone["steps"].values():
        if verdict["outcome"] == "alerted":
            verdict["visibility"].update(
                answer="telemetry only", basis="the agents recorded the step; no rule set ran"
            )
            verdict["outcome"] = "seen"
            del verdict["first_alert"]
    alone["ordinary"]["matches"] = []
    score = alone["score"]
    score.update(alerted=0, seen=score["seen"] + score["alerted"])
    del score["first_alert_seconds"]
    whole["defenses"] = copy.deepcopy([stock, alone])
    return whole


def with_packet_capture(value: dict[str, Any], place: int = 1) -> dict[str, Any]:
    """A fourth sensor, a packet capture on web, that only the defense at ``place`` has: it
    recorded one more event of the last step, which only that defense counts."""

    last = value["events"][-1]
    value["network"]["sensors"].append(
        {
            "id": "packet-capture",
            "name": "Packet capture",
            "host": last["host"],
            "records": "packets",
        }
    )
    value["events"].append(
        {**last, "id": "capture-1", "sensor": "packet-capture", "kind": "packet"}
    )
    defense = value["defenses"][place]
    defense["sensors"].append("packet-capture")
    defense["steps"][last["step"]]["visibility"]["events"] += 1
    return value


def on_the_capture(value: dict[str, Any]) -> dict[str, Any]:
    """A match of the stock rules, below alert level, on the event the packet capture recorded."""

    seen = value["events"][-1]
    return {
        "id": "on-the-capture",
        "time": seen["time"],
        "host": seen["host"],
        "detector": "pinned",
        "rule": {"id": "1", "title": "A packet", "level": "low", "origin": "pinned"},
        "counts": False,
        "step": seen["step"],
        "events": [seen["id"]],
    }


def rule_set(detector_id: str) -> dict[str, Any]:
    return {"id": detector_id, "name": f"{detector_id} rules", "rules": 1, "when": "after the run"}


def problems_of(value: dict[str, Any]) -> list[str]:
    with pytest.raises(recordings.RecordingError) as refused:
        recordings.validate_recording(value)
    return refused.value.problems


@pytest.fixture
def service(tmp_path: Path) -> Iterator[BlueFireService]:
    instance = BlueFireService(
        project_root=ROOT, runs_dir=tmp_path / "runs", product_db_path=tmp_path / "product.sqlite3"
    )
    try:
        yield instance
    finally:
        instance.close()


def test_one_run_judged_by_two_defenses_is_imported_and_read_back_whole(
    service: BlueFireService,
) -> None:
    recording = judged_twice()

    stored = service.import_recording({"recording": recording})
    detail = service.recording(recording["id"])

    assert stored["created"] is True
    # The list entry gives the first defense's score, which is the top level's.
    assert stored["summary"]["score"] == recording["defenses"][0]["score"] == recording["score"]
    assert detail["recording"] == recording
    # The second defense saw the step the first alerted on, and never alerted.
    second = detail["recording"]["defenses"][1]
    assert [verdict["outcome"] for verdict in second["steps"].values()] == ["seen"] * 11
    assert (second["score"]["alerted"], second["score"]["seen"]) == (0, 11)
    assert "first_alert_seconds" not in second["score"]


def test_a_defense_counts_only_what_its_own_sensors_recorded() -> None:
    recording = with_packet_capture(judged_twice())
    last = recording["steps"][-1]["id"]

    assert recordings.validate_recording(recording) is recording
    # The capture's event is the second defense's alone: the first counts one event of the
    # step, the second two.
    assert recording["defenses"][0]["steps"][last]["visibility"]["events"] == 1
    assert recording["defenses"][1]["steps"][last]["visibility"]["events"] == 2


def test_an_alert_is_judged_by_the_defense_that_has_its_rule_set_and_recorded_its_events() -> None:
    # A third defense has the stock rules and the capture too; the first has the rules without
    # it. A match of those rules on the capture's event is the third's alone: the first's
    # view, which does not hold that event, agrees with itself without it.
    recording = judged_twice()
    third = copy.deepcopy(recording["defenses"][0])
    third.update(id="stock-and-capture", name="Wazuh with its stock rules and a packet capture")
    recording["defenses"].append(third)
    with_packet_capture(recording, 2)
    recording["alerts"].append(on_the_capture(recording))

    assert recordings.validate_recording(recording) is recording


def test_a_recording_with_defenses_holds_eight_rule_sets_and_a_defense_four_of_them() -> None:
    recording = judged_twice()
    more = [f"set-{number}" for number in range(recordings.MAX_DETECTORS_WITH_DEFENSES - 1)]
    recording["network"]["detectors"] += [rule_set(detector_id) for detector_id in more]
    recording["defenses"][1]["detectors"] = more[: recordings.MAX_DETECTORS]

    assert recordings.validate_recording(recording) is recording


def _no_defense(value: dict[str, Any]) -> list[str]:
    value["defenses"] = []
    return ["defenses is empty; a recording with defenses has at least one."]


def _nine_defenses(value: dict[str, Any]) -> list[str]:
    value["defenses"] += [
        {**value["defenses"][1], "id": f"more-{number}"}
        for number in range(recordings.MAX_DEFENSES - 1)
    ]
    return ["defenses has 9 entries; at most 8 are allowed."]


def _an_id_twice(value: dict[str, Any]) -> list[str]:
    value["defenses"][1]["id"] = "wazuh-stock"
    return ["defenses[1].id repeats the id 'wazuh-stock'."]


def _an_id_with_a_space(value: dict[str, Any]) -> list[str]:
    value["defenses"][1]["id"] = "agents alone"
    return ["defenses[1].id must be 1 to 64 letters, digits, '-' or '_'."]


def _a_sensor_the_network_lacks(value: dict[str, Any]) -> list[str]:
    value["defenses"][1]["sensors"].append("packet-capture")
    return ["defenses[1].sensors names sensor 'packet-capture' that the recording does not have."]


def _a_rule_set_the_network_lacks(value: dict[str, Any]) -> list[str]:
    value["defenses"][1]["detectors"] = ["sigma"]
    return ["defenses[1].detectors names detector 'sigma' that the recording does not have."]


def _no_sensor(value: dict[str, Any]) -> list[str]:
    value["defenses"][1]["sensors"] = []
    return ["defenses[1].sensors is empty; a defense records with at least one sensor."]


def _five_rule_sets_in_a_defense(value: dict[str, Any]) -> list[str]:
    more = [f"set-{number}" for number in range(recordings.MAX_DETECTORS)]
    value["network"]["detectors"] += [rule_set(detector_id) for detector_id in more]
    value["defenses"][1]["detectors"] = ["pinned", *more]
    return [
        "defenses[1].detectors names 5 detectors; at most 4 are allowed, the most the live "
        "view's map draws."
    ]


def _a_step_left_out(value: dict[str, Any]) -> list[str]:
    del value["defenses"][1]["steps"]["s03"]
    return ["defenses[1].steps has no entry for the step 's03'; a defense judges every step."]


def _a_step_the_run_lacks(value: dict[str, Any]) -> list[str]:
    value["defenses"][1]["steps"]["s99"] = value["defenses"][1]["steps"]["s10"]
    return ["defenses[1].steps names step 's99' that the recording does not have."]


def _an_outcome_the_format_does_not_have(value: dict[str, Any]) -> list[str]:
    value["defenses"][1]["steps"]["s01"]["outcome"] = "missed"
    return [
        "defenses[1].steps.s01.outcome must be one of: stopped, no effect, alerted, seen, unseen, "
        "inconclusive."
    ]


def _an_event_of_a_sensor_no_defense_has(value: dict[str, Any]) -> list[str]:
    with_packet_capture(value)
    second = value["defenses"][1]
    second["sensors"].remove("packet-capture")
    second["steps"][value["events"][-1]["step"]]["visibility"]["events"] -= 1
    return [
        f"events[{len(value['events']) - 1}].sensor is 'packet-capture', a sensor of no defense: "
        "every event of a recording with defenses is of a sensor that one of them has."
    ]


def _an_alert_of_a_rule_set_no_defense_has(value: dict[str, Any]) -> list[str]:
    value["network"]["detectors"].append(rule_set("sigma"))
    # Rules that ran after the run raise nothing: the copied alert loses its raised time.
    alert = {**value["alerts"][-1], "id": "sigma-1", "detector": "sigma"}
    alert.pop("raised", None)
    value["alerts"].append(alert)
    return [
        f"alerts[{len(value['alerts']) - 1}].detector is 'sigma', a detector of no defense: every "
        "alert of a recording with defenses is of a rule set that one of them has."
    ]


def _an_alert_on_an_event_its_defense_did_not_record(value: dict[str, Any]) -> list[str]:
    # The stock rules are the first defense's, and the capture is the second's.
    with_packet_capture(value)
    value["alerts"].append(on_the_capture(value))
    return [
        f"alerts[{len(value['alerts']) - 1}] is in no defense's view: no defense has its "
        "detector, 'pinned', and the sensor of every event it names."
    ]


def _another_outcome_at_the_top(value: dict[str, Any]) -> list[str]:
    value["steps"][1]["outcome"] = "unseen"
    return [f"steps[1].outcome differs from defenses[0].steps.s02.outcome: {TOP_IS_FIRST}"]


def _another_score_at_the_top(value: dict[str, Any]) -> list[str]:
    value["score"]["seen"] -= 1
    return [f"score differs from defenses[0].score: {TOP_IS_FIRST}"]


def _no_ordinary_activity_at_the_top(value: dict[str, Any]) -> list[str]:
    del value["ordinary"]
    return [f"ordinary differs from defenses[0].ordinary: {TOP_IS_FIRST}"]


def _a_score_that_says_1_where_the_first_defense_says_true(value: dict[str, Any]) -> list[str]:
    # A key the format does not name is kept as it is given, and in JSON true is not 1.
    value["score"]["extra"] = 1
    value["defenses"][0]["score"]["extra"] = True
    return [f"score differs from defenses[0].score: {TOP_IS_FIRST}"]


def _a_visibility_that_says_true_where_the_first_defense_says_1(value: dict[str, Any]) -> list[str]:
    value["steps"][1]["visibility"]["sure"] = True
    value["defenses"][0]["steps"]["s02"]["visibility"]["sure"] = 1
    return [f"steps[1].visibility differs from defenses[0].steps.s02.visibility: {TOP_IS_FIRST}"]


def _a_verdict_the_defenses_view_does_not_give(value: dict[str, Any]) -> list[str]:
    # The second defense runs no rule set, so nothing it holds alerts on the first step.
    value["defenses"][1]["steps"]["s01"]["outcome"] = "alerted"
    return [
        "defenses[1].steps.s01.outcome is alerted, but happened 'took effect' and visibility "
        "'telemetry only' give seen.",
        "defenses[1].score.alerted is 0, but the steps give 1.",
        "defenses[1].score.seen is 11, but the steps give 10.",
    ]


def _a_first_alert_only_another_defense_raised(value: dict[str, Any]) -> list[str]:
    second = value["defenses"][1]
    second["steps"]["s01"]["first_alert"] = value["steps"][0]["first_alert"]
    second["score"]["first_alert_seconds"] = value["score"]["first_alert_seconds"]
    return [
        "defenses[1].steps.s01.first_alert is set, but the step has no counting alert of a "
        "published rule.",
        "defenses[1].score.first_alert_seconds is set, but no step of role test has a counting "
        "alert of a published rule.",
    ]


def _false_alerts_without_ordinary_activity(value: dict[str, Any]) -> list[str]:
    del value["defenses"][1]["ordinary"]
    return [
        "defenses[1].score.false_alerts is set, but the defense has no ordinary activity to "
        "count it from."
    ]


def _an_event_on_another_host_than_its_sensor(value: dict[str, Any]) -> list[str]:
    # Both defenses hold the event, and what is wrong with it does not depend on either.
    index = next(i for i, event in enumerate(value["events"]) if event["step"] == "s06")
    value["events"][index]["host"] = "db"
    return [f"events[{index}].host is not the host its sensor runs on."]


def _events_out_of_time_order_that_no_view_holds_together(value: dict[str, Any]) -> list[str]:
    # A third defense records with a packet capture alone, which recorded one event of the last
    # step. That event comes first in the recording's list, before the agents' earlier events:
    # the view of each defense is in time order, and the recording's list is not.
    last = value["events"][-1]
    value["network"]["sensors"].append(
        {
            "id": "packet-capture",
            "name": "Packet capture",
            "host": last["host"],
            "records": "packets",
        }
    )
    value["events"].insert(0, {**last, "id": "capture-1", "sensor": "packet-capture"})
    nothing = {"answer": "no telemetry", "basis": "the capture recorded nothing of it", "events": 0}
    verdicts: dict[str, Any] = {
        step["id"]: {"visibility": nothing, "outcome": "unseen"} for step in value["steps"]
    }
    verdicts[last["step"]] = {
        "visibility": {"answer": "telemetry only", "basis": "one packet", "events": 1},
        "outcome": "seen",
        "first_event": last["time"],
    }
    score = {**value["score"], "alerted": 0, "seen": 1, "unseen": 10}
    del score["first_alert_seconds"], score["false_alerts"]
    value["defenses"].append(
        {
            "id": "capture-alone",
            "name": "A packet capture alone",
            "sensors": ["packet-capture"],
            "detectors": [],
            "steps": verdicts,
            "score": score,
        }
    )
    return ["events must be sorted by time."]


@pytest.mark.parametrize(
    "change",
    [
        _no_defense,
        _nine_defenses,
        _an_id_twice,
        _an_id_with_a_space,
        _a_sensor_the_network_lacks,
        _a_rule_set_the_network_lacks,
        _no_sensor,
        _five_rule_sets_in_a_defense,
        _a_step_left_out,
        _a_step_the_run_lacks,
        _an_outcome_the_format_does_not_have,
        _an_event_of_a_sensor_no_defense_has,
        _an_alert_of_a_rule_set_no_defense_has,
        _an_alert_on_an_event_its_defense_did_not_record,
        _another_outcome_at_the_top,
        _another_score_at_the_top,
        _no_ordinary_activity_at_the_top,
        _a_score_that_says_1_where_the_first_defense_says_true,
        _a_visibility_that_says_true_where_the_first_defense_says_1,
        _a_verdict_the_defenses_view_does_not_give,
        _a_first_alert_only_another_defense_raised,
        _false_alerts_without_ordinary_activity,
        _an_event_on_another_host_than_its_sensor,
        _events_out_of_time_order_that_no_view_holds_together,
    ],
    ids=lambda change: change.__name__.strip("_").replace("_", " "),
)
def test_a_recording_with_defenses_is_refused_with_the_defense_and_the_key_named(
    change: Callable[[dict[str, Any]], list[str]],
) -> None:
    """Each change is to one thing, and gives the sentences it returns and no other."""

    recording = judged_twice()
    expected = change(recording)

    assert problems_of(recording) == expected


def test_more_rule_sets_than_a_recording_with_defenses_holds_are_refused() -> None:
    recording = judged_twice()
    recording["network"]["detectors"] += [
        rule_set(f"set-{number}") for number in range(recordings.MAX_DETECTORS_WITH_DEFENSES)
    ]

    assert problems_of(recording)[0] == (
        "network.detectors has 9 entries; at most 8 are allowed in a recording with defenses."
    )


def test_the_import_gives_a_refused_defense_its_sentence(service: BlueFireService) -> None:
    recording = judged_twice()
    recording["defenses"][1]["steps"]["s01"]["outcome"] = "alerted"

    with pytest.raises(APIError) as refused:
        service.import_recording({"recording": recording})

    assert refused.value.code == "recording_invalid"
    assert refused.value.message == (
        "The recording is not valid: defenses[1].steps.s01.outcome is alerted, but happened "
        "'took effect' and visibility 'telemetry only' give seen."
    )
