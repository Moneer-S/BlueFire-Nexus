"""The recording, written from the run.json and results.json of a small run built by hand."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from bluefire_lab import recording
from bluefire_lab.__main__ import main

HIGH = {"id": "rule-high", "title": "History File Deletion", "level": "high", "origin": "pinned"}
LOW = {**HIGH, "id": "rule-low", "title": "File Deletion", "level": "low"}
OURS = {**HIGH, "id": "rule-ours", "title": "Shell History File Emptied", "origin": "lab", "accepted": True}
REJECTED = {
    **OURS,
    "id": "rule-rejected",
    "title": "A Rule That Matches Ordinary Work Too",
    "accepted": False,
    "reason": "it matched 3 events of ordinary activity",
}
CHANGE = {"name": "lock", "title": "the history file made immutable", "why": "A reason.", "apply": "true"}


def at(order: int, second: float) -> str:
    """A sensor's time. Each test of the run has the minute of its order to itself."""

    return f"2026-11-16 04:{order:02d}:{second:06.3f}"


MEDIUM = {**HIGH, "id": "rule-medium", "title": "Suspicious Shell Activity", "level": "medium"}
AUDITD_START = {
    "kind": "execve (auditd)",
    "detail": "/usr/bin/rm, /lib64/ld-linux-x86-64.so.2 by rm /home/bluefire-lab/.bash_history",
    "fields": {
        "pid": "121",
        "paths": "/usr/bin/rm, /lib64/ld-linux-x86-64.so.2",
        "command": "rm /home/bluefire-lab/.bash_history",
    },
}


def cited(rule: dict, *records, alert: bool | None = None) -> dict:
    """A rule match as results.json holds it, with the run's own word on whether it alerts."""

    return {**rule, "records": list(records), "alert": rule["level"] == "high" if alert is None else alert}


def an_event(order: int, record, second: float = 3.1, **changes) -> dict:
    event = {
        "record": record,
        "time": at(order, second),
        "kind": "process start",
        "process_id": "121",
        "user": "bluefire-lab",
        "image": "/usr/bin/rm",
        "detail": "rm /home/bluefire-lab/.bash_history",
        "why": "session",
        "fields": {"ProcessId": "121", "ParentCommandLine": "sh -c " + "x" * 400, "Hashes": "SHA256=00"},
    }
    return {**event, **changes}


def a_test(order: int, role: str = "test", execution: str = "took effect", events=(), **seen) -> dict:
    """A test as results.json holds it. Its launcher starts in second 3 of its window, from 1 to 6."""

    alert = any(rule["alert"] for rule in seen.get("rules", []))
    answer = "alert" if alert else "telemetry only" if events else "no telemetry"
    lab = seen.pop("lab", [])
    visibility = {
        "answer": answer,
        "basis": "what the answer rests on",
        "window": [at(order, 1), at(order, 6)],
        "events": len(events),
        "rules": [],
        "launcher": an_event(order, order * 1000, 3, detail="sh -c rm ~/.bash_history", why="launcher"),
        "launcher_only_rules": [],
        "with_lab_rules": {
            "answer": "alert" if any(rule["accepted"] for rule in lab) else answer,
            "rules": lab,
        },
        **seen,
    }
    return {
        "order": order,
        "role": role,
        "technique": "T1070.003",
        "guid": f"guid-{order}",
        "name": f"Test {order}",
        "executor": "sh",
        "elevated": False,
        "user": "bluefire-lab",
        "execution": {"answer": execution, "basis": "the effect check exited with status 0"},
        "visibility": visibility,
        "events": list(events),
    }


def a_run() -> list[dict]:
    """A canary, a control, and one test for each outcome, then a hardened run and a variant."""

    hardened = a_test(9, "hardened", "blocked", [an_event(9, 90)])
    hardened.update(defense=CHANGE, compared_with=4)
    not_run = a_test(8, execution="not attempted")
    not_run["visibility"] = {"answer": "not applicable", "basis": "the test did not run"}
    return [
        # auditd's clock put the program start 7 ms before Sysmon saw the shell that carried the test.
        a_test(
            1,
            "canary",
            events=[
                an_event(1, "audit 1794801662.993:530", 2.993, **AUDITD_START),
                an_event(1, 7, 3.2),
            ],
            rules=[cited(HIGH, 7), cited(LOW, "audit 1794801662.993:530", 7)],
        ),
        a_test(2, "control", events=[an_event(2, 20)], rules=[cited(LOW, 20)]),
        a_test(4, events=[an_event(4, 40)], rules=[cited(HIGH, 40)]),
        a_test(5, events=[an_event(5, 50)], launcher_only_rules=[cited(HIGH, 5000)]),
        a_test(6, events=[an_event(6, 60)], lab=[cited(OURS, 60), cited(REJECTED, 60)]),
        a_test(7),
        not_run,
        hardened,
        {**a_test(10, "variant", events=[an_event(10, 100)], lab=[cited(OURS, 100)]), "compared_with": 6},
    ]


def recorded(folder: Path, tests: list[dict], *arguments: str, printed: str | None = None, **changes) -> dict:
    """Write the two files of a run with these tests, and return the recording the lab makes of them.
    Each test prints a line of its own, or else what printed says."""

    results = {
        "run": {
            "id": "r1",
            "started": "2026-11-16T04:00:00Z",
            "finished": "2026-11-16T04:30:00Z",
            "account": "bluefire-lab",
            "target": {
                "os": "Ubuntu 24.04.5 LTS",
                "kernel": "7.0.0-1017-azure",
                "runner_image": "ubuntu24 20261111.370.1",
            },
            "tools": {
                "atomic-red-team": "a" * 40,
                "invoke-atomicredteam": "b" * 40,
                "lab": "example/lab@" + "c" * 40,
                # The run of a pair that loaded the base commit's rules and sensor settings.
                "lab-defense": "example/lab@" + "e" * 40,
            },
        },
        "sensor": {"name": "Sysmon for Linux", "version": "1.6.0"},
        "audit": {"name": "auditd", "version": "3.1.2"},
        "rules": {
            "source": "SigmaHQ/sigma@" + "d" * 40,
            "evaluated": {"process_creation": 122, "auditd": 53},
            "alert_levels": ["high", "critical"],
            "lab": 2,
        },
        "lab_rules": [OURS, REJECTED],
        "ordinary_activity": {
            "baseline_events": 40,
            "system_events": 900,
            "pinned_rules": [{**HIGH, "events": 2}, {**LOW, "events": 5}],
        },
        "engine": {"name": "Zircolite", "version": "4.7.1"},
        "controls": [{"name": "loss", "passed": True, "detail": "the sensor reported 0 lost events"}],
        "tests": tests,
        "dropped": [],
        **changes,
    }
    attacks = [
        {
            "order": test["order"],
            "role": test["role"],
            "steps": [
                {
                    "label": "attack",
                    "output": f"printed by test {test['order']}\n" if printed is None else printed,
                    "error": "",
                }
            ],
        }
        for test in tests
    ]
    run = {
        "tests": [{"order": 3, "role": "baseline", "name": "Ordinary administration", "steps": []}, *attacks]
    }
    (folder / "run.json").write_text(json.dumps(run), encoding="utf-8")
    (folder / "results.json").write_text(json.dumps(results), encoding="utf-8")
    assert main(["recording", str(folder), *arguments]) == 0
    return json.loads((folder / "recording.json").read_text(encoding="utf-8"))


def test_a_run_becomes_one_file_with_its_steps_in_order_and_where_it_ran(tmp_path: Path) -> None:
    made = recorded(tmp_path, a_run(), "--run-url", "https://example.org/runs/1")

    assert (made["schema"], made["id"], made["kind"]) == ("bluefire.recording/1", "r1", "test list")
    assert made["title"] == "5 published tests on one Linux host"
    assert made["attacker"]["kind"] == "scripted" and made["attacker"]["goal"] is None
    assert [(step["id"], step["order"]) for step in made["steps"]] == [
        ("canary:guid-1", 1), ("control:guid-2", 2), ("test:guid-4", 4), ("test:guid-5", 5), ("test:guid-6", 6),
        ("test:guid-7", 7), ("test:guid-8", 8), ("hardened:guid-9:lock", 9), ("variant:guid-10", 10),
    ]  # fmt: skip
    first = made["steps"][0]
    assert (first["title"], first["host"], first["command"]) == (
        "Test 1",
        "target",
        "sh -c rm ~/.bash_history",
    )
    assert first["technique"] == {"id": "T1070.003"}
    assert first["test"] == {
        "project": "Atomic Red Team",
        "guid": "guid-1",
        "executor": "sh",
        "elevated": False,
    }
    # From the start of the shell that carried the test to the marker after it, not the marker before.
    assert (first["started"], first["ended"]) == ("2026-11-16T04:01:03.000Z", "2026-11-16T04:01:06.000Z")
    assert first["output"] == "printed by test 1"
    assert made["source"] == {
        "engine": "bluefire-lab",
        "environment": "GitHub-hosted runner",
        "started": "2026-11-16T04:00:00Z",
        "finished": "2026-11-16T04:30:00Z",
        "repository": "example/lab",
        "commit": "c" * 40,
        "defense_commit": "e" * 40,
        "run_url": "https://example.org/runs/1",
        "tools": [
            {"name": "Atomic Red Team", "version": "a" * 40, "role": "tests"},
            {"name": "Invoke-AtomicRedTeam", "version": "b" * 40, "role": "executor"},
            {"name": "Sysmon for Linux", "version": "1.6.0", "role": "sensor"},
            {"name": "auditd", "version": "3.1.2", "role": "sensor"},
            {"name": "SigmaHQ/sigma", "version": "d" * 40, "role": "rules"},
            {"name": "Zircolite", "version": "4.7.1", "role": "rule engine"},
        ],
        # The results of this run hold no digest of a sensor's settings, so the setup names none.
        "setup": {
            "atomic_commit": "a" * 40,
            "images": {"target": "ubuntu24 20261111.370.1"},
            "kernels": {"target": "7.0.0-1017-azure"},
        },
    }
    host = made["network"]["hosts"][0]
    assert (host["id"], host["kind"], host["role"]) == ("target", "host", "Linux host under test")
    assert host["os"] == "Ubuntu 24.04.5 LTS, kernel 7.0.0-1017-azure, runner image ubuntu24 20261111.370.1"
    assert [(sensor["id"], sensor["name"]) for sensor in made["network"]["sensors"]] == [
        ("sysmon", "Sysmon for Linux 1.6.0"),
        ("auditd", "auditd 3.1.2"),
    ]
    assert [(rules["id"], rules["rules"], rules["when"]) for rules in made["network"]["detectors"]] == [
        ("pinned", 175, "after the run"),
        ("lab", 2, "after the run"),
    ]
    assert made["notes"][0] == (
        "The rules were evaluated after the run ended, so an alert's time is the time of the event it matched."
    )
    assert any("Position 3 of the run was ordinary administration" in note for note in made["notes"])


def test_every_step_gets_an_outcome_and_the_score_counts_the_tests(tmp_path: Path) -> None:
    made = recorded(tmp_path, a_run())

    steps = {str(step["order"]): step for step in made["steps"]}
    assert {name: step["outcome"] for name, step in steps.items()} == {
        "1": "alerted",
        "2": "seen",
        "4": "alerted",
        "5": "seen",
        "6": "seen",
        "7": "unseen",
        "8": "no effect",
        "9": "stopped",
        "10": "seen",
    }
    assert steps["7"]["happened"] == {
        "answer": "took effect",
        "basis": "the effect check exited with status 0",
    }
    assert steps["7"]["visibility"] == {
        "answer": "no telemetry",
        "basis": "what the answer rests on",
        "events": 0,
    }
    # Nothing was measured for a test that did not run, so no count of its events is written.
    assert steps["8"]["visibility"] == {"answer": "not applicable", "basis": "the test did not run"}
    assert steps["9"]["compared_with"] == "test:guid-4"
    assert steps["9"]["defense"] == {"title": "the history file made immutable", "why": "A reason."}
    # A test that did not run has no times, and nothing is made up for them.
    assert not {"started", "ended", "command", "first_event"} & set(steps["8"])
    assert made["score"] == {
        "steps": 5,
        "took_effect": 4,
        "alerted": 1,
        "seen": 2,
        "unseen": 1,
        "alerted_with_lab_rules": 2,
        "stopped": 1,
        # One rule that matched ordinary activity at an alert level, whatever the number of its events.
        "false_alerts": 1,
    }
    assert made["ordinary"] == {
        "events": 940,
        "matches": [
            {"rule": "History File Deletion", "level": "high", "count": 2},
            {"rule": "File Deletion", "level": "low", "count": 5},
        ],
    }


def test_only_a_high_rule_that_matched_what_the_test_did_counts_as_an_alert(tmp_path: Path) -> None:
    made = recorded(tmp_path, a_run())

    steps = {str(step["order"]): step for step in made["steps"]}
    order = {step["id"]: name for name, step in steps.items()}
    alerts = {(order[alert["step"]], alert["rule"]["id"]): alert for alert in made["alerts"]}
    assert len(alerts) == len(made["alerts"]) == 7
    assert [alert["id"] for alert in made["alerts"]] == [f"alert-{number}" for number in range(1, 8)]
    assert [alert["time"] for alert in made["alerts"]] == sorted(alert["time"] for alert in made["alerts"])
    # The low rule's first event, auditd's, is earlier than the high rule's: it comes first.
    assert [(alert["step"], alert["rule"]["id"]) for alert in made["alerts"]][:2] == [
        ("canary:guid-1", "rule-low"),
        ("canary:guid-1", "rule-high"),
    ]
    caught = alerts["1", "rule-high"]
    assert caught["counts"] and caught["events"] == ["1-2"] and "raised" not in caught
    assert (caught["detector"], caught["rule"]) == ("pinned", HIGH)
    # A rule of a lower level is a match for review. Its time is that of the first event it matched.
    review = alerts["1", "rule-low"]
    assert not review["counts"] and review["events"] == ["1-1", "1-2"]
    assert review["time"] == "2026-11-16T04:01:02.993Z"
    # The rule matched only the line that carried the whole test: shown, never counted.
    launcher = alerts["5", "rule-high"]
    assert launcher["launcher_only"] and not launcher["counts"] and launcher["events"] == []
    assert launcher["time"] == steps["5"]["started"]
    assert "first_alert" not in steps["5"] and "first_alert_with_lab_rules" not in steps["5"]
    # The run evaluated rules of the lab's own, so every step has the second answer, the same or not.
    assert steps["5"]["outcome_with_lab_rules"] == steps["5"]["outcome"] == "seen"
    assert all("outcome_with_lab_rules" in step for step in made["steps"])
    # A rule of the lab's own that the run accepted counts in the second answer only.
    ours = alerts["6", "rule-ours"]
    assert ours["counts"] and (ours["detector"], ours["rule"]["origin"]) == ("lab", "lab")
    assert (steps["6"]["outcome"], steps["6"]["outcome_with_lab_rules"]) == ("seen", "alerted")
    assert "first_alert" not in steps["6"]
    assert steps["6"]["first_alert_with_lab_rules"] == "2026-11-16T04:06:03.100Z"
    assert steps["6"]["visibility"]["answer"] == "telemetry only"
    assert ("6", "rule-rejected") not in alerts
    assert steps["4"]["first_alert"] == steps["4"]["first_alert_with_lab_rules"] == "2026-11-16T04:04:03.100Z"
    assert steps["4"]["outcome_with_lab_rules"] == steps["4"]["outcome"] == "alerted"


def test_an_event_keeps_a_few_fields_of_its_record_and_points_at_its_step(tmp_path: Path) -> None:
    made = recorded(tmp_path, a_run())

    assert [event["time"] for event in made["events"]] == sorted(event["time"] for event in made["events"])
    by_auditd, by_sysmon = made["events"][:2]
    assert by_auditd == {
        "id": "1-1",
        "time": "2026-11-16T04:01:02.993Z",
        "host": "target",
        "sensor": "auditd",
        "kind": "execve",
        # The command, not every path of the record before it.
        "text": "rm /home/bluefire-lab/.bash_history",
        "step": "canary:guid-1",
        "tied_by": "session",
        "user": "bluefire-lab",
        "image": "/usr/bin/rm",
        "fields": {
            "pid": "121",
            "paths": "/usr/bin/rm, /lib64/ld-linux-x86-64.so.2",
            "command": "rm /home/bluefire-lab/.bash_history",
            "msg": "audit(1794801662.993:530)",
        },
    }
    assert (by_sysmon["id"], by_sysmon["sensor"], by_sysmon["kind"]) == ("1-2", "sysmon", "process start")
    assert by_sysmon["tied_by"] == "session"
    assert set(by_sysmon["fields"]) == {"ProcessId", "ParentCommandLine"}
    assert len(by_sysmon["fields"]["ParentCommandLine"]) == 300
    assert made["steps"][0]["first_event"] == "2026-11-16T04:01:02.993Z"
    assert any(
        "earlier than the start of its step, here by up to 7 ms (1 event)" in note for note in made["notes"]
    )


def test_a_step_with_very_many_events_keeps_the_first_and_those_a_rule_matched(tmp_path: Path) -> None:
    events = [an_event(4, 1000 + number, 3 + number / 1000) for number in range(1, 311)]
    busy = a_test(4, events=events, rules=[cited(HIGH, 1002, 1305)], lab=[cited(REJECTED, 1310)])

    made = recorded(tmp_path, [busy])

    assert made["steps"][0]["visibility"] == {
        "answer": "alert",
        "basis": "what the answer rests on",
        "events": 310,
        "kept": 301,
    }
    assert [event["id"] for event in made["events"]] == [f"4-{number}" for number in (*range(1, 301), 305)]
    assert [alert["events"] for alert in made["alerts"]] == [["4-2", "4-305"]]
    assert any("1 step left more than 300 events" in note for note in made["notes"])


def test_plain_words_and_technique_names_come_from_the_run_or_else_from_the_list(tmp_path: Path) -> None:
    named = a_test(4, events=[an_event(4, 40)])
    named.update(plain="Deletes the shell history file with rm.", tactic="stealth")
    named["technique_name"] = "Indicator Removal: Clear Command History"
    older = a_test(5, events=[an_event(5, 50)])
    tests = {
        "canary": {"guid": "guid-1"},
        "tests": [{"guid": "guid-5", "plain": "Empties the history file."}],
    }
    (tmp_path / "pinned-tests.yaml").write_text(json.dumps(tests), encoding="utf-8")

    made = recorded(tmp_path, [named, older], "--tests", str(tmp_path / "pinned-tests.yaml"))

    assert made["steps"][0]["plain"] == "Deletes the shell history file with rm."
    assert made["steps"][0]["technique"] == {
        "id": "T1070.003",
        "name": "Indicator Removal: Clear Command History",
        "tactic": "stealth",
    }
    assert made["steps"][1]["plain"] == "Empties the history file."
    assert made["steps"][1]["technique"] == {"id": "T1070.003"}
    # A sentence the run did not record itself is named as coming from the list.
    assert (
        "The plain sentence of 1 step comes from the list of tests given to the converter, not from the run."
        in made["notes"]
    )
    alone = recorded(tmp_path, [older])
    assert "plain" not in alone["steps"][0]
    assert not any("plain sentence" in note for note in alone["notes"])


def test_a_failed_control_is_among_the_notes(tmp_path: Path) -> None:
    failed = [{"name": "loss", "passed": False, "detail": "the sensor reported 3 lost events"}]

    made = recorded(tmp_path, a_run(), controls=failed)

    assert (
        "1 control of the run failed, so this run does not support its results: "
        "the sensor reported 3 lost events." in made["notes"]
    )
    assert not any("does not support" in note for note in recorded(tmp_path, a_run())["notes"])


def test_a_dropped_test_an_early_stop_and_a_rule_not_accepted_are_among_the_notes(tmp_path: Path) -> None:
    plain = recorded(tmp_path, a_run())
    assert (
        "The run accepted 1 of the 2 rules written in this repository. A match of a rule it did not accept "
        "is not in the recording. Not accepted: A Rule That Matches Ordinary Work Too "
        "(it matched 3 events of ordinary activity)." in plain["notes"]
    )
    assert not any("did not run" in note or "stopped early" in note for note in plain["notes"])

    dropped = [{"technique": "T1070.003", "name": "Some test", "reason": "needs a package the runner lacks"}]
    recorded(tmp_path, a_run(), dropped=dropped)
    results = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    results["run"]["aborted"] = "the canary failed"
    (tmp_path / "results.json").write_text(json.dumps(results), encoding="utf-8")
    assert main(["recording", str(tmp_path)]) == 0
    made = json.loads((tmp_path / "recording.json").read_text(encoding="utf-8"))

    assert (
        "1 test on the list did not run: T1070.003 Some test (needs a package the runner lacks)."
        in made["notes"]
    )
    assert "The run stopped early: the canary failed." in made["notes"]


def test_only_a_match_the_run_says_alerts_counts_whatever_its_time(tmp_path: Path) -> None:
    # A medium rule matched before the high one on step 4, and was the only match on step 5.
    caught = a_test(
        4, events=[an_event(4, 40, 2.5), an_event(4, 41, 3.5)], rules=[cited(MEDIUM, 40), cited(HIGH, 41)]
    )
    reviewed = a_test(5, events=[an_event(5, 50)], rules=[cited(MEDIUM, 50)])

    made = recorded(tmp_path, [caught, reviewed])

    steps = {str(step["order"]): step for step in made["steps"]}
    assert [alert["counts"] for alert in made["alerts"] if alert["rule"]["id"] == "rule-medium"] == [
        False,
        False,
    ]
    assert steps["4"]["first_alert"] == "2026-11-16T04:04:03.500Z"
    assert (steps["5"]["outcome"], "first_alert" in steps["5"]) == ("seen", False)
    assert (made["score"]["alerted"], made["score"]["seen"]) == (1, 1)


def test_a_step_without_effect_has_no_effect_whatever_the_sensors_saw(tmp_path: Path) -> None:
    alerted = a_test(
        1, execution="attempted without effect", events=[an_event(1, 10)], rules=[cited(HIGH, 10)]
    )
    seen = a_test(2, execution="attempted without effect", events=[an_event(2, 20)])
    unknown = a_test(4, execution="inconclusive")
    unmeasured = a_test(5)
    unmeasured["visibility"] = {
        "answer": "inconclusive",
        "basis": "a marker command is missing from the telemetry",
    }

    made = recorded(tmp_path, [alerted, seen, unknown, unmeasured])

    assert [step["outcome"] for step in made["steps"]] == [
        "no effect",
        "no effect",
        "inconclusive",
        "inconclusive",
    ]
    assert "events" not in made["steps"][3]["visibility"]
    score = made["score"]
    assert (score["steps"], score["took_effect"], score["alerted"], score["seen"], score["unseen"]) == (
        4,
        1,
        0,
        0,
        0,
    )


def test_a_user_sysmon_does_not_know_is_left_out() -> None:
    found = recording.event(an_event(1, 5, user="-"), "1", 1)

    assert "user" not in found and found["image"] == "/usr/bin/rm"


def test_output_keeps_its_end_and_a_command_and_an_event_text_their_start(tmp_path: Path) -> None:
    events = [
        an_event(4, 40, detail="echo a\necho b"),
        an_event(
            4,
            "audit 1794802083.200:600",
            3.2,
            kind="openat (auditd)",
            detail="/home/bluefire-lab/.bashrc, /etc/ld.so.cache by sh",
            fields={"paths": "/home/bluefire-lab/.bashrc, /etc/ld.so.cache", "command": "sh"},
        ),
        an_event(
            4,
            "audit 1794802083.300:601",
            3.3,
            kind="execve (auditd)",
            detail="the kernel refused to start /tmp/payload (exit -2)",
            fields={"paths": "/tmp/payload", "command": ""},
        ),
    ]
    long = a_test(4, events=events)
    long["visibility"]["launcher"]["detail"] = "sh -c " + "z" * 2500

    made = recorded(tmp_path, [long], printed="first\n" + "y" * 2500 + "\nlast line\n")

    step = made["steps"][0]
    assert len(step["output"]) == 2000 and step["output"].startswith("...")
    assert step["output"].endswith("\nlast line") and "first" not in step["output"]
    assert (
        len(step["command"]) == 2000
        and step["command"].startswith("sh -c z")
        and step["command"].endswith("...")
    )
    assert [event["text"] for event in made["events"]] == [
        "echo a echo b",
        "/home/bluefire-lab/.bashrc",
        "the kernel refused to start /tmp/payload (exit -2)",
    ]


def test_a_run_without_rules_of_its_own_or_auditd_has_no_second_answer(tmp_path: Path) -> None:
    made = recorded(tmp_path, a_run(), lab_rules=[], audit=None)

    assert not any(
        "outcome_with_lab_rules" in step or "first_alert_with_lab_rules" in step for step in made["steps"]
    )
    assert "alerted_with_lab_rules" not in made["score"]
    assert not any(alert["detector"] == "lab" for alert in made["alerts"])
    assert [detector["id"] for detector in made["network"]["detectors"]] == ["pinned"]
    assert [sensor["id"] for sensor in made["network"]["sensors"]] == ["sysmon"]
    assert "auditd" not in [tool["name"] for tool in made["source"]["tools"]]


def test_a_step_has_the_same_id_in_every_run_of_the_same_list(tmp_path: Path) -> None:
    def the_list() -> list[dict]:
        canary, closing = a_test(1, "canary"), a_test(12, "canary")
        closing["guid"] = canary["guid"]
        searched = {**a_test(4), "guid": "46959285-0a8d-4f2c-9c27-5e3a01b8e2a1", "args": {"search_path": "~"}}
        varied = {**a_test(10, "variant"), "guid": searched["guid"], "compared_with": 4}
        varied["args"] = {"filename": "id_ed25519", "search_path": "~"}
        locked = {**a_test(11, "hardened"), "guid": searched["guid"], "args": {"search_path": "~"}}
        locked.update(defense=CHANGE, compared_with=4)
        return [canary, searched, varied, locked, closing]

    first = recorded(tmp_path, the_list())
    # The same list with one more position in front of it, as when the ordinary activity moves.
    shifted = the_list()
    for test in shifted:
        test["order"] += 1
        if "compared_with" in test:
            test["compared_with"] += 1
    second = recorded(tmp_path, shifted)

    ids = [step["id"] for step in first["steps"]]
    assert ids == [step["id"] for step in second["steps"]]
    # Arguments as compact JSON with sorted keys: {"search_path":"~"} has the SHA-256 that starts 85163a.
    assert ids == [
        "canary:guid-1:1",
        "test:46959285:85163a",
        "variant:46959285:5e4f5f",
        "hardened:46959285:85163a:lock",
        "canary:guid-1:2",
    ]
    assert {step.get("compared_with") for made in (first, second) for step in made["steps"][2:4]} == {
        "test:46959285:85163a"
    }


def test_the_setup_names_each_sensors_settings_and_each_detector_the_digest_of_its_rules(
    tmp_path: Path,
) -> None:
    rules = tmp_path / "lab-rules" / "linux" / "process_creation"
    rules.mkdir(parents=True)
    (rules / "a.yml").write_text("title: A\n", encoding="utf-8")
    (tmp_path / "rules" / "linux").mkdir(parents=True)
    sums = {"sensor": {"name": "Sysmon for Linux", "configuration_sha256": "1" * 64}}
    audit = {"audit": {"name": "auditd", "rules_sha256": "2" * 64}}

    made = recorded(tmp_path, a_run(), **sums, **audit)

    assert made["source"]["setup"]["sensors"] == {"sysmon": "1" * 64, "auditd": "2" * 64}
    digests = {detector["id"]: detector["digest"] for detector in made["network"]["detectors"]}
    # As sha256sum prints the folder's files, sorted by path, and that listing hashed once more.
    listing = hashlib.sha256(b"title: A\n").hexdigest() + "  process_creation/a.yml\n"
    assert digests == {
        "pinned": hashlib.sha256(b"").hexdigest(),
        "lab": hashlib.sha256(listing.encode()).hexdigest(),
    }
    (rules / "a.yml").write_text("title: B\n", encoding="utf-8")
    changed = recorded(tmp_path, a_run(), **sums, **audit)
    assert {detector["id"]: detector["digest"] for detector in changed["network"]["detectors"]} != digests


def test_the_auditd_sensor_says_which_audit_keys_its_rules_as_loaded_define(tmp_path: Path) -> None:
    rules = (
        "## A watch that is only a comment: -w /etc/hosts -p wa -k not-loaded\n"
        "-D\n"
        "-w /home/bluefire-lab/.bash_history -p wa -k shell-history\n"
        "-a always,exit -F arch=b64 -S execve -F auid!=unset -F key=process-start\n"
        "  # -w /etc/shadow -p wa -k also-not-loaded\n"
        "-w /root/.bashrc -p wa -k shell-start\n"
    )

    made = recorded(tmp_path, a_run(), audit={"name": "auditd", "rules_text": rules})
    older = recorded(tmp_path, a_run(), audit={"name": "auditd"})

    auditd = next(sensor for sensor in made["network"]["sensors"] if sensor["id"] == "auditd")
    assert auditd["audit_keys"] == ["process-start", "shell-history", "shell-start"]
    # A run whose results do not hold the rules' text does not say which keys they define.
    assert "audit_keys" not in next(
        sensor for sensor in older["network"]["sensors"] if sensor["id"] == "auditd"
    )


def test_the_lab_detector_carries_each_rule_with_its_file_text_digest_and_verdict(tmp_path: Path) -> None:
    text = "title: A\nlevel: high\n"
    lab_rules = [
        {**OURS, "file": "linux/auditd/a.yml", "text": text, "reason": "it alerted"},
        {**REJECTED, "text": "title: R\n"},
    ]
    (tmp_path / "lab-rules").mkdir()
    (tmp_path / "lab-rules" / "SOURCE").write_text("example/lab@" + "e" * 40 + "\n", encoding="utf-8")

    made = recorded(tmp_path, a_run(), lab_rules=lab_rules)

    lab = next(detector for detector in made["network"]["detectors"] if detector["id"] == "lab")
    assert lab["commit"] == "e" * 40
    # A reader can show the rule beside the step it alerted on: its path in the repository and its lines.
    assert lab["verdicts"] == [
        {
            "rule": "rule-ours",
            "title": "Shell History File Emptied",
            "file": "lab/rules/linux/auditd/a.yml",
            "digest": hashlib.sha256(text.encode()).hexdigest(),
            "lines": ["title: A", "level: high"],
            "accepted": True,
            "reason": "it alerted",
        },
        {
            "rule": "rule-rejected",
            "title": "A Rule That Matches Ordinary Work Too",
            "digest": hashlib.sha256(b"title: R\n").hexdigest(),
            "lines": ["title: R"],
            "accepted": False,
            "reason": "it matched 3 events of ordinary activity",
        },
    ]
    assert "\n".join(lab["verdicts"][0]["lines"]) + "\n" == text


def test_events_are_in_time_order_even_when_a_step_outlasts_the_next_ones_start(tmp_path: Path) -> None:
    late = an_event(1, 11, time="2026-11-16 04:02:10.000")
    tests = [a_test(1, events=[an_event(1, 10), late]), a_test(2, events=[an_event(2, 20)])]

    made = recorded(tmp_path, tests)

    assert [(event["id"], event["step"]) for event in made["events"]] == [
        ("1-1", "test:guid-1"),
        ("2-1", "test:guid-2"),
        ("1-2", "test:guid-1"),
    ]
