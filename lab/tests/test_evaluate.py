"""The two answers and the controls, on events built by hand.

The events have the shape Sysmon for Linux gave in the sensor spike: the
executor's children carry no parent GUID and the id of the executor's thread as
parent, and a detached child has parent 1. They are constructed, not recorded.
"""

from __future__ import annotations

from bluefire_lab import evaluate, sysmon

ACCOUNT = "bluefire-lab"
RUN = {"id": "r1", "account": ACCOUNT, "sensor": {"ready_after_seconds": 1}}
RULES = {
    name: {
        "id": name,
        "title": name,
        "level": level,
        "author": "someone",
        "file": f"linux/{name}.yml",
        "text": "",
    }
    for name, level in (("high-rule", "high"), ("medium-rule", "medium"), ("critical-rule", "critical"))
}


def start(record, second, pid, parent_pid, command, session, user=ACCOUNT, parent_known=False) -> dict:
    return {
        "EventID": sysmon.PROCESS_START,
        "EventRecordID": str(record),
        "UtcTime": f"2026-11-16 04:00:{second:06.3f}",
        "ProcessGuid": f"{{guid-{pid}}}",
        "ProcessId": str(pid),
        "ParentProcessId": str(parent_pid),
        "ParentProcessGuid": f"{{guid-{parent_pid}}}" if parent_known else sysmon.NO_PARENT,
        "Image": "/usr/bin/" + command.split()[0],
        "CommandLine": command,
        "TerminalSessionId": str(session),
        "User": user,
    }


def other(record, second, kind, pid, **fields) -> dict:
    return {
        "EventID": kind,
        "EventRecordID": str(record),
        "UtcTime": f"2026-11-16 04:00:{second:06.3f}",
        "ProcessGuid": f"{{guid-{pid}}}",
        "ProcessId": str(pid),
        "Image": "/usr/bin/dash",
        "User": ACCOUNT,
        **fields,
    }


def step(label, session, status=0) -> dict:
    return {
        "label": label,
        "session": str(session),
        "exit_status": status,
        "timed_out": False,
        "output": "",
        "error": "",
    }


def a_test(**changes) -> dict:
    test = {
        "order": 1,
        "role": "test",
        "user": ACCOUNT,
        "executor": "sh",
        "prerequisites": "none declared",
        "launcher_pid": 120,
        "exit_code": 0,
        "effect": "test -e /tmp/x",
        "steps": [step("marker-start", 10), step("attack", 11), step("marker-end", 12), step("effect", 13)],
    }
    test.update(changes)
    return test


def telemetry() -> list[dict]:
    marker = "/usr/bin/true bluefire-lab-marker r1 1"
    return [
        start(1, 1.0, 90, 89, f"{marker} start", 10),
        start(2, 2.0, 100, 99, "sudo -u bluefire-lab pwsh", 11, user="root"),
        start(3, 2.01, 101, 100, "pwsh -Command Invoke-AtomicTest", 11, parent_known=True),
        start(4, 2.5, 110, 105, "hostname", 11),  # the executor's own, before the test
        start(5, 5.0, 120, 105, "sh -c touch /tmp/x; id", 11),  # the launcher
        other(6, 5.005, sysmon.FILE_CREATED, 120, TargetFilename="/tmp/x"),
        start(7, 5.01, 121, 120, "id", 11, parent_known=True),
        start(8, 5.02, 130, 1, "sleep 600", 11),  # detached from the test
        start(9, 5.5, 140, 105, "ip -4 -br addr show", 11),  # the executor's own, after the test
        other(10, 5.6, sysmon.PROCESS_END, 120),
        start(11, 5.7, 200, 50, "sh -c /tmp/x", 77),  # started for the account by cron
        start(12, 5.8, 300, 1, "apt-get update", sysmon.NO_SESSION, user="root"),
        start(13, 6.0, 91, 89, f"{marker} end", 12),
        start(14, 7.0, 201, 50, "sh -c /tmp/x", 78),  # after the window
    ]


def see(test, events, matched=None, system=()):
    starts = [event for event in events if event["EventID"] == sysmon.PROCESS_START]
    edges = [evaluate.marker_time(starts, "r1", test["order"], edge) for edge in ("start", "end")]
    context = {
        "account": ACCOUNT,
        "known_sessions": {step["session"] for step in test["steps"]},
        "windows": {test["order"]: tuple(edges)},
        "system_commands": set(system),
    }
    return evaluate.visibility(test, events, starts, matched or {}, RULES, context)


def records(events) -> list[int]:
    return [event["record"] for event in events]


def test_a_test_owns_its_session_but_not_what_the_executor_runs_for_itself() -> None:
    answer, mine = see(a_test(), telemetry())

    assert answer["answer"] == "telemetry only"
    assert records(mine) == [6, 7, 8, 11]
    assert [event["why"] for event in mine] == ["launcher", "session", "session", "account"]
    assert answer["launcher"]["record"] == 5


def test_the_executors_own_commands_are_left_out_when_the_sensor_knows_their_parent() -> None:
    events = telemetry()
    for event in events:
        if event.get("ParentProcessId") == "105":
            event.update(ParentProcessId="101", ParentProcessGuid="{guid-101}")

    _, mine = see(a_test(), events)

    assert records(mine) == [6, 7, 8, 11]


def test_a_test_run_as_root_owns_what_systemd_started_in_its_window_and_not_the_accounts_cron() -> None:
    _, mine = see(a_test(user="root"), telemetry())

    assert records(mine) == [6, 7, 8, 12]
    assert mine[-1]["why"] == "systemd"


def test_what_systemd_also_runs_outside_every_window_is_the_systems_own_work() -> None:
    _, mine = see(a_test(user="root"), telemetry(), system={("/usr/bin/apt-get", "apt-get update")})

    assert records(mine) == [6, 7, 8]


def test_systemds_own_helper_is_not_part_of_a_test() -> None:
    helper = start(15, 5.9, 301, 1, "systemd-executor --deserialize 72", sysmon.NO_SESSION, user="root")

    _, mine = see(a_test(user="root"), [*telemetry(), helper])

    assert records(mine) == [6, 7, 8, 12]


def test_system_commands_are_what_systemd_started_outside_every_window() -> None:
    window = ("2026-11-16 04:00:01.000", "2026-11-16 04:00:06.000")
    starts = [
        start(1, 0.5, 400, 1, "sa1 1 1", sysmon.NO_SESSION, user="root"),
        start(2, 5.5, 401, 1, "touch /tmp/marker", sysmon.NO_SESSION, user="root"),
        start(3, 0.6, 402, 7, "run-parts /etc/cron.daily", 55, user="root"),
    ]

    assert evaluate.system_commands(starts, [window]) == {("/usr/bin/sa1", "sa1 1 1")}


def test_only_the_launcher_recorded_is_no_telemetry() -> None:
    events = [
        event for event in telemetry() if event["EventRecordID"] in ("1", "2", "3", "4", "5", "9", "10", "13")
    ]

    answer, mine = see(a_test(), events)

    assert (answer["answer"], mine) == ("no telemetry", [])


def test_an_alert_needs_a_rule_of_an_alert_level_on_an_event_of_the_test() -> None:
    quiet, _ = see(a_test(), telemetry(), {"7": ["medium-rule"]})
    loud, _ = see(a_test(), telemetry(), {"7": ["medium-rule"], "8": ["high-rule"]})

    assert quiet["answer"] == "telemetry only"
    assert [rule["id"] for rule in quiet["rules"]] == ["medium-rule"]
    assert loud["answer"] == "alert"
    assert [(rule["id"], rule["alert"], rule["records"]) for rule in loud["rules"]] == [
        ("high-rule", True, [8]),
        ("medium-rule", False, [7]),
    ]


def test_a_rule_that_matches_only_the_launcher_or_the_executor_is_not_a_detection() -> None:
    answer, _ = see(
        a_test(), telemetry(), {"5": ["high-rule"], "4": ["critical-rule"], "9": ["critical-rule"]}
    )

    assert answer["answer"] == "telemetry only"
    assert answer["rules"] == []
    assert [rule["id"] for rule in answer["launcher_only_rules"]] == ["high-rule"]


def test_a_missing_marker_is_inconclusive() -> None:
    events = [event for event in telemetry() if event["EventRecordID"] != "13"]

    answer, mine = see(a_test(), events, {"8": ["high-rule"]})

    assert (answer["answer"], mine) == ("inconclusive", [])


def test_a_missing_launcher_is_inconclusive() -> None:
    answer, mine = see(a_test(launcher_pid=999), telemetry(), {"8": ["high-rule"]})

    assert (answer["answer"], mine) == ("inconclusive", [])


def test_a_launcher_that_is_not_the_tests_shell_is_inconclusive() -> None:
    not_a_shell, _ = see(a_test(launcher_pid=121), telemetry(), {"8": ["high-rule"]})  # the test's own id
    other_shell, _ = see(a_test(executor="bash"), telemetry(), {"8": ["high-rule"]})

    assert not_a_shell["answer"] == "inconclusive"
    assert other_shell["answer"] == "inconclusive"


def test_execution_follows_the_prerequisites_and_the_effect_check() -> None:
    took = evaluate.execution(a_test())
    failed = evaluate.execution(a_test(steps=[step("attack", 11), step("effect", 13, status=1)]))
    missing = evaluate.execution(a_test(prerequisites="not met", steps=[]))
    by_exit_code = a_test(steps=[step("attack", 11)], exit_code=3)
    del by_exit_code["effect"]
    unstarted = a_test(steps=[step("attack", 11)])
    del unstarted["launcher_pid"]
    printed = a_test(
        steps=[{**step("attack", 11), "output": "uid=1001(bluefire-lab)\nExit code: 0\n"}], output="uid="
    )
    silent = a_test(steps=[step("attack", 11)], output="uid=")
    del printed["effect"], silent["effect"]

    assert took["answer"] == "took effect"
    assert failed["answer"] == "attempted without effect"
    assert missing["answer"] == "not attempted"
    assert evaluate.execution(by_exit_code)["answer"] == "attempted without effect"
    assert evaluate.execution(unstarted)["answer"] == "inconclusive"
    assert evaluate.execution(printed)["answer"] == "took effect"
    assert evaluate.execution(silent)["answer"] == "attempted without effect"


def hardened(applied=True, effect_status=1, **changes) -> dict:
    change = {"name": "lock", "title": "a change", "applied": applied}
    steps = [
        step("defense", 9),
        step("attack", 11),
        step("effect", 13, status=effect_status),
        step("revert", 14),
    ]
    return a_test(**{"role": "hardened", "defense": change, "compared_with": 3, "steps": steps, **changes})


def test_a_hardening_change_blocks_only_what_took_effect_without_it() -> None:
    took, failed = {"answer": "took effect"}, {"answer": "attempted without effect"}

    blocked = evaluate.execution(hardened(), took)
    never_worked = evaluate.execution(hardened(), failed)
    not_stopped = evaluate.execution(hardened(effect_status=0), took)

    assert blocked["answer"] == "blocked"
    assert blocked["basis"].startswith("with the change in place the effect check exited with status 1")
    assert never_worked["answer"] == "attempted without effect"
    assert not_stopped["answer"] == "took effect"


def test_a_change_that_was_not_put_in_place_proves_nothing() -> None:
    took = {"answer": "took effect"}
    unapplied = hardened(applied=False, steps=[step("defense", 9, status=1), step("revert", 14)])
    del unapplied["launcher_pid"]
    unprepared = hardened(prerequisites="not met", steps=[])
    del unprepared["defense"]["applied"]

    assert evaluate.execution(unapplied, took)["answer"] == "inconclusive"
    assert evaluate.execution(unapplied, took)["basis"] == "the hardening change could not be put in place"
    assert evaluate.execution(unprepared, took)["answer"] == "not attempted"


def test_a_test_that_ran_out_of_time_with_the_change_in_place_is_not_blocked() -> None:
    late = hardened()
    late["steps"][1]["timed_out"] = True

    assert evaluate.execution(late, {"answer": "took effect"})["answer"] == "inconclusive"


def measured(
    role, execution="took effect", visibility="telemetry only", rules=(), launcher_only=(), rule=None
) -> dict:
    seen = {
        "answer": visibility,
        "basis": "a reason",
        "window": ["2026-11-16 04:00:01.000", "2026-11-16 04:00:06.000"],
        "rules": list(rules),
        "launcher_only_rules": list(launcher_only),
    }
    done = {"answer": execution, "basis": "the effect check exited with status 1"}
    return {"role": role, "name": role, "rule": rule, "execution": done, "visibility": seen}


CLEAN = {
    "sensor_reported": True,
    "lost_events": 0,
    "bad_events": 0,
    "records": 5,
    "missing_records": 0,
    "repeated_records": 0,
    "sensor_starts": 1,
}
ENGINE = {
    "process_creation": {"rules": 122, "loaded": 122, "given": 900, "read": 900},
    "file_event": {"rules": 8, "loaded": 8, "given": 300, "read": 300},
}
PROBE = [{"CommandLine": "/usr/bin/true bluefire-lab-probe r1", "UtcTime": "2026-11-16 04:00:00.500"}]
CAUGHT = measured("canary", visibility="alert", rules=[{"id": "high-rule", "alert": True}], rule="high-rule")


def failed_controls(tests, lost=CLEAN, starts=PROBE, engine=ENGINE) -> list[str]:
    checks = evaluate.check_controls(RUN, tests, starts, lost, engine)
    return [check["name"] for check in checks if not check["passed"]]


def test_controls_pass_on_a_sound_run() -> None:
    assert failed_controls([CAUGHT, measured("control"), measured("test"), CAUGHT]) == []


def test_a_missed_canary_fails_the_run() -> None:
    missed = measured("canary", rules=[{"id": "medium-rule", "alert": False}], rule="high-rule")
    without_effect = {**CAUGHT, "execution": {"answer": "attempted without effect"}}

    assert failed_controls([CAUGHT, measured("control"), missed]) == ["canary"]
    assert failed_controls([CAUGHT, measured("control"), without_effect]) == ["canary"]
    assert failed_controls([CAUGHT, measured("control")]) == ["canary"]


def test_an_alert_on_the_harmless_command_fails_the_run() -> None:
    alert = measured("control", visibility="alert", rules=[{"id": "high-rule", "alert": True}])
    on_launcher = measured("control", launcher_only=[{"id": "high-rule", "alert": True}])

    assert failed_controls([CAUGHT, alert, CAUGHT]) == ["control"]
    assert failed_controls([CAUGHT, on_launcher, CAUGHT]) == ["control"]


def test_lost_events_a_missing_marker_or_an_unseen_probe_fail_the_run() -> None:
    tests = [CAUGHT, measured("control"), CAUGHT]
    unmarked = measured("test", visibility="inconclusive")
    del unmarked["visibility"]["window"]

    assert failed_controls(tests, lost={**CLEAN, "lost_events": 4}) == ["loss"]
    assert failed_controls(tests, lost={**CLEAN, "missing_records": 1}) == ["loss"]
    assert failed_controls(tests, lost={**CLEAN, "sensor_starts": 2}) == ["loss"]
    assert failed_controls(tests, lost={**CLEAN, "sensor_reported": False, "lost_events": None}) == ["loss"]
    assert failed_controls([*tests, unmarked]) == ["markers"]
    assert failed_controls(tests, starts=[]) == ["readiness"]


def test_a_repeated_record_or_a_missing_count_of_bad_events_fails_the_run() -> None:
    tests = [CAUGHT, measured("control"), CAUGHT]

    assert failed_controls(tests, lost={**CLEAN, "repeated_records": 1}) == ["loss"]
    assert failed_controls(tests, lost={**CLEAN, "bad_events": None}) == ["loss"]


def test_any_test_that_could_not_be_measured_fails_the_run() -> None:
    no_launcher = measured("test", visibility="inconclusive")  # its markers are there, its launcher not
    undecided = measured("hardened", execution="inconclusive")  # e.g. its change could not be put in place

    assert failed_controls([CAUGHT, measured("control"), no_launcher, CAUGHT]) == ["markers"]
    assert failed_controls([CAUGHT, measured("control"), undecided, CAUGHT]) == ["markers"]


def test_a_hardening_change_left_in_place_fails_the_run() -> None:
    removed = {
        **measured("hardened", execution="blocked"),
        "defense": {"title": "a", "applied": True, "reverted": True},
    }
    left = {**removed, "defense": {"title": "a", "applied": True, "reverted": False}}
    never_applied = {**removed, "defense": {"title": "a", "applied": False}}

    assert failed_controls([CAUGHT, measured("control"), removed, CAUGHT]) == []
    assert failed_controls([CAUGHT, measured("control"), left, CAUGHT]) == ["changes"]
    assert failed_controls([CAUGHT, measured("control"), never_applied, CAUGHT]) == []


def test_the_probe_must_be_seen_before_the_first_test() -> None:
    late = [{**PROBE[0], "UtcTime": "2026-11-16 04:00:02.000"}]

    assert failed_controls([CAUGHT, measured("control"), CAUGHT], starts=late) == ["readiness"]


def test_a_rule_the_engine_did_not_load_or_an_event_it_did_not_read_fails_the_run() -> None:
    tests = [CAUGHT, measured("control"), CAUGHT]
    skipped_rule = {**ENGINE, "file_event": {**ENGINE["file_event"], "loaded": 7}}
    unread = {**ENGINE, "file_event": {**ENGINE["file_event"], "read": 299}}
    no_events = {**ENGINE, "file_event": {**ENGINE["file_event"], "given": 0, "loaded": 0, "read": 0}}

    for engine in (skipped_rule, unread, no_events):
        assert failed_controls(tests, engine=engine) == ["engine"]


def test_the_engines_own_log_says_what_it_loaded_and_read() -> None:
    # The lines as Zircolite 4.7.1 wrote them in run 44015299571, with its markup.
    log = (
        "2026-11-17 04:15:10 INFO     [green]\\[✓][/] Converted [cyan]122[/] rules\n"
        "2026-11-17 04:15:10 INFO     [+] 122 rules loaded\n"
        "2026-11-17 04:15:10 INFO     [+] Total events processed: [magenta]1,295[/]\n"
    )

    assert evaluate.engine_counts(log) == (122, 1295)
    assert evaluate.engine_counts("") == (None, None)


def test_the_control_says_when_the_harmless_command_did_not_take_effect() -> None:
    idle = measured("control", execution="attempted without effect")

    checks = evaluate.check_controls(RUN, [CAUGHT, idle, CAUGHT], PROBE, CLEAN, ENGINE)

    assert [check["detail"] for check in checks if check["name"] == "control"] == [
        "the harmless command did not take effect: the effect check exited with status 1"
    ]
