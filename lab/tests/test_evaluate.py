"""The two answers and the controls, on events built by hand.

The events have the shape Sysmon for Linux gave in the sensor spike: the
executor's children carry no parent GUID and the id of the executor's thread as
parent, and a detached child has parent 1. They are constructed, not recorded.
"""

from __future__ import annotations

from pathlib import Path

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
        "origin": origin,
    }
    for name, level, origin in (
        ("high-rule", "high", "pinned"),
        ("medium-rule", "medium", "pinned"),
        ("critical-rule", "critical", "pinned"),
        ("lab-rule", "high", "lab"),
    )
}
# Rules of a rule set given as an input, under names of their own. One gives no level.
RULES["other:their-rule"] = {**RULES["high-rule"], "id": "their-rule", "level": "no level", "origin": "other"}
RULES["other:high-rule"] = {**RULES["high-rule"], "level": "low", "origin": "other"}


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
        "upstream_cleanup": True,
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


def see(test, events, matched=None, system=(), audit=(), rule_set=None):
    starts = [event for event in events if event["EventID"] == sysmon.PROCESS_START]
    edges = [evaluate.marker_time(starts, "r1", test["order"], edge) for edge in ("start", "end")]
    context = {
        "account": ACCOUNT,
        "known_sessions": {step["session"] for step in test["steps"]},
        "windows": {test["order"]: tuple(edges)},
        "system_commands": set(system),
        "audit_events": list(audit),
        "lookups": evaluate.lookups(list(audit)),
        "rule_set": rule_set,
    }
    return evaluate.visibility(test, events, starts, matched or {}, RULES, context)


def written(serial, session, second=5.1, pid="120") -> dict:
    """An auditd event: a write to a watched file, as auditd.events joins its records."""

    return {
        "event": f"1794893574.919:{serial}",
        "serial": str(serial),
        "time": f"2026-11-16 04:00:{second:06.3f}",
        "types": ["SYSCALL", "CWD", "PATH", "PATH", "PROCTITLE"],
        "call": {
            "syscall": "257",
            "ses": str(session),
            "pid": pid,
            "exe": "/usr/bin/dash",
            "key": "shell-start",
        },
        "names": {"SYSCALL": "openat", "UID": ACCOUNT},
        "paths": ["/home/bluefire-lab/.bashrc"],
        "command": "sh -c echo hi >> ~/.bashrc",
    }


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


def test_systemds_own_steps_are_not_part_of_a_test() -> None:
    helper = start(15, 5.9, 301, 1, "systemd-executor --deserialize 72", sysmon.NO_SESSION, user="root")
    # logind removing the runtime folder of an account an earlier test logged in as, 10 s later.
    removal = start(16, 5.95, 302, 1, "systemd-user-runtime-dir stop 1003", sysmon.NO_SESSION, user="root")
    # Setting one up, when the test itself logs in as an account, is the test's.
    setup = start(17, 5.96, 303, 1, "systemd-user-runtime-dir start 1004", sysmon.NO_SESSION, user="root")

    _, mine = see(a_test(user="root"), [*telemetry(), helper, removal, setup])

    assert records(mine) == [6, 7, 8, 12, 17]


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


def test_a_write_auditd_recorded_in_the_attack_session_is_the_tests_telemetry() -> None:
    events = [
        event for event in telemetry() if event["EventRecordID"] in ("1", "2", "3", "4", "5", "9", "10", "13")
    ]

    key = "audit 1794893574.919:178"
    others = [written(179, 55, pid="4242")]  # another step's write

    answer, mine = see(a_test(), events, {key: ["medium-rule"]}, audit=[written(178, 11), *others])

    assert answer["answer"] == "telemetry only"
    assert [(event["record"], event["kind"], event["detail"]) for event in mine] == [
        (key, "openat (auditd)", "/home/bluefire-lab/.bashrc by sh -c echo hi >> ~/.bashrc")
    ]
    assert [(rule["id"], rule["records"]) for rule in answer["rules"]] == [("medium-rule", [key])]


def test_an_auditd_event_counts_when_its_process_is_the_tests_and_not_the_drivers() -> None:
    events = [
        event
        for event in telemetry()
        if event["EventRecordID"] in ("1", "2", "3", "4", "5", "9", "10", "11", "13")
    ]
    # The kernel's record when the driver starts the step's session, and sudo's own record: process 100.
    shim = {**written(177, 11, pid="100"), "types": ["LOGIN", "SYSCALL", "PROCTITLE"], "paths": []}
    sudo = {**written(180, 11, pid="100"), "types": ["USER_CMD"], "paths": [], "command": ""}
    # A record the test's own process wrote itself, with no system call and no rule's key.
    added = {**written(181, 11), "types": ["ADD_USER"], "paths": [], "command": ""}
    added["call"] = {"pid": "120", "ses": "11", "op": "adding user", "id": "999", "res": "success"}
    added["names"] = {}
    # A write by what cron started for the test account, in a session of its own, inside the window.
    cron = written(182, 77, second=5.75, pid="200")

    answer, mine = see(a_test(), events, audit=[shim, sudo, added, cron])

    assert [
        (event["record"], event["kind"], event["why"]) for event in mine if event["kind"].endswith("(auditd)")
    ] == [
        ("audit 1794893574.919:181", "ADD_USER (auditd)", "session"),
        ("audit 1794893574.919:182", "openat (auditd)", "window"),
    ]
    assert [event["detail"] for event in mine if str(event["record"]).endswith(":181")] == [
        "op=adding user res=success"
    ]


def test_auditds_record_of_the_launchers_start_is_the_launcher_line_not_telemetry() -> None:
    events = [
        event for event in telemetry() if event["EventRecordID"] in ("1", "2", "3", "4", "5", "9", "10", "13")
    ]
    # execve of the launcher (process 120), whose arguments are the whole test, and of its child id.
    launched = {**written(184, 11, second=5.0), "types": ["SYSCALL", "EXECVE", "CWD", "PATH", "PATH"]}
    child = {**written(185, 11, second=5.01, pid="121"), "types": ["SYSCALL", "EXECVE", "CWD", "PATH"]}
    with_child = [*events, start(7, 5.01, 121, 120, "id", 11, parent_known=True)]
    matched = {"audit 1794893574.919:184": ["high-rule"]}

    # bash -c "sysctl ...": the shell becomes the one command it was given, in the same process.
    became = {**written(186, 11, second=5.002), "types": ["SYSCALL", "EXECVE", "CWD", "PATH", "PATH"]}

    alone, nothing = see(a_test(), events, matched, audit=[launched])
    answer, mine = see(a_test(), with_child, matched, audit=[launched, child])
    _, same_process = see(a_test(), events, {**matched, "audit 1794893574.919:186": ["high-rule"]},
                          audit=[became, launched])  # fmt: skip

    assert (alone["answer"], nothing) == ("no telemetry", [])
    assert [(rule["id"], rule["records"]) for rule in alone["launcher_only_rules"]] == [
        ("high-rule", ["audit 1794893574.919:184"])
    ]
    assert answer["answer"] == "telemetry only"
    assert "audit 1794893574.919:185" in [event["record"] for event in mine]
    assert "audit 1794893574.919:184" not in [event["record"] for event in mine]
    assert [event["record"] for event in same_process] == ["audit 1794893574.919:186"]


def test_the_launchers_start_is_its_own_first_and_compared_by_number() -> None:
    events = [
        event for event in telemetry() if event["EventRecordID"] in ("1", "2", "3", "4", "5", "9", "10", "13")
    ]
    with_child = [*events, start(7, 5.01, 121, 120, "id", 11, parent_known=True)]
    execve = ["SYSCALL", "EXECVE", "CWD", "PATH"]
    launched = {**written(184, 11, second=5.0), "types": execve}
    # The child's start, recorded a moment before the launcher's: still not the launcher's.
    earlier = {**written(187, 11, second=4.999, pid="121"), "types": execve}
    # The same millisecond, where the serials cross a power of ten.
    first = {**written(9999, 11, second=5.0), "types": execve}
    became = {**written(10000, 11, second=5.0), "types": execve}

    _, mine = see(a_test(), with_child, audit=[earlier, launched])
    _, tie = see(a_test(), events, audit=[became, first])

    assert [event["record"] for event in mine if str(event["record"]).startswith("audit")] == [
        "audit 1794893574.919:187"
    ]
    assert [event["record"] for event in tie] == ["audit 1794893574.919:10000"]


def test_a_search_of_the_path_is_not_telemetry_but_a_start_the_kernel_refused_is() -> None:
    events = [
        event for event in telemetry() if event["EventRecordID"] in ("1", "2", "3", "4", "5", "9", "10", "13")
    ]
    launched = {**written(184, 11, second=5.0), "types": ["SYSCALL", "EXECVE", "CWD", "PATH"]}

    def refused(serial: int, error: str, path: str, pid: str = "125", parent: str = "120") -> dict:
        # In a fork that never started a program, so Sysmon saw no start of it, as with
        # /tmp/crond under noexec in run 44063265542 (process 11981, forked by the launcher).
        event = {
            **written(serial, 11, second=5.002, pid=pid),
            "types": ["SYSCALL", "CWD", "PATH", "PROCTITLE"],
        }
        event["call"] = {**event["call"], "ppid": parent, "syscall": "59", "success": "no", "exit": error}
        event["names"] = {**event["names"], "SYSCALL": "execve"}
        event["paths"] = [path]
        return event

    audit = [
        launched,
        # A shell trying each folder of its search path for id (ENOENT): a lookup.
        refused(186, "-2", "/usr/local/sbin/id"),
        refused(187, "-2", "/usr/local/bin/id"),
        # One start of a file that does not exist, as a planted job's missing payload: an action.
        refused(188, "-2", "/tmp/evil.sh", pid="126"),
        # /tmp mounted noexec (EACCES), and the same in a fork of the executor, not the test's.
        refused(189, "-13", "/tmp/crond", pid="127"),
        refused(190, "-13", "/tmp/crond", pid="128", parent="101"),
    ]
    _, mine = see(a_test(), events, audit=audit)

    assert [event["record"] for event in mine] == ["audit 1794893574.919:188", "audit 1794893574.919:189"]
    # Named by the file it tried to start, not by the shell's command line the fork still holds.
    assert mine[1]["detail"] == "the kernel refused to start /tmp/crond (exit -13)"
    assert mine[1]["fields"]["command"] == ""


def test_sudos_record_of_a_command_the_test_ran_shows_the_command() -> None:
    events = [
        event for event in telemetry() if event["EventRecordID"] in ("1", "2", "3", "4", "5", "9", "10", "13")
    ]
    ran = {**written(183, 11), "types": ["USER_CMD"], "paths": [], "command": ""}
    command = b"chmod u+xs /tmp/x".hex().upper()  # as sudo writes it
    ran["call"] = {"pid": "120", "ses": "11", "cmd": command, "res": "success"}
    ran["names"] = {}

    _, mine = see(a_test(), events, audit=[ran])

    assert [event["detail"] for event in mine] == ["cmd=chmod u+xs /tmp/x res=success"]


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


def test_an_effect_that_was_there_before_the_test_is_not_the_tests_doing() -> None:
    absent = a_test(steps=[step("effect-before", 9, status=1), step("attack", 11), step("effect", 13)])
    present = a_test(steps=[step("effect-before", 9, status=0), step("attack", 11), step("effect", 13)])

    assert evaluate.execution(absent)["answer"] == "took effect"
    assert evaluate.execution(present)["answer"] == "inconclusive"
    assert "before the test ran" in evaluate.execution(present)["basis"]


def test_a_cleanup_held_when_what_the_test_did_is_no_longer_found_after_it() -> None:
    def after(status, **changes) -> dict:
        steps = [step("attack", 11), step("effect", 13), step("cleanup", 14), step("leftover", 15, status)]
        return a_test(steps=steps, leftover="test -e /tmp/x", **changes)

    held, left = evaluate.cleanup(after(1)), evaluate.cleanup(after(0))
    no_cleanup_upstream = evaluate.cleanup(after(0, upstream_cleanup=False))
    prints_only = a_test(steps=[step("attack", 11), step("cleanup", 14)])
    late = after(1)
    late["steps"][2]["timed_out"] = True
    unchecked = a_test(steps=[step("attack", 11), step("cleanup", 14)], leftover="test -e /tmp/x")

    assert held["answer"] == "held"
    assert (left["answer"], left["check"]["command"]) == ("left behind", "test -e /tmp/x")
    assert no_cleanup_upstream["basis"].endswith("the test has no cleanup command upstream")
    assert evaluate.cleanup(prints_only)["answer"] == "nothing to check"
    assert evaluate.cleanup(late)["answer"] == "not checked"
    assert evaluate.cleanup(unchecked)["answer"] == "not checked"
    assert evaluate.cleanup(a_test(prerequisites="not met", steps=[])) is None
    from_an_earlier_version = after(1)
    del from_an_earlier_version["upstream_cleanup"]
    assert evaluate.cleanup(from_an_earlier_version) is None


def test_a_cleanup_that_could_not_be_checked_fails_the_run_and_one_left_behind_is_named() -> None:
    tests = [CAUGHT, measured("control", cleanup="nothing to check"), CAUGHT]
    left = measured("test", cleanup="left behind")

    checks = evaluate.check_controls(RUN, [*tests, left], PROBE, CLEAN, ENGINE)
    detail = next(check["detail"] for check in checks if check["name"] == "cleanup")

    assert failed_controls([*tests, left]) == []
    assert "2 held, 1 leave nothing the list names, and 1 left what they did behind: T1 test" in detail
    assert failed_controls([*tests, measured("test", cleanup="not checked")]) == ["cleanup"]
    unrecorded = [{key: value for key, value in test.items() if key != "cleanup"} for test in tests]
    assert failed_controls(unrecorded) == ["cleanup"]


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
    role,
    execution="took effect",
    visibility="telemetry only",
    rules=(),
    launcher_only=(),
    rule=None,
    cleanup="held",
) -> dict:
    seen = {
        "answer": visibility,
        "basis": "a reason",
        "window": ["2026-11-16 04:00:01.000", "2026-11-16 04:00:06.000"],
        "rules": list(rules),
        "launcher_only_rules": list(launcher_only),
    }
    done = {"answer": execution, "basis": "the effect check exited with status 1"}
    undone = {"answer": cleanup, "basis": "after the cleanup the check exited with status 1"}
    return {"role": role, "technique": "T1", "name": role, "rule": rule, "execution": done,
            "visibility": seen, "cleanup": undone}  # fmt: skip


CLEAN = {
    "sensor_reported": True,
    "lost_events": 0,
    "bad_events": 0,
    "records": 5,
    "missing_records": 0,
    "repeated_records": 0,
    "sensor_starts": 1,
}
ENGINE = [
    {"category": "process_creation", "origin": "pinned", "kind": "process start",
     "rules": 122, "loaded": 122, "given": 900, "read": 900},
    {"category": "file_event", "origin": "pinned", "kind": "file created",
     "rules": 8, "loaded": 8, "given": 300, "read": 300},
    {"category": "process_creation", "origin": "lab", "kind": "process start",
     "rules": 4, "loaded": 4, "given": 900, "read": 900},
    # The lab has no rule for network connections, so the engine had nothing to evaluate there.
    {"category": "network_connection", "origin": "lab", "kind": "network connection",
     "rules": 0, "loaded": 0, "given": 50, "read": 0},
]  # fmt: skip
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


def test_the_labs_rules_give_a_second_answer_and_never_change_the_first() -> None:
    answer, _ = see(a_test(), telemetry(), {"7": ["medium-rule", "lab-rule"]})
    test = {"visibility": answer}

    assert answer["answer"] == "telemetry only"
    assert [rule["id"] for rule in answer["rules"]] == ["medium-rule"]
    assert [rule["id"] for rule in answer["with_lab_rules"]["rules"]] == ["lab-rule"]
    evaluate.second_answers([test], [{"id": "lab-rule", "accepted": True}])
    assert answer["with_lab_rules"]["answer"] == "alert"
    evaluate.second_answers([test], [{"id": "lab-rule", "accepted": False}])
    assert answer["with_lab_rules"]["answer"] == "telemetry only"
    assert answer["with_lab_rules"]["rules"][0]["accepted"] is False
    assert answer["answer"] == "telemetry only"


def test_ordinary_activity_is_the_baseline_and_what_ran_in_no_session_outside_the_tests() -> None:
    run_record = {
        "tests": [
            {
                "role": "baseline",
                "steps": [step("baseline-root", 30), step("marker-end", 31)],
                "parts": [
                    {
                        "name": "root",
                        "what": "ordinary work",
                        "author": "the lab",
                        "session": "30",
                        "exit_status": 0,
                    }
                ],
            }
        ]
    }
    events = [
        start(1, 0.5, 400, 1, "useradd --system bluefire-lab-service", 30, user="root"),  # baseline
        start(2, 0.6, 401, 1, "true marker", 31, user="root"),  # a marker step: the lab's own
        start(3, 0.7, 402, 1, "apt-get update", sysmon.NO_SESSION, user="root"),  # the system, outside
        start(4, 3.0, 403, 1, "touch /tmp/marker", sysmon.NO_SESSION, user="root"),  # the system, inside
        start(5, 3.1, 404, 120, "id", 11),  # a test's
    ]
    window = [("2026-11-16 04:00:01.000", "2026-11-16 04:00:06.000")]
    matched = {"1": ["lab-rule"], "3": ["medium-rule"], "4": ["lab-rule"], "5": ["lab-rule"]}

    ordinary = evaluate.ordinary_activity(run_record, events, events, matched, RULES, window)

    assert (ordinary["baseline_events"], ordinary["system_events"]) == (1, 1)
    assert ordinary["parts"] == [
        {"name": "root", "what": "ordinary work", "author": "the lab", "exit_status": 0, "events": 1}
    ]
    assert ordinary["rules"] == {"lab-rule": [1], "medium-rule": [3]}
    assert [(rule["id"], rule["events"]) for rule in ordinary["pinned_rules"]] == [("medium-rule", 1)]


def test_ordinary_activity_leaves_out_a_failed_lookup_as_a_tests_events_do() -> None:
    run_record = {"tests": [{"role": "baseline", "steps": [step("baseline-root", 30)]}]}

    def start_of(serial: int, error: str, path: str, pid: str = "120") -> dict:
        event = {**written(serial, 30, second=0.5, pid=pid), "types": ["SYSCALL", "CWD", "PATH", "PROCTITLE"]}
        event["call"] = {**event["call"], "syscall": "59", "success": "no", "exit": error}
        event["names"] = {**event["names"], "SYSCALL": "execve"}
        event["paths"] = [path]
        return event

    # A baseline shell trying two folders of its search path (ENOENT), a start refused (EACCES),
    # and one start of a file that does not exist (ENOENT, no search), which is an action.
    audit = [
        start_of(299, "-2", "/usr/local/sbin/truncate"),
        start_of(300, "-2", "/usr/local/bin/truncate"),
        start_of(301, "-13", "/tmp/ordinary"),
        start_of(302, "-2", "/tmp/missing", pid="121"),
    ]
    matched = {f"audit {event['event']}": ["lab-rule"] for event in audit}

    ordinary = evaluate.ordinary_activity(run_record, [], [], matched, RULES, [], audit)

    assert ordinary["baseline_events"] == 2
    assert ordinary["rules"] == {"lab-rule": ["audit 1794893574.919:301", "audit 1794893574.919:302"]}


def judged(
    test_rules=("lab-rule",),
    variant_rules=("lab-rule",),
    variant_took=True,
    noise=None,
    sibling=False,
    parts=(),
) -> dict:
    def result(order, role, rules, answer="took effect", **extra) -> dict:
        lab = [{**RULES[rule_id], "alert": True} for rule_id in rules]
        seen = {
            "answer": "telemetry only",
            "with_lab_rules": {"answer": "alert" if lab else "telemetry only", "rules": lab},
        }
        return {"order": order, "role": role, "technique": "T1", "guid": "g", "name": "a test",
                "execution": {"answer": answer}, "visibility": seen, **extra}  # fmt: skip

    tests = [result(3, "test", test_rules)]
    if sibling:  # a second published procedure the rule alerts on, which ran with its defaults only
        tests.append(result(4, "test", test_rules, guid="g2", name="a sibling."))
    if variant_rules is not None:
        answer = "took effect" if variant_took else "attempted without effect"
        tests.append(result(9, "variant", variant_rules, answer, compared_with=3, args={"name": "other"}))
    ordinary = {"rules": noise or {}, "parts": list(parts)}
    return evaluate.judge_lab_rules({"lab-rule": RULES["lab-rule"]}, tests, ordinary)[0]


def test_a_lab_rule_is_accepted_only_when_it_holds_on_a_variant_and_stays_quiet_on_ordinary_work() -> None:
    accepted = judged()

    assert accepted["accepted"] is True
    assert accepted["variants"] == [
        {"order": 9, "technique": "T1", "name": "a test", "compared_with": 3, "args": {"name": "other"},
         "took_effect": True, "alerted": True}
    ]  # fmt: skip
    assert judged(test_rules=())["reason"] == "it matched no event of a test"
    assert judged(noise={"lab-rule": [40, 41]})["reason"] == "it matched 2 events of ordinary activity"
    assert judged(variant_rules=())["reason"] == "it missed 1 of 1 runs with changed input arguments"
    assert judged(variant_rules=None)["accepted"] is False
    # A rule is not judged quiet on ordinary activity that did not happen.
    ran = {"name": "role", "exit_status": 0}
    broke = {"name": "packages", "exit_status": 100}
    assert judged(parts=[ran])["accepted"] is True
    assert judged(parts=[ran, broke])["reason"].endswith("not judged on it: packages (exit status 100)")
    assert judged(variant_took=False)["accepted"] is False


def test_every_procedure_a_lab_rule_alerts_on_needs_a_run_with_changed_input_arguments() -> None:
    verdict = judged(sibling=True)

    assert verdict["accepted"] is False
    assert verdict["procedures"] == 2
    assert verdict["reason"] == (
        "not every procedure it alerts on ran again with changed input arguments and took effect: T1 a sibling"
    )


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


def test_auditd_must_record_its_probe_in_time_and_lose_no_record() -> None:
    tests = [CAUGHT, measured("control"), CAUGHT]
    sound = {"probe_time": "2026-11-16 04:00:00.600", "lost_before": 0, "lost_after": 0}

    def failed(audit: dict) -> list[str]:
        checks = evaluate.check_controls(RUN, tests, PROBE, CLEAN, ENGINE, audit)
        return [check["name"] for check in checks if not check["passed"]]

    assert failed(sound) == []
    assert failed({**sound, "probe_time": None}) == ["readiness"]
    assert failed({**sound, "probe_time": "2026-11-16 04:00:02.000"}) == ["readiness"]
    assert failed({**sound, "lost_after": 3}) == ["loss"]
    assert failed({**sound, "lost_before": None}) == ["loss"]
    # auditd rotated its log during the run, as in run 44050159740: the export holds only the last part.
    assert failed({**sound, "rotated": ["/var/log/audit/audit.log.1"]}) == ["loss"]
    # And what the driver recorded about the run reaches the control.
    recorded = {"probe": "/var/tmp/p", "before": {"lost": "0"}, "after": {"lost": "0"}, "rotated": ["x.1"]}
    probe = {**written(190, 11, second=0.6), "paths": ["/var/tmp/p"]}
    assert evaluate.audit_facts(recorded, [probe]) == {
        "probe_time": "2026-11-16 04:00:00.600",
        "lost_before": 0,
        "lost_after": 0,
        "rotated": ["x.1"],
    }


def test_a_rule_the_engine_did_not_load_or_an_event_it_did_not_read_fails_the_run() -> None:
    tests = [CAUGHT, measured("control"), CAUGHT]

    def changed(index: int, **values) -> list[dict]:
        return [{**counts, **values} if place == index else counts for place, counts in enumerate(ENGINE)]

    skipped_rule = changed(1, loaded=7)
    unread = changed(1, read=299)
    no_events = changed(1, given=0, loaded=0, read=0)
    skipped_lab_rule = changed(2, loaded=3)

    for engine in (skipped_rule, unread, no_events, skipped_lab_rule):
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


def test_another_rule_set_has_a_column_of_its_own_and_changes_no_other_answer() -> None:
    given = {"source": "someone/rules@" + "a" * 40}
    # Their rule without a level matched the test's "id"; their copy of a pinned rule, which
    # they give the level low, matched it too, and only their rule matched the launcher.
    matched = {"7": ["other:their-rule", "other:high-rule"], "5": ["other:their-rule"]}

    seen, _ = see(a_test(), telemetry(), matched, rule_set=given)
    without, _ = see(a_test(), telemetry(), matched)
    quiet, _ = see(
        a_test(), telemetry(), {"7": ["other:high-rule"], "5": ["other:their-rule"]}, rule_set=given
    )

    assert seen["answer"] == "telemetry only" and seen["rules"] == [] and seen["launcher_only_rules"] == []
    assert seen["other_rules"]["answer"] == "alert"  # a match of a rule without a level counts as an alert
    assert [(rule["id"], rule["level"], rule["alert"]) for rule in seen["other_rules"]["rules"]] == [
        ("high-rule", "low", False),
        ("their-rule", "no level", True),
    ]
    assert "other_rules" not in without
    assert quiet["other_rules"]["answer"] == "telemetry only"
    assert [rule["id"] for rule in quiet["other_rules"]["launcher_only_rules"]] == ["their-rule"]


def test_a_rule_set_is_sorted_by_the_kind_of_event_and_what_is_left_out_says_why(tmp_path: Path) -> None:
    files = tmp_path / "rule-set" / "files"
    (files / "linux").mkdir(parents=True)
    (tmp_path / "rule-set" / "SOURCE").write_text("someone/rules@" + "a" * 40 + ":rules\n")
    (tmp_path / "rule-set" / "LICENSE").write_text("a licence\n")

    def rule(name: str, logsource: str, extra: str = "id: 1\n") -> None:
        (files / "linux" / name).write_text(f"title: {name}\n{extra}logsource:\n{logsource}detection: {{}}\n")

    rule("process.yml", "  product: linux\n  category: process_creation\n", "id: 1\nlevel: high\n")
    rule("audit.yaml", "  product: Linux\n  service: auditd\n", "id: 2\n")  # no level
    rule("windows.yml", "  product: windows\n  category: process_creation\n")
    rule("syslog.yml", "  product: linux\n  service: syslog\n")
    rule("no-id.yml", "  product: linux\n  category: file_event\n", "")
    (files / "collection.yml").write_text("action: global\n---\ntitle: a\n---\ntitle: b\n")
    (files / "broken.yml").write_text("title: [unclosed\n")
    (files / "README.md").write_text("not a rule\n")

    found = evaluate.sort_rule_set(tmp_path)

    assert (found["files"], found["sorted"], found["no_level"]) == (7, 2, 1)
    assert found["license_files"] == ["LICENSE"]
    assert sorted(found["paths"].items()) == [
        ("linux/auditd/0001.yml", "linux/audit.yaml"),
        ("linux/process_creation/0002.yml", "linux/process.yml"),
    ]
    assert (tmp_path / "engine" / "rule-set" / "linux" / "auditd" / "0001.yml").is_file()
    assert {item["reason"]: item["rules"] for item in found["left_out"]} == {
        "for the product windows": 1,
        "for a Linux log source the lab's sensors do not provide: syslog": 1,
        "no id, by which the rule engine names a rule that matched": 1,
        "not one Sigma rule with a log source and a detection": 1,
        "not readable as YAML": 1,
    }
    index = evaluate.rule_index(tmp_path / "engine" / "rule-set" / "linux", "other")
    assert (index["other:1"]["level"], index["other:2"]["level"]) == ("high", evaluate.NO_LEVEL)
    assert index["other:2"]["file"] == "linux/auditd/0001.yml"


def test_what_the_engine_made_of_another_rule_set_does_not_fail_the_run() -> None:
    theirs = {"category": "process_creation", "origin": "other", "kind": "process start",
              "rules": 30, "loaded": 22, "given": 900, "read": 900}  # fmt: skip

    assert failed_controls([CAUGHT, measured("control"), CAUGHT], engine=[*ENGINE, theirs]) == []
    assert failed_controls(
        [CAUGHT, measured("control"), CAUGHT], engine=[{**theirs, "origin": "pinned"}]
    ) == ["engine"]
