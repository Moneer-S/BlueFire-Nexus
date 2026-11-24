"""The comparison of two recordings, on small recordings built by hand, read from what the command writes."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from bluefire_lab.__main__ import main

ANSWER = {"alerted": "alert", "seen": "telemetry only", "unseen": "no telemetry"}
ACCEPTED = "The run accepted 1 of the 2 rules written in this repository. A match of a rule it did not accept is not in the recording."
RULE = {"id": "rule-ours", "title": "Private Key Files Searched With Find", "level": "high", "origin": "lab"}


def a_step(
    step_id: str, order: int, role: str = "test", outcome: str = "seen", guid: str = "", **extra
) -> dict:
    """A step as a recording holds it: its outcome by the published rules, and the same with the lab's."""

    return {
        "id": step_id,
        "order": order,
        "role": role,
        "title": f"Test {guid or step_id}",
        "technique": {"id": "T1552.004"},
        "test": {"project": "Atomic Red Team", "guid": guid or step_id, "executor": "sh", "elevated": False},
        "host": "target",
        "happened": {"answer": "took effect", "basis": "the effect check exited with status 0"},
        "visibility": {
            "answer": ANSWER[outcome],
            "basis": "what the answer rests on",
            "events": 0 if outcome == "unseen" else 2,
        },
        "outcome": outcome,
        "outcome_with_lab_rules": outcome,
        **extra,
    }


def a_recording(*steps: dict, setup: bool = True) -> dict:
    """A test list on one host, with two sensors and two rule sets, each with its digest."""

    source = {
        "engine": "bluefire-lab",
        "environment": "GitHub-hosted runner",
        "started": "2026-11-16T04:00:00Z",
        "finished": "2026-11-16T04:30:00Z",
        "commit": "c" * 40,
        "run_url": "https://example.org/runs/1",
        "tools": [{"name": "Zircolite", "version": "4.7.1", "role": "rule engine"}],
    }
    if setup:
        source["setup"] = {
            "atomic_commit": "a" * 40,
            "images": {"target": "ubuntu24 20261116.133.1"},
            "kernels": {"target": "7.0.0-1014-aws"},
            "sensors": {"sysmon": "1" * 64, "auditd": "2" * 64},
        }
    return {
        "schema": "bluefire.recording/1",
        "id": "r1",
        "title": "A few published tests on one Linux host",
        "kind": "test list",
        "source": source,
        "network": {
            "hosts": [
                {
                    "id": "target",
                    "name": "GitHub-hosted runner",
                    "role": "Linux host under test",
                    "kind": "host",
                }
            ],
            "sensors": [
                {
                    "id": "sysmon",
                    "name": "Sysmon for Linux 1.6.0",
                    "host": "target",
                    "records": "process starts",
                },
                {"id": "auditd", "name": "auditd 3.1.2", "host": "target", "records": "program starts"},
            ],
            "detectors": [
                {
                    "id": "pinned",
                    "name": "Published Sigma rules",
                    "rules": 188,
                    "when": "after the run",
                    "digest": "3" * 64,
                },
                {
                    "id": "lab",
                    "name": "Rules written in this repository",
                    "rules": 2,
                    "when": "after the run",
                    "digest": "4" * 64,
                    "verdicts": [
                        {"rule": "rule-ours", "title": RULE["title"], "digest": "7" * 64, "accepted": False}
                    ],
                },
            ],
        },
        "attacker": {"kind": "scripted", "description": "Invoke-AtomicRedTeam ran each test.", "goal": None},
        "steps": list(steps),
        "events": [],
        "alerts": [],
        "ordinary": {"events": 940, "matches": []},
        "score": {
            "steps": len(steps),
            "took_effect": len(steps),
            "alerted": 0,
            "seen": len(steps),
            "unseen": 0,
            "stopped": 0,
            "false_alerts": 2,
        },
        "notes": [ACCEPTED],
    }


def three_steps() -> list[dict]:
    return [
        a_step("test:46959285", 4, guid="46959285"),
        a_step("test:7c247dc7", 5, guid="7c247dc7"),
        a_step("variant:46959285:5e4f5f", 6, "variant", guid="46959285"),
    ]


def compared(folder: Path, before: dict, after: dict, *arguments: str) -> tuple[dict, str]:
    """Run the command on the two recordings and return what it wrote: delta.json and delta.md."""

    for name, recording in (("before.json", before), ("after.json", after)):
        (folder / name).write_text(json.dumps(recording), encoding="utf-8")
    out = folder / "delta"
    assert (
        main(
            [
                "compare",
                str(folder / "before.json"),
                str(folder / "after.json"),
                "--out",
                str(out),
                *arguments,
            ]
        )
        == 0
    )
    return json.loads((out / "delta.json").read_text(encoding="utf-8")), (out / "delta.md").read_text(
        encoding="utf-8"
    )


def test_a_recording_against_itself_says_nothing_changed(tmp_path: Path) -> None:
    recording = a_recording(*three_steps())

    delta, text = compared(tmp_path, recording, recording)

    assert delta["schema"] == "bluefire.delta/1"
    assert delta["before"]["sha256"] == delta["after"]["sha256"]
    assert (delta["comparable"], delta["refused_because"], delta["differences"]) == (True, [], [])
    # Every result is counted, also one no step has.
    assert delta["counts"] == {
        "paired": 3,
        "same": 3,
        "better": 0,
        "worse": 0,
        "changed": 0,
        "not attributable": 0,
        "without cause": 0,
        "no verdict": 0,
        "by_mark": 0,
        "new": 0,
        "gone": 0,
    }
    assert {step["verdict"] for step in delta["steps"]} == {"no change"}
    assert "**Comparable.** The same steps, made with the same setup." in text
    assert "The lab's code" not in text
    assert "3 steps paired by id: 3 same. 0 new and 0 gone, listed and not counted." in text
    assert "No race: the rules ran after each run, so there is no race to compare." in text
    assert "All of this rests on one pair of runs." in text


def a_lab_rule_change(before: dict, step: int = 0, edited: bool = True) -> dict:
    """The after recording of a change of the lab's rules: the rule now accepted, and matching one step.
    edited says whether the rule's own file changed, or only another file of the lab's rules."""

    after = copy.deepcopy(before)
    lab = after["network"]["detectors"][1]
    lab["digest"] = "5" * 64
    lab["verdicts"][0].update(accepted=True, digest="8" * 64 if edited else "7" * 64)
    after["steps"][step]["outcome_with_lab_rules"] = "alerted"
    after["alerts"] = [
        {"id": "alert-1", "step": after["steps"][step]["id"], "rule": RULE, "counts": True, "events": []}
    ]
    return after


def test_a_declared_rule_change_names_the_step_it_changed_with_its_price(tmp_path: Path) -> None:
    before = a_recording(*three_steps())
    after = a_lab_rule_change(before)

    delta, text = compared(tmp_path, before, after, "--change", "detectors:lab")

    assert delta["comparable"] and delta["declared_change"] == "detectors:lab"
    assert delta["judged"] == ["outcome_with_lab_rules"]
    assert delta["control"] == {
        "fields": ["happened", "recorded", "outcome"],
        "same": 3,
        "of": 3,
        "varied": [],
    }
    changed = [step for step in delta["steps"] if step["result"] != "same"]
    assert [(step["id"], step["result"]) for step in changed] == [("test:46959285", "better")]
    assert changed[0]["procedures"] == {"better": 1, "of": 2}
    assert changed[0]["underneath"] == ["matches now: high: Private Key Files Searched With Find"]
    # The gain and its price on one line: the single host leaves the price out of the recording, and says so,
    # with both recordings' notes on the rules they accepted.
    assert (
        "| `test:46959285` | T1552.004 Test 46959285 | took effect | recorded | seen | seen to alerted | better: "
        "seen to alerted with the lab's rules, on 1 of the 2 published procedures of T1552.004 in the list; price "
        "not counted: the lab's rules that matched ordinary activity are left out of the recording before it is "
        f"written (before: {ACCEPTED.rstrip('.')}; after: {ACCEPTED.rstrip('.')}); one pair of runs (matches now: "
        "high: Private Key Files Searched With Find) |"
    ) in text
    assert "Declared change: the rules of detector `lab`." in text
    assert "| the rules of detector `lab` (declared) | 444444444444 | 555555555555 |" in text
    assert (
        "The control, what happened, whether a sensor recorded the step and the outcome by the published rules, "
        "which the declared change" in text
    )


def test_an_unchanged_lab_rule_accepted_by_this_run_only_is_not_the_declared_change(tmp_path: Path) -> None:
    # Another file of the lab's rules changed; this rule's file did not, and only its acceptance moved.
    before = a_recording(*three_steps())
    after = a_lab_rule_change(before, edited=False)

    delta, _ = compared(tmp_path, before, after, "--change", "detectors:lab")

    step = delta["steps"][0]
    assert step["result"] == "not attributable" and "price" not in step
    assert step["verdict"] == (
        "not attributable: the lab's rule `Private Key Files Searched With Find` is the same in both runs "
        "(before not accepted; after accepted), so this is run variation; one pair of runs"
    )
    assert delta["unexplained"] == ["test:46959285"]


def test_a_rule_change_gets_no_credit_for_a_step_the_sensors_missed_before(tmp_path: Path) -> None:
    before = a_recording(*three_steps())
    before["steps"][1] = a_step("test:7c247dc7", 5, outcome="unseen", guid="7c247dc7")
    after = copy.deepcopy(before)
    after["network"]["detectors"][0]["digest"] = "5" * 64
    after["steps"][1] = a_step("test:7c247dc7", 5, outcome="alerted", guid="7c247dc7")

    delta, _ = compared(tmp_path, before, after, "--change", "detectors:pinned")

    step = delta["steps"][1]
    assert (step["result"], step["changed"]) == (
        "not attributable",
        ["recorded", "outcome", "outcome_with_lab_rules"],
    )
    assert "recorded now: 2 events" in step["underneath"]


def test_the_published_rules_pin_is_part_of_their_change_and_other_versions_still_refuse(
    tmp_path: Path,
) -> None:
    before = a_recording(*three_steps())
    before["source"]["tools"] += [
        {"name": "SigmaHQ/sigma", "version": "b" * 40, "role": "rules"},
        {"name": "auditd", "version": "3.1.2", "role": "sensor"},
    ]
    after = copy.deepcopy(before)
    after["source"]["tools"][1]["version"] = "e" * 40
    after["network"]["detectors"][0]["digest"] = "5" * 64
    after["steps"][1].update(outcome="alerted", outcome_with_lab_rules="alerted")

    delta, text = compared(tmp_path, before, after, "--change", "detectors:pinned")

    assert delta["comparable"] and delta["refused_because"] == []
    assert [(row["what"], row.get("declared")) for row in delta["differences"]] == [
        ("detectors:pinned", True),
        ("tools:SigmaHQ/sigma", True),
    ]
    assert delta["steps"][1]["result"] == "better"
    assert "| the version of `SigmaHQ/sigma` (part of the declared change) | " in text

    # The rule engine is not the published rules: its version refuses.
    engine = copy.deepcopy(after)
    engine["source"]["tools"][0]["version"] = "4.8.0"
    delta, _ = compared(tmp_path, before, engine, "--change", "detectors:pinned")
    assert delta["refused_because"] == [
        "also differed: the version of `Zircolite` (4.7.1 before, 4.8.0 after)"
    ]

    # A sensor's program is not its settings: its version refuses a declared change of its settings.
    sensor = copy.deepcopy(before)
    sensor["source"]["setup"]["sensors"]["auditd"] = "6" * 64
    sensor["source"]["tools"][2]["version"] = "3.1.3"
    delta, _ = compared(tmp_path, before, sensor, "--change", "sensors:auditd")
    assert delta["refused_because"] == ["also differed: the version of `auditd` (3.1.2 before, 3.1.3 after)"]


def test_an_unchanged_lab_rule_that_matched_in_one_run_only_is_credited_to_a_sensor_change_only(
    tmp_path: Path,
) -> None:
    # The lab's rules are the same files in both runs; one of them was accepted by the after run only,
    # and matched a step whose outcome by the published rules stayed seen.
    before = a_recording(*three_steps())
    moved = a_lab_rule_change(before, edited=False)
    moved["network"]["detectors"][1]["digest"] = "4" * 64
    published, sensor = copy.deepcopy(moved), copy.deepcopy(moved)
    published["network"]["detectors"][0]["digest"] = "5" * 64
    sensor["source"]["setup"]["sensors"]["auditd"] = "6" * 64

    delta, _ = compared(tmp_path, before, published, "--change", "detectors:pinned")

    step = delta["steps"][0]
    assert (step["result"], step["changed"]) == ("not attributable", ["outcome_with_lab_rules"])
    assert step["verdict"] == (
        "not attributable: the lab's rule `Private Key Files Searched With Find` matched it in one run only, "
        "and a change of the published rules cannot make a rule of the lab's own match, so this is run "
        "variation; one pair of runs"
    )
    assert delta["unexplained"] == ["test:46959285"]

    # A sensor's new telemetry can make an unchanged rule match: that is the sensor change's effect.
    delta, _ = compared(tmp_path, before, sensor, "--change", "sensors:auditd")

    assert delta["steps"][0]["result"] == "better"


def test_a_sensor_change_is_judged_on_whether_the_step_was_recorded(tmp_path: Path) -> None:
    before = a_recording(*three_steps())
    before["steps"][1] = a_step("test:7c247dc7", 5, outcome="unseen", guid="7c247dc7")
    after = copy.deepcopy(before)
    after["source"]["setup"]["sensors"]["auditd"] = "6" * 64
    after["steps"][1] = a_step("test:7c247dc7", 5, outcome="seen", guid="7c247dc7")

    delta, _ = compared(tmp_path, before, after, "--change", "sensors:auditd")

    step = delta["steps"][1]
    assert step["result"] == "better"
    assert step["verdict"].startswith(
        "better: no telemetry to recorded by the sensors; unseen to seen by the published rules"
    )


def an_event(
    step: str, number: int, sensor: str, kind: str, text: str, key: str = "", paths: str | None = None
) -> dict:
    """An event as a recording holds it. auditd's openat names the path it opened, as its text and in
    the field paths, as the recording writes them, unless paths says otherwise."""

    if paths is None and (sensor, kind) == ("auditd", "openat"):
        paths = text
    return {
        "id": f"{step}-{number}",
        "time": f"2026-11-16T04:10:0{number}.000Z",
        "host": "target",
        "sensor": sensor,
        "kind": kind,
        "text": text,
        "step": step,
        "tied_by": "session",
        "fields": {**({"key": key} if key else {}), **({"paths": paths} if paths is not None else {})},
    }


def test_a_sensor_change_lists_what_it_recorded_and_credits_no_step_it_recorded_the_same(
    tmp_path: Path,
) -> None:
    before = a_recording(*three_steps())
    before["steps"][1] = a_step("test:7c247dc7", 5, outcome="unseen", guid="7c247dc7")
    before["events"] = [
        an_event("test:46959285", 1, "auditd", "execve", "cc -o /tmp/ccm3GO8m.s", "process-start")
    ]
    after = copy.deepcopy(before)
    after["source"]["setup"]["sensors"]["auditd"] = "6" * 64
    after["steps"][1] = a_step("test:7c247dc7", 5, outcome="seen", guid="7c247dc7")
    # The step the change was for: the shell's write to the history file, which only the new watch records.
    after["events"].append(
        an_event("test:7c247dc7", 2, "auditd", "openat", "/home/bluefire-lab/.bash_history", "shell-history")
    )
    # A step whose outcome moved while auditd recorded for it only what is new in every run, here a
    # compiler's temporary file name under a rule both runs have: run variation.
    after["events"][0]["text"] = "cc -o /tmp/ccOZCXa6.s"
    after["steps"][0].update(outcome="alerted", outcome_with_lab_rules="alerted")

    delta, text = compared(tmp_path, before, after, "--change", "sensors:auditd", "--two-runners")

    history, find_step = delta["steps"][1], delta["steps"][0]
    assert history["result"] == "better"
    assert history["records"] == {
        "sensor": "auditd",
        "new": {"count": 1, "lines": ["openat: /home/bluefire-lab/.bash_history"]},
        "gone": {"count": 0, "lines": []},
    }
    assert find_step["result"] == "not attributable"
    assert find_step["verdict"] == (
        "not attributable: sensor `auditd` recorded nothing of this step under an audit key that only one run's "
        "events carry, so this is run variation; one pair of runs"
    )
    assert find_step["records"]["new"] == {"count": 0, "lines": []}
    assert delta["unexplained"] == ["test:46959285"] and delta["runners"] == 2
    assert delta["audit_keys"] == {
        "only_before": {},
        "only_after": {"shell-history": {"events": 1, "steps": ["test:7c247dc7"]}},
    }
    assert text.startswith("## A pair of runs, before and after the change")
    assert "each on a fresh runner of its own, not one after the other on one runner" in text
    assert (
        "- `test:7c247dc7` T1552.004 Test 7c247dc7: only after, `openat: /home/bluefire-lab/.bash_history`; "
        "only before, none."
    ) in text
    assert "Recorded now, and by no sensor before: `test:7c247dc7` T1552.004 Test 7c247dc7." in text
    # Like with like, a key that only one run's events carry is described, with no word on a mark.
    assert (
        "Events of an audit key that only the after run's events carry: `shell-history`, 1 event of 1 step."
        in text
    )
    assert (
        "Same in both: the tests' commit, the rules of detector `lab`, the rules of detector `pinned`, the image "
        "of host `target`, the kernel of host `target`, the settings of sensor `sysmon`, the version of `Zircolite`."
    ) in text


PUBLISHED = {"id": "rule-published", "title": "A Published Rule", "level": "high", "origin": "pinned"}


def an_alert(step: str, *events: str, rule: dict = PUBLISHED) -> dict:
    return {"id": f"alert-{step}", "step": step, "rule": rule, "counts": True, "events": list(events)}


def test_an_audit_rule_change_credits_no_step_whose_alert_rests_on_other_events(tmp_path: Path) -> None:
    before = a_recording(*three_steps())
    before["steps"][1] = a_step("test:7c247dc7", 5, outcome="unseen", guid="7c247dc7")
    before["events"] = [an_event("test:46959285", 1, "sysmon", "process start", "find / -name id_rsa")]
    after = copy.deepcopy(before)
    after["source"]["setup"]["sensors"]["auditd"] = "6" * 64
    # The step the change was for: recorded now, by the new watch alone.
    after["steps"][1] = a_step("test:7c247dc7", 5, outcome="seen", guid="7c247dc7")
    after["events"].append(an_event("test:7c247dc7", 2, *HISTORY_WRITE))
    # Another step got an event of the new key too, and in this run only a published rule matched one of
    # its Sysmon events: the change of the audit rules cannot have made that match.
    after["events"] += [
        an_event("test:46959285", 3, *HISTORY_WRITE),
        an_event("test:46959285", 4, "sysmon", "process start", "find / -name id_ed25519"),
    ]
    after["alerts"] = [an_alert("test:46959285", "test:46959285-4")]
    after["steps"][0].update(outcome="alerted", outcome_with_lab_rules="alerted")

    delta, _ = compared(tmp_path, before, after, "--change", "sensors:auditd", "--two-runners")

    history, find_step = delta["steps"][1], delta["steps"][0]
    assert history["result"] == "better" and history["procedures"] == {"better": 1, "of": 2}
    assert find_step["result"] == "not attributable"
    assert find_step["verdict"] == (
        "not attributable: the rule `A Published Rule` matched it in one run only, on events other than those "
        "of an audit key that only one run's events carry, so this is run variation; one pair of runs"
    )


def test_a_change_of_sysmon_settings_is_not_credited_with_a_step_its_events_cannot_tell(
    tmp_path: Path,
) -> None:
    before = a_recording(*three_steps())
    before["events"] = [
        an_event("test:46959285", 1, "sysmon", "file created", "/var/spool/cron/crontabs/tmp.sxmsyR"),
        an_event("test:46959285", 2, "auditd", "execve", "crontab /tmp/job", "process-start"),
    ]
    after = copy.deepcopy(before)
    after["source"]["setup"]["sensors"]["sysmon"] = "6" * 64
    # Sysmon's text differs only by a temporary name, as between any two runs, and in this run only a
    # published rule matched the step's auditd event, which a change of Sysmon's settings cannot do.
    after["events"][0]["text"] = "/var/spool/cron/crontabs/tmp.EGNV1e"
    after["alerts"] = [an_alert("test:46959285", "test:46959285-2")]
    after["steps"][0].update(outcome="alerted", outcome_with_lab_rules="alerted")

    delta, _ = compared(tmp_path, before, after, "--change", "sensors:sysmon", "--two-runners")

    step = delta["steps"][0]
    assert delta["comparable"] and step["result"] == "not attributable" and "price" not in step
    assert step["verdict"] == (
        "not attributable: two runs of the same settings of sensor `sysmon` already differ in what it records "
        "of a step, such as temporary file names, and nothing a recording holds tells what a change of those "
        "settings recorded from that, so this is run variation; one pair of runs"
    )


def test_an_empty_change_declares_nothing(tmp_path: Path) -> None:
    # As the workflow passes it when its plan declared no one change.
    recording = a_recording(*three_steps())

    delta, text = compared(tmp_path, recording, recording, "--change", "")

    assert (delta["declared_change"], delta["comparable"], delta["runners"]) == (None, True, None)
    assert "Declared change: none." in text and "fresh runner" not in text


def test_a_sensor_change_that_recorded_nothing_new_says_so_and_names_the_step_still_unseen(
    tmp_path: Path,
) -> None:
    before = a_recording(*three_steps())
    before["steps"][1] = a_step("test:7c247dc7", 5, outcome="unseen", guid="7c247dc7")
    after = copy.deepcopy(before)
    after["source"]["setup"]["sensors"]["auditd"] = "6" * 64

    delta, text = compared(tmp_path, before, after, "--change", "sensors:auditd")

    assert delta["counts"]["same"] == 3
    assert "No step that no sensor recorded before is recorded now." in text
    assert "Unseen in both runs: `test:7c247dc7` T1552.004 Test 7c247dc7." in text
    assert "No event of an audit key that only the after run's events carry." in text
    assert "the whole audit log of each run is `audit.txt` in its artifact" in text


def test_two_runs_said_to_be_side_by_side_must_name_one_ci_run(tmp_path: Path) -> None:
    before = a_recording(*three_steps())
    after = copy.deepcopy(before)
    after["source"]["setup"]["sensors"]["auditd"] = "6" * 64
    after["source"]["run_url"] = "https://example.org/runs/2"

    delta, text = compared(tmp_path, before, after, "--change", "sensors:auditd", "--two-runners")

    assert (delta["comparable"], delta["runners"]) == (False, None)
    assert delta["refused_because"] == [
        "the two runs were said to be made side by side in one CI run, but the recordings name different CI runs"
    ]
    assert "fresh runner" not in text


RUNNERS = (
    "the image of host `target` (ubuntu24 20261116.133.1 before, ubuntu24 20261116.376.1 after), "
    "the kernel of host `target` (7.0.0-1014-aws before, 7.0.0-1017-azure after)"
)


def watch(path: str) -> str:
    """A watch on a file for writes and changes of attributes, in the form a recording writes it."""

    return f"-a always,exit -F path={path} -F perm=aw"


HOME = "/home/bluefire-lab"
# What the audit rules of the first real pair watch, as its two runs' audit-rules.txt say: the history
# files are the after run's new watches; the rest the base commit's, the same in both runs.
HISTORY_FILES = [
    watch(f"{HOME}/{name}")
    for name in (".bash_history", ".zsh_history", ".histfile", ".sh_history", ".history")
]
BASE_WATCHES = {
    "bluefire-lab-probe": [watch("/var/tmp/bluefire-lab-audit-probe")],
    "process-start": ["-a always,exit -S execve -F auid!=unset"],
    "shell-start": sorted(
        watch(path)
        for path in (
            "/etc/profile",
            "/etc/profile.d",
            "/etc/bash.bashrc",
            "/etc/environment",
            "/root/.bashrc",
            "/root/.profile",
            *(
                f"{HOME}/{name}"
                for name in (".bashrc", ".profile", ".bash_profile", ".bash_login", ".bash_logout")
            ),
        )
    ),
}
# Why a key of a rule both runs have gives no mark, as the verdict says it.
SAME_PATH = (
    "its events' audit key `shell-history` gives no mark: the before run's rule "
    f"`{watch(HOME + '/.bash_history')}` watches the same path, `{HOME}/.bash_history`"
)
NO_PATH = (
    "its events' audit key `process-start` gives no mark: its rule `-a always,exit -S execve -F auid!=unset` "
    "watches no one path, and what such a rule records cannot be told apart by its text from what another rule "
    "records"
)


def watching(recording: dict, watches: dict[str, list[str]]) -> None:
    """Say in the recording's auditd sensor what its run's audit rules watch under each key."""

    recording["network"]["sensors"][1]["audit_watches"] = watches


def the_first_pair() -> tuple[dict, dict]:
    """Two recordings of the shape of the first real pair, CI run 45350480637 (its recordings hold 91
    steps and about 1 MB each, too big to keep here): the audit rules gained a watch on the shell history
    files, key shell-history, and the two runners got another image and kernel. "Clear Bash history
    (echo)" was unseen before, with no event and no alert; after, its one event is the history-file
    write, as that run recorded it. A discovery test printed less on the after runner, so what happened
    changed. 89 other steps are the same, one of them with a shell-history event next to events of a
    rule both runs have. Each recording's auditd says what its rules watch under each key, as that
    run's audit-rules.txt does: no rule of the before run watches a history file, a folder above one or a
    path under one, and its one rule without a path records program starts alone, so the history watches
    can carry the change's mark."""

    others = [a_step(f"test:{number:08x}", number, guid=f"{number:08x}") for number in range(89)]
    before = a_recording(
        a_step("test:23b91cd2", 89, guid="23b91cd2"),
        a_step("test:cbf506a5", 90, outcome="unseen", guid="cbf506a5"),
        *others,
    )
    before["source"]["setup"]["sensors"]["auditd"] = "7" * 64
    watching(before, BASE_WATCHES)
    before["events"] = [
        an_event("test:23b91cd2", 1, "auditd", "execve", "ps aux", "process-start"),
        an_event("test:00000000", 1, "auditd", "execve", "cat /etc/passwd", "process-start"),
    ]
    after = copy.deepcopy(before)
    after["source"]["setup"].update(
        images={"target": "ubuntu24 20261116.376.1"}, kernels={"target": "7.0.0-1017-azure"}
    )
    after["source"]["setup"]["sensors"]["auditd"] = "6" * 64
    watching(after, {**BASE_WATCHES, "shell-history": HISTORY_FILES})
    after["ordinary"]["events"] = 921
    after["steps"][0]["happened"] = {"answer": "attempted without effect", "basis": "it printed less"}
    after["steps"][0].update(outcome="no effect", outcome_with_lab_rules="no effect")
    after["steps"][1] = a_step("test:cbf506a5", 90, outcome="seen", guid="cbf506a5")
    after["steps"][1]["visibility"]["events"] = 1
    history = an_event(
        "test:cbf506a5", 1, "auditd", "openat", "/home/bluefire-lab/.bash_history", "shell-history"
    )
    after["events"] += [
        history,
        an_event("test:00000000", 2, "auditd", "openat", "/home/bluefire-lab/.bash_history", "shell-history"),
    ]
    after["alerts"] = [
        {
            "id": "alert-108",
            "step": "test:cbf506a5",
            "detector": "pinned",
            "rule": {
                "id": "9e1bef8d",
                "title": "Use Of Hidden Paths Or Files",
                "level": "low",
                "origin": "pinned",
            },
            "counts": False,
            "events": [history["id"]],
        }
    ]
    return before, after


def test_a_pair_on_runners_that_differed_credits_the_audit_rules_only_where_their_mark_is(
    tmp_path: Path,
) -> None:
    before, after = the_first_pair()

    delta, text = compared(tmp_path, before, after, "--change", "sensors:auditd", "--two-runners")

    assert (delta["comparable"], delta["refused_because"], delta["runners"]) == (True, [], 2)
    assert delta["limit"] == {
        "why": "the two runners differed",
        "differences": ["images:target", "kernels:target"],
        "credits": "only a step that carries the change's own mark: every event the recordings hold of it is "
        "of an audit key whose every rule in that run watches a path that no rule of the other run, as written, "
        "could have recorded (none there watches that path, any other path the event names, a folder above one "
        "or a path under one, and none without a path records the same kind of event, a program start being one "
        "kind and a read, a write or a change of attributes the other; paths are compared as written, so a "
        "second name that a link gives a file is not found out), and the other run holds nothing of it",
        "credited": 1,
        "not_attributable": 1,
    }
    history, discovery = delta["steps"][1], delta["steps"][0]
    assert history["result"] == "better"
    assert history["mark"] == {"run": "after", "keys": ["shell-history"], "events": 1}
    assert history["verdict"].startswith(
        "better by the change's own mark, on two runners that differed: no telemetry to recorded by the sensors; "
        "unseen to seen by the published rules; unseen to seen with the lab's rules"
    )
    # The ordinary activity of each run was counted on its own runner: no difference of the two is a price.
    assert history["price"] == (
        "price not known: each run counted its ordinary activity on its own runner, and the two runners "
        "differed, so what differs between the counts is not the change's price (each run's own, published "
        "rules that alerted on ordinary activity: 2 before, 2 after; ordinary events: 940 before, 921 after)"
    )
    assert history["verdict"].endswith(
        f"; {history['price']}; it rests on 1 event of the audit key `shell-history`, whose every rule in the "
        "after run watches a path that no rule of the before run, as written, could have recorded, the only events "
        "either run "
        "holds of the step, on two runners that differed (the image of host `target`, the kernel of host "
        "`target`); one pair of runs"
    )
    # The description of the keys only one run's events carry says the same as the verdict.
    assert delta["audit_keys"] == {
        "only_before": {},
        "only_after": {
            "shell-history": {"events": 2, "steps": ["test:00000000", "test:cbf506a5"], "mark": True}
        },
    }
    assert (
        "Events of an audit key that only the after run's events carry: `shell-history`, 2 events of 2 steps, a "
        "key that can carry the change's own mark."
    ) in text
    assert (discovery["result"], "mark" in discovery) == ("not attributable", False)
    assert discovery["verdict"] == (
        "not attributable: the two runners differed (the image of host `target`, the kernel of host `target`), "
        "the control changed too, and the step does not carry the change's own mark (both runs hold events of "
        "it), so this is run variation or the runners' difference; one pair of runs"
    )
    assert {step["result"] for step in delta["steps"][2:]} == {"same"}
    assert (delta["counts"]["same"], delta["unexplained"]) == (89, ["test:23b91cd2"])
    # The one better step is counted with the limit beside it, where a reader of the counts looks.
    assert (delta["counts"]["better"], delta["counts"]["by_mark"]) == (1, 1)
    assert (
        "91 steps paired by id: 89 same, 1 better (1 of them by the change's own mark alone, on two runners "
        "that differed), 1 not attributable."
    ) in text
    assert "each on a fresh runner of its own, not one after the other on one runner" in text
    assert f"but the two runners differed: {RUNNERS}." in text
    assert "**A limited verdict, not like with like.**" in text and "**Comparable.**" not in text
    assert "1 step credited by the mark, 1 not attributable." in text
    assert (
        "| the image of host `target` (the runners) | ubuntu24 20261116.133.1 | ubuntu24 20261116.376.1 |"
        in text
    )

    # A step whose new outcome rests on a marked event, while it also has events of a rule both runs have,
    # is not carried by the mark alone: on other runners those other events could have moved it.
    mixed = copy.deepcopy(after)
    mixed["steps"][2] = a_step("test:00000000", 0, outcome="alerted", guid="00000000")
    mixed["alerts"].append(
        {**after["alerts"][0], "id": "alert-1", "step": "test:00000000", "events": ["test:00000000-2"]}
    )
    delta, _ = compared(tmp_path, before, mixed, "--change", "sensors:auditd", "--two-runners")
    step = delta["steps"][2]
    assert step["result"] == "not attributable"
    assert "the step does not carry the change's own mark (both runs hold events of it)" in step["verdict"]


def a_step_unseen_before(*events: dict, counted: int | None = None) -> tuple[dict, dict]:
    """The first pair, with one more step that no sensor recorded before and that holds these events
    after: counted is the number of events the after run tied to it, by default the events given."""

    before, after = the_first_pair()
    before["steps"][3] = a_step("test:00000001", 1, outcome="unseen", guid="00000001")
    after["steps"][3] = a_step("test:00000001", 1, outcome="seen", guid="00000001")
    after["steps"][3]["visibility"]["events"] = len(events) if counted is None else counted
    after["events"] += list(events)
    return before, after


def judged(tmp_path: Path, before: dict, after: dict, index: int = 3) -> tuple[dict, dict]:
    """The delta of a pair on runners that differed under a change of the audit rules, and one step of it."""

    delta, _ = compared(tmp_path, before, after, "--change", "sensors:auditd", "--two-runners")
    assert delta["limit"] is not None
    return delta, delta["steps"][index]


HISTORY_WRITE = ("auditd", "openat", "/home/bluefire-lab/.bash_history", "shell-history")


def test_events_of_a_key_both_rule_sets_define_are_no_mark_also_when_only_one_run_has_them(
    tmp_path: Path,
) -> None:
    # Both runs' rules watch /root/.bashrc under shell-start, and only the after runner recorded a write
    # to it: a key that fired on one runner only is the runners' difference, not the change's mark.
    before, after = a_step_unseen_before(
        an_event("test:00000001", 1, "auditd", "openat", "/root/.bashrc", "shell-start")
    )

    delta, step = judged(tmp_path, before, after)

    assert (step["result"], "mark" in step) == ("not attributable", False)
    assert (
        "the step does not carry the change's own mark (its events' audit key `shell-start` gives no mark: the "
        f"before run's rule `{watch('/etc/bash.bashrc')}` watches the same path, `/etc/bash.bashrc`)"
    ) in step["verdict"]
    assert (delta["counts"]["by_mark"], delta["limit"]["credited"]) == (1, 1)


def history_watched_before(watches: dict[str, list[str]]) -> tuple[dict, dict]:
    """The first pair, with the before run's audit rules watching this as well. Its runner recorded
    nothing of the history step, as the real before run did not."""

    before, after = the_first_pair()
    watching(before, {**BASE_WATCHES, **watches})
    return before, after


def test_a_key_renamed_on_a_rule_both_runs_have_is_no_mark(tmp_path: Path) -> None:
    # The change only gave the history watch a new key: what the rule watches is the same, so on two
    # runners that differed the step's new event is the after runner's, not the change's.
    before, after = history_watched_before({"old-history": HISTORY_FILES})

    delta, step = judged(tmp_path, before, after, index=1)

    assert (step["result"], "mark" in step) == ("not attributable", False)
    assert f"({SAME_PATH})" in step["verdict"]
    assert (delta["counts"]["better"], delta["counts"]["by_mark"], delta["limit"]["credited"]) == (0, 0, 0)
    # The key's events are still described as of a key only the after run's events carry, with why that
    # is no mark, so the description does not read as a credit the verdict withholds.
    assert (
        delta["audit_keys"]["only_after"]["shell-history"]["no_mark"] == SAME_PATH.partition("no mark: ")[2]
    )


def test_a_key_split_in_two_or_two_keys_merged_is_no_mark(tmp_path: Path) -> None:
    # Split: the before run watched the two history files under a key each, the after run under one.
    split = history_watched_before({"history-bash": HISTORY_FILES[:1], "history-zsh": HISTORY_FILES[1:]})
    # Merged: the before run watched the start files and the history file under two keys, the after run
    # watches both under the one key shell-history.
    merged = history_watched_before({"old-history": HISTORY_FILES[:1]})
    merged_watches = {key: forms for key, forms in BASE_WATCHES.items() if key != "shell-start"}
    watching(merged[1], {**merged_watches, "shell-history": BASE_WATCHES["shell-start"] + HISTORY_FILES[:1]})

    for before, after in (split, merged):
        delta, step = judged(tmp_path, before, after, index=1)

        assert (step["result"], "mark" in step) == ("not attributable", False)
        assert delta["counts"]["by_mark"] == 0


def test_a_key_that_gained_a_rule_and_kept_an_old_one_is_no_mark(tmp_path: Path) -> None:
    # Both runs watch ~/.bash_history under shell-history; the after run watches ~/.zsh_history too.
    # The step's event of that key could come from the old watch, which both runs have.
    before, after = history_watched_before({"shell-history": HISTORY_FILES[:1]})

    delta, step = judged(tmp_path, before, after, index=1)

    assert (step["result"], "mark" in step) == ("not attributable", False)
    assert delta["counts"]["by_mark"] == 0


def test_a_rule_without_a_key_in_the_other_run_is_watched_there_too(tmp_path: Path) -> None:
    before, after = history_watched_before({"": HISTORY_FILES})

    delta, step = judged(tmp_path, before, after, index=1)

    assert (step["result"], "mark" in step) == ("not attributable", False)
    assert delta["counts"]["by_mark"] == 0


def test_a_key_whose_rules_are_all_new_is_a_mark_whatever_its_name(tmp_path: Path) -> None:
    # The before run had a key of the same name on another watch: what counts is what the rules watch.
    # Its events carry the key too, so the key is not one that only one run's events carry; the step still
    # lists the event that carries the mark.
    before, after = history_watched_before({"shell-history": [watch("/home/bluefire-lab/.lesshst")]})
    before["events"].append(
        an_event("test:00000000", 3, "auditd", "openat", f"{HOME}/.lesshst", "shell-history")
    )

    delta, step = judged(tmp_path, before, after, index=1)

    assert (step["result"], step["mark"]) == (
        "better",
        {"run": "after", "keys": ["shell-history"], "events": 1},
    )
    assert step["records"]["new"] == {"count": 1, "lines": [f"openat: {HOME}/.bash_history"]}
    assert delta["counts"]["by_mark"] == 1


def no_mark(step: dict) -> str:
    """Why the step carries no mark, as its verdict says it."""

    assert (step["result"], "mark" in step) == ("not attributable", False)
    return step["verdict"].partition("the step does not carry the change's own mark (")[2]


def test_a_watch_on_a_folder_above_the_new_watch_in_the_other_run_is_no_mark(tmp_path: Path) -> None:
    # A watch on a folder records what happens to every file under it: the before run's rule could have
    # recorded the history-file write that only the after run holds.
    before, after = history_watched_before({"home": [watch(HOME)]})

    delta, step = judged(tmp_path, before, after, index=1)

    assert no_mark(step).startswith(
        f"its events' audit key `shell-history` gives no mark: the before run's rule `{watch(HOME)}` watches "
        f"`{HOME}`, a folder above `{HOME}/.bash_history`)"
    )
    assert (delta["counts"]["by_mark"], delta["limit"]["credited"]) == (0, 0)


def test_a_watch_under_the_new_watch_in_the_other_run_is_no_mark(tmp_path: Path) -> None:
    # The after run watches a folder, the before run a file in it: the text does not say whether a watched
    # path is a folder, so the old rule may cover part of the new one's ground.
    before, after = history_watched_before({"old": [watch(f"{HOME}/.config/fish/fish_history")]})
    watching(after, {**BASE_WATCHES, "shell-history": [watch(f"{HOME}/.config")]})

    delta, step = judged(tmp_path, before, after, index=1)

    assert (
        f"watches `{HOME}/.config/fish/fish_history`, under `{HOME}/.config`, which may be a folder"
        in no_mark(step)
    )
    assert delta["counts"]["by_mark"] == 0


def test_the_same_path_with_other_permission_letters_under_another_key_is_no_mark(tmp_path: Path) -> None:
    # The before run watched the history file for writes alone; the after run for writes and changes of
    # attributes. The write the after run holds is one the before run's rule could have recorded.
    old = f"-a always,exit -F path={HOME}/.bash_history -F perm=w"
    before, after = history_watched_before({"old-history": [old]})

    delta, step = judged(tmp_path, before, after, index=1)

    assert no_mark(step).startswith(
        f"its events' audit key `shell-history` gives no mark: the before run's rule `{old}` watches the same "
        f"path, `{HOME}/.bash_history`)"
    )
    assert delta["counts"]["by_mark"] == 0


def test_a_marking_key_whose_rule_names_no_path_is_no_mark(tmp_path: Path) -> None:
    # The after run's new key holds a system call rule for every program: what it records cannot be told
    # apart by the text from what the before run's rules record.
    before, after = the_first_pair()
    watching(after, {**BASE_WATCHES, "shell-history": ["-a always,exit -S openat -F auid!=unset"]})

    delta, step = judged(tmp_path, before, after, index=1)

    assert no_mark(step).startswith(
        "its events' audit key `shell-history` gives no mark: its rule `-a always,exit -S openat -F auid!=unset` "
        "watches no one path"
    )
    assert delta["counts"]["by_mark"] == 0


def test_a_rule_without_a_path_in_the_other_run_that_could_record_the_event_is_no_mark(
    tmp_path: Path,
) -> None:
    # A system call rule on opening and truncating files, with no path, records the shell's write to the
    # history file as well, under its own key. Its program starts alone, which the real before run has, could not.
    files = "-a always,exit -S open,openat,truncate -F auid!=unset"
    before, after = history_watched_before({"file-writes": [files]})

    delta, step = judged(tmp_path, before, after, index=1)

    assert no_mark(step).startswith(
        f"its events' audit key `shell-history` gives no mark: the before run's rule `{files}` watches no path "
        "and could record the same kind of event (reads, writes and changes of attributes))"
    )
    assert delta["counts"]["by_mark"] == 0
    # A rule on another list, which holds no system call's records, leaves the mark standing.
    before, after = history_watched_before({"quiet": ["-a always,exclude -F msgtype=CWD"]})
    _, step = judged(tmp_path, before, after, index=1)
    assert step["result"] == "better"


@pytest.mark.parametrize(
    "reads",
    ["-a always,exit -F auid!=unset -F perm=r", "-a always,exit -S openat -F auid!=unset -F perm=r"],
)
def test_a_rule_without_a_path_for_reads_in_the_other_run_is_no_mark(tmp_path: Path, reads: str) -> None:
    # The kernel matches perm r and perm w alike on an open for reading and writing, so a rule for reads
    # records an open that the new watch for writes records: reads, writes and changes of attributes are
    # one kind. Without a system call the rule selects every one; with openat, that one.
    before, after = history_watched_before({"reads": [reads]})

    delta, step = judged(tmp_path, before, after, index=1)

    assert no_mark(step).startswith(
        f"its events' audit key `shell-history` gives no mark: the before run's rule `{reads}` watches no "
        "path and could record the same kind of event (reads, writes and changes of attributes))"
    )
    assert (delta["counts"]["by_mark"], delta["audit_keys"]["only_after"]["shell-history"]["mark"]) == (
        0,
        False,
    )


def test_a_rule_without_a_path_for_program_starts_in_the_other_run_leaves_the_mark_standing(
    tmp_path: Path,
) -> None:
    # perm x selects only the system calls that start a program, and no watch for writes records one.
    before, after = history_watched_before({"starts": ["-a always,exit -F perm=x"]})

    delta, step = judged(tmp_path, before, after, index=1)

    assert (step["result"], step["mark"]) == (
        "better",
        {"run": "after", "keys": ["shell-history"], "events": 1},
    )
    assert delta["counts"]["by_mark"] == 1


def test_an_event_that_names_a_path_the_other_run_watches_is_no_mark(tmp_path: Path) -> None:
    # A rename onto the history file names the file it came from as well, and the before run's watch on
    # that file records the same rename under its own key.
    before, after = the_first_pair()
    after["events"][2]["fields"]["paths"] = f"{HOME}/.bashrc, {HOME}/.bash_history"

    delta, step = judged(tmp_path, before, after, index=1)

    assert no_mark(step).startswith(
        "its event `test:cbf506a5-1` of the audit key `shell-history` gives no mark: the before run's rule "
        f"`{watch(HOME + '/.bashrc')}` watches the same path, `{HOME}/.bashrc`)"
    )
    assert delta["counts"]["by_mark"] == 0
    # A path the comparison cannot compare, here one relative to the working folder, gives no mark either.
    after["events"][2]["fields"]["paths"] = ".bash_history"
    _, step = judged(tmp_path, before, after, index=1)
    assert no_mark(step).startswith(
        "its event `test:cbf506a5-1` of the audit key `shell-history` gives no mark: its event names the path "
        "`.bash_history` in a form the comparison does not compare)"
    )
    # A field the recording cut short leaves out the paths after the cut, which may be watched.
    after["events"][2]["fields"]["paths"] = f"{HOME}/.bash_history, {HOME}/.bas..."
    _, step = judged(tmp_path, before, after, index=1)
    assert "its event's paths may be cut short, so not every path it names is known)" in no_mark(step)
    # A path the recording could not read is an empty piece: it is not left out, it gives no mark.
    after["events"][2]["fields"]["paths"] = f"{HOME}/.bash_history, "
    _, step = judged(tmp_path, before, after, index=1)
    assert "its event names the path `` in a form the comparison does not compare)" in no_mark(step)


def test_a_marked_event_next_to_an_unmarked_one_is_not_attributable(tmp_path: Path) -> None:
    # The other run holds nothing of the step, but the after run holds a program start of it too, under
    # a rule both runs have: on another runner that start alone could have made the step seen.
    before, after = a_step_unseen_before(
        an_event("test:00000001", 1, *HISTORY_WRITE),
        an_event("test:00000001", 2, "auditd", "execve", "sh -c history -c", "process-start"),
    )

    _, step = judged(tmp_path, before, after)

    assert (step["result"], "mark" in step) == ("not attributable", False)
    assert f"({NO_PATH})" in step["verdict"]


def test_a_step_whose_recording_kept_fewer_events_than_it_counted_is_not_credited(tmp_path: Path) -> None:
    # The recording keeps the first events of a step: the two it left out may be of any key.
    before, after = a_step_unseen_before(an_event("test:00000001", 1, *HISTORY_WRITE), counted=3)

    _, step = judged(tmp_path, before, after)

    assert (step["result"], "mark" in step) == ("not attributable", False)
    assert "(the recording did not keep every event of it)" in step["verdict"]


def test_a_step_with_an_alert_that_rests_on_an_event_without_the_mark_is_not_credited(tmp_path: Path) -> None:
    before, after = a_step_unseen_before(an_event("test:00000001", 1, *HISTORY_WRITE))
    after["alerts"].append(
        {**after["alerts"][0], "id": "alert-2", "step": "test:00000001", "events": ["test:00000000-1"]}
    )

    _, step = judged(tmp_path, before, after)

    assert (step["result"], "mark" in step) == ("not attributable", False)
    assert "(an alert on it does not rest on those events alone)" in step["verdict"]


def test_an_alert_that_cites_a_marked_event_and_an_unmarked_one_is_not_credited(tmp_path: Path) -> None:
    # Every event an alert cites must carry the mark: the program start of a rule both runs have, which
    # it cites too, could have raised it on its own.
    before, after = a_step_unseen_before(an_event("test:00000001", 1, *HISTORY_WRITE))
    after["alerts"].append(
        {
            **after["alerts"][0],
            "id": "alert-2",
            "step": "test:00000001",
            "events": ["test:00000001-1", "test:00000000-1"],
        }
    )

    delta, step = judged(tmp_path, before, after)

    assert (step["result"], "mark" in step) == ("not attributable", False)
    assert "(an alert on it does not rest on those events alone)" in step["verdict"]
    assert (delta["counts"]["by_mark"], delta["limit"]["credited"]) == (1, 1)


def test_a_step_the_other_run_counted_events_of_and_kept_none_is_not_credited(tmp_path: Path) -> None:
    # The before run holds no event of the step, but it says a sensor recorded two: the recording left
    # them out, so what that run recorded of the step is not known and the after run's events are no mark.
    before, after = a_step_unseen_before(an_event("test:00000001", 1, *HISTORY_WRITE))
    before["steps"][3] = a_step("test:00000001", 1, outcome="seen", guid="00000001")
    after["steps"][3] = a_step("test:00000001", 1, outcome="alerted", guid="00000001")
    after["steps"][3]["visibility"]["events"] = 1
    after["alerts"].append(
        {**after["alerts"][0], "id": "alert-2", "step": "test:00000001", "events": ["test:00000001-1"]}
    )

    delta, step = judged(tmp_path, before, after)

    assert [event for event in before["events"] if event["step"] == "test:00000001"] == []
    assert (step["before"]["recorded"], step["after"]["recorded"]) == ("recorded", "recorded")
    assert (step["result"], "mark" in step) == ("not attributable", False)
    assert "(the other run does not say that no sensor recorded it)" in step["verdict"]
    assert (delta["counts"]["by_mark"], delta["limit"]["credited"]) == (1, 1)


def test_an_event_of_another_sensor_under_a_key_of_the_marks_name_is_not_marked(tmp_path: Path) -> None:
    # Only auditd's events carry audit keys: a field of the same name on another sensor's event says
    # nothing of which audit rule wrote it, so the step holds an event that is not the change's.
    before, after = a_step_unseen_before(
        an_event("test:00000001", 1, *HISTORY_WRITE),
        an_event("test:00000001", 2, "sysmon", "file", "/home/bluefire-lab/.bash_history", "shell-history"),
    )

    delta, step = judged(tmp_path, before, after)

    assert (step["result"], "mark" in step) == ("not attributable", False)
    assert "(not every event of it is auditd's under an audit key)" in step["verdict"]
    assert (delta["counts"]["by_mark"], delta["limit"]["credited"]) == (1, 1)


def test_a_step_that_lost_its_only_events_with_a_removed_rule_is_worse_by_the_mark(tmp_path: Path) -> None:
    # The first pair the other way round: the watch on the history files removed.
    with_watch, without = the_first_pair()

    delta, step = judged(tmp_path, without, with_watch, index=1)

    assert (step["result"], step["mark"]) == (
        "worse",
        {"run": "before", "keys": ["shell-history"], "events": 1},
    )
    assert step["verdict"].startswith(
        "worse by the change's own mark, on two runners that differed: recorded to no telemetry by the sensors; "
        "seen to unseen by the published rules; seen to unseen with the lab's rules"
    )
    assert (
        "whose every rule in the before run watches a path that no rule of the after run, as written, could have "
        "recorded" in step["verdict"]
    )
    assert "price" not in step
    assert (delta["counts"]["worse"], delta["counts"]["by_mark"]) == (1, 1)


def test_a_launcher_only_match_in_the_run_that_recorded_nothing_leaves_the_mark_standing(
    tmp_path: Path,
) -> None:
    # A rule that matched only the launcher's start, whose command line is the whole test, moves no outcome.
    before, after = the_first_pair()
    before["alerts"] = [
        {
            "id": "alert-0",
            "step": "test:cbf506a5",
            "rule": RULE,
            "counts": False,
            "launcher_only": True,
            "events": [],
        }
    ]

    _, step = judged(tmp_path, before, after, index=1)

    assert (step["result"], step["mark"]["run"]) == ("better", "after")


def test_a_pair_on_runners_that_differed_whose_recording_does_not_say_what_its_rules_watch_is_refused(
    tmp_path: Path,
) -> None:
    # A recording written before it said what the rules watch names only their keys, and a key is no mark.
    before, after = the_first_pair()
    before["network"]["sensors"][1].pop("audit_watches")
    before["network"]["sensors"][1]["audit_keys"] = sorted(BASE_WATCHES)

    delta, text = compared(tmp_path, before, after, "--change", "sensors:auditd", "--two-runners")

    assert (delta["comparable"], delta["limit"]) == (False, None)
    reason = (
        "the two runners differed (the image of host `target`, the kernel of host `target`), and the before "
        "recording does not say what its audit rules watch under each audit key, so no step can be shown to "
        "carry the change's own mark: write the recordings again with `bluefire-lab recording` from each run's "
        "folder, which holds the audit rules as they were loaded, or run the pair again"
    )
    assert delta["refused_because"][-1] == reason
    assert len(delta["refused_because"]) == 3
    assert {step["result"] for step in delta["steps"] if step["changed"]} == {"no verdict"}
    assert f"- {reason}" in text and "**No verdict.**" in text


def test_a_change_without_a_mark_of_its_own_on_runners_that_differed_is_refused_with_what_to_do(
    tmp_path: Path,
) -> None:
    before, after = the_first_pair()
    after["source"]["setup"]["sensors"]["auditd"] = "7" * 64
    sysmon, lab = copy.deepcopy(after), copy.deepcopy(after)
    sysmon["source"]["setup"]["sensors"]["sysmon"] = "8" * 64
    lab["network"]["detectors"][1]["digest"] = "5" * 64

    for changed, declared, words in (
        (sysmon, "sensors:sysmon", "the settings of sensor `sysmon`"),
        (lab, "detectors:lab", "the rules of detector `lab`"),
    ):
        delta, text = compared(tmp_path, before, changed, "--change", declared, "--two-runners")

        assert (delta["comparable"], delta["limit"]) == (False, None)
        advice = (
            "the two runners differed (the image of host `target`, the kernel of host `target`), and a change of "
            f"{words} leaves no mark of its own on a step that tells its effect from theirs: run the pair again, "
            "which gives two new runners"
        )
        assert delta["refused_because"][-1] == advice
        assert {step["result"] for step in delta["steps"] if step["changed"]} == {"no verdict"}
        assert f"- {advice}" in text and "**No verdict.**" in text


def test_a_pair_on_runners_that_differed_in_anything_else_too_is_refused_as_before(tmp_path: Path) -> None:
    before, after = the_first_pair()
    before["source"]["tools"].append({"name": "auditd", "version": "3.1.2", "role": "sensor"})
    tool = copy.deepcopy(after)
    tool["source"]["tools"].append({"name": "auditd", "version": "3.1.3", "role": "sensor"})

    delta, text = compared(tmp_path, before, tool, "--change", "sensors:auditd", "--two-runners")

    assert (delta["comparable"], delta["limit"]) == (False, None)
    assert "also differed: the version of `auditd` (3.1.2 before, 3.1.3 after)" in delta["refused_because"]
    assert "run the pair again" not in text

    # Without --two-runners nothing says the runs were made side by side: a runner's difference refuses.
    delta, _ = compared(tmp_path, *the_first_pair(), "--change", "sensors:auditd")
    assert (delta["comparable"], delta["limit"]) == (False, None)
    assert len(delta["refused_because"]) == 2


def test_each_side_names_the_commit_its_rules_and_sensor_settings_came_from(tmp_path: Path) -> None:
    before = a_recording(*three_steps())
    before["source"]["defense_commit"] = "b" * 40
    after = copy.deepcopy(before)
    after["source"]["defense_commit"] = "c" * 40
    after["source"]["setup"]["sensors"]["auditd"] = "6" * 64

    delta, text = compared(tmp_path, before, after, "--change", "sensors:auditd", "--two-runners")

    assert (delta["before"]["defense_commit"], delta["after"]["defense_commit"]) == ("b" * 40, "c" * 40)
    assert (
        "Before: [1](https://example.org/runs/1), GitHub-hosted runner, commit `cccccccc`, its rules and sensor "
        "settings from commit `bbbbbbbb`. After: [1](https://example.org/runs/1), GitHub-hosted runner, commit "
        "`cccccccc`, its rules and sensor settings from that commit."
    ) in text


def test_an_alert_on_the_control_step_is_worse_and_other_roles_name_no_procedures(tmp_path: Path) -> None:
    before = a_recording(*three_steps(), a_step("control:486e88ea", 8, "control", guid="486e88ea"))
    after = copy.deepcopy(before)
    after["network"]["detectors"][1]["digest"] = "5" * 64
    after["network"]["detectors"][1]["verdicts"][0]["digest"] = "8" * 64
    after["steps"][2]["outcome_with_lab_rules"] = "alerted"
    after["steps"][3]["outcome_with_lab_rules"] = "alerted"
    after["alerts"] = [
        {"id": f"alert-{n}", "step": step, "rule": RULE, "counts": True, "events": []}
        for n, step in enumerate(("variant:46959285:5e4f5f", "control:486e88ea"), start=1)
    ]

    delta, _ = compared(tmp_path, before, after, "--change", "detectors:lab")

    variant, control = delta["steps"][2], delta["steps"][3]
    assert variant["result"] == "better" and "procedures" not in variant
    assert "published procedure" not in variant["verdict"] and "; price not counted" in variant["verdict"]
    assert (control["result"], control["verdict"]) == (
        "worse",
        "worse: seen to alerted with the lab's rules (a false alert: a step of role control must raise none); "
        "one pair of runs",
    )


def test_another_commit_of_the_lab_is_named_and_kept_from_being_called_run_variation(tmp_path: Path) -> None:
    before = a_recording(*three_steps())
    after = copy.deepcopy(before)
    after["source"]["commit"] = "d" * 40
    after["steps"][1].update(outcome="alerted", outcome_with_lab_rules="alerted")

    delta, text = compared(tmp_path, before, after)

    assert delta["comparable"]
    assert delta["lab_code"] == {"before": "c" * 40, "after": "d" * 40, "same": False}
    assert delta["steps"][1]["verdict"] == (
        "changed without a cause: run variation or a change of the lab's code, not an effect; one pair of runs"
    )
    assert "The lab's code differed (`cccccccc` before, `dddddddd` after)." in text


def test_the_tests_commit_of_an_older_recording_is_read_from_its_tools(tmp_path: Path) -> None:
    tests = {"name": "Atomic Red Team", "version": "a" * 40, "role": "tests"}
    before = a_recording(*three_steps(), setup=False)
    before["source"]["tools"].append(tests)
    after = a_recording(*three_steps())

    delta, text = compared(tmp_path, before, after)

    assert "atomic_commit" in delta["same_in_both"]
    assert "the tests' commit" not in "\n".join(delta["refused_because"])
    assert "| the settings of sensor `sysmon` | not recorded | 111111111111 |" in text


def test_a_tests_commit_recorded_nowhere_is_not_known_to_be_the_same(tmp_path: Path) -> None:
    before = a_recording(*three_steps())
    del before["source"]["setup"]["atomic_commit"]
    after = copy.deepcopy(before)

    delta, text = compared(tmp_path, before, after)

    assert not delta["comparable"]
    assert delta["refused_because"] == [
        "not recorded in either recording: the tests' commit, so not known to be the same"
    ]
    assert "- not recorded in either recording: the tests' commit, so not known to be the same" in text
    assert "| What differed |" not in text


def test_a_change_the_declared_one_cannot_explain_is_run_variation(tmp_path: Path) -> None:
    before = a_recording(*three_steps())
    after = copy.deepcopy(before)
    after["network"]["detectors"][1]["digest"] = "5" * 64
    after["steps"][1].update(outcome="alerted", outcome_with_lab_rules="alerted")

    delta, _ = compared(tmp_path, before, after, "--change", "detectors:lab")

    step = next(step for step in delta["steps"] if step["id"] == "test:7c247dc7")
    assert (step["result"], step["changed"]) == ("not attributable", ["outcome", "outcome_with_lab_rules"])
    assert delta["unexplained"] == ["test:7c247dc7"] and delta["control"]["varied"] == ["test:7c247dc7"]


def test_another_sensor_digest_with_no_declared_change_is_refused_and_named(tmp_path: Path) -> None:
    before = a_recording(*three_steps())
    after = copy.deepcopy(before)
    after["source"]["setup"]["sensors"]["auditd"] = "6" * 64
    after["steps"][2]["outcome"] = after["steps"][2]["outcome_with_lab_rules"] = "unseen"
    after["steps"][2]["visibility"] = {"answer": "no telemetry", "basis": "none", "events": 0}

    delta, text = compared(tmp_path, before, after)

    assert not delta["comparable"]
    assert delta["differences"] == [{"what": "sensors:auditd", "before": "2" * 64, "after": "6" * 64}]
    assert delta["refused_because"] == [
        f"also differed: the settings of sensor `auditd` ({'2' * 64} before, {'6' * 64} after)"
    ]
    assert [step["result"] for step in delta["steps"]] == ["same", "same", "no verdict"]
    assert "**No verdict.** The comparison is refused, and still lists what differed:" in text
    assert "| the settings of sensor `auditd` | 222222222222 | 666666666666 |" in text
    assert "no verdict: the comparison is refused; one pair of runs (no longer recorded: 2 events)" in text


def test_a_declared_change_that_is_the_same_in_both_is_refused(tmp_path: Path) -> None:
    recording = a_recording(*three_steps())

    delta, _ = compared(tmp_path, recording, recording, "--change", "sensors:auditd")

    assert delta["refused_because"] == [
        "the declared change, the settings of sensor `auditd`, is the same in both recordings"
    ]


def test_a_step_on_one_side_only_is_listed_and_not_counted(tmp_path: Path) -> None:
    before = a_recording(*three_steps())
    after = a_recording(*three_steps(), a_step("test:9f1b2c3d", 7, outcome="alerted"))

    delta, text = compared(tmp_path, before, after)

    assert {key: delta["counts"][key] for key in ("paired", "same", "new", "gone")} == {
        "paired": 3,
        "same": 3,
        "new": 1,
        "gone": 0,
    }
    assert [step["id"] for step in delta["new"]] == ["test:9f1b2c3d"] and delta["gone"] == []
    assert "test:9f1b2c3d" not in [step["id"] for step in delta["steps"]]
    assert delta["refused_because"] == [
        "the two recordings are not of the same steps: 1 only in the after recording, 0 only in the before recording"
    ]
    assert "New: `test:9f1b2c3d` T1552.004 Test test:9f1b2c3d." in text
    assert "3 steps paired by id: 3 same. 1 new and 0 gone, listed and not counted." in text


def test_recordings_without_stable_ids_pair_by_role_test_and_order_and_say_so(tmp_path: Path) -> None:
    # Ids as an older lab wrote them, the run's positions, which differ between the two runs.
    canary = {"role": "canary", "guid": "a934276e"}
    before = a_recording(
        a_step("1", 1, **canary), a_step("4", 4, guid="46959285"), a_step("92", 92, **canary), setup=False
    )
    after = a_recording(
        a_step("1", 1, **canary),
        a_step("5", 5, guid="46959285", outcome="alerted", outcome_with_lab_rules="alerted"),
        a_step("93", 93, **canary),
        setup=False,
    )

    delta, text = compared(tmp_path, before, after)

    assert [
        (step["before_id"] if "before_id" in step else step["id"], step["id"]) for step in delta["steps"]
    ] == [
        ("1", "1"),
        ("4", "5"),
        ("92", "93"),
    ]
    assert {step["paired_by"] for step in delta["steps"]} == {"role, test and order"}
    assert delta["refused_because"][:2] == [
        "the before recording has no source.setup, so what it was made with is not known",
        "the after recording has no source.setup, so what it was made with is not known",
    ]
    assert "3 steps paired by role, test and order: 2 same, 1 no verdict." in text
    assert (
        "A recording has no stable step ids, so each pair rests on its role, its test and its order." in text
    )
    assert "| `5` (paired by role, test and order) | T1552.004 Test 46959285 |" in text


def one_run_evaluated_twice() -> tuple[dict, dict]:
    """One run's two recordings: its telemetry evaluated with the base's lab rules and with the head's,
    which adds a rule that the run accepts and that matched an event of the first step."""

    before = a_recording(*three_steps())
    before["events"] = [
        {"id": "4-1", "time": "2026-11-16T04:01:00.000Z", "host": "target", "sensor": "auditd",
         "kind": "openat", "text": "/home/bluefire-lab/.bash_history", "step": "test:46959285",
         "tied_by": "session", "fields": {"key": "shell-history"}},
    ]  # fmt: skip
    before["network"]["detectors"][1]["commit"] = "b" * 40
    after = a_lab_rule_change(before)
    after["network"]["detectors"][1]["commit"] = "c" * 40
    after["alerts"][0]["events"] = ["4-1"]
    return before, after


def test_one_run_evaluated_twice_names_the_changed_step_and_its_price_with_no_run_variation(
    tmp_path: Path,
) -> None:
    before, after = one_run_evaluated_twice()

    delta, text = compared(tmp_path, before, after, "--change", "detectors:lab", "--one-run")

    assert (delta["comparable"], delta["one_run"], delta["runners"]) == (True, True, None)
    assert delta["claim"] == "one run evaluated with two rule sets"
    assert delta["before"]["lab_rules_commit"] == "b" * 40 and delta["after"]["lab_rules_commit"] == "c" * 40
    changed = [step for step in delta["steps"] if step["result"] != "same"]
    assert [(step["id"], step["result"]) for step in changed] == [("test:46959285", "better")]
    # The price as the lab tells it for its own rules: not counted, with each evaluation's notes.
    assert changed[0]["verdict"] == (
        "better: seen to alerted with the lab's rules, on 1 of the 2 published procedures of T1552.004 in the "
        "list; price not counted: the lab's rules that matched ordinary activity are left out of the recording "
        f"before it is written (before: {ACCEPTED.rstrip('.')}; after: {ACCEPTED.rstrip('.')}); one run "
        "evaluated with two rule sets"
    )
    assert delta["lab_rules"] == [
        {
            "rule": "rule-ours",
            "title": RULE["title"],
            "change": "changed",
            "before": {"accepted": False},
            "after": {"accepted": True},
        }
    ]
    assert text.startswith("## One run, evaluated with two sets of the lab's rules")
    assert (
        "the lab's rules from commit `bbbbbbbb`" in text and "the lab's rules from commit `cccccccc`" in text
    )
    assert (
        "the comparison checked that they are, so there is no run variation and no difference of runners."
        in text
    )
    assert "- Private Key Files Searched With Find, changed: before not accepted; after accepted." in text
    assert "All of this rests on one run evaluated with two rule sets." in text


def test_one_run_evaluated_twice_is_refused_when_anything_but_the_lab_rules_differs(tmp_path: Path) -> None:
    before, after = one_run_evaluated_twice()
    published = copy.deepcopy(after)
    published["steps"][1].update(outcome="alerted")
    other_run = copy.deepcopy(after)
    other_run["source"]["run_url"] = "https://example.org/runs/2"
    events = copy.deepcopy(after)
    events["events"][0]["text"] = "/home/bluefire-lab/.zsh_history"
    # An unchanged rule cannot be judged two ways on the same run's tests and ordinary activity.
    flipped = a_lab_rule_change(before, edited=False)

    refusals = {}
    for name, recording in (
        ("published", published),
        ("other run", other_run),
        ("events", events),
        ("flipped", flipped),
    ):
        delta, text = compared(tmp_path, before, recording, "--change", "detectors:lab", "--one-run")
        assert not delta["comparable"] and "and found that they are not: see below." in text
        refusals[name] = delta["refused_because"]

    said = "the two were said to be one run evaluated twice, but "
    assert refusals["published"] == [said + "step `test:7c247dc7` differs in outcome"]
    assert refusals["other run"] == [said + "the two recordings do not name the same CI run"]
    assert refusals["events"] == [
        said
        + "the events differ: 1 held by both differ, and 0 held by one only are not kept for an alert of "
        "the lab's rules"
    ]
    assert refusals["flipped"] == [
        said
        + "the lab's rule `Private Key Files Searched With Find` is the same file in both, and was judged "
        "differently"
    ]


def test_a_refused_one_run_comparison_does_not_say_it_rests_on_one_run(tmp_path: Path) -> None:
    before, after = one_run_evaluated_twice()
    after["id"] = "r2"

    delta, text = compared(tmp_path, before, after, "--change", "detectors:lab", "--one-run")

    assert not delta["comparable"]
    step = delta["steps"][0]
    assert (step["result"], step["verdict"]) == ("no verdict", "no verdict: the comparison is refused")
    assert "rests on one run evaluated with two rule sets" not in text
    assert "There is no verdict here: the comparison is refused." in text


def test_a_lab_rule_moved_to_another_file_is_named_as_moved(tmp_path: Path) -> None:
    before, _ = one_run_evaluated_twice()
    before["network"]["detectors"][1]["verdicts"][0]["file"] = "lab/rules/linux/a.yml"
    after = copy.deepcopy(before)
    after["network"]["detectors"][1].update(digest="5" * 64, commit="c" * 40)
    after["network"]["detectors"][1]["verdicts"][0]["file"] = "lab/rules/linux/b.yml"

    delta, text = compared(tmp_path, before, after, "--change", "detectors:lab", "--one-run")

    assert delta["comparable"]
    assert [(row["change"], row["before"]["file"], row["after"]["file"]) for row in delta["lab_rules"]] == [
        ("moved", "lab/rules/linux/a.yml", "lab/rules/linux/b.yml")
    ]
    assert (
        "- Private Key Files Searched With Find, the same text moved from lab/rules/linux/a.yml to "
        "lab/rules/linux/b.yml: before not accepted; after not accepted." in text
    )


def test_one_run_evaluated_twice_shows_only_a_change_of_the_lab_rules(tmp_path: Path) -> None:
    before, after = one_run_evaluated_twice()
    after["source"]["setup"]["sensors"]["auditd"] = "6" * 64

    delta, _ = compared(tmp_path, before, after, "--change", "sensors:auditd", "--one-run")

    assert not delta["comparable"]
    assert delta["refused_because"][0] == (
        "one run evaluated twice can show only a change of the lab's rules, and the declared change is the "
        "settings of sensor `auditd`"
    )
