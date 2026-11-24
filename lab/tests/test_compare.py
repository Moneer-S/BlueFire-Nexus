"""The comparison of two recordings, on small recordings built by hand, read from what the command writes."""

from __future__ import annotations

import copy
import json
from pathlib import Path

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


def an_event(step: str, number: int, sensor: str, kind: str, text: str, key: str = "") -> dict:
    return {
        "id": f"{step}-{number}",
        "time": f"2026-11-16T04:10:0{number}.000Z",
        "host": "target",
        "sensor": sensor,
        "kind": kind,
        "text": text,
        "step": step,
        "tied_by": "session",
        "fields": {"key": key} if key else {},
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
        "not attributable: sensor `auditd` recorded nothing of this step under an audit key that only one of "
        "the runs has, so this is run variation; one pair of runs"
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
    assert "Events of an audit key that only the after run has: `shell-history`, 1 event of 1 step." in text
    assert (
        "Same in both: the tests' commit, the rules of detector `lab`, the rules of detector `pinned`, the image "
        "of host `target`, the kernel of host `target`, the settings of sensor `sysmon`, the version of `Zircolite`."
    ) in text


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
    assert "No event of an audit key that only the after run has." in text
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


def the_first_pair() -> tuple[dict, dict]:
    """Two recordings of the shape of the first real pair, CI run 45350480637 (its recordings hold 91
    steps and about 1 MB each, too big to keep here): the audit rules gained a watch on the shell history
    files, key shell-history, and the two runners got another image and kernel. "Clear Bash history
    (echo)" was unseen before; after, its one event is the history-file write, as that run recorded it.
    A discovery test printed less on the after runner, so what happened changed. 89 other steps are the
    same, one of them with a shell-history event next to events of a rule both runs have."""

    others = [a_step(f"test:{number:08x}", number, guid=f"{number:08x}") for number in range(89)]
    before = a_recording(
        a_step("test:23b91cd2", 89, guid="23b91cd2"),
        a_step("test:cbf506a5", 90, outcome="unseen", guid="cbf506a5"),
        *others,
    )
    before["source"]["setup"]["sensors"]["auditd"] = "7" * 64
    # A rule that matched the launcher's start only, whose command line is the whole test: no telemetry.
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
    before["events"] = [
        an_event("test:23b91cd2", 1, "auditd", "execve", "ps aux", "process-start"),
        an_event("test:00000000", 1, "auditd", "execve", "cat /etc/passwd", "process-start"),
    ]
    after = copy.deepcopy(before)
    after["source"]["setup"].update(
        images={"target": "ubuntu24 20261116.376.1"}, kernels={"target": "7.0.0-1017-azure"}
    )
    after["source"]["setup"]["sensors"]["auditd"] = "6" * 64
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
        "of an audit key that only one run's audit rules define, and the other run holds nothing of it",
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
    assert history["verdict"].endswith(
        "; it rests on 1 event of the audit key `shell-history`, which only the after run's audit rules define, "
        "the only events either run holds of the step, on two runners that differed (the image of host "
        "`target`, the kernel of host `target`); one pair of runs"
    )
    assert (discovery["result"], "mark" in discovery) == ("not attributable", False)
    assert discovery["verdict"] == (
        "not attributable: the two runners differed (the image of host `target`, the kernel of host `target`), "
        "the control changed too, and the step does not carry the change's own mark (both runs hold events of "
        "it), so this is run variation or the runners' difference; one pair of runs"
    )
    assert {step["result"] for step in delta["steps"][2:]} == {"same"}
    assert (delta["counts"]["same"], delta["unexplained"]) == (89, ["test:23b91cd2"])
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
