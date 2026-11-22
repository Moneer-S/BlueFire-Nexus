"""The answers of several runners combined, on results documents built by hand."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_report import results as a_report

from bluefire_lab import combine, evaluate, report


def a_run(role, guid, execution="took effect", visibility="telemetry only", lab=None, **extra) -> dict:
    seen = {"answer": visibility, "rules": [], "with_lab_rules": {"answer": lab or visibility, "rules": []}}
    return {"role": role, "guid": guid, "technique": "T1", "name": f"test {guid}", "order": 1,
            "execution": {"answer": execution, "basis": "the effect check exited with status 0"},
            "visibility": seen, **extra}  # fmt: skip


def a_runner(*tests, controls_pass=True, lab_rules=()) -> dict:
    return {"run": {"id": "r", "started": "2026-11-22T04:00:00Z", "target": {"kernel": "7.0.0-1017-azure"}},
            "controls": [{"name": "loss", "passed": controls_pass, "detail": "the sensor lost 0 events"}],
            "summary": {}, "tests": list(tests), "lab_rules": list(lab_rules)}  # fmt: skip


def test_telemetry_without_an_alert_is_a_gap_a_rule_could_close_only_where_it_shows_the_technique() -> None:
    tests = [
        a_run("test", "a", shows_technique=True),
        a_run("test", "b", shows_technique=False),
        a_run("test", "c"),  # not judged
        a_run("test", "d", visibility="alert", shows_technique=True),
        a_run("test", "e", execution="attempted without effect", shows_technique=True),
    ]

    summary = evaluate.summarize(tests)

    assert summary["telemetry_only"] == 3
    assert summary["gaps_a_rule_could_close"] == 1
    assert summary["telemetry_beside_the_technique"] == 1
    assert summary["telemetry_not_judged"] == 1


def test_an_answer_every_runner_gave_is_the_answer() -> None:
    runners = [a_runner(a_run("test", "a", visibility="alert"), a_run("test", "b")) for _ in range(3)]

    combined = combine.combine(runners)

    assert [test.get("unstable") for test in combined["tests"]] == [None, None]
    assert combined["summary"]["tests"] == 2
    assert (combined["summary"]["alert"], combined["summary"]["telemetry_only"]) == (1, 1)
    assert combined["summary"]["unstable"] == 0
    assert len(combined["runners"]) == 3


def test_an_answer_the_runners_did_not_agree_on_is_unstable_and_in_no_total() -> None:
    steady = a_run("test", "a", visibility="alert")
    runners = [
        a_runner(steady, a_run("test", "b", lab="alert")),
        a_runner(steady, a_run("test", "b", lab="alert")),
        a_runner(steady, a_run("test", "b")),  # here the sensor missed the event the rule needs
    ]

    combined = combine.combine(runners)
    unstable = combined["tests"][1]

    assert unstable["unstable"] == ["with the lab's rules"]
    assert unstable["visibility"]["answer"] == "telemetry only"  # the first answer is the same everywhere
    assert unstable["visibility"]["with_lab_rules"]["answer"] == "unstable"
    assert [runner["with the lab's rules"] for runner in unstable["runners"]] == [
        "alert",
        "alert",
        "telemetry only",
    ]
    # Only the test all three agree on counts as an alert with the lab's rules.
    assert combined["summary"]["alert_with_lab_rules"] == 1
    assert combined["summary"]["telemetry_only"] == 1
    assert combined["summary"]["unstable"] == 1


def test_a_technique_that_took_effect_on_some_runners_only_is_unstable() -> None:
    runners = [
        a_runner(a_run("test", "a")),
        a_runner(a_run("test", "a", execution="attempted without effect")),
    ]

    combined = combine.combine(runners)

    assert combined["tests"][0]["execution"]["answer"] == "unstable"
    assert "took effect, attempted without effect" in combined["tests"][0]["execution"]["basis"]
    assert combined["summary"]["took_effect"] == 0


def test_a_test_that_runs_twice_is_matched_in_order_and_one_a_runner_left_out_is_unstable() -> None:
    first = a_runner(a_run("canary", "c", visibility="alert"), a_run("canary", "c", visibility="alert"))
    second = a_runner(
        a_run("canary", "c", visibility="alert"),
        a_run("canary", "c", visibility="alert"),
        a_run("test", "only-here"),
    )

    combined = combine.combine([first, second])

    assert [test.get("unstable") for test in combined["tests"][:2]] == [None, None]
    assert combined["tests"][2]["runners"][0]["execution"] == "not run"
    assert combined["tests"][2]["execution"]["answer"] == "unstable"


def test_a_rule_of_the_labs_own_counts_only_when_every_runner_accepted_it() -> None:
    def verdict(accepted: bool) -> dict:
        reason = "it alerted on every run" if accepted else "it matched no event of a test"
        return {"id": "rule-1", "title": "A Rule", "accepted": accepted, "reason": reason}

    runners = [a_runner(lab_rules=[verdict(True)]), a_runner(lab_rules=[verdict(False)])]

    rule = combine.combine(runners)["lab_rules"][0]

    assert not rule["accepted"]
    assert rule["reason"] == "not accepted on every runner; runner 2: it matched no event of a test"


def test_a_control_that_failed_on_one_runner_fails_the_run() -> None:
    combined = combine.combine([a_runner(), a_runner(controls_pass=False), a_runner()])

    assert combined["controls"] == [
        {"name": "loss", "passed": False, "detail": "runner 2: the sensor lost 0 events"}
    ]
    assert [runner["controls_passed"] for runner in combined["runners"]] == [True, False, True]


def test_the_command_writes_the_combined_answers_and_fails_with_a_failed_control(tmp_path: Path) -> None:
    for name, passed in (("lab-run-1", True), ("lab-run-2", False)):
        (tmp_path / name).mkdir()
        (tmp_path / name / "results.json").write_text(
            json.dumps(a_runner(a_run("test", "a"), controls_pass=passed))
        )

    assert combine.main(tmp_path) == 1
    written = json.loads((tmp_path / "results.json").read_text())
    assert [runner["folder"] for runner in written["runners"]] == ["lab-run-1", "lab-run-2"]

    (tmp_path / "lab-run-2").rename(tmp_path / "unfinished")
    (tmp_path / "unfinished" / "results.json").unlink()
    with pytest.raises(SystemExit, match="at least two"):
        combine.main(tmp_path)


def test_the_report_shows_an_unstable_answer_with_each_runners_answer() -> None:
    runners = [a_report(), a_report(), a_report()]
    runners[2]["tests"][2]["visibility"]["answer"] = "no telemetry"

    combined = combine.combine(runners)
    page, summary = report.html_report(combined), report.markdown_summary(combined)

    assert "each of 3 GitHub-hosted runners" in page
    assert "runners: telemetry only, telemetry only, no telemetry" in page
    assert "unstable (runners: telemetry only, telemetry only, no telemetry)" in summary
    assert "1 test got different answers on different runners" in summary
    # The stable alert still counts, the unstable answer is in no total.
    assert "Of those, 1 raised an alert, 0 left telemetry but no alert, and 0 left no telemetry" in summary
