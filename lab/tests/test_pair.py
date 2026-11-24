"""Whether a change to the defense needs a pair of runs, as "bluefire-lab pair" prints it for the workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bluefire_lab.__main__ import main

RULE = "title: Private Key Files Searched With Find\nid: rule-ours\nlevel: high\n"


def a_lab(folder: Path, audit: str = "-w {home}/.bashrc -p wa -k shell-start\n", rule: str = RULE) -> Path:
    """A lab folder with what a run loads of the defense, and a file it does not load."""

    (folder / "sensors").mkdir(parents=True)
    (folder / "sensors" / "sysmon.xml").write_text("<Sysmon schemaversion='4.81'/>\n", encoding="utf-8")
    (folder / "sensors" / "audit.rules").write_text(audit, encoding="utf-8")
    (folder / "rules" / "linux" / "process_creation").mkdir(parents=True)
    (folder / "rules" / "linux" / "process_creation" / "find_keys.yml").write_text(rule, encoding="utf-8")
    (folder / "README.md").write_text("The lab.\n", encoding="utf-8")
    return folder


def decided(capsys: pytest.CaptureFixture[str], head: Path, base: Path | None = None) -> dict[str, str]:
    assert main(["pair", *(["--base", str(base)] if base else []), str(head)]) == 0
    lines = capsys.readouterr().out.splitlines()
    return dict(line.split("=", 1) for line in lines)


def test_a_run_without_a_base_commit_runs_once(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    head = a_lab(tmp_path / "head")

    said = decided(capsys, head)
    missing = decided(capsys, head, tmp_path / "base" / "lab")  # the base checkout was not made

    assert (said["pair"], json.loads(said["sides"]), said["change"]) == ("no", ["head"], "")
    assert missing == said


def test_the_same_files_need_no_pair_whatever_else_changed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base, head = a_lab(tmp_path / "base"), a_lab(tmp_path / "head")
    (head / "README.md").write_text("The lab, described again.\n", encoding="utf-8")

    said = decided(capsys, head, base)

    assert (said["pair"], json.loads(said["sides"]), said["change"]) == ("no", ["head"], "")
    assert "the same as the base commit's" in said["said"]


def test_a_change_of_the_audit_rules_alone_is_two_runs_that_declare_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = a_lab(tmp_path / "base")
    head = a_lab(
        tmp_path / "head", audit="-w {home}/.bashrc -p wa -k shell-start\n-w {home}/.bash_history -p wa\n"
    )

    said = decided(capsys, head, base)

    assert (said["pair"], json.loads(said["sides"]), said["change"]) == (
        "runs",
        ["base", "head"],
        "sensors:auditd",
    )
    # The sentence claims nothing about the rest of the pull request, only that both runs share it.
    assert said["said"].startswith("Of the defense, this pull request changes only the rules of auditd:")
    assert said["said"].endswith("Both runs use this commit's code, list and tools.")


def test_a_change_of_the_lab_rules_alone_is_one_run_evaluated_twice(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = a_lab(tmp_path / "base")
    head = a_lab(tmp_path / "head", rule=RULE + "status: test\n")

    said = decided(capsys, head, base)

    # Only the head's side runs the list; the base commit's rules are evaluated over its telemetry.
    assert (said["pair"], json.loads(said["sides"]), said["change"]) == ("rules", ["head"], "detectors:lab")
    assert said["said"].startswith("Of the defense, this pull request changes only the lab's own rules.")
    assert "the list runs once" in said["said"] and "evaluated twice" in said["said"]


def test_a_lab_rule_moved_to_another_file_is_a_change_of_the_lab_rules(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base, head = a_lab(tmp_path / "base"), a_lab(tmp_path / "head")
    folder = head / "rules" / "linux" / "process_creation"
    (folder / "find_keys.yml").rename(folder / "find_private_keys.yml")

    said = decided(capsys, head, base)

    assert (said["pair"], said["change"]) == ("rules", "detectors:lab")


def test_more_than_one_change_runs_twice_and_declares_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = a_lab(tmp_path / "base")
    head = a_lab(tmp_path / "head", audit="-w {home}/.bash_history -p wa\n", rule=RULE + "status: test\n")

    said = decided(capsys, head, base)

    # The lab's rules changed too, but with a sensor change the telemetry differs: two runs, no verdict.
    assert (said["pair"], json.loads(said["sides"]), said["change"]) == ("runs", ["base", "head"], "")
    assert "the rules of auditd and the lab's own rules" in said["said"]
    assert "no one change is declared, so the comparison gives no verdict" in said["said"]
