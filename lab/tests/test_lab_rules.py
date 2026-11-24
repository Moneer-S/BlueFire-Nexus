"""The lab's own auditd rule for a history file emptied in place, evaluated by the rule engine the lab
runs, over real records of a CI run and over records built by hand from what the shells do."""

from __future__ import annotations

import shutil
from pathlib import Path

from bluefire_lab import auditd, evaluate

LAB = Path(__file__).resolve().parents[1]
RULE = LAB / "rules" / "linux" / "auditd" / "lnx_auditd_history_file_truncated_in_place.yml"
FIXTURES = Path(__file__).parent / "fixtures" / "auditd"


def matched(engine: Path, folder: Path, log: str) -> tuple[set[str], dict]:
    """The events the rule matched among the records of a log, and what the engine said it loaded and read."""

    (folder / "lab-rules" / "linux" / "auditd").mkdir(parents=True)
    shutil.copy(RULE, folder / "lab-rules" / "linux" / "auditd" / RULE.name)
    records = auditd.read(FIXTURES / log)
    found, counts = evaluate.run_audit_engine(engine, folder, records, "lab-rules")
    assert (counts["origin"], counts["loaded"], counts["read"]) == ("lab", 1, len(records))
    return {event.removeprefix("audit ") for event, ids in found.items() if ids}, counts


def test_the_shells_truncating_write_alerts_and_an_append_or_another_way_does_not(
    engine: Path, tmp_path: Path
) -> None:
    # Real records of run 45350480637, unchanged.
    found, _ = matched(engine, tmp_path, "shell-history-45350480637.txt")

    assert found == {
        "1795506722.104:6375",  # test:cbf506a5, echo "" > ~/.bash_history: O_WRONLY|O_CREAT|O_TRUNC
        "1795506725.899:6501",  # test:b1251c35, cat /dev/null > ~/.bash_history: the same open
    }
    # Not matched, each for its reason: 6206, a preparation's append (>>) to the existing file; 493, an
    # append that created it; 6250, the truncate program, which opens without O_TRUNC and then
    # truncates; 6628, ln -sf, which renames a new link over the file.


def test_an_evaluation_runs_the_lab_auditd_rules_beside_the_pinned_ones_and_counts_them(
    engine: Path, tmp_path: Path
) -> None:
    # What evaluate's main runs over a run's audit log: the pinned auditd rules (none here) and the lab's.
    (tmp_path / "lab-rules" / "linux" / "auditd").mkdir(parents=True)
    shutil.copy(RULE, tmp_path / "lab-rules" / "linux" / "auditd" / RULE.name)
    records = auditd.read(FIXTURES / "shell-history-45350480637.txt")
    lab_rules = evaluate.rule_index(tmp_path / "lab-rules" / "linux", "lab")
    [rule_id] = lab_rules

    found, tally = evaluate.run_audit_engines(engine, tmp_path, records, {}, lab_rules)

    assert {event for event, ids in found.items() if rule_id in ids} == {
        "audit 1795506722.104:6375",
        "audit 1795506725.899:6501",
    }
    assert [(row["origin"], row["category"], row["rules"], row["loaded"]) for row in tally] == [
        ("pinned", "auditd", 0, 0),
        ("lab", "auditd", 1, 1),
    ]


def test_built_records_alert_on_every_truncating_open_that_succeeded_and_on_nothing_else(
    engine: Path, tmp_path: Path
) -> None:
    # Records built by hand, as the fixture's header says, from the shells' and the kernel's source code.
    found, _ = matched(engine, tmp_path, "shell-history-built.txt")

    # bash's append on exit (900001) and its rewrite by a renamed temporary file (900003) do not match,
    # nor does a truncating open the kernel refused (900007). The false positives the rule names do:
    # bash creating a missing file (900002), zsh with HIST_SAVE_BY_COPY unset (900004) and bash 4.3
    # trimming its file (900005). So does the redirect on an older kernel, whose record has two items.
    assert found == {
        "1795600000.002:900002",
        "1795600000.004:900004",
        "1795600000.005:900005",
        "1795600000.006:900006",
    }
