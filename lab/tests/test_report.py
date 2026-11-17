"""The report, rendered from a small results document built by hand."""

from __future__ import annotations

import json
from pathlib import Path

from bluefire_lab import report

RULE = {
    "id": "1182f3b3-e716-4efa-99ab-d2685d04360f",
    "title": "History File Deletion",
    "level": "high",
    "author": "Florian Roth (Nextron Systems)",
    "file": "linux/process_creation/proc_creation_lnx_susp_history_delete.yml",
    "text": "title: History File Deletion\nlevel: high\n",
    "records": [7],
    "alert": True,
}
EVENT = {
    "record": 7,
    "time": "2026-11-16 04:00:05.010",
    "kind": "process start",
    "process_id": "121",
    "user": "bluefire-lab",
    "image": "/usr/bin/rm",
    "detail": "rm /home/bluefire-lab/.bash_history <script>alert(1)</script>",
    "why": "session",
    "fields": {"Image": "/usr/bin/rm", "CommandLine": "rm /home/bluefire-lab/.bash_history"},
}


def a_test(order, role, name, execution, visibility, rules=()) -> dict:
    seen = {
        "answer": visibility,
        "basis": "a reason",
        "window": ["2026-11-16 04:00:01.000", "2026-11-16 04:00:06.000"],
    }
    seen.update(events=1, events_by_kind={"process start": 1}, rules=list(rules), launcher_only_rules=[])
    seen["launcher"] = {**EVENT, "record": 5, "detail": "sh -c rm ~/.bash_history"}
    done = {
        "answer": execution,
        "basis": "the effect check exited with status 0",
        "prerequisites": "none declared",
    }
    done.update(
        exit_code=0,
        timed_out=False,
        effect_check={"command": "test ! -e ~/.bash_history", "exit_status": 0, "output": ""},
    )
    return {"order": order, "role": role, "technique": "T1070.003", "guid": "g", "name": name, "executor": "sh",
            "elevated": False, "user": "bluefire-lab", "execution": done, "visibility": seen, "events": [EVENT]}  # fmt: skip


def results(controls_pass=True) -> dict:
    return {
        "run": {
            "id": "r1",
            "started": "2026-11-16T04:00:00Z",
            "target": {
                "os": "Ubuntu 24.04.5 LTS",
                "kernel": "7.0.0-1017-azure",
                "runner_image": "ubuntu24 20261111.370.1",
            },
            "tools": {"atomic-red-team": "a" * 40, "invoke-atomicredteam": "b" * 40, "powershell": "7.6.10"},
        },
        "sensor": {
            "name": "Sysmon for Linux",
            "version": "1.6.0",
            "events": 300,
            "configuration_sha256": "c" * 64,
            "configuration_text": '<Sysmon schemaversion="4.81"/>',
        },  # fmt: skip
        "rules": {
            "source": "SigmaHQ/sigma@" + "d" * 40,
            "license": "Detection Rule License 1.1",
            "evaluated": {"process_creation": 122},
            "alert_levels": ["high", "critical"],
        },  # fmt: skip
        "engine": {"name": "Zircolite", "version": "4.7.1"},
        "controls": [
            {"name": "loss", "passed": controls_pass, "detail": "the sensor reported 0 lost events"}
        ],
        "summary": {
            "tests": 2,
            "took_effect": 2,
            "alert": 1,
            "telemetry_only": 1,
            "no_telemetry": 0,
            "inconclusive": 0,
        },
        "tests": [
            a_test(1, "canary", "Canary run", "took effect", "alert", [RULE]),
            a_test(2, "test", "Clear Bash history (rm)", "took effect", "alert", [RULE]),
            a_test(3, "test", "Some | discovery", "took effect", "telemetry only"),
        ],
        "dropped": [
            {"technique": "T1003", "name": "A dropped test", "reason": "reads other processes' memory"}
        ],
    }


def test_the_report_is_one_file_that_loads_nothing(tmp_path: Path) -> None:
    (tmp_path / "results.json").write_text(json.dumps(results()), encoding="utf-8")

    report.main(tmp_path)
    page = (tmp_path / "report.html").read_text(encoding="utf-8")

    assert report.loads_anything(page) == []
    assert chr(0x2014) not in page  # the em dash


def test_the_offline_check_finds_what_would_fetch_something() -> None:
    for page in (
        '<img alt="" src="https://example.org/a.png">',
        "<style>body { background: url(a.png) }</style>",
        "<style>@import 'a.css';</style>",
        '<object data="a.pdf"></object>',
        '<video poster="a.png"></video>',
        "<script>fetch('/a')</script>",
    ):
        assert report.loads_anything(page), page
    assert report.loads_anything('<a href="https://github.com">a link</a><p>url(a) in text</p>') == []


def test_the_table_comes_first_and_leads_to_the_events_and_the_rule() -> None:
    page = report.html_report(results())

    table, evidence = page.index("<table"), page.index('id="t2"')
    assert page.index("<h1>") < table < evidence
    assert '<a href="#t2">Clear Bash history (rm)</a>' in page
    assert "History File Deletion" in page[evidence:]
    assert "Florian Roth (Nextron Systems)" in page[evidence:]
    assert "rm /home/bluefire-lab/.bash_history" in page[evidence:]
    assert f"https://github.com/SigmaHQ/sigma/blob/{'d' * 40}/rules/{RULE['file']}" in page


def test_text_from_telemetry_cannot_become_markup() -> None:
    page = report.html_report(results())

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_the_report_states_what_was_measured_with() -> None:
    page = report.html_report(results())

    for fact in ("2026-11-16", "7.0.0-1017-azure", "ubuntu24 20261111.370.1", "Sysmon for Linux 1.6.0",
                 "Zircolite 4.7.1", "aaaaaaaaaaaa", "dddddddddddd", "schemaversion", "A dropped test"):  # fmt: skip
        assert fact in page


def test_a_failed_control_is_said_at_the_top() -> None:
    sound, broken = report.html_report(results()), report.html_report(results(controls_pass=False))

    assert "does not support its results" not in sound
    assert broken.index("does not support its results") < broken.index("<table")
    assert "does not support its results" in report.markdown_summary(results(controls_pass=False))


def test_a_rule_that_matched_only_the_launcher_is_shown_and_not_counted() -> None:
    document = results()
    document["tests"][2]["visibility"]["launcher_only_rules"] = [{**RULE, "level": "medium"}, RULE]

    page, summary = report.html_report(document), report.markdown_summary(document)

    assert "2 rules (high, medium) matched only the launcher line, not counted" in page
    assert (
        "| telemetry only | none (2 rules (high, medium) matched only the launcher line, not counted) | 1 |"
        in summary
    )


def test_the_summary_is_the_same_table_in_markdown() -> None:
    summary = report.markdown_summary(results())

    assert "2 published attack tests ran on a GitHub-hosted runner" in summary
    assert (
        "| T1070.003 | Clear Bash history (rm) | took effect | alert | high: History File Deletion | 1 |"
        in summary
    )
    assert "| T1070.003 | Some \\| discovery | took effect | telemetry only | none | 1 |" in summary
    assert "Canary run" not in summary.split("| Control |")[0]
    assert "| loss | passed |" in summary
