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


def with_a_hardened_run() -> dict:
    document = results()
    change = {"name": "lock", "title": "the history file made immutable", "why": "A reason.",
              "apply": "chattr +i <script>", "revert": "chattr -i", "applied": True, "reverted": True}  # fmt: skip
    run = a_test(4, "hardened", "Clear Bash history (rm)", "blocked", "telemetry only")
    run.update(defense=change, compared_with=2, output="rm: cannot remove: Operation not permitted")
    document["tests"].insert(3, run)
    document["summary"].update(hardened=1, blocked=1)
    return document


def test_a_hardened_run_is_shown_beside_the_same_test_without_the_change() -> None:
    page = report.html_report(with_a_hardened_run())

    section = page[page.index("<h2>With a hardening change</h2>") : page.index("<h2>Controls</h2>")]
    assert '<a href="#t4">Clear Bash history (rm)</a>' in section
    assert "the history file made immutable" in section
    assert section.index(">took effect<") < section.index(">blocked<")
    evidence = page[page.index('id="t4"') :]
    assert "Operation not permitted" in evidence
    assert "chattr +i &lt;script&gt;" in evidence
    assert "1 test ran again with a hardening change in place, and 1 of those changes blocked" in page


def test_a_run_without_hardening_has_no_hardening_section() -> None:
    assert "With a hardening change" not in report.html_report(results())
    assert "Hardening change" not in report.markdown_summary(results())


def test_the_summary_shows_the_hardened_runs() -> None:
    summary = report.markdown_summary(with_a_hardened_run())

    row = "| T1070.003 | Clear Bash history (rm) | the history file made immutable | took effect | blocked | telemetry only |"
    assert row in summary


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


def with_a_lab_rule(accepted=True) -> dict:
    document = results()
    rule = {
        **RULE,
        "id": "lab-1",
        "title": "Shell History File Emptied",
        "origin": "lab",
        "file": "linux/x.yml",
    }
    document["tests"][2]["visibility"]["with_lab_rules"] = {
        "answer": "alert" if accepted else "telemetry only",
        "rules": [{**rule, "accepted": accepted}],
    }
    document["summary"]["alert_with_lab_rules"] = 2
    reason = (
        "it alerted on every run with changed input arguments and on no ordinary activity"
        if accepted
        else "it matched 1 event of ordinary activity"
    )
    document["lab_rules"] = [
        {**rule, "accepted": accepted, "reason": reason, "procedures": 1, "ordinary_matches": [] if accepted else [7],
         "fires_on": [{"order": 3, "technique": "T1070.003", "guid": "g", "name": "Some | discovery"}],
         "variants": [{"order": 9, "technique": "T1070.003", "name": "x", "compared_with": 3, "args": {},
                       "took_effect": True, "alerted": True}]}
    ]  # fmt: skip
    document["ordinary_activity"] = {"baseline_events": 40, "system_events": 900, "pinned_rules": []}
    return document


def test_the_labs_rules_have_their_own_column_and_section() -> None:
    page = report.html_report(with_a_lab_rule())

    assert "<th>With the lab's rules too</th>" in page
    section = page[page.index("<h2>The lab's own rules</h2>") : page.index("<h2>Controls</h2>")]
    assert "Shell History File Emptied" in section
    assert "alerted on 1 of 1" in section
    assert ">accepted<" in section
    assert "The baseline of ordinary activity left 40 events" in section
    assert "outside the tests left 900 events" in section
    assert "With the lab's own rules as well, 2 of the 2 raised an alert." in report.markdown_summary(
        with_a_lab_rule()
    )


def test_a_rule_that_is_not_accepted_says_why() -> None:
    page, summary = (
        report.html_report(with_a_lab_rule(False)),
        report.markdown_summary(with_a_lab_rule(False)),
    )

    assert ">not accepted<" in page
    assert "It matched 1 event of ordinary activity." in page
    assert "not accepted: it matched 1 event of ordinary activity" in summary
    assert "| telemetry only (high: Shell History File Emptied, not accepted) |" in summary


def test_the_report_shows_the_inventory_of_the_target() -> None:
    document = results()
    document["run"]["inventory"] = {
        "accounts": ["bluefire-lab", "root"],
        "services": ["cron.service", "ssh.service"],
        "listening": ["tcp 0.0.0.0:22"],
        "sensors": {"sysmon": "active", "auditd": "active"},
        "programs": {"crontab": "/usr/bin/crontab", "systemctl": ""},
    }

    page = report.html_report(document)

    assert "2 accounts that can log in, 2 running services, 1 listening address." in page
    section = page[page.index('id="inventory"') :]
    rows = [
        ("Accounts that can log in", "bluefire-lab, root"),
        ("Running services", "cron.service, ssh.service"),
        ("Listening addresses", "tcp 0.0.0.0:22"),
        ("Sensors", "sysmon active, auditd active"),
        ("Programs the tests need", "crontab at /usr/bin/crontab, systemctl at none"),
    ]
    for label, value in rows:
        assert f'<tr><td>{label}</td><td class="mono wide">{value}</td></tr>' in section
    assert 'under <a href="#left-out">Tests left out</a>' in section
    assert '<h2 id="left-out">Tests left out</h2>' in page
    assert "Inventory of the target" not in report.html_report(results())
    document["run"]["inventory"]["listening"].append("udp 127.0.0.53%lo:53")
    assert "2 listening addresses." in report.html_report(document)


def test_the_report_says_how_many_rules_could_not_match_under_this_configuration() -> None:
    document = results()
    document["engine"]["counts"] = [
        {"category": "auditd", "origin": "pinned", "unmatchable": 27, "needed_types": ["EXECVE"]}
    ]

    page = report.html_report(document)

    assert "(27 of the auditd rules need EXECVE records, which this configuration does not produce)" in page


def test_the_run_page_lists_each_test_left_out_with_the_reason() -> None:
    summary = report.markdown_summary(results())

    assert "| T1003 | A dropped test | reads other processes' memory |" in summary
