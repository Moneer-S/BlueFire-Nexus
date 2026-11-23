"""The defense of a range, judged on files captured from real runs of lab/range/wazuh-check.yaml.

The stock ossec.conf files are excerpts of those the pinned Wazuh agent package
and manager image install. The delivery, state and agent_control fixtures are
trimmed from one run on Docker 29: its run ID is replaced by a stand-in.
"""

import gzip
import io
import json
import re
import subprocess
import tarfile
import time
from pathlib import Path

import pytest

from bluefire_lab.range import build, engine, ossec, wazuh
from bluefire_lab.range import spec as range_spec

FIXTURES = Path(__file__).parent / "fixtures" / "range" / "wazuh"
WAZUH_CHECK = Path(__file__).parents[1] / "range" / "wazuh-check.yaml"
AGENT_STOCK = (FIXTURES / "agent-ossec.conf.stock").read_text()
MANAGER_STOCK = (FIXTURES / "manager-ossec.conf.stock").read_text()
WEB = {
    "name": "web",
    "manager": "manager",
    "logs": [
        {"path": "/var/log/auth.log", "format": "syslog"},
        {"path": "/var/log/dpkg.log", "format": "syslog"},
    ],
    "fim_realtime": ["/etc", "/tmp"],
    "off": ["command_monitoring", "sca", "rootcheck", "syscollector"],
}


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_the_agent_reports_to_the_manager_and_enrolls_itself_as_its_host() -> None:
    text, _ = ossec.agent(AGENT_STOCK, WEB)

    assert "<address>manager</address>" in text
    assert "<auto_restart>no</auto_restart>" in text
    assert "<agent_name>web</agent_name>" in text
    assert "<delay_after_enrollment>1</delay_after_enrollment>" in text


def test_the_agent_collects_the_watched_logs_and_watches_the_folders_in_real_time() -> None:
    text, changes = ossec.agent(AGENT_STOCK, WEB)

    assert "<location>/var/log/auth.log</location>" in text
    # The stock file collects dpkg.log already: it is not added a second time.
    assert text.count("<location>/var/log/dpkg.log</location>") == 1
    assert '<directories realtime="yes">/etc,/tmp</directories>' in text
    # /etc leaves the stock scan every 12 hours, so that only the real-time line names it.
    assert "<directories>/usr/bin,/usr/sbin</directories>" in text
    assert [c["change"] for c in changes if c["label"] == ossec.LAB] == [
        "collects /var/log/auth.log (syslog)",
        "file integrity monitoring in real time (inotify) on /etc, /tmp "
        "(/etc moved from the stock file's scan every 12 hours)",
    ]


def test_the_features_switched_off_are_disabled_and_the_others_stay_as_stock() -> None:
    every, _ = ossec.agent(AGENT_STOCK, WEB)
    only_sca, changes = ossec.agent(AGENT_STOCK, {**WEB, "off": ["sca"]})

    assert "<command>" not in every
    assert "<sca>\n    <enabled>no</enabled>" in every
    assert "<rootcheck>\n    <disabled>yes</disabled>" in every
    assert '<wodle name="syscollector">\n    <disabled>yes</disabled>' in every
    assert "<command>df -P</command>" in only_sca
    assert "<rootcheck>\n    <disabled>no</disabled>" in only_sca
    assert [c["change"] for c in changes if c["label"] == ossec.REMOVED] == [
        "security configuration assessment (sca), not live telemetry of what happens on the host"
    ]


def test_the_diff_shows_the_stock_and_the_range_lines_of_the_labelled_edits() -> None:
    text, changes = ossec.agent(AGENT_STOCK, WEB)
    diff = ossec.diff(AGENT_STOCK, text)

    assert diff.startswith("--- ossec.conf (stock)\n+++ ossec.conf (range)\n")
    assert {c["label"] for c in changes} == set(ossec.LABELS)
    removed = [
        line[1:].strip() for line in diff.splitlines() if line.startswith("-") and not line.startswith("---")
    ]
    added = [
        line[1:].strip() for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")
    ]
    assert "<command>last -n 20</command>" in removed
    assert "<auto_restart>yes</auto_restart>" in removed
    assert "<auto_restart>no</auto_restart>" in added
    assert [c["change"].split(":")[0] for c in changes if c["label"] == ossec.STARTUP] == [
        "the agent reports to manager, the manager's name in the range",
        "auto_restart no",
        "enrollment",
    ]


def test_the_manager_archives_every_event_and_drops_what_needs_an_indexer_or_the_internet() -> None:
    text, changes = ossec.manager(MANAGER_STOCK)

    assert "<logall_json>yes</logall_json>" in text
    assert "<vulnerability-detection>\n    <enabled>no</enabled>" in text
    assert "<indexer>\n    <enabled>no</enabled>" in text
    assert "<update_check>no</update_check>" in text
    assert "<syscheck>\n    <disabled>yes</disabled>" in text
    # The second <global> block, with the white list, is left as it is.
    assert "<white_list>127.0.0.1</white_list>" in text
    assert [c["label"] for c in changes].count(ossec.LAB) == 1
    assert "<use_password>no</use_password>" in text


def test_a_stock_file_without_the_text_an_edit_expects_stops_the_edit() -> None:
    changed = AGENT_STOCK.replace("<address>MANAGER_IP</address>", "<address>10.0.0.1</address>")

    with pytest.raises(ossec.ConfError, match="<address>MANAGER_IP</address>"):
        ossec.agent(changed, WEB)


def test_the_build_writes_the_files_the_engine_would_make(tmp_path: Path) -> None:
    settings = {"manager": "manager", "agents": {"web": WEB}}
    (tmp_path / "settings.json").write_text(json.dumps(settings))
    (tmp_path / "manager.conf").write_text(MANAGER_STOCK)
    (tmp_path / "agent.conf").write_text(AGENT_STOCK)

    code = ossec.main(
        [str(tmp_path / n) for n in ("settings.json", "manager.conf", "agent.conf")] + [str(tmp_path / "out")]
    )

    assert code == 0
    assert (tmp_path / "out" / "web" / "ossec.conf").read_text() == ossec.agent(AGENT_STOCK, WEB)[0]
    assert (tmp_path / "out" / "manager" / "ossec.conf").read_text() == ossec.manager(MANAGER_STOCK)[0]


def test_the_lab_decoder_reads_the_fields_of_a_real_snoopy_line() -> None:
    pattern = re.search(r'<regex type="pcre2">(.*)</regex>', build.SNOOPY_DECODER).group(1)
    order = re.search(r"<order>(.*)</order>", build.SNOOPY_DECODER).group(1).split(", ")
    line = next(
        event["full_log"]
        for event in fixture("delivery-web.json")["archive"]
        if "bluefire-mark-program" in event["full_log"] and event["location"] == "/var/log/snoopy.log"
    )
    message = line.split(": ", 1)[1]

    fields = dict(zip(order, re.match(pattern, message).groups(), strict=True))

    assert fields["tag"] == "engine:mark"
    assert fields["command"] == "/bin/echo bluefire-mark-program-20261123T000000Z-000000"
    assert fields["uid"] == "0"
    # What Wazuh decoded from the same line, in the run.
    decoded = next(e for e in fixture("delivery-web.json")["archive"] if e["full_log"] == line)
    assert decoded["data"] == fields


def delivery(recorded: dict) -> list[dict]:
    return wazuh.delivery(
        recorded["agent"],
        recorded["logs"],
        {path: tuple(span) for path, span in recorded["windows"].items()},
        recorded["archive"],
        recorded["nonces"]["ready"],
        recorded["nonces"]["end"],
    )


def test_every_line_from_the_ready_nonce_to_the_end_reached_the_archive() -> None:
    recorded = fixture("delivery-web.json")

    assert delivery(recorded) == recorded["expected"]
    assert [(row["source"], row["lines"], row["missing"]) for row in delivery(recorded)] == [
        ("/var/log/auth.log", 8, 0),
        ("/var/log/snoopy.log", 35, 0),
        ("/var/log/dpkg.log", 0, 0),
    ]


def test_a_line_the_archive_lacks_is_counted_missing_and_lines_outside_the_window_do_not_count() -> None:
    recorded = fixture("delivery-web.json")
    mark = next(
        e
        for e in recorded["archive"]
        if "bluefire-mark-2-" in e["full_log"] and e["location"] == "/var/log/auth.log"
    )
    before = recorded["logs"]["/var/log/auth.log"][0]
    recorded["archive"] = [e for e in recorded["archive"] if e is not mark and e["full_log"] != before]

    rows = {row["source"]: row for row in delivery(recorded)}

    assert rows["/var/log/auth.log"]["missing"] == 1
    assert rows["/var/log/auth.log"]["delivered"] == 7
    assert rows["/var/log/snoopy.log"]["missing"] == 0


def test_a_line_lost_in_the_window_is_missing_although_the_same_line_outside_it_reached_the_archive() -> None:
    recorded = fixture("delivery-web.json")
    path = "/var/log/auth.log"
    start, end = recorded["windows"][path]
    inside = recorded["logs"][path][start + 1]
    assert [e["full_log"] for e in recorded["archive"] if e["location"] == path].count(inside) == 1
    # The same line once more after the window. The archive's one event with it is now that line's,
    # and the line inside the window was lost.
    recorded["logs"][path].append(inside)

    rows = {row["source"]: row for row in delivery(recorded)}

    assert rows[path]["missing"] == 1
    assert end < len(recorded["logs"][path])


def test_a_log_that_was_not_copied_or_is_shorter_than_its_window_is_not_counted() -> None:
    recorded = fixture("delivery-web.json")
    recorded["logs"]["/var/log/auth.log"] = None
    recorded["logs"]["/var/log/snoopy.log"] = recorded["logs"]["/var/log/snoopy.log"][:10]

    rows = {row["source"]: row for row in delivery(recorded)}

    assert rows["/var/log/auth.log"]["missing"] is None
    assert rows["/var/log/auth.log"]["not counted"] == "the file was not copied out of the host"
    assert rows["/var/log/snoopy.log"]["missing"] is None
    assert "the copied file has 10 lines" in rows["/var/log/snoopy.log"]["not counted"]
    assert rows["/var/log/dpkg.log"]["missing"] == 0


def test_a_log_is_split_into_lines_at_newlines_only_as_the_engine_counts_them() -> None:
    # A command line with a line separator in it is one line of snoopy.log.
    content = "one\nsnoopy: /bin/echo a b\x0cc\nthree\n"

    assert wazuh.lines_of(content) == ["one", "snoopy: /bin/echo a b\x0cc", "three"]
    assert wazuh.lines_of("one\npartial") == ["one", "partial"]


def test_an_event_of_another_agent_with_the_same_line_does_not_count_as_delivered() -> None:
    recorded = fixture("delivery-web.json")
    for event in recorded["archive"]:
        if event["location"] == "/var/log/auth.log":
            event["agent"] = {"name": "db"}

    rows = {row["source"]: row for row in delivery(recorded)}

    assert rows["/var/log/auth.log"]["missing"] == 8


def test_the_drop_counters_are_read_from_wazuhs_state_files() -> None:
    states = {name: wazuh.state(text) for name, text in fixture("states.json").items()}

    counters = wazuh.drops(states)

    assert counters["manager: wazuh-analysisd.state"] == {"events_dropped": "0"}
    assert counters["manager: wazuh-remoted.state"] == {"discarded_count": "0"}
    assert counters["web: wazuh-logcollector.state"]["/var/log/auth.log drops"] == "0"
    until = counters["web: wazuh-logcollector.state"]["counted until"]
    assert until == "2026-11-23 19:52:33"
    assert wazuh.state_time(until) == wazuh.timestamp("2026-11-23T19:52:33.000+0000")
    assert states["web: wazuh-agentd.state"]["status"] == "connected"
    assert not wazuh.dropped(counters)
    states["manager: wazuh-analysisd.state"]["events_dropped"] = "3"
    assert wazuh.dropped(wazuh.drops(states))


def test_the_agent_list_gives_each_agent_its_status_and_version() -> None:
    outputs = fixture("agent-control.json")

    listed = wazuh.agents(outputs["agent_control -l"])
    info = wazuh.agent_info(outputs["agent_control -i 001"])

    assert listed == {"web": {"id": "001", "status": "Active"}}
    assert info == {"status": "Active", "version": "4.14.10"}


def test_the_daily_archive_files_are_read_oldest_first_and_the_link_to_today_is_left_out(
    tmp_path: Path,
) -> None:
    folder = tmp_path / "archives"
    for relative in ("2026/Nov/ossec-archive-30.json.gz", "2026/Dec/ossec-archive-01.json", "archives.json"):
        path = folder / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "wt") as out:
            out.write(json.dumps({"full_log": relative}) + "\n")

    files = wazuh.daily_files(folder)

    assert [p.relative_to(folder).as_posix() for p in files] == [
        "2026/Nov/ossec-archive-30.json.gz",
        "2026/Dec/ossec-archive-01.json",
    ]
    assert [e["full_log"] for e in wazuh.events(files)] == [
        "2026/Nov/ossec-archive-30.json.gz",
        "2026/Dec/ossec-archive-01.json",
    ]


def test_the_engines_counts_and_time_are_read_from_its_command_output() -> None:
    output = "lines\t/var/log/auth.log\t3\nlines\t/var/log/dpkg.log\t2071\ntime\t1795463529.771409\n"

    assert wazuh.window_counts(output) == (
        {"/var/log/auth.log": 3, "/var/log/dpkg.log": 2071},
        1795463529.771409,
    )


def test_the_summary_shows_the_delivery_table_and_the_gap() -> None:
    recorded = fixture("delivery-web.json")
    manifest = {
        "range": "wazuh-check",
        "result": "sealed",
        "exit_code": 0,
        "environment": "GitHub-hosted runner",
        "docker": {"server": "28.0.4"},
        "defense": {
            "wazuh_version": "4.14.10",
            "ready": {"parts": {"manager ports": 10.1}, "nonces": {"web": {"delay_seconds": 1.407}}},
            "delivery": {"web": delivery(recorded)},
            "delivery_gap": False,
            "drops": {"manager: wazuh-analysisd.state": {"events_dropped": "0"}},
        },
    }

    text = wazuh.summary(manifest, seal_passed=True)

    assert text.startswith("### Defense of wazuh-check: no delivery gap")
    assert "| web | /var/log/snoopy.log | 35 | 35 | 0 | 35 |" in text
    assert "| web | /var/log/dpkg.log | 0 | | not shown: no line in the window |" in text
    assert "| web | 1.407 |" in text


def a_run(tmp_path: Path) -> engine.Run:
    """An engine run of wazuh-check.yaml whose containers were never made; its commands are stood in for."""

    run = engine.Run(range_spec.load(WAZUH_CHECK), "wazuh-check.yaml", tmp_path, None, 0)
    run.containers = {"manager": "m" * 64, "web": "w" * 64}
    run.manifest["ready"]["manager"] = {"listening": True, "seconds": 9.0}
    return run


@pytest.mark.parametrize(
    ("state", "log", "message"),
    [
        (
            "status='pending'",
            wazuh.REALTIME_STARTED,
            "the agent on web is not connected, or its real-time file monitoring has not started, within 180 s: "
            "look at raw/hosts/web/var/ossec/logs/ossec.log",
        ),
        (
            "status='connected'",
            "ERROR: (6700): Unable to add inotify watch to real time monitoring: '/etc'. '-1' '28': The maximum "
            f"limit of inotify watches has been reached.\n{wazuh.REALTIME_STARTED}",
            "the agent on web could not watch every folder in real time",
        ),
    ],
)
def test_a_range_whose_agent_is_not_ready_stops_and_says_what_to_look_at(
    tmp_path: Path, state: str, log: str, message: str
) -> None:
    run = a_run(tmp_path)
    files = tmp_path / "host"
    files.mkdir()
    (files / "state").write_text(f"# State\n{state}\n")
    (files / "ossec.log").write_text(log + "\n")

    def execute(identifier: str, script: str, timeout: float, tag: str = "") -> subprocess.CompletedProcess:
        # The engine's check, run by bash here on files that stand in for the host's.
        assert identifier == "w" * 64 and "agent_control" not in script
        script = script.replace(wazuh.AGENT_STATE, str(files / "state")).replace(
            wazuh.OSSEC_LOG, str(files / "ossec.log")
        )
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)

    run.execute = execute

    with pytest.raises(engine.NotReady) as stopped:
        run.defense_ready(time.monotonic(), 180)

    assert message in str(stopped.value)
    assert run.manifest["defense"]["ready"]["parts"] == {
        "manager ports": 9.0,
        "web: agent connected, real-time file monitoring started": None,
    }


def test_a_mark_that_never_reached_the_archive_is_a_delivery_gap(tmp_path: Path) -> None:
    run = a_run(tmp_path)
    run.manifest["defense"]["marks"] = [
        {
            "host": "web",
            "mark": "file created in /etc",
            "source": "syscheck",
            "made": True,
            "archived": False,
        },
        {
            "host": "web",
            "mark": "logger line 1",
            "source": "/var/log/auth.log",
            "made": True,
            "archived": True,
        },
    ]

    run.analyse()

    defense = run.manifest["defense"]
    assert defense["delivery_gap"] is True
    assert defense["delivery_findings"] == ["web: the mark 'file created in /etc' did not reach the archive"]
    assert defense["drops"]["web: wazuh-logcollector.state"] == {"counted until": "not written yet"}


def test_a_copy_out_of_a_host_keeps_its_files_and_folders_and_leaves_out_links(tmp_path: Path) -> None:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, kind, target in (
            ("run", tarfile.DIRTYPE, ""),
            ("run/wazuh-agentd.state", tarfile.REGTYPE, ""),
            ("run/x.state", tarfile.SYMTYPE, "/proc/self/environ"),
            ("run/y.state", tarfile.LNKTYPE, "run/wazuh-agentd.state"),
            ("../outside", tarfile.REGTYPE, ""),
        ):
            member = tarfile.TarInfo(name)
            member.type, member.linkname = kind, target
            data = b"status='connected'\n" if kind == tarfile.REGTYPE else b""
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    stream.seek(0)

    refused = engine.untar(stream, tmp_path / "copy")

    assert refused == [
        "run/x.state: a link to /proc/self/environ",
        "run/y.state: a link to run/wazuh-agentd.state",
        "../outside: a path outside the copy",
    ]
    copied = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))
    assert copied == ["copy", "copy/run", "copy/run/wazuh-agentd.state"]
    assert (tmp_path / "copy" / "run" / "wazuh-agentd.state").read_text() == "status='connected'\n"
