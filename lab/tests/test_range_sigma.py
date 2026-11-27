"""Sigma rules over a run's host events: the row each kind of event becomes, and what the engine matches.

The archive lines are written by hand here, in the shape Wazuh writes them,
and the rules are those made up for the tests (fixtures/range/rule-set).
Nothing in this file was recorded on a machine. The tests that run the rule
engine need its program: pass --engine <path to Zircolite>.
"""

from pathlib import Path

import pytest
import yaml

from bluefire_lab.range import ecs, sigma

RULE_SET = Path(__file__).parent / "fixtures" / "range" / "rule-set"
CORRELATION_SET = Path(__file__).parent / "fixtures" / "range" / "sigma-correlation"
FOLDERS = [
    "rules/linux/process_creation",
    "rules/linux/file_event",
    "rules/linux/builtin",
    "rules/web/webserver_generic",
]


def clock(second: int) -> str:
    """A made-up minute and second within the test hour."""

    minute, second = divmod(second, 60)
    return f"{minute:02d}:{second:02d}"


def snoopy(
    command: str,
    exe: str | None = "/usr/bin/find",
    login: str = "webadmin",
    cwd: str = "/tmp",
    *,
    second: int = 0,
    host: str = "web",
) -> dict:
    data = {"login": login, "cwd": cwd, "tag": "step:s07", "command": command}
    if exe is not None:
        data["exe"] = exe
    line = (
        f"2026-11-01T00:{clock(second)}.000000+00:00 {host} snoopy[7]: "
        f"[login:{login} cwd:{cwd} tag:step:s07]: {command}"
    )
    return {
        "timestamp": f"2026-11-01T00:{clock(second)}.000+0000",
        "agent": {"name": host},
        "location": "/var/log/snoopy.log",
        "full_log": line,
        "predecoder": {"program_name": "snoopy"},
        "decoder": {"name": "bluefire-snoopy"},
        "data": data,
    }


def auth(program: str, text: str, *, second: int = 1, host: str = "web") -> dict:
    return {
        "timestamp": f"2026-11-01T00:{clock(second)}.000+0000",
        "agent": {"name": host},
        "location": "/var/log/auth.log",
        "full_log": f"2026-11-01T00:{clock(second)}.000000+00:00 {host} {program}[9]: {text}",
        "predecoder": {"program_name": program},
    }


def access(
    request: str,
    status: int,
    agent: str = "curl/8.5.0",
    referer: str = "-",
    *,
    second: int = 2,
    host: str = "web",
) -> dict:
    line = (
        f'10.9.0.4 - - [01/Nov/2026:00:{clock(second)} +0000] "{request}" {status} 153 "{referer}" "{agent}"'
    )
    return {
        "timestamp": f"2026-11-01T00:{clock(second)}.000+0000",
        "agent": {"name": host},
        "location": "/var/log/nginx/access.log",
        "full_log": line,
    }


def file_event(path: str, event: str, *, second: int = 3, host: str = "web") -> dict:
    return {
        "timestamp": f"2026-11-01T00:{clock(second)}.000+0000",
        "agent": {"name": host},
        "location": "syscheck",
        "full_log": f"File '{path}' {event}\nMode: realtime\n",
        "syscheck": {"path": path, "event": event},
    }


def test_a_program_start_is_a_row_with_the_path_the_command_line_the_account_and_the_folder() -> None:
    row = sigma.PROCESS.row(snoopy("find /srv/keys -name id_rsa -type f"))

    assert row == {
        "Image": "/usr/bin/find",
        "CommandLine": "find /srv/keys -name id_rsa -type f",
        "User": "webadmin",
        "CurrentDirectory": "/tmp",
    }
    # Other kinds of event are not program starts.
    assert sigma.PROCESS.row(auth("sshd", "Invalid user admin from 10.9.0.2 port 4001")) is None
    assert sigma.PROCESS.row(file_event("/tmp/T1082.txt", "added")) is None


def test_a_program_start_of_a_run_made_before_the_path_was_recorded_has_no_image() -> None:
    row = sigma.PROCESS.row(snoopy("uname -a", exe=None, login="(unknown)"))

    # snoopy's word for a login it does not know is no account's name either.
    assert row == {"CommandLine": "uname -a", "CurrentDirectory": "/tmp"}


def test_a_path_snoopy_recorded_relative_to_the_working_folder_is_joined_to_it() -> None:
    assert ecs.executable({"exe": "./atomic.sh", "cwd": "/tmp"}) == "/tmp/atomic.sh"
    assert ecs.executable({"exe": "/usr/bin/grep", "cwd": "/tmp"}) == "/usr/bin/grep"
    assert ecs.executable({"exe": "tools/run", "cwd": "/"}) == "/tools/run"
    assert ecs.executable({"cwd": "/tmp"}) is None
    assert sigma.PROCESS.row(snoopy("./atomic.sh", exe="./atomic.sh"))["Image"] == "/tmp/atomic.sh"


def test_a_file_added_or_changed_is_a_row_with_its_path_and_a_file_removed_is_none() -> None:
    assert sigma.FILE.row(file_event("/tmp/T1082.txt", "added")) == {"TargetFilename": "/tmp/T1082.txt"}
    assert sigma.FILE.row(file_event("/tmp/T1082.txt", "modified")) == {"TargetFilename": "/tmp/T1082.txt"}
    assert sigma.FILE.row(file_event("/tmp/T1082.txt", "deleted")) is None
    assert sigma.FILE.row(snoopy("rm /tmp/T1082.txt")) is None


def test_an_access_line_is_a_row_with_the_fields_the_web_rules_name_taken_from_the_line() -> None:
    event = access("GET /admin.php?id=1 HTTP/1.1", 404, agent="Mozilla/5.0", referer="http://web/")

    assert sigma.WEB.row(event) == {
        "message": event["full_log"],
        "c-ip": "10.9.0.4",
        "sc-status": 404,
        "cs-method": "GET",
        "cs-uri-query": "/admin.php?id=1",
        "cs-uri-stem": "/admin.php",
        "cs-referer": "http://web/",
        "cs-user-agent": "Mozilla/5.0",
    }
    # nginx writes - for a header the request did not send: the row has no such field.
    plain = sigma.WEB.row(access("GET / HTTP/1.1", 200, agent="-"))
    assert "cs-referer" not in plain and "cs-user-agent" not in plain
    # A request nginx could not read has no method and no path, and is still a line.
    broken = sigma.WEB.row(access("\\x16\\x03\\x01", 400))
    assert sorted(broken) == ["c-ip", "cs-user-agent", "message", "sc-status"]
    assert sigma.WEB.row(auth("sshd", "Accepted password for webadmin")) is None


@pytest.mark.parametrize(
    ("logsource", "given", "not_given"),
    [
        # A rule without a service is given every line of a collected log file.
        ({"product": "linux"}, ["sshd", "snoopy", "access"], ["file"]),
        ({"product": "linux", "service": "sshd"}, ["sshd"], ["cron", "snoopy", "access", "file"]),
        ({"product": "linux", "service": "cron"}, ["cron"], ["sshd", "snoopy"]),
        ({"product": "linux", "service": "auth"}, ["sshd", "cron"], ["snoopy", "access"]),
        # Every line with a syslog header, and not a line a program wrote to a file of its own.
        ({"product": "linux", "service": "syslog"}, ["sshd", "cron", "snoopy"], ["access", "file"]),
    ],
)
def test_a_rule_that_looks_for_words_is_given_the_lines_of_its_service_only(
    logsource: dict, given: list[str], not_given: list[str]
) -> None:
    events = {
        "sshd": auth("sshd", "Invalid user admin from 10.9.0.2 port 4001"),
        "cron": auth("CRON", "pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)"),
        "snoopy": snoopy("uname -a"),
        "access": access("GET / HTTP/1.1", 200),
        "file": file_event("/tmp/T1082.txt", "added"),
    }

    source = sigma.source_of(logsource)

    assert [name for name in given if source.row(events[name]) is None] == []
    assert [name for name in not_given if source.row(events[name]) is not None] == []
    assert source.row(events[given[0]]) == {"message": events[given[0]]["full_log"]}


@pytest.mark.parametrize(
    ("logsource", "why"),
    [
        ({"product": "linux", "service": "vsftpd"}, "the lab gives no lines for the service vsftpd"),
        (
            {"product": "windows", "category": "process_creation"},
            "category: process_creation, product: windows",
        ),
        ({"product": "linux", "category": "network_connection"}, "category: network_connection"),
    ],
)
def test_a_rule_of_a_log_source_the_range_has_no_events_of_is_given_nothing(
    logsource: dict, why: str
) -> None:
    assert why in sigma.source_of(logsource)


@pytest.mark.parametrize(
    ("logsource", "source"),
    [
        ({"category": "process_creation"}, sigma.PROCESS),
        ({"product": "linux", "category": "process_creation"}, sigma.PROCESS),
        ({"category": "file_event"}, sigma.FILE),
        ({"product": "linux", "category": "file_event"}, sigma.FILE),
    ],
)
def test_a_generic_or_linux_process_or_file_rule_uses_the_ranges_linux_events(
    logsource: dict, source: sigma.Source
) -> None:
    assert sigma.source_of(logsource) is source


@pytest.mark.parametrize("product", ["windows", "macos"])
@pytest.mark.parametrize("category", ["process_creation", "file_event"])
def test_a_non_linux_process_or_file_rule_never_uses_the_ranges_linux_events(
    product: str, category: str
) -> None:
    assert isinstance(sigma.source_of({"product": product, "category": category}), str)


def test_a_rule_file_is_read_with_its_level_its_author_and_the_fields_it_names() -> None:
    file = "rules/web/webserver_generic/web_made_up_missing_page.yml"

    rule = sigma.read_rule((RULE_SET / file).read_text(), file)

    assert (rule["id"], rule["level"], rule["author"]) == (
        "00000000-0000-4000-8000-000000000008",
        "medium",
        "The lab's tests",
    )
    assert rule["logsource"] == {"category": "webserver"}
    assert rule["fields"] == ["cs-method", "cs-uri-query", "cs-user-agent", "sc-status"]
    assert sigma.read_rule((RULE_SET / "rules/linux/builtin/notes.yml").read_text(), "notes.yml") == (
        "not one Sigma atomic rule or correlation the lab can evaluate"
    )
    assert sigma.read_rule("title: [unclosed\n", "broken.yml") == "not readable as YAML"


@pytest.mark.parametrize("kind", sigma.CORRELATION_TYPES)
def test_each_supported_sigma_v2_correlation_type_is_read_with_its_references(kind: str) -> None:
    text = (
        "title: Made Up - Correlation\nname: made_up_correlation\n"
        "id: 10000000-0000-4000-8000-0000000000ff\n"
        f"correlation:\n    type: {kind}\n    rules:\n        - made_up_base\n"
        "    group-by:\n        - Computer\n    field: User\nlevel: high\n"
    )

    rule = sigma.read_rule(text, "made_up.yml")

    assert rule["kind"] == "correlation"
    assert rule["type"] == kind
    assert rule["references"] == ["made_up_base"]
    assert rule["fields"] == ["Computer", "User"]


def test_the_engines_copy_of_a_rule_names_a_field_as_the_engine_names_its_column_and_changes_nothing_else() -> (
    None
):
    text = (RULE_SET / "rules/web/webserver_generic/web_made_up_missing_page.yml").read_text()

    copy = sigma.engine_copy(text, sigma.WEB.fields)

    changed = [
        (old, new) for old, new in zip(text.splitlines(), copy.splitlines(), strict=True) if old != new
    ]
    assert changed == [
        ("        cs-method: 'GET'", "        csmethod: 'GET'"),
        ("        cs-uri-query|contains: '/admin'", "        csuriquery|contains: '/admin'"),
        ("        sc-status: 404", "        scstatus: 404"),
        ("        cs-user-agent|contains: 'curl/'", "        csuseragent|contains: 'curl/'"),
    ]
    # A rule whose fields are letters only is given to the engine as it is.
    plain = (RULE_SET / "rules/linux/process_creation/proc_creation_lnx_made_up_find.yml").read_text()
    assert sigma.engine_copy(plain, sigma.PROCESS.fields) == plain


def test_an_engine_copy_for_a_correlation_requires_its_real_sigma_source() -> None:
    path = CORRELATION_SET / "rules" / "stage_one.yml"

    copy = sigma.engine_copy(path.read_text(), sigma.PROCESS.fields, sigma.PROCESS)
    made = yaml.safe_load(copy)

    assert made["id"] == "10000000-0000-4000-8000-000000000001"
    assert made["name"] == "made_up_ordered_first_stage"
    assert made["detection"]["bluefire_source"] == {"BlueFireSource": sigma.PROCESS.name}
    assert made["detection"]["condition"] == "(selection) and bluefire_source"


def test_a_locked_value_placeholder_pipeline_and_hyphenated_correlation_fields_run_in_the_real_engine(
    engine: Path, tmp_path: Path
) -> None:
    root = tmp_path / "set"
    rules = root / "rules"
    pipeline = root / "pipelines" / "values.yml"
    rules.mkdir(parents=True)
    pipeline.parent.mkdir()
    pipeline.write_text(
        "name: Made Up Values\npriority: 10\nvars:\n"
        "  approved_sources:\n    - '0.0.0.0/32'\n"
        "transformations:\n  - id: made_up_values\n    type: value_placeholders\n"
    )
    (rules / "base.yml").write_text(
        "title: Made Up - Pipeline Base\nname: made_up_pipeline_base\n"
        "id: 20000000-0000-4000-8000-000000000001\nauthor: The lab's tests\n"
        "logsource:\n    category: webserver\ndetection:\n"
        "    selection:\n        sc-status: 404\n"
        "    filter_approved:\n        c-ip|expand: '%approved_sources%'\n"
        "    condition: selection and not filter_approved\nlevel: low\n"
    )
    (rules / "count.yml").write_text(
        "title: Made Up - Pipeline Event Count\nname: made_up_pipeline_count\n"
        "id: 20000000-0000-4000-8000-000000000002\nauthor: The lab's tests\n"
        "correlation:\n    type: event_count\n    rules:\n        - made_up_pipeline_base\n"
        "    group-by:\n        - c-ip\n    timespan: 1m\n"
        "    condition:\n        gte: 2\n    generate: false\nlevel: high\n"
    )
    (rules / "value.yml").write_text(
        "title: Made Up - Pipeline Value Count\nname: made_up_pipeline_value\n"
        "id: 20000000-0000-4000-8000-000000000003\nauthor: The lab's tests\n"
        "correlation:\n    type: value_count\n    rules:\n        - made_up_pipeline_base\n"
        "    group-by:\n        - c-ip\n    timespan: 1m\n"
        "    condition:\n        field: cs-user-agent\n        gte: 2\n"
        "    generate: false\nlevel: high\n"
    )
    events = [
        access("GET /first HTTP/1.1", 404, agent="one", second=0),
        access("GET /second HTTP/1.1", 404, agent="two", second=10),
    ]

    found = sigma.evaluate_set(
        engine,
        root,
        ["rules"],
        events,
        tmp_path / "engine",
        ("pipelines/values.yml",),
    )

    correlations = [match for match in found["matches"] if match["rule"]["kind"] == "correlation"]
    assert found["pipelines"] == ["pipelines/values.yml"]
    assert (found["atomic loaded"], found["correlations loaded"]) == (1, 2)
    assert found["conversion errors"] == []
    assert {match["rule"]["title"] for match in correlations} == {
        "Made Up - Pipeline Event Count",
        "Made Up - Pipeline Value Count",
    }
    assert [(match["event"], match["evidence"]) for match in correlations] == [
        (1, [0, 1]),
        (1, [0, 1]),
    ]


def test_the_engine_matches_each_rule_on_the_events_of_its_log_source_and_no_others(
    engine: Path, tmp_path: Path
) -> None:
    events = [
        snoopy("find /srv/keys -name id_rsa -type f"),
        snoopy("uname -a", exe="/usr/bin/uname"),
        file_event("/tmp/T1082.txt", "added"),
        file_event("/tmp/T1082.txt", "deleted"),
        auth("sshd", "Invalid user admin from 10.9.0.2 port 4001"),
        auth("sudo", "the words Invalid user in a line that sshd did not write"),
        auth("sshd", "Accepted password for webadmin from 10.9.0.2 port 4002 ssh2"),
        access("GET /admin.php HTTP/1.1", 404, agent="Mozilla/5.0"),
        access("GET /admin.php HTTP/1.1", 404),
        access("GET /admin.php HTTP/1.1", 200, agent="Mozilla/5.0"),
    ]

    found = sigma.evaluate_set(engine, RULE_SET, FOLDERS, events, tmp_path / "engine")

    matched = sorted((match["event"], match["rule"]["title"]) for match in found["matches"])
    assert matched == [
        (0, "Made Up - Find Started"),
        (1, "Made Up - System Name Asked"),
        (2, "Made Up - File Written In Tmp"),
        (4, "Made Up - A Word In A Line Of sshd"),
        (6, "Made Up - A Word In Any Line"),
        # The rule's fields have hyphens in their names: the status, the path and the user agent decide.
        (7, "Made Up - A Page That Is Not There"),
    ]
    assert found["engine"]["name"] == "Zircolite" and found["engine"]["version"]
    groups = {(group["folder"], group["log source"]): group for group in found["groups"]}
    starts = groups[("rules/linux/process_creation", "linux process_creation")]
    assert (starts["rules"], starts["loaded"], starts["given"], starts["read"]) == (3, 3, 2, 2)
    assert starts["fields given"] == [
        "CommandLine",
        "Computer",
        "CurrentDirectory",
        "Image",
        "User",
        "UtcTime",
    ]
    # No sensor of the range records a program's parent, and one rule asks for it.
    assert starts["fields the rules name that are not given"] == {"ParentImage": 1}
    words = groups[("rules/linux/builtin", "linux")]
    assert (words["rules"], words["given"], words["read"], words["matches"]) == (1, 8, 8, 1)
    assert groups[("rules/linux/builtin", "linux sshd")]["given"] == 2
    web = groups[("rules/web/webserver_generic", "webserver")]
    assert (web["rules"], web["loaded"], web["given"], web["matches"]) == (1, 1, 3, 1)
    skipped = groups[("rules/linux/builtin", "none the lab gives")]
    assert (
        skipped["not evaluated"] == "the lab gives no lines for the service vsftpd" and skipped["loaded"] == 0
    )
    assert found["files that are not a rule"] == [
        {
            "file": "rules/linux/builtin/notes.yml",
            "why": "not one Sigma atomic rule or correlation the lab can evaluate",
        }
    ]
    assert (found["rules"], found["loaded"]) == (8, 7)


def test_a_run_without_the_path_of_its_programs_gives_no_image_and_the_rule_that_needs_one_matches_nothing(
    engine: Path, tmp_path: Path
) -> None:
    events = [snoopy("find /srv/keys -name id_rsa -type f", exe=None), snoopy("uname -a", exe=None)]

    found = sigma.evaluate_set(engine, RULE_SET, FOLDERS[:1], events, tmp_path / "engine")

    assert [(match["event"], match["rule"]["title"]) for match in found["matches"]] == [
        (1, "Made Up - System Name Asked")
    ]
    assert found["groups"][0]["fields given"] == [
        "CommandLine",
        "Computer",
        "CurrentDirectory",
        "User",
        "UtcTime",
    ]
    assert found["groups"][0]["fields the rules name that are not given"] == {"Image": 2, "ParentImage": 1}


def correlation_matches(found: dict, title: str = "Made Up - Three Stages In Order") -> list[dict]:
    return [match for match in found["matches"] if match["rule"]["title"] == title]


def test_an_ordered_correlation_anchors_to_its_latest_real_event_and_keeps_ordered_evidence(
    engine: Path, tmp_path: Path
) -> None:
    # Archive order is deliberately not time order. No retrospective origin, step, job or result label is
    # present in the fields the evaluator gives Sigma.
    events = [
        snoopy("made-up-stage-three", second=50),
        snoopy("made-up-stage-one", second=10),
        snoopy("made-up-stage-two", second=30),
    ]
    for event in events:
        event["data"].pop("tag")

    found = sigma.evaluate_set(engine, CORRELATION_SET, ["rules"], events, tmp_path / "engine")

    (match,) = correlation_matches(found)
    assert match["event"] == 0  # The third stage is latest in real time, although it was archived first.
    assert match["evidence"] == [1, 2, 0]
    assert match["evidence ids"] == ["archive-2", "archive-3", "archive-1"]
    assert match["event"] in match["evidence"]
    assert (found["atomic rules"], found["correlations"], found["correlations loaded"]) == (5, 2, 2)
    correlation = next(group for group in found["groups"] if group["kind"] == "correlation")
    assert (correlation["rules"], correlation["loaded"], correlation["matches"]) == (2, 2, 1)
    assert {rule["title"] for rule in correlation["rules loaded"]} == {
        "Made Up - Cross Source Guard",
        "Made Up - Three Stages In Order",
    }


def test_an_ordered_correlation_includes_a_sequence_59_seconds_apart(engine: Path, tmp_path: Path) -> None:
    events = [
        snoopy("made-up-stage-one", second=0),
        snoopy("made-up-stage-two", second=30),
        snoopy("made-up-stage-three", second=59),
    ]

    found = sigma.evaluate_set(engine, CORRELATION_SET, ["rules"], events, tmp_path / "engine")

    (match,) = correlation_matches(found)
    assert (match["event"], match["evidence"]) == (2, [0, 1, 2])


@pytest.mark.parametrize("case", ["missing", "reversed", "cross-host", "cross-user", "outside-window"])
def test_an_ordered_correlation_rejects_an_incomplete_or_wrong_sequence(
    case: str, engine: Path, tmp_path: Path
) -> None:
    events = [
        snoopy("made-up-stage-one", second=0),
        snoopy("made-up-stage-two", second=20),
        snoopy("made-up-stage-three", second=40),
    ]
    if case == "missing":
        events.pop(1)
    elif case == "reversed":
        events = [
            snoopy("made-up-stage-two", second=0),
            snoopy("made-up-stage-one", second=20),
            snoopy("made-up-stage-three", second=40),
        ]
    elif case == "cross-host":
        events[1] = snoopy("made-up-stage-two", second=20, host="database")
    elif case == "cross-user":
        events[1] = snoopy("made-up-stage-two", second=20, login="another-user")
    else:
        events[2] = snoopy("made-up-stage-three", second=61)

    found = sigma.evaluate_set(engine, CORRELATION_SET, ["rules"], events, tmp_path / case)

    assert correlation_matches(found) == []


def test_a_correlation_cannot_match_a_rule_against_another_log_sources_rows(
    engine: Path, tmp_path: Path
) -> None:
    # The made-up process rule deliberately asks for TargetFilename. Both events are file events: without
    # the mandatory BlueFireSource selector the first would wrongly satisfy that process rule and the
    # two-stage correlation would fire.
    events = [
        file_event("/tmp/made-up-first", "added", second=0),
        file_event("/tmp/made-up-second", "added", second=10),
    ]

    found = sigma.evaluate_set(engine, CORRELATION_SET, ["rules"], events, tmp_path / "engine")

    assert correlation_matches(found, "Made Up - Cross Source Guard") == []
    assert [(match["event"], match["rule"]["title"]) for match in found["matches"]] == [
        (1, "Made Up - File Stage")
    ]


def test_rejected_correlations_count_as_not_loaded_with_their_reasons(engine: Path, tmp_path: Path) -> None:
    folder = tmp_path / "set" / "rules"
    folder.mkdir(parents=True)
    (folder / "unsupported.yml").write_text(
        "title: Made Up - Unsupported Correlation\nname: made_up_unsupported\n"
        "id: 10000000-0000-4000-8000-0000000000fa\ncorrelation:\n"
        "    type: made_up_type\n    rules:\n        - made_up_base\nlevel: high\n"
    )
    (folder / "missing.yml").write_text(
        "title: Made Up - Missing Dependency\nname: made_up_missing\n"
        "id: 10000000-0000-4000-8000-0000000000fb\ncorrelation:\n"
        "    type: temporal\n    rules:\n        - made_up_absent\n    timespan: 1m\nlevel: high\n"
    )

    found = sigma.evaluate_set(engine, tmp_path / "set", ["rules"], [], tmp_path / "engine")

    (group,) = found["groups"]
    assert (found["rules"], found["correlations"], found["correlations loaded"], found["loaded"]) == (
        2,
        2,
        0,
        0,
    )
    assert group["not evaluated"] == "none of its correlations has dependencies the lab can evaluate"
    assert group["rules loaded"] == []
    assert [item["title"] for item in group["rules not loaded"]] == [
        "Made Up - Missing Dependency",
        "Made Up - Unsupported Correlation",
    ]
    reasons = " ".join(item["why"] for item in group["rules not loaded"])
    assert "names no rule" in reasons and "does not evaluate the correlation type made_up_type" in reasons


def test_a_folder_whose_rules_the_engine_can_convert_none_of_counts_as_none_loaded(
    engine: Path, tmp_path: Path
) -> None:
    # Made up here: the old form of a count in the condition, which the engine cannot convert.
    folder = tmp_path / "set" / "rules" / "linux" / "builtin"
    folder.mkdir(parents=True)
    (folder / "made_up_count.yml").write_text(
        "title: Made Up - A Count\nid: 00000000-0000-4000-8000-0000000000ff\nauthor: The lab's tests\n"
        "logsource:\n    product: linux\ndetection:\n    keywords:\n        - 'Invalid user'\n"
        "    condition: keywords | count() > 5\nlevel: high\n"
    )

    events = [auth("sshd", "Invalid user admin")]

    found = sigma.evaluate_set(engine, tmp_path / "set", ["rules/linux/builtin"], events, tmp_path / "w")

    (group,) = found["groups"]
    assert (group["rules"], group["loaded"], group["given"], group["matches"]) == (1, 0, 1, 0)
    assert (found["rules"], found["loaded"], found["matches"]) == (1, 0, [])
    (error,) = found["conversion errors"]
    assert (error["folder"], error["kind"], error["rule"]) == (
        "rules/linux/builtin",
        "atomic",
        "Made Up - A Count",
    )
    assert "pipe syntax" in error["reason"].lower()


@pytest.mark.parametrize("row_id", [0, -1, 2])
def test_correlation_evidence_cannot_name_a_row_outside_the_rows_the_engine_was_given(
    row_id: int,
) -> None:
    row = {
        sigma.TIME_FIELD: "2026-11-01T00:00:00.000Z",
        sigma.EVENT_FIELD: "archive-1",
    }
    match = {"evidence": [{"event": {"row_id": row_id, sigma.EVENT_FIELD: "archive-1"}}]}

    with pytest.raises(sigma.EngineError, match="names an event the engine was not given"):
        sigma._evidence(match, [(0, row)], "made-up-correlation")


def test_a_program_that_is_not_the_rule_engine_is_said_to_be_so(tmp_path: Path) -> None:
    program = tmp_path / "not-an-engine"
    program.write_text("#!/bin/sh\nexit 3\n")
    program.chmod(0o755)

    with pytest.raises(sigma.EngineError, match="the rule engine failed on .*exit code 3"):
        sigma.evaluate_set(program, RULE_SET, FOLDERS[:1], [snoopy("uname -a")], tmp_path / "engine")


def test_matches_the_engine_writes_in_another_shape_are_said_to_be_so(tmp_path: Path) -> None:
    # A stand-in for the engine, made up here: it says it loaded the rules and read the events, and writes
    # its matches as one object, where the engine writes a list of the rules that matched.
    program = tmp_path / "odd-engine"
    program.write_text(
        "#!/bin/sh\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in --outfile) out="$2" ;; --logfile) log="$2" ;; esac\n'
        "  shift\n"
        "done\n"
        '[ -n "$log" ] || exit 0\n'
        "printf '[+] 1 rules loaded\\n[+] Total events processed: 1\\n' > \"$log\"\n"
        'printf \'{"unexpected": "shape"}\' > "$out"\n'
    )
    program.chmod(0o755)

    with pytest.raises(sigma.EngineError, match="are not a list of rules, each with its matches"):
        sigma.evaluate_set(program, RULE_SET, FOLDERS[:1], [snoopy("uname -a")], tmp_path / "engine")
