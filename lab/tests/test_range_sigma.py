"""Sigma rules over a run's host events: the row each kind of event becomes, and what the engine matches.

The archive lines are written by hand here, in the shape Wazuh writes them,
and the rules are those made up for the tests (fixtures/range/rule-set).
Nothing in this file was recorded on a machine. The tests that run the rule
engine need its program: pass --engine <path to Zircolite>.
"""

from pathlib import Path

import pytest

from bluefire_lab.range import ecs, sigma

RULE_SET = Path(__file__).parent / "fixtures" / "range" / "rule-set"
FOLDERS = [
    "rules/linux/process_creation",
    "rules/linux/file_event",
    "rules/linux/builtin",
    "rules/web/webserver_generic",
]


def snoopy(
    command: str, exe: str | None = "/usr/bin/find", login: str = "webadmin", cwd: str = "/tmp"
) -> dict:
    data = {"login": login, "cwd": cwd, "tag": "step:s07", "command": command}
    if exe is not None:
        data["exe"] = exe
    line = (
        f"2026-11-01T00:00:00.000000+00:00 web snoopy[7]: [login:{login} cwd:{cwd} tag:step:s07]: {command}"
    )
    return {
        "agent": {"name": "web"},
        "location": "/var/log/snoopy.log",
        "full_log": line,
        "predecoder": {"program_name": "snoopy"},
        "decoder": {"name": "bluefire-snoopy"},
        "data": data,
    }


def auth(program: str, text: str) -> dict:
    return {
        "agent": {"name": "web"},
        "location": "/var/log/auth.log",
        "full_log": f"2026-11-01T00:00:01.000000+00:00 web {program}[9]: {text}",
        "predecoder": {"program_name": program},
    }


def access(request: str, status: int, agent: str = "curl/8.5.0", referer: str = "-") -> dict:
    line = f'10.9.0.4 - - [01/Nov/2026:00:00:02 +0000] "{request}" {status} 153 "{referer}" "{agent}"'
    return {"agent": {"name": "web"}, "location": "/var/log/nginx/access.log", "full_log": line}


def file_event(path: str, event: str) -> dict:
    return {
        "agent": {"name": "web"},
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
        "not one Sigma rule with an id, a log source and a detection"
    )
    assert sigma.read_rule("title: [unclosed\n", "broken.yml") == "not readable as YAML"


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
    assert starts["fields given"] == ["CommandLine", "CurrentDirectory", "Image", "User"]
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
            "why": "not one Sigma rule with an id, a log source and a detection",
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
    assert found["groups"][0]["fields given"] == ["CommandLine", "CurrentDirectory", "User"]
    assert found["groups"][0]["fields the rules name that are not given"] == {"Image": 2, "ParentImage": 1}


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
