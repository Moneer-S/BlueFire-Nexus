"""The manager's events and alerts as ECS lines: the fields of each kind of line, its origin, the score."""

import copy
import gzip
import json
from pathlib import Path

import pytest
import yaml

from bluefire_lab.range import ecs, engine, score
from bluefire_lab.range import spec as range_spec

RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"
FIXTURES = Path(__file__).parent / "fixtures" / "range" / "ecs"
# Lines of one run of range one, one of each kind, picked and trimmed (see run.json).
RUN = json.loads((FIXTURES / "run.json").read_text())
ARCHIVE = [json.loads(line) for line in (FIXTURES / "archive.ndjson").read_text().splitlines()]
ALERTS = [json.loads(line) for line in (FIXTURES / "alerts.ndjson").read_text().splitlines()]
# Every field of ECS 8.17.0 with its type, pinned (see THIRD_PARTY_NOTICES.md).
PINNED = yaml.safe_load((FIXTURES / "ecs-8.17.0-fields.yml").read_text())


def jobs():
    return range_spec.load(RANGE_ONE).activity


def line(name: str) -> dict:
    return copy.deepcopy(ARCHIVE[RUN["lines"].index(name)])


def alert_for(name: str) -> dict:
    event = line(name)
    return copy.deepcopy(next(a for a in ALERTS if a["full_log"] == event["full_log"]))


def origin_of(events: list[dict]) -> list[tuple[str, str | None]]:
    return score.origins(events, RUN["run_id"], jobs(), RUN["addresses"], RUN["go"], RUN["stop"])


def origin(name: str) -> tuple[str, str | None]:
    return origin_of(ARCHIVE)[RUN["lines"].index(name)]


def test_an_sshd_login_is_an_authentication_event_at_rsyslogs_time() -> None:
    raw = line("sshd login of the admin job")

    mapped = ecs.event(raw, *origin("sshd login of the admin job"))

    assert mapped["@timestamp"] == raw["predecoder"]["timestamp"].replace("+00:00", "Z")
    assert mapped["labels"] == {"origin": "ordinary", "job": "admin", "time_source": "rsyslog"}
    assert mapped["event"]["kind"] == "event"
    assert mapped["event"]["category"] == ["authentication"]
    assert mapped["event"]["outcome"] == "success"
    assert mapped["event"]["provider"] == "sshd"
    assert mapped["event"]["original"] == raw["full_log"]
    assert mapped["user"]["name"] == "ops"
    assert mapped["source"]["ip"] in RUN["addresses"]["client"]
    assert isinstance(mapped["source"]["port"], int)
    assert mapped["host"]["name"] == "web"
    assert mapped["rule"]["id"] == raw["rule"]["id"]


def test_a_sudo_line_names_who_ran_it_and_as_whom() -> None:
    mapped = ecs.event(line("sudo of the admin job"), *origin("sudo of the admin job"))

    assert mapped["user"] == {"name": "ops", "effective": {"name": "root"}}
    assert mapped["labels"]["job"] == "admin"
    assert "category" not in mapped["event"]


def test_the_pam_session_of_a_sudo_names_who_ran_it_and_as_whom_too() -> None:
    raw = alert_for("sudo session of the admin job")

    mapped = ecs.alert(raw, "ordinary", "admin")

    assert raw["data"] == {"srcuser": "ops", "dstuser": "root", "uid": "1002"}
    assert mapped["user"] == {"name": "ops", "effective": {"name": "root"}}
    assert mapped["related"]["user"] == ["ops", "root"]


def test_a_cron_session_names_its_account_once() -> None:
    mapped = ecs.event(line("cron session of ci"), "unattributed")

    assert mapped["user"] == {"name": "ci"}


def test_a_mariadb_line_gets_the_second_mariadb_wrote_also_before_ten() -> None:
    raw = line("mariadb error log line")

    mapped = ecs.event(raw, "unattributed")

    assert raw["full_log"].startswith("2026-11-24  6:19:48 ")
    assert mapped["@timestamp"] == "2026-11-24T06:19:48.000000Z"
    assert mapped["labels"]["time_source"] == "log-second"


def test_a_snoopy_line_is_a_process_start_with_the_jobs_tag_as_its_origin() -> None:
    raw = line("snoopy line of the cache job")

    mapped = ecs.event(raw, *origin("snoopy line of the cache job"))

    assert mapped["event"]["category"] == ["process"]
    assert mapped["event"]["type"] == ["start"]
    assert mapped["process"]["command_line"] == raw["data"]["command"]
    assert mapped["user"]["id"] == raw["data"]["uid"]
    assert mapped["labels"]["origin"] == "ordinary"
    assert mapped["labels"]["job"] == "cache"
    assert mapped["wazuh"]["data"]["tag"] == "job:cache"


def test_an_nginx_line_from_client_is_a_web_access_at_the_second_nginx_wrote() -> None:
    raw = line("nginx 404 from client")

    mapped = ecs.event(raw, *origin("nginx 404 from client"))

    assert mapped["labels"] == {"origin": "ordinary", "job": "browse", "time_source": "log-second"}
    stamp = raw["full_log"].split("[", 1)[1].split(" ", 1)[0]  # 24/Nov/2026:06:21:39
    assert mapped["@timestamp"].endswith(stamp[-8:] + ".000000Z")
    assert mapped["event"]["category"] == ["web"]
    assert mapped["http"] == {"request": {"method": "GET"}, "response": {"status_code": 404}}
    assert mapped["url"]["original"] == "/missing"
    assert mapped["source"]["ip"] in RUN["addresses"]["client"]


def test_a_file_integrity_event_is_a_file_creation_at_the_managers_time() -> None:
    raw = line("file added by the cache job")

    mapped = ecs.event(raw, *origin("file added by the cache job"))

    assert mapped["labels"] == {"origin": "ordinary", "job": "cache", "time_source": "manager"}
    assert mapped["@timestamp"] == mapped["event"]["ingested"]
    assert mapped["event"]["category"] == ["file"]
    assert mapped["event"]["type"] == ["creation"]
    assert mapped["file"]["path"] == raw["syscheck"]["path"]
    assert mapped["file"]["owner"] == "www-data"
    assert mapped["file"]["hash"]["sha256"] == raw["syscheck"]["sha256_after"]
    assert isinstance(mapped["file"]["size"], int)


def test_an_alert_with_mitre_ids_is_an_alert_at_the_time_it_was_raised() -> None:
    raw = alert_for("file deleted by the cache job")
    events = [line("file deleted by the cache job")]
    found = origin_of(events)
    picked, matched = score.alert_origins([raw], events, found, origin_of([raw]))

    mapped = ecs.alert(raw, *picked[0])

    assert matched == 1
    assert mapped["event"]["kind"] == "alert"
    assert mapped["event"]["dataset"] == "wazuh.alerts"
    assert mapped["@timestamp"] == mapped["event"]["created"]
    assert mapped["labels"] == {"origin": "ordinary", "job": "cache", "time_source": "manager"}
    assert mapped["event"]["severity"] == raw["rule"]["level"]
    assert mapped["message"] == raw["rule"]["description"]
    assert mapped["threat"]["framework"] == "MITRE ATT&CK"
    # Wazuh lists T1070.004 and T1485: ECS keeps the subtechnique apart from its technique.
    assert mapped["threat"]["technique"]["id"] == ["T1070", "T1485"]
    assert mapped["threat"]["technique"]["subtechnique"]["id"] == ["T1070.004"]
    assert mapped["threat"]["tactic"]["name"] == raw["rule"]["mitre"]["tactic"]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("snoopy line of an engine mark", ("engine", None)),
        ("file of an engine mark", ("engine", None)),
        ("ready nonce", ("engine", None)),
        # A plant check, before the activity's go: neither the engine's by its marks nor a job's.
        ("password login of webadmin by a plant check", ("unattributed", None)),
        # Cron opens a session for the build job's account each minute, before the go too: inside the
        # job's window it is ordinary, but not the job's, since it does not tell one entry from another.
        ("cron session of ci", ("unattributed", None)),
        ("cron session of ci in the window", ("ordinary", None)),
        ("mariadb error log line", ("unattributed", None)),
        ("php session file of a plant check", ("unattributed", None)),
    ],
)
def test_each_line_has_the_origin_of_the_first_rule_that_holds(name: str, expected: tuple) -> None:
    assert origin(name) == expected


def test_a_file_written_before_the_go_is_no_jobs_when_the_manager_reports_it_late() -> None:
    # Built from the real line: the manager's time is moved past web's go, as a slow delivery would
    # put it. The file's own time is still before the go.
    late = line("php session file of a plant check")
    late["timestamp"] = "2026-11-24T06:21:08.000+0000"
    written = copy.deepcopy(late)
    written["syscheck"]["mtime_after"] = "2026-11-24T06:21:08"

    assert origin_of([late, written]) == [("unattributed", None), ("ordinary", "browse")]


def test_a_job_line_outside_the_jobs_window_is_not_the_jobs_unless_it_carries_its_tag() -> None:
    late = {host: 0.0 for host in RUN["go"]}
    nginx, snoopy = line("nginx 404 from client"), line("snoopy line of the cache job")

    found = score.origins([nginx, snoopy], RUN["run_id"], jobs(), RUN["addresses"], RUN["go"], late)

    assert found == [("unattributed", None), ("ordinary", "cache")]


def test_an_nginx_line_from_client_for_a_path_no_job_fetches_is_unattributed() -> None:
    # Built from the real line: the same request from client's address, inside browse's window,
    # for a path that is not one of browse's.
    other = line("nginx 404 from client")
    other["full_log"] = other["full_log"].replace("GET /missing ", "GET /admin.php ")
    other["data"]["url"] = "/admin.php"

    assert origin_of([line("nginx 404 from client"), other]) == [
        ("ordinary", "browse"),
        ("unattributed", None),
    ]


def test_a_program_start_with_another_jobs_tag_is_that_jobs_and_not_the_ssh_job_of_its_account() -> None:
    # Built from the real line: cache's program start as it would be with ops as its login, the
    # account admin logs in to web as. Its tag says whose it is, whichever job comes first.
    tagged = line("snoopy line of the cache job")
    tagged["data"]["login"] = "ops"

    assert origin_of([tagged]) == [("ordinary", "cache")]


def test_every_ecs_line_keeps_the_whole_raw_line_under_wazuh() -> None:
    for raw in ARCHIVE:
        mapped = ecs.event(raw, "unattributed")
        again = {**mapped["wazuh"], "full_log": mapped["event"]["original"], "timestamp": raw["timestamp"]}
        assert again == raw
    for raw in ALERTS:
        mapped = ecs.alert(raw, "unattributed")
        assert {
            **mapped["wazuh"],
            "full_log": mapped["event"]["original"],
            "timestamp": raw["timestamp"],
        } == raw


def test_every_field_the_mapper_can_write_is_an_ecs_8_17_field_of_its_type() -> None:
    fields = PINNED["fields"]

    wrong = {name: kind for name, kind in ecs.FIELDS.items() if fields.get(name) != kind}

    assert PINNED["tag"] == "v8.17.0" and ecs.VERSION == "8.17.0"
    assert wrong == {}
    assert (
        fields["labels"] == "object"
        and "wazuh" not in fields
        and not any(n.startswith("wazuh.") for n in fields)
    )
    for name, values in ecs.CATEGORIES.items():
        assert set(values) <= set(PINNED["allowed_values"][name]), name


def test_every_line_written_holds_only_declared_fields_and_set_categories_ecs_allows_together() -> None:
    expected = PINNED["expected_event_types"]
    for mapped in [ecs.event(raw, "ordinary", "x") for raw in ARCHIVE] + [
        ecs.alert(raw, "engine") for raw in ALERTS
    ]:
        assert set(ecs.names(mapped)) - {"labels", "wazuh"} <= set(ecs.FIELDS)
        assert all(isinstance(value, str) for value in mapped["labels"].values())
        event = mapped["event"]
        for category in event.get("category", []):
            assert set(event.get("type", [])) <= set(expected[category]), category


def test_a_line_without_a_field_every_line_needs_is_refused() -> None:
    raw = line("ready nonce")
    with pytest.raises(ecs.ConversionError, match="without labels.origin"):
        ecs.event(raw, "")
    del raw["timestamp"]
    with pytest.raises(ecs.ConversionError, match="no manager timestamp"):
        ecs.event(raw, "engine")


def logs_folder(root: Path, archive_lines: list[str], alert_lines: list[str]) -> Path:
    logs = root / "logs"
    for kind, name, lines in (
        ("archives", "ossec-archive-23.json.gz", archive_lines),
        ("alerts", "ossec-alerts-23.json.gz", alert_lines),
    ):
        folder = logs / kind / "2026" / "Nov"
        folder.mkdir(parents=True)
        with gzip.open(folder / name, "wt", encoding="utf-8") as target:
            target.write("".join(f"{text}\n" for text in lines))
    return logs


def raw_lines(lines: list[dict]) -> list[str]:
    return [json.dumps(item) for item in lines]


def test_the_conversion_writes_one_ecs_line_for_each_raw_line(tmp_path: Path) -> None:
    logs = logs_folder(tmp_path, raw_lines(ARCHIVE), raw_lines(ALERTS))

    section, result = score.record(tmp_path, logs, RUN["run_id"], 12, jobs(), RUN, RUN["addresses"])

    assert section["error"] is None
    files = section["files"]
    assert files["events.ecs.ndjson"]["raw lines"] == files["events.ecs.ndjson"]["ECS lines"] == len(ARCHIVE)
    assert files["alerts.ecs.ndjson"]["ECS lines"] == len(ALERTS)
    written = (tmp_path / "events.ecs.ndjson").read_text().splitlines()
    assert [json.loads(text)["event"]["original"] for text in written] == [raw["full_log"] for raw in ARCHIVE]
    assert section["alerts with their event in the archive"] == len(ALERTS)
    assert result["denominators"]["events of each origin"] == {
        origin: sum(1 for o, _ in origin_of(ARCHIVE) if o == origin) for origin in score.ORIGINS
    }


@pytest.mark.parametrize(
    ("broken", "reason"),
    [
        (
            '{"timestamp": "2026-11-23T23:21:14.196+0000", "full_log": "cut',
            "line 2 of ossec-archive-23.json.gz",
        ),
        ("[1, 2]", "is not a JSON object"),
        ("", "cannot be parsed"),
    ],
)
def test_a_raw_line_that_cannot_be_read_fails_the_conversion(
    tmp_path: Path, broken: str, reason: str
) -> None:
    lines = raw_lines(ARCHIVE)
    logs = logs_folder(tmp_path, [lines[0], broken, *lines[1:]], raw_lines(ALERTS))

    section, result = score.record(tmp_path, logs, RUN["run_id"], 12, jobs(), RUN, RUN["addresses"])

    assert reason in section["error"]
    assert result is None


def test_a_line_that_cannot_be_mapped_fails_the_conversion_and_says_where_it_is(tmp_path: Path) -> None:
    lines = raw_lines(ARCHIVE)
    no_time, wrong_shape = line("ready nonce"), line("ready nonce")
    del no_time["timestamp"]
    wrong_shape["predecoder"] = "sshd"

    for broken, reason in (
        (no_time, "line 2 of ossec-archive-23.json.gz: a line has no manager timestamp"),
        (wrong_shape, "line 2 of ossec-archive-23.json.gz: predecoder is not a JSON object"),
    ):
        logs = logs_folder(
            tmp_path / reason[-9:], [lines[0], json.dumps(broken), *lines[1:]], raw_lines(ALERTS)
        )
        section, result = score.record(tmp_path, logs, RUN["run_id"], 12, jobs(), RUN, RUN["addresses"])

        assert section["error"].startswith(reason)
        assert result is None


def test_a_line_lost_on_the_way_to_the_file_fails_the_conversion(tmp_path: Path, monkeypatch) -> None:
    logs = logs_folder(tmp_path, raw_lines(ARCHIVE), raw_lines(ALERTS))
    write = ecs.write
    monkeypatch.setattr(ecs, "write", lambda path, documents: write(path, documents[:-1]))

    section, result = score.record(tmp_path, logs, RUN["run_id"], 12, jobs(), RUN, RUN["addresses"])

    assert section["error"] == f"events.ecs.ndjson has {len(ARCHIVE) - 1} lines for {len(ARCHIVE)} raw lines"
    assert result is None


def test_write_gzip_is_lossless_and_deterministic(tmp_path: Path) -> None:
    documents = [{"event": {"id": "network-1"}}, {"message": "packet telemetry"}]
    first = tmp_path / "first.ndjson.gz"
    second = tmp_path / "second.ndjson.gz"

    assert ecs.write(first, documents) == 2
    assert ecs.write(second, documents) == 2

    compressed = first.read_bytes()
    assert compressed == second.read_bytes()
    assert compressed[:3] == b"\x1f\x8b\x08"
    assert compressed[3] & 0x08 == 0  # no source filename in the gzip header
    assert compressed[4:8] == b"\x00\x00\x00\x00"  # deterministic mtime
    with gzip.open(first, "rt", encoding="utf-8") as source:
        assert [json.loads(line) for line in source] == documents


def test_a_missing_archive_fails_the_conversion(tmp_path: Path) -> None:
    section, _ = score.record(tmp_path, tmp_path / "logs", RUN["run_id"], 12)

    assert section["error"] == "no file of the manager's archives was copied out"


def test_a_failed_conversion_makes_a_sealed_run_invalid_with_the_reason() -> None:
    sealed = (engine.EXIT_OK, "sealed", None)

    assert engine.outcome(sealed, True, True, None, None) == sealed
    assert engine.outcome(sealed, True, True, None, "line 2 of x cannot be parsed") == (
        engine.EXIT_INVALID,
        "invalid",
        "the conversion to ECS failed: line 2 of x cannot be parsed",
    )


def test_false_alerts_count_the_distinct_rules_at_the_alert_level_on_ordinary_work() -> None:
    # Built from real alerts of the run: the level of the 404 alert on browse's page is raised
    # from 5 to 12, so that one ordinary event carries an alert at the counting level, and a copy
    # of the engine mark's alert is raised to 12 too. Neither level is what the stock rule gives.
    built = alert_for("nginx 404 from client")
    built["rule"]["level"] = 12
    twice = copy.deepcopy(built)
    review = alert_for("file deleted by the cache job")
    bench = alert_for("file of an engine mark")
    bench["rule"]["level"] = 12
    alerts = [built, twice, review, bench, alert_for("sudo of the admin job")]
    picked = origin_of(alerts)
    record = {"minutes": 2.5, "started": "x", "jobs": counted(browse=9, cache=2)}

    result = score.ordinary_day(alerts, picked, {"ordinary": 4}, 12, jobs(), record)

    assert result["false alerts"] == 1
    assert result["false alert rules"] == [
        {
            "rule": "31101",
            "description": built["rule"]["description"],
            "level": 12,
            "alerts": 2,
            "on": {"browse (web)": 2},
        }
    ]
    assert result["for review"] == 1
    assert result["for review rules"][0]["rule"] == review["rule"]["id"]
    assert result["for review rules"][0]["on"] == {"cache (web)": 1}
    elsewhere = result["alerts at the alert level on the engine's work and unattributed events"]
    assert [(r["rule"], r["on"]) for r in elsewhere] == [
        (bench["rule"]["id"], {"engine (" + bench["agent"]["name"] + ")": 1})
    ]
    assert result["alerts by origin and level"]["ordinary"]["12 to 14"] == 2
    assert result["scored"] is True
    assert result["denominators"]["runs of each job"]["browse"] == {"runs": 9, "archived runs": 9}


def counted(**runs: int) -> dict:
    """Each job of range one counted, with one run unless given, in the host's log and in the archive."""

    return {
        job.name: {"runs": runs.get(job.name, 1), "archived runs": runs.get(job.name, 1)}
        for job in jobs().jobs
    }


@pytest.mark.parametrize(
    ("activity", "record", "reason"),
    [
        (jobs(), {"minutes": None, "jobs": counted()}, "the minutes of activity were not counted"),
        (
            jobs(),
            {"minutes": 3.1, "jobs": {**counted(), "admin": {"runs": 2, "archived runs": 0}}},
            "a job had no run that reached the defense, so no number of false alerts is a result: "
            "admin (runs 2, archived runs 0)",
        ),
        (jobs(), {"minutes": 3.1, "jobs": {}}, "browse (runs None, archived runs None)"),
        (None, None, "the range has no ordinary activity, so no false alert can be counted"),
    ],
)
def test_zero_false_alerts_is_no_result_without_its_denominators(activity, record, reason: str) -> None:
    result = score.ordinary_day([], [], {}, 12, activity, record)
    manifest = {
        "range": "range-one",
        "result": "sealed",
        "ecs": {"error": None, "files": {}},
        "score": result,
    }

    text = score.summary(manifest)

    assert result["scored"] is False
    assert reason in result["not scored"]
    assert text.startswith("### Ordinary day of range-one: not scored: ")
    assert "False alerts" not in text and "0 rules" not in text and "None minutes" not in text


def test_the_summary_gives_the_score_with_its_denominators_and_what_the_jobs_leave_out() -> None:
    alerts = [alert_for("file deleted by the cache job")]
    record = {"minutes": 3.9, "started": "2026-11-24T00:00:00Z", "jobs": counted(cache=4)}
    result = score.ordinary_day(alerts, origin_of(alerts), {"ordinary": 1}, 12, jobs(), record)

    manifest = {
        "range": "range-one",
        "result": "sealed",
        "ecs": {"error": None, "files": {}},
        "score": result,
    }

    text = score.summary(manifest)

    assert text.startswith(
        "### Ordinary day of range-one: 0 false alerts at level 12 or higher on 3.9 minutes"
    )
    assert "cache 4 runs (4 in the archive)" in text
    assert "For review (levels 7 to 11, ordinary): 1 rules." in text
    assert "a password login or a failed login over SSH" in text


def test_a_run_that_did_not_end_sealed_headlines_no_score() -> None:
    alerts = [alert_for("file deleted by the cache job")]
    record = {"minutes": 1.49, "started": "2026-11-24T00:00:00Z", "jobs": counted()}
    result = score.ordinary_day(alerts, origin_of(alerts), {"ordinary": 1}, 12, jobs(), record)
    manifest = {
        "range": "range-one",
        "result": "invalid",
        "exit_code": 4,
        "reason": "the seal failed after the path: event watch",
        "ecs": {"error": None, "files": {}},
        "score": result,
    }

    text = score.summary(manifest)

    assert result["scored"] is True
    assert text.startswith(
        "### Ordinary day of range-one: not a result, the run ended invalid (exit code 4)\n"
    )
    assert "Reason: the seal failed after the path: event watch" in text
    assert "0 false alerts at level 12 or higher" not in text.splitlines()[0]


INVALID = {
    "range": "range-one",
    "result": "invalid",
    "exit_code": 4,
    "reason": "the seal failed before any step of the path ran: event watch",
}


@pytest.mark.parametrize(
    ("ecs_section", "day", "said"),
    [
        (
            {"error": None, "files": {}},
            score.ordinary_day([], [], {}, 12, jobs(), {"minutes": 3.1, "jobs": {}}),
            "The ordinary day was not scored: a job had no run that reached the defense",
        ),
        (
            {"error": "ValueError: a line that is not JSON", "files": {}},
            None,
            "The ordinary day was not scored: the conversion to ECS failed: ValueError: a line that is not JSON",
        ),
    ],
    ids=["day-not-scored", "conversion-failed"],
)
def test_a_run_that_did_not_end_sealed_is_headed_not_a_result_also_when_nothing_was_scored(
    ecs_section: dict, day: dict | None, said: str
) -> None:
    manifest = {**INVALID, "ecs": ecs_section, "score": day}

    lines = score.markdown(manifest).splitlines()

    assert lines[:4] == [
        "### Ordinary day of range-one: not a result, the run ended invalid (exit code 4)",
        "",
        "Reason: the seal failed before any step of the path ran: event watch",
        "",
    ]
    assert lines[4].startswith(said)
    assert not any(line.startswith("### ") for line in lines[1:])
