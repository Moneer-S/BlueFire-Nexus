"""What the defense made of each step of a range's path: the ties, the outcomes, the race and the recording.

Every input here is built by hand in the test: a run folder of range one with
two steps, a few archive lines and alerts in the shape Wazuh writes them, at
made-up times and addresses. Nothing in it was recorded on a machine.
"""

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from bluefire_lab.range import engine, recording, score

RANGE_ONE = Path(__file__).parents[1] / "range" / "range-one.yaml"
# A made-up start of the first step, in seconds since the epoch.
T0 = 1_795_000_000.0
ADDRESSES = {
    "attacker": {"edge": "10.9.0.2"},
    "inet": {"edge": "10.9.0.3"},
    "client": {"edge": "10.9.0.4"},
    "web": {"edge": "10.9.0.5", "inside": "10.9.1.2", "mgmt": "10.9.2.2"},
    "db": {"inside": "10.9.1.3", "mgmt": "10.9.2.3"},
    "build": {"inside": "10.9.1.4", "mgmt": "10.9.2.4"},
    "manager": {"mgmt": "10.9.2.5"},
}


def iso(moment: float) -> str:
    return datetime.fromtimestamp(moment, tz=timezone.utc).isoformat()


def manager_time(moment: float) -> str:
    return datetime.fromtimestamp(moment, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"


def line(host: str, moment: float, location: str, text: str, received: float = 0.4, **parts) -> dict:
    """An archive line as Wazuh writes one, from a log rsyslog stamped at `moment`."""

    found = {
        "timestamp": manager_time(moment + received),
        "agent": {"id": "001", "name": host, "ip": ADDRESSES[host]["mgmt"]},
        "manager": {"name": "manager"},
        "location": location,
        "full_log": f"{iso(moment)} {host} {text}",
        "predecoder": {"timestamp": iso(moment), "hostname": host, "program_name": text.split("[")[0]},
        "decoder": {"name": "sshd"},
        "id": str(int(moment * 1000)),
    }
    found.update(parts)
    return found


def snoopy(host: str, moment: float, tag: str, command: str, login: str = "webadmin") -> dict:
    return line(
        host,
        moment,
        "/var/log/snoopy.log",
        f"snoopy[7]: [login:{login} ssh:((undefined)) sid:7 uid:1001 euid:1001 cwd:/tmp tag:{tag}]: {command}",
        decoder={"name": "bluefire-snoopy"},
        data={"login": login, "tag": tag, "command": command, "cwd": "/tmp"},
    )


def file_event(host: str, moment: float, path: str, event: str, owner: str) -> dict:
    return {
        "timestamp": manager_time(moment),
        "agent": {"id": "001", "name": host, "ip": ADDRESSES[host]["mgmt"]},
        "manager": {"name": "manager"},
        "location": "syscheck",
        "full_log": f"File '{path}' {event}\nMode: realtime\n",
        "syscheck": {"path": path, "event": event, "uname_after": owner, "mtime_after": iso(moment)},
        "decoder": {"name": "syscheck_new_entry"},
        "id": str(int(moment * 1000)),
    }


def alert_on(event: dict, rule: str, level: int, description: str) -> dict:
    """An alert as Wazuh writes one: its event's line, at the manager's same time, with the rule."""

    return {**event, "rule": {"id": rule, "level": level, "description": description}}


# Each archive line of the small run, by what it is, with what the ties must make of it:
# (origin, step, tied_by).
LINES = {
    "a failed login from attacker's address": (
        lambda: line(
            "web",
            T0 + 2,
            "/var/log/auth.log",
            "sshd[11]: Invalid user admin from 10.9.0.2 port 4001",
            data={"srcip": "10.9.0.2", "srcuser": "admin"},
        ),
        ("step", "s01", "address"),
    ),
    "webadmin's login": (
        lambda: line(
            "web",
            T0 + 9,
            "/var/log/auth.log",
            "sshd[12]: Accepted password for webadmin from 10.9.0.2 port 4002 ssh2",
            data={"srcip": "10.9.0.2", "dstuser": "webadmin"},
        ),
        ("step", "s01", "account"),
    ),
    "a program the test started": (
        lambda: snoopy("web", T0 + 20.05, "step:s03", "uname -a"),
        ("step", "s03", "session"),
    ),
    "the test's output file, owned by root": (
        lambda: file_event("web", T0 + 20.4, "/tmp/T1082.txt", "added", "root"),
        ("step", "s03", "content"),
    ),
    "the engine's effect check": (
        lambda: snoopy("web", T0 + 26, "engine:check:s03", "grep -q Linux /tmp/T1082.txt", login="root"),
        ("engine", None, None),
    ),
    "the cleanup's program": (
        lambda: snoopy("web", T0 + 27.02, "cleanup:s03", "rm /tmp/T1082.txt"),
        ("cleanup", None, None),
    ),
    "the file the cleanup removed": (
        lambda: file_event("web", T0 + 27.3, "/tmp/T1082.txt", "deleted", "root"),
        ("cleanup", None, None),
    ),
    "a program of the cache job": (
        lambda: snoopy("web", T0 + 22, "job:cache", "php /var/www/app/cron.php", login="www-data"),
        ("ordinary", None, None),
    ),
    "cron's session on web during s03": (
        lambda: line(
            "web",
            T0 + 23,
            "/var/log/auth.log",
            "CRON[30]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
        ),
        ("unattributed", "s03", "window"),
    ),
    "a line on db long after the path": (
        lambda: line("db", T0 + 300, "/var/log/auth.log", "CRON[40]: something else happened"),
        ("unattributed", None, None),
    ),
}


def step_record(step_id: str, host: str, start: float, end: float, **more) -> dict:
    return {
        "id": step_id,
        "host": host,
        "to": [],
        "account": "webadmin",
        "workdir": "/tmp",
        "technique": "T1082",
        "guid": "cccb070c-df86-4216-a5bc-9fb60c74e27c",
        "name": "List OS Information",
        "plain": "Writes what the system is into a file.",
        "args": {},
        "expect": [],
        "argv": ["sh", "-c", "uname -a >> /tmp/T1082.txt"],
        # The engine's own time of the step, as the executor writes it.
        "handled": iso(start - 1).replace("+00:00", "Z"),
        "happened": "took effect",
        "why": "the effect check passed",
        "exit_code": 0,
        "started_ns": int(start * 1e9),
        "ended_ns": int(end * 1e9),
        "started": iso(start).replace("+00:00", "Z"),
        "ended": iso(end).replace("+00:00", "Z"),
        "time_source": "daemon",
        "check": {"result": "pass", "parts": []},
        **more,
    }


def small_run(folder: Path, lines: list[dict] | None = None, alerts: list[dict] | None = None) -> Path:
    """A run folder of range one with two steps, as `bluefire-lab range run` leaves one, built by hand."""

    archive = [make() for make, _ in LINES.values()] if lines is None else lines
    if alerts is None:
        named = dict(zip(LINES, archive, strict=True))
        alerts = [
            alert_on(
                named["webadmin's login"],
                "40112",
                12,
                "Multiple authentication failures followed by a success.",
            ),
            alert_on(
                named["a failed login from attacker's address"],
                "5710",
                5,
                "sshd: Attempt to login using a non-existent user",
            ),
            alert_on(named["the test's output file, owned by root"], "554", 5, "File added to the system."),
            alert_on(named["a program of the cache job"], "100", 3, "A stand-in rule on the cache job."),
        ]
    logs = folder / "raw" / "hosts" / "manager" / "var" / "ossec" / "logs"
    for kind, name, found in (
        ("archives", "ossec-archive-01.json.gz", archive),
        ("alerts", "ossec-alerts-01.json.gz", alerts),
    ):
        where = logs / kind / "2026" / "Nov"
        where.mkdir(parents=True)
        with gzip.open(where / name, "wt", encoding="utf-8") as target:
            for item in found:
                target.write(json.dumps(item) + "\n")
    (logs / "ossec.log").write_text("2026/11/01 00:00:00 wazuh-analysisd: INFO: Total rules enabled: '100'\n")
    cleanup = folder / "raw" / "steps" / "s03"
    cleanup.mkdir(parents=True)
    (cleanup / "cleanup.txt").write_text(
        "command: docker exec --user webadmin --workdir /tmp ccc sh -c 'rm /tmp/T1082.txt'\nexit code: 0\n"
    )
    (cleanup / "stdout").write_text("Linux web 6.1\n")
    s01 = step_record(
        "s01",
        "attacker",
        T0,
        T0 + 10,
        to=["web"],
        account="root",
        technique="T1110.004",
        guid="4f08197a-2a8a-472d-9589-cd2895ef22ad",
        name="SSH Credential Stuffing From Linux",
        args={"target_host": "web"},
        expect=[40112, 5715],
    )
    s03 = step_record(
        "s03",
        "web",
        T0 + 20,
        T0 + 20.2,
        args={"output_file": "/tmp/T1082.txt"},
        cleanup_run={"started_ns": int((T0 + 27) * 1e9), "ended_ns": int((T0 + 27.1) * 1e9)},
    )
    manifest = {
        "range": "range-one",
        "run_id": "20261101T000000Z-abcdef",
        "spec": {"file": "range-one.yaml", "text": RANGE_ONE.read_text(encoding="utf-8")},
        "environment": "GitHub-hosted runner",
        "run_url": None,
        "result": "sealed",
        "reason": None,
        "exit_code": 0,
        "containers": {host: {"addresses": found} for host, found in ADDRESSES.items()},
        "images": {},
        "atomic_red_team": {"commit": "a" * 40},
        "weaknesses": [],
        "defense": {"wazuh_version": "4.14.10", "agents": ["web", "db", "build"], "manager": "manager"},
        "activity": {
            "go": {host: T0 - 60 for host in ("client", "web", "build", "db")},
            "stop": {host: T0 + 600 for host in ("client", "web", "build", "db")},
            "started": iso(T0 - 60),
            "minutes": 11.0,
            "jobs": {},
        },
        "path": {
            "planned": ["s01", "s03"],
            "steps": [s01, s03],
            "goal": {"plain": "the system's name is written down", "after": "s03", "passed": True},
            "notes": [],
        },
    }
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (folder / "docker-events.ndjson").write_text(
        "".join(json.dumps({"timeNano": int(t * 1e9)}) + "\n" for t in (T0 - 120, T0 + 700))
    )
    return folder


def scored(folder: Path) -> dict:
    assert engine.rescore(folder) == 0
    return json.loads((folder / "manifest.json").read_text())


def score_of(folder: Path) -> dict:
    """The manifest after scoring, for a run folder whose few lines give the clock check nothing to check.

    Such a run's race is not a result, so it has no recording, and `range score` exits 1 for that.
    """

    engine.rescore(folder)
    return json.loads((folder / "manifest.json").read_text())


def ecs_lines(folder: Path, name: str) -> list[dict]:
    return [json.loads(text) for text in (folder / name).read_text().splitlines()]


def test_each_event_is_the_engines_a_cleanups_a_jobs_a_steps_or_unattributed(tmp_path: Path) -> None:
    folder = small_run(tmp_path)

    scored(folder)

    written = ecs_lines(folder, score.EVENTS_FILE)
    for (name, (_, expected)), document in zip(LINES.items(), written, strict=True):
        labels = document["labels"]
        assert (labels["origin"], labels.get("step_id"), labels.get("tied_by")) == expected, name


def test_the_counts_of_each_origin_add_up_to_the_raw_lines(tmp_path: Path) -> None:
    manifest = scored(small_run(tmp_path))

    found = manifest["score"]["path"]
    assert sum(found["events"]["of each origin"].values()) == len(LINES)
    assert sum(found["alerts"]["of each origin"].values()) == 4
    assert found["events"]["unattributed, coincident with a step"] == 1
    assert manifest["ecs"]["files"]["steps.ecs.ndjson"]["ECS lines"] == 2


def test_an_alert_takes_its_events_tie_and_the_first_alert_at_the_level_makes_the_step_alerted(
    tmp_path: Path,
) -> None:
    manifest = scored(small_run(tmp_path))

    steps = {step["id"]: step for step in manifest["score"]["path"]["steps"]}
    assert steps["s01"]["visibility"] == "alert" and steps["s01"]["outcome"] == "alerted"
    assert steps["s01"]["first_alert"]["rule"] == "40112"
    assert steps["s01"]["events by tie"] == {"address": 1, "account": 1}
    assert steps["s01"]["expected rules that did not appear"] == ["5715"]
    assert steps["s03"]["visibility"] == "telemetry only" and steps["s03"]["outcome"] == "seen"
    assert steps["s03"]["coincident events"] == 1 and steps["s03"]["events"] == 2
    alerts = ecs_lines(tmp_path, score.ALERTS_FILE)
    assert [(a["labels"]["origin"], a["labels"].get("step_id")) for a in alerts] == [
        ("step", "s01"),
        ("step", "s01"),
        ("step", "s03"),
        ("ordinary", None),
    ]
    assert alerts[0]["labels"]["event_id"] == "archive-2"


def test_the_race_counts_to_the_first_alert_and_to_the_end_of_the_goals_step(tmp_path: Path) -> None:
    manifest = scored(small_run(tmp_path))

    race = manifest["score"]["path"]["race"]
    # webadmin's login is at T0 + 9, and the manager has it, and raises 40112 on it, 0.4 s later.
    assert race["first_alert_seconds"] == pytest.approx(9.4, abs=0.002)
    assert race["goal_seconds"] == pytest.approx(20.2, abs=0.002)
    assert race["says"] == "alert before goal by 10.8 s"
    assert (
        (tmp_path / "score.md").read_text().startswith("### Path of range-one: alert before goal by 10.8 s")
    )


@pytest.mark.parametrize(
    ("first_alert", "goal", "says"),
    [
        (None, True, "no alert"),
        (None, False, "no alert; the goal was not reached"),
        (30.0, True, "alert after goal by 9.8 s"),
        (5.0, False, "first alert after 5.0 s; the goal was not reached"),
    ],
)
def test_the_race_says_what_happened(first_alert: float | None, goal: bool, says: str) -> None:
    def at(seconds: float) -> str:
        return iso(T0 + seconds).replace("+00:00", "Z")

    steps = [
        {"id": "s01", "started": at(0), "ended": at(10), "time_source": "daemon", "first_alert": None},
        {"id": "s03", "started": at(20), "ended": at(20.2), "time_source": "daemon", "first_alert": None},
    ]
    if first_alert is not None:
        steps[1]["first_alert"] = {"raised": at(first_alert), "rule": "1", "description": "d", "level": 12}

    found = score.race(steps, {"plain": "p", "after": "s03", "passed": goal})

    assert found["says"] == says
    assert ("goal_seconds" in found) is goal


@pytest.mark.parametrize(
    ("happened", "events", "alert", "outcome"),
    [
        ("took effect", ["a program the test started"], True, "alerted"),
        ("took effect", ["a program the test started"], False, "seen"),
        ("took effect", [], False, "unseen"),
        ("attempted without effect", ["a program the test started"], True, "no effect"),
        ("inconclusive", ["a program the test started"], False, "seen"),
        ("inconclusive", [], False, "inconclusive"),
    ],
)
def test_a_steps_outcome_follows_what_happened_and_what_the_defense_made_of_it(
    tmp_path: Path, happened: str, events: list[str], alert: bool, outcome: str
) -> None:
    archive = [LINES[name][0]() for name in events] + [LINES["a line on db long after the path"][0]()]
    alerts = [alert_on(archive[0], "200", 12, "A stand-in rule.")] if alert else []
    folder = small_run(tmp_path, archive, alerts)
    manifest = json.loads((folder / "manifest.json").read_text())
    manifest["path"]["steps"][1]["happened"] = happened
    (folder / "manifest.json").write_text(json.dumps(manifest))

    steps = {step["id"]: step for step in score_of(folder)["score"]["path"]["steps"]}

    assert steps["s03"]["outcome"] == outcome
    assert steps["s01"]["visibility"] == "no telemetry"


def test_a_step_whose_test_did_not_start_is_not_applicable(tmp_path: Path) -> None:
    folder = small_run(tmp_path)
    manifest = json.loads((folder / "manifest.json").read_text())
    s03 = manifest["path"]["steps"][1]
    for key in ("started_ns", "ended_ns", "started", "ended", "exit_code"):
        s03.pop(key)
    s03.update({"happened": "not attempted", "why": "the published prerequisite check did not pass"})
    manifest["path"]["goal"]["passed"] = False
    (folder / "manifest.json").write_text(json.dumps(manifest))

    steps = {step["id"]: step for step in score_of(folder)["score"]["path"]["steps"]}

    assert (steps["s03"]["visibility"], steps["s03"]["outcome"]) == ("not applicable", "no effect")


def test_the_recording_holds_the_network_the_steps_their_events_and_the_race(tmp_path: Path) -> None:
    manifest = scored(small_run(tmp_path))

    made = json.loads((tmp_path / recording.FILE).read_text())

    assert manifest["recording"]["error"] is None
    assert made["kind"] == "attack path" and made["attacker"]["goal"] == "the system's name is written down"
    assert [host["id"] for host in made["network"]["hosts"]] == list(ADDRESSES)
    assert {(link["from"], link["to"]) for link in made["network"]["links"]} >= {
        ("attacker", "web"),
        ("web", "build"),
    }
    assert [s["host"] for s in made["network"]["sensors"]] == ["web", "db", "build"]
    assert made["network"]["detectors"] == [
        {
            "id": "pinned",
            "name": "Wazuh 4.14.10 stock rules with the lab's decoder for snoopy, on manager",
            "rules": 100,
            "when": "live",
        }
    ]
    first, second = made["steps"]
    # s01 ran on attacker and went to web, so it is on web, from attacker.
    assert (first["host"], first["from"], first["outcome"]) == ("web", "attacker", "alerted")
    assert second["plain"] == "Writes what the system is into a file." and second["output"] == "Linux web 6.1"
    assert [(e["step"], e["tied_by"]) for e in made["events"]] == [
        ("s01", "address"),
        ("s01", "account"),
        ("s03", "session"),
        ("s03", "content"),
    ]
    assert made["score"]["first_alert_seconds"] == pytest.approx(9.4, abs=0.002)
    assert made["score"]["goal_seconds"] == pytest.approx(20.2, abs=0.002)
    assert made["ordinary"] == {
        "events": 1,
        "matches": [
            {"rule": "A stand-in rule on the cache job.", "id": "100", "level": "informational", "count": 1}
        ],
    }
    assert made["score"]["false_alerts"] == 0


def rewrite(folder: Path, change) -> None:
    manifest = json.loads((folder / "manifest.json").read_text())
    change(manifest)
    (folder / "manifest.json").write_text(json.dumps(manifest))


@pytest.mark.parametrize(
    ("host", "text", "tied"),
    [
        # sshd's line on build names web's address only in its text: no decoder took it out.
        ("build", "sshd[51]: banner exchange: Connection from 10.9.1.2 port 4100: invalid format", "address"),
        # MariaDB's line on db names web's container.
        (
            "db",
            "mariadbd[1]: Aborted connection 8 to db: 'unconnected' user: 'unauthenticated' host: "
            "'bluefire-lab-x1-web.bluefire-lab-x1-inside'",
            "address",
        ),
        # Another address that begins with web's is not web's.
        ("build", "sshd[52]: Connection closed by 10.9.1.23 port 4101", "window"),
    ],
)
def test_a_line_on_a_host_the_step_reached_that_names_the_steps_host_is_tied_by_address(
    tmp_path: Path, host: str, text: str, tied: str
) -> None:
    archive = [line(host, T0 + 20.1, "/var/log/auth.log", text)]
    folder = small_run(tmp_path, archive, [])

    def reach(manifest: dict) -> None:
        manifest["path"]["steps"][1]["to"] = ["build", "db"]
        for name, entry in manifest["containers"].items():
            entry["name"] = f"bluefire-lab-x1-{name}"

    rewrite(folder, reach)

    steps = {step["id"]: step for step in score_of(folder)["score"]["path"]["steps"]}

    assert ecs_lines(folder, score.EVENTS_FILE)[0]["labels"]["tied_by"] == tied
    expected = ("telemetry only", "seen") if tied == "address" else ("no telemetry", "unseen")
    assert (steps["s03"]["visibility"], steps["s03"]["outcome"]) == expected


def test_a_line_that_names_an_account_of_the_path_goes_only_to_a_step_on_its_host(tmp_path: Path) -> None:
    # webadmin's login on web comes in the grace after s01, which reached web, and after s03 started on build.
    archive = [
        line(
            "web",
            T0 + 13,
            "/var/log/auth.log",
            "sshd[12]: Accepted password for webadmin from 10.9.0.9 port 4002 ssh2",
            data={"dstuser": "webadmin"},
        )
    ]
    folder = small_run(tmp_path, archive, [])

    def elsewhere(manifest: dict) -> None:
        s03 = manifest["path"]["steps"][1]
        s03.update(host="build", started_ns=int((T0 + 12) * 1e9), ended_ns=int((T0 + 12.2) * 1e9))

    rewrite(folder, elsewhere)

    score_of(folder)

    labels = ecs_lines(folder, score.EVENTS_FILE)[0]["labels"]
    assert (labels["origin"], labels["step_id"], labels["tied_by"]) == ("step", "s01", "account")


def test_a_first_step_timed_by_the_engines_clock_gives_no_race_and_no_recording(tmp_path: Path) -> None:
    folder = small_run(tmp_path)
    rewrite(folder, lambda m: m["path"]["steps"][0].update(time_source="engine clock (not matched)"))

    assert engine.rescore(folder) == 1
    manifest = json.loads((folder / "manifest.json").read_text())

    found = manifest["score"]["path"]
    assert found["race"]["says"] == "no race: s01 has no times on the Docker daemon's clock"
    assert "first_alert_seconds" not in found["race"]
    assert found["clock"]["steps on the engine's clock"] == ["s01"] and found["clock"]["agree"] is False
    assert manifest["recording"]["error"] is not None
    assert not (folder / recording.FILE).exists()


def test_a_goal_step_timed_by_the_engines_clock_gives_no_goal_time_and_no_recording(tmp_path: Path) -> None:
    folder = small_run(tmp_path)
    rewrite(folder, lambda m: m["path"]["steps"][1].update(time_source="engine clock (not matched)"))

    assert engine.rescore(folder) == 1
    manifest = json.loads((folder / "manifest.json").read_text())

    race = manifest["score"]["path"]["race"]
    assert "goal_seconds" not in race
    assert race["says"].startswith("not a result, the clocks are not shown to agree: first alert after")
    assert race["says"].endswith("the goal's step s03 has no times on the Docker daemon's clock")
    assert "not a result" in manifest["recording"]["error"]
    assert not (folder / recording.FILE).exists()


def test_a_race_the_clock_check_does_not_back_is_labelled_and_has_no_recording(tmp_path: Path) -> None:
    # Without its session's program start, s03 gives the clock check nothing to check.
    archive = [make() for name, (make, _) in LINES.items() if name != "a program the test started"]
    named = dict(zip([n for n in LINES if n != "a program the test started"], archive, strict=True))
    alerts = [alert_on(named["webadmin's login"], "40112", 12, "Multiple authentication failures.")]
    folder = small_run(tmp_path, archive, alerts)

    assert engine.rescore(folder) == 1
    manifest = json.loads((folder / "manifest.json").read_text())

    race = manifest["score"]["path"]["race"]
    assert manifest["score"]["path"]["clock"]["agree"] is False
    assert race["result"] is False
    assert race["says"] == "not a result, the clocks are not shown to agree: alert before goal by 10.8 s"
    assert (folder / "score.md").read_text().startswith("### Path of range-one: not a result")
    assert not (folder / recording.FILE).exists()


def test_a_step_recorded_with_its_daemon_end_before_its_start_is_never_told_so(tmp_path: Path) -> None:
    # The daemon's times of s03, as a manifest can hold them: its end 0.749 s before its start. The folder was
    # scored once before, with a recording.
    folder = small_run(tmp_path)
    scored(folder)
    rewrite(
        folder,
        lambda m: m["path"]["steps"][1].update(
            ended_ns=int((T0 + 20 - 0.749) * 1e9), ended=iso(T0 + 20 - 0.749).replace("+00:00", "Z")
        ),
    )

    assert engine.rescore(folder) == 1
    manifest = json.loads((folder / "manifest.json").read_text())

    found = manifest["score"]["path"]
    assert found["clock"]["steps on the engine's clock"] == ["s03"] and found["clock"]["agree"] is False
    assert found["race"]["says"].startswith("not a result")
    assert found["steps"][1]["started"] is None and found["steps"][1]["ended"] is None
    s03 = ecs_lines(folder, score.STEPS_FILE)[1]
    assert "start" not in s03["event"] and "end" not in s03["event"] and "duration" not in s03["event"]
    assert s03["labels"]["time_source"] == "daemon, its end before its start"
    assert not (folder / recording.FILE).exists()


def test_an_alert_the_managers_time_puts_before_its_line_counts_from_its_line(tmp_path: Path) -> None:
    # The manager's time of this line, and of the alert raised on it, runs 2.4 s behind the time on the line.
    archive = [
        line(
            "web",
            T0 + 9,
            "/var/log/auth.log",
            "sshd[12]: Accepted password for webadmin from 10.9.0.2 port 4002 ssh2",
            received=-2.4,
            data={"srcip": "10.9.0.2", "dstuser": "webadmin"},
        ),
        LINES["a program the test started"][0](),
    ]
    alerts = [alert_on(archive[0], "40112", 12, "Multiple authentication failures followed by a success.")]
    folder = small_run(tmp_path, archive, alerts)

    manifest = scored(folder)

    assert manifest["score"]["path"]["race"]["first_alert_seconds"] == pytest.approx(9.0, abs=0.002)
    made = json.loads((folder / recording.FILE).read_text())
    assert "raised" not in made["alerts"][0]
    assert made["steps"][0]["first_alert"] == made["alerts"][0]["time"]
    assert any("behind" in note for note in made["notes"])
