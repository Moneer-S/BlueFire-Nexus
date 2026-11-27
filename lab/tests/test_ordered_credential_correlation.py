"""The lab's ordered credential-search correlation over made-up process rows.

The events in this file were written for the tests. They carry only the
ordinary Snoopy process fields the rule receives: no range step, origin,
expected result, path, or outcome label.
"""

from __future__ import annotations

from pathlib import Path

from bluefire_lab.range import sigma

LAB = Path(__file__).resolve().parents[1]
RULES = LAB / "rules"
FOLDERS = ["ordered-credential"]
CORRELATION_ID = "cd5a0e6f-d3b5-42ec-bff3-a9a0a36365dd"
ATOMIC_FIELDS = {"Image", "CommandLine", "CurrentDirectory"}
CORRELATION_FIELDS = {"Computer", "User"}


def clock(second: int) -> str:
    """A made-up time within the test day."""

    minute, second = divmod(second, 60)
    hour, minute = divmod(minute, 60)
    return f"{hour:02d}:{minute:02d}:{second:02d}"


def snoopy(
    command: str,
    exe: str,
    *,
    second: int,
    host: str,
    login: str,
    cwd: str = "/tmp",
) -> dict:
    """One made-up Wazuh archive event in the shape of a Snoopy process start."""

    moment = clock(second)
    return {
        "timestamp": f"2026-11-01T{moment}.000+0000",
        "agent": {"name": host},
        "location": "/var/log/snoopy.log",
        "full_log": (
            f"2026-11-01T{moment}.000000+00:00 {host} snoopy[7]: [login:{login} cwd:{cwd}]: {command}"
        ),
        "predecoder": {"program_name": "snoopy"},
        "decoder": {"name": "bluefire-snoopy"},
        "data": {"login": login, "cwd": cwd, "command": command, "exe": exe},
    }


def recursive_search(*, second: int, host: str, login: str) -> dict:
    return snoopy(
        "grep -R password /srv/www/store",
        "/usr/bin/grep",
        second=second,
        host=host,
        login=login,
    )


def private_key_search(*, second: int, host: str, login: str) -> dict:
    return snoopy(
        "find /var/lib/app-data -name id_ed25519 -type f",
        "/usr/bin/find",
        second=second,
        host=host,
        login=login,
    )


def remote_archive(*, second: int, host: str, login: str, cwd: str = "/var/tmp/stage") -> dict:
    return snoopy(
        "ssh deploy@builder '(cd /etc && tar -zcf - *)'",
        "/usr/bin/ssh",
        second=second,
        host=host,
        login=login,
        cwd=cwd,
    )


def correlations(result: dict) -> list[dict]:
    return [match for match in result["matches"] if match["rule"]["id"] == CORRELATION_ID]


def evaluated(engine: Path, tmp_path: Path, events: list[dict]) -> dict:
    return sigma.evaluate_set(engine, RULES, FOLDERS, events, tmp_path / "engine")


def test_the_range_only_set_stays_out_of_the_legacy_one_host_rule_tree() -> None:
    ordered = (RULES / FOLDERS[0]).resolve()

    assert ordered.is_dir()
    assert not ordered.is_relative_to((RULES / "linux").resolve())


def test_the_published_set_uses_only_observed_process_and_correlation_fields() -> None:
    read = []
    text = []
    for path in sorted((RULES / FOLDERS[0]).glob("*.yml")):
        source = path.read_text(encoding="utf-8")
        text.append(source)
        rule = sigma.read_rule(source, path.name)
        assert isinstance(rule, dict)
        read.append(rule)

    atomics = [rule for rule in read if rule["kind"] == "atomic"]
    correlation = [rule for rule in read if rule["kind"] == "correlation"]
    assert len(atomics) == 3
    assert len(correlation) == 1
    assert all(set(rule["fields"]) <= ATOMIC_FIELDS for rule in atomics)
    assert set(correlation[0]["fields"]) == CORRELATION_FIELDS
    assert all(rule["level"] == "informational" for rule in atomics)
    assert correlation[0]["level"] == "high"

    published = "\n".join(text)
    for forbidden in (
        "labels.step_id",
        "labels.origin",
        "wazuh.data.tag",
        "path_id",
        "step:s",
        "webadmin",
    ):
        assert forbidden not in published


def test_ordered_evidence_anchors_to_the_terminal_event_at_the_window_boundary(
    engine: Path, tmp_path: Path
) -> None:
    first = [
        remote_archive(second=40, host="shop-web", login="release"),
        recursive_search(second=0, host="shop-web", login="release"),
        private_key_search(second=20, host="shop-web", login="release"),
    ]
    boundary = [
        recursive_search(second=120, host="build-web", login="operator"),
        private_key_search(second=150, host="build-web", login="operator"),
        remote_archive(second=179, host="build-web", login="operator"),
    ]
    events = first + boundary

    for event in events:
        assert not {"labels", "origin", "step", "path", "outcome", "expected"} & event.keys()
        assert not {"tag", "origin", "step", "path", "outcome", "expected"} & event["data"].keys()

    result = evaluated(engine, tmp_path, events)
    matches = correlations(result)

    assert result["rules"] == 4
    assert result["atomic rules"] == 3
    assert result["correlations"] == 1
    assert result["loaded"] == 4
    assert result["conversion errors"] == []
    assert result["files that are not a rule"] == []
    assert [(match["event"], match["evidence"], match["evidence ids"]) for match in matches] == [
        (0, [1, 2, 0], ["archive-2", "archive-3", "archive-1"]),
        (5, [3, 4, 5], ["archive-4", "archive-5", "archive-6"]),
    ]
    assert events[matches[0]["event"]]["timestamp"] == "2026-11-01T00:00:40.000+0000"


def test_incomplete_reversed_split_late_and_ordinary_activity_do_not_correlate(
    engine: Path, tmp_path: Path
) -> None:
    events = [
        # Missing terminal stage.
        recursive_search(second=0, host="missing", login="missing-user"),
        private_key_search(second=20, host="missing", login="missing-user"),
        # The terminal action precedes the private-key search.
        recursive_search(second=0, host="reversed", login="reversed-user"),
        remote_archive(second=20, host="reversed", login="reversed-user"),
        private_key_search(second=40, host="reversed", login="reversed-user"),
        # Split across computers.
        recursive_search(second=0, host="host-a", login="split-host"),
        private_key_search(second=20, host="host-a", login="split-host"),
        remote_archive(second=40, host="host-b", login="split-host"),
        # Split across recorded logins.
        recursive_search(second=0, host="split-user", login="user-a"),
        private_key_search(second=20, host="split-user", login="user-a"),
        remote_archive(second=40, host="split-user", login="user-b"),
        # One second beyond the one-minute window.
        recursive_search(second=0, host="late", login="late-user"),
        private_key_search(second=30, host="late", login="late-user"),
        remote_archive(second=61, host="late", login="late-user"),
        # Repeating one stage cannot stand in for the other two.
        recursive_search(second=0, host="repeat", login="repeat-user"),
        recursive_search(second=20, host="repeat", login="repeat-user"),
        recursive_search(second=40, host="repeat", login="repeat-user"),
        # A nonrecursive grep does not satisfy the first stage.
        snoopy(
            "grep password /srv/www/store",
            "/usr/bin/grep",
            second=0,
            host="plain-grep",
            login="plain-user",
        ),
        private_key_search(second=20, host="plain-grep", login="plain-user"),
        remote_archive(second=40, host="plain-grep", login="plain-user"),
        # A key-looking path inspected with another program is not a find search.
        recursive_search(second=0, host="not-find", login="not-find-user"),
        snoopy(
            "stat /var/lib/app-data/id_rsa",
            "/usr/bin/stat",
            second=20,
            host="not-find",
            login="not-find-user",
        ),
        remote_archive(second=40, host="not-find", login="not-find-user"),
        # An ordinary SSH command is not a remote archive.
        recursive_search(second=0, host="ssh-uptime", login="ssh-user"),
        private_key_search(second=20, host="ssh-uptime", login="ssh-user"),
        snoopy(
            "ssh deploy@builder uptime",
            "/usr/bin/ssh",
            second=40,
            host="ssh-uptime",
            login="ssh-user",
            cwd="/var/tmp/stage",
        ),
        # The remote archive must start from a temporary staging tree.
        recursive_search(second=0, host="home-cwd", login="home-user"),
        private_key_search(second=20, host="home-cwd", login="home-user"),
        remote_archive(second=40, host="home-cwd", login="home-user", cwd="/srv/work"),
        # A local tar is not an SSH client.
        recursive_search(second=0, host="local-tar", login="tar-user"),
        private_key_search(second=20, host="local-tar", login="tar-user"),
        snoopy(
            "tar -czf /var/tmp/archive.tgz /srv/app",
            "/usr/bin/tar",
            second=40,
            host="local-tar",
            login="tar-user",
            cwd="/var/tmp/stage",
        ),
        # A terminal event without its precursors remains an atomic observation.
        remote_archive(second=40, host="terminal-only", login="terminal-user"),
        # Ordinary administrative, build, cache, and backup activity.
        snoopy(
            "grep -R TODO /srv/www/store",
            "/usr/bin/grep",
            second=0,
            host="ordinary",
            login="admin",
        ),
        snoopy(
            "find /var/lib/caches -name '*.pem'",
            "/usr/bin/find",
            second=10,
            host="ordinary",
            login="admin",
        ),
        snoopy(
            "ssh backup@builder uptime",
            "/usr/bin/ssh",
            second=20,
            host="ordinary",
            login="admin",
            cwd="/var/tmp/cache",
        ),
        snoopy(
            "tar -czf /var/backups/app.tgz /srv/app",
            "/usr/bin/tar",
            second=30,
            host="ordinary",
            login="admin",
            cwd="/var/backups",
        ),
    ]

    assert correlations(evaluated(engine, tmp_path, events)) == []
