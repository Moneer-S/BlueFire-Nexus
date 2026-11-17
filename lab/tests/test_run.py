import json
from pathlib import Path

import pytest

from bluefire_lab import run

CANARY = {"technique": "T1070.003", "guid": "a", "name": "canary"}
CONTROL = {"technique": "T1082", "guid": "b", "name": "control"}
CHANGE = {"title": "a change", "why": "a reason", "apply": "true", "revert": "true"}


def a_plan(**changes) -> dict:
    document = {
        "canary": CANARY,
        "control": CONTROL,
        "tests": [
            {"technique": "T1", "guid": "c", "name": "first", "defenses": ["lock"]},
            {"technique": "T2", "guid": "d", "name": "second"},
            {"technique": "T3", "guid": "e", "name": "third", "defenses": ["lock", "other"]},
        ],
        "defenses": {"lock": CHANGE, "other": {**CHANGE, "title": "another change"}},
    }
    document.update(changes)
    return document


def test_hardened_runs_come_after_every_test_and_before_the_last_canary() -> None:
    runs = run.plan(a_plan())

    assert [(item["order"], item["role"], item["spec"]["name"]) for item in runs] == [
        (1, "canary", "canary"),
        (2, "control", "control"),
        (3, "test", "first"),
        (4, "test", "second"),
        (5, "test", "third"),
        (6, "hardened", "first"),
        (7, "hardened", "third"),
        (8, "hardened", "third"),
        (9, "canary", "canary"),
    ]
    hardened = [item for item in runs if item["role"] == "hardened"]
    assert [(item["compared_with"], item["defense"]["name"]) for item in hardened] == [
        (3, "lock"),
        (5, "lock"),
        (5, "other"),
    ]
    assert hardened[2]["defense"]["title"] == "another change"


def test_a_plan_without_hardening_runs_the_tests_between_two_canaries() -> None:
    document = a_plan(tests=[{"technique": "T1", "guid": "c", "name": "first"}])
    del document["defenses"]

    assert [item["role"] for item in run.plan(document)] == ["canary", "control", "test", "canary"]


def test_a_change_that_is_not_defined_stops_the_run() -> None:
    document = a_plan(defenses={"lock": CHANGE})

    with pytest.raises(SystemExit, match="'other'"):
        run.plan(document)


def test_commands_name_the_test_account_through_placeholders() -> None:
    context = {"home": "/home/bluefire-lab", "account": "bluefire-lab"}

    filled = run.fill("chown -R {account}:{account} {home}/.ssh", context)

    assert filled == "chown -R bluefire-lab:bluefire-lab /home/bluefire-lab/.ssh"


def test_the_baseline_runs_after_the_control_and_variants_after_the_hardened_runs() -> None:
    document = a_plan(baseline={"name": "ordinary work", "root": "true", "account": "true"})
    document["tests"][1]["variants"] = [{"args": {"path": "/var/tmp/x"}, "effect": "test -e /var/tmp/x"}]

    runs = run.plan(document)

    assert [item["role"] for item in runs] == [
        "canary", "control", "baseline", "test", "test", "test",
        "hardened", "hardened", "hardened", "variant", "canary",
    ]  # fmt: skip
    variant = runs[9]
    assert variant["compared_with"] == 5
    assert variant["spec"]["args"] == {"path": "/var/tmp/x"}
    assert variant["spec"]["effect"] == "test -e /var/tmp/x"
    assert "variants" not in variant["spec"]
    assert [item["compared_with"] for item in runs if item["role"] == "hardened"] == [4, 6, 6]


def test_an_input_argument_the_test_does_not_declare_stops_the_run(tmp_path: Path) -> None:
    guid = "23d348f3-cc5c-4ba9-bd0a-ae09069f0914"
    upstream = {"name": "a test", "auto_generated_guid": guid, "supported_platforms": ["linux"],
                "input_arguments": {"history_path": {"default": "~/.bash_history"}},
                "executor": {"name": "sh", "command": "true"}}  # fmt: skip
    (tmp_path / "T1070.003").mkdir()
    (tmp_path / "T1070.003" / "T1070.003.yaml").write_text(json.dumps({"atomic_tests": [upstream]}))
    spec = {"technique": "T1070.003", "guid": guid, "name": "a test"}

    assert run.upstream_definition({**spec, "args": {"history_path": "~/.zsh_history"}}, tmp_path) == upstream
    with pytest.raises(SystemExit, match="no input argument histroy_path"):
        run.upstream_definition({**spec, "args": {"histroy_path": "~/.zsh_history"}}, tmp_path)


def test_the_inventory_reads_accounts_sockets_and_services() -> None:
    passwd = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "bluefire-lab:x:1002:1002::/home/bluefire-lab:/bin/bash\n"
    )
    ss = (
        "udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*\n"
        "tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*\n"
        "tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*\n"
    )
    units = "cron.service loaded active running Regular background program processing daemon\n"
    shells = "# /etc/shells: valid login shells\n/bin/sh\n/bin/bash\n/usr/bin/bash\n"

    assert run.login_accounts(passwd, shells) == ["bluefire-lab", "root"]  # sync's /bin/sync is no shell
    assert run.listening(ss) == ["tcp 0.0.0.0:22", "tcp 127.0.0.53%lo:53", "udp 127.0.0.53%lo:53"]
    assert run.running_services(units) == ["cron.service"]


def test_a_test_whose_program_the_target_lacks_is_dropped_with_the_reason() -> None:
    document = a_plan()
    document["tests"][0]["needs"] = ["crontab"]
    document["tests"][2]["needs"] = ["systemctl", "useradd"]
    found = {"programs": {"crontab": "/usr/bin/crontab", "systemctl": "", "useradd": "/usr/sbin/useradd"}}

    kept, dropped = run.select(document, found)

    assert [spec["name"] for spec in kept["tests"]] == ["first", "second"]
    assert dropped == [
        {"technique": "T3", "name": "third", "reason": "the target has no systemctl, which the test needs"}
    ]
    assert [item["role"] for item in run.plan(kept)] == [
        "canary",
        "control",
        "test",
        "test",
        "hardened",
        "canary",
    ]
