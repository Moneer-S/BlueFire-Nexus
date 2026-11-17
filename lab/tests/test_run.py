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
