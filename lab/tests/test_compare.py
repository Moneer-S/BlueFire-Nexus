"""The comparison of two runs, on results documents built by hand."""

from __future__ import annotations

from bluefire_lab import compare


def a_run(
    role, guid, execution="took effect", visibility="telemetry only", rules=(), lab=(), **extra
) -> dict:
    seen = {
        "answer": visibility,
        "rules": [{"level": level, "title": title} for level, title in rules],
        "events_by_kind": {"file created": 2} if visibility != "no telemetry" else {},
        "with_lab_rules": {
            "answer": "alert" if lab else visibility,
            "rules": [{"title": title, "accepted": True} for title in lab],
        },
    }
    return {"role": role, "guid": guid, "technique": "T1", "name": f"test {guid}",
            "execution": {"answer": execution, "basis": "the effect check exited with status 1"},
            "visibility": seen, **extra}  # fmt: skip


def results(*tests, lab_rules=()) -> dict:
    return {"run": {"id": "r1", "started": "2026-11-16T04:00:00Z", "tools": {}}, "tests": list(tests),
            "lab_rules": list(lab_rules)}  # fmt: skip


def test_a_test_that_runs_twice_is_matched_in_order() -> None:
    before = results(a_run("canary", "c"), a_run("test", "a"), a_run("canary", "c"))
    after = results(a_run("canary", "c"), a_run("test", "a"), a_run("canary", "c", visibility="alert"))

    result = compare.compare(before, after)

    assert (result["same"], len(result["changed"]), result["new"], result["gone"]) == (2, 1, [], [])


def test_each_change_says_what_changed_underneath() -> None:
    rule = {"title": "Rule Of The Lab", "procedures": 2}
    before = results(
        a_run("test", "seen", visibility="no telemetry"),
        a_run("test", "ruled"),
        a_run("test", "quiet"),
        a_run("test", "fixed"),
        a_run("hardened", "locked", defense={"name": "lock", "title": "a lock"}),
    )
    after = results(
        a_run("test", "seen"),
        a_run("test", "ruled", visibility="alert", rules=[("high", "A Pinned Rule")]),
        a_run("test", "quiet", rules=[("medium", "A Medium Rule")]),  # an answer that did not change
        a_run("test", "fixed", lab=["Rule Of The Lab"]),
        a_run("hardened", "locked", execution="blocked", defense={"name": "lock", "title": "a lock"}),
        lab_rules=[rule],
    )

    why = {row["test"]["guid"]: row["why"] for row in compare.compare(before, after)["changed"]}

    assert why["seen"] == ["recorded now: 2 file created events"]
    assert why["ruled"] == ["high: A Pinned Rule matches now"]
    assert "quiet" not in why
    assert why["fixed"] == ["the lab's rule Rule Of The Lab is accepted now, covering 2 published procedures"]
    assert why["locked"] == ["execution: the effect check exited with status 1"]


def test_runs_that_only_one_side_has_are_new_or_gone() -> None:
    before = results(a_run("test", "a"), a_run("test", "old"))
    after = results(
        a_run("test", "a"),
        a_run("variant", "a", args={"path": "/var/tmp/x"}),
        a_run("test", "narrowed", args={"search_path": "~"}),  # the list's own argument, not a variant
        a_run("hardened", "a", execution="blocked", defense={"name": "lock", "title": "a lock"}),
    )

    result = compare.compare(before, after)
    summary = compare.markdown(before, after)

    assert [test["guid"] for test in result["gone"]] == ["old"]
    assert [test["role"] for test in result["new"]] == ["variant", "test", "hardened"]
    assert (
        "New: T1 test narrowed, with search_path=~; T1 test a, with a lock: blocked; "
        "T1 test a with changed input arguments (1x)."
    ) in summary
    assert "Gone: T1 test old." in summary
    assert "1 run of a test gave the same answers, 0 changed, 3 are new and 1 are gone." in summary


def test_each_hardening_change_says_which_procedures_it_blocked() -> None:
    lock = {"name": "lock", "title": "a lock"}
    after = results(
        a_run("hardened", "a", execution="blocked", defense=lock),
        a_run("hardened", "b", execution="took effect", defense=lock),
        a_run("hardened", "c", execution="blocked", defense={"name": "wall", "title": "a wall"}),
    )

    assert compare.coverage(after) == [
        "- a lock: blocked 1 of the 2 published procedures it was tried on; not T1 test b (took effect)",
        "- a wall: blocked 1 of the 1 published procedure it was tried on",
    ]
