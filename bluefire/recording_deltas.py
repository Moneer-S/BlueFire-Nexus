"""Comparisons of two recordings (deltas): format checks and storage.

A delta (``bluefire.delta/1``, the section "A delta" of ``docs/RECORDING.md``)
says what differs between a recording made before a change and one made after
it, and whether one declared change can explain it. ``bluefire-lab compare``
computes it, and it is the only place where that claim is computed or refused:
BlueFire never computes or corrects a delta. On import it checks that the delta
follows the format in every key the app reads, that both recordings it names are
kept here as the very files it was made from (by their SHA-256 and id), finished,
with the facts it copies from their source, and that every step id it names is a
step of its recording. A delta is served only while both files are still the ones
it names. A delta of one run evaluated twice names two files of one recording id,
and the checks hold its recordings to one run: the same source, steps, events,
published rules' alerts and ordinary activity, and the lab's rules said to differ
as the recordings judged them. A delta of two runners that differed carries a ``limit``: its verdict
credits only the steps that carry the change's own ``mark``, and the checks
refuse a delta whose limit, marks, audit keys, counts and differences do not
agree, or whose recordings do not say what their audit rules watch. The checks
hold the format's structure and the few phrases the format fixes; the lab's
other sentences are its own to improve, and are drawn as it wrote them.

Shipped deltas are files under ``bluefire/data/recordings/deltas/``; imported ones
are kept under ``<runs-dir>/recordings/deltas/``, written under the recording
store's import lock.
"""

from __future__ import annotations

import hashlib
import json
import re
from http import HTTPStatus
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

from .application_errors import APIError
from .recordings import (
    _HAPPENED,
    _ID,
    _OUTCOMES,
    MAX_STEPS,
    RecordingError,
    RecordingLibrary,
    _Checker,
    _reject_constant,
    _reject_duplicate_keys,
    _walk,
    _write_atomically,
)
from .util import canonical_json_bytes

DELTA_SCHEMA = "bluefire.delta/1"
CLAIM = "one pair of runs"
ONE_RUN = "one run evaluated with two rule sets"
LAB_RULES = "detectors:lab"
MAX_DELTA_BYTES = 8 * 1024 * 1024
MAX_LISTED = 200
FIELDS = ("happened", "recorded", "outcome", "outcome_with_lab_rules")
RESULTS = ("same", "better", "worse", "changed", "not attributable", "without cause", "no verdict")
_RECORDED = ("recorded", "no telemetry", "not known")
_PAIRED_BY = ("id", "role, test and order")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
DELTA_ID = re.compile(r"^[0-9a-f]{16}$")
_TOP_LEVEL = {
    "schema", "claim", "before", "after", "declared_change", "comparable", "refused_because",
    "differences", "same_in_both", "lab_code", "judged", "control", "counts", "unexplained",
    "steps", "new", "gone", "race",
}  # fmt: skip
# Keys a delta of two runners side by side, of a change of the audit rules or of one run
# evaluated twice adds; a delta without them reads as one of two alike runs.
_OPTIONAL = {"runners", "limit", "audit_keys", "one_run", "lab_rules"}
_LAB_RULE_CHANGES = ("new", "gone", "changed", "moved")
_LINE = 2_000
_LIST = 2_000
_RECORDS_LINES = 20
# What a side of a delta copies from its recording's source; the page shows these.
_SOURCE_FACTS = ("run_url", "environment", "commit", "defense_commit", "started")
# The results the counts credit to the declared change; under a limit, only by its mark.
_CREDITED = ("better", "worse", "changed")
_MARK_LEAD = "{result} by the change's own mark, on two runners that differed"
_UNKNOWN_PRICE = "price not known"
# What two fresh runners can differ in, which a limit may name; and the declared changes that
# leave a mark of their own, the only ones a limited verdict is given for.
_RUNNER_NAMES = ("images:", "kernels:")
_MARKED_CHANGES = ("sensors:auditd",)

IMPORTED_DELTA_NOTE = (
    "Imported. BlueFire checked that this comparison follows the delta format, that both "
    "recordings it names are kept here as the files it was made from, by their SHA-256, and "
    "that every step it names is in them. It did not make the comparison and does not check "
    "what it says of the two runs."
)
SHIPPED_DELTA_NOTE = (
    "Shipped with BlueFire, with both of its recordings. BlueFire checked that this "
    "comparison follows the delta format and names both recordings by the SHA-256 of their "
    "files, with every step it lists. It did not make the comparison: bluefire-lab compare did."
)
SHIPPED_ONE_RUN_NOTE = (
    "Shipped with BlueFire, with both of its recordings. This repository's lab workflow ran "
    "the list once, evaluated its telemetry with two sets of the lab's rules, and compared "
    "the two, in the CI run at {run_url}. BlueFire checked that the comparison follows the "
    "delta format, names both recordings by the SHA-256 of their files with every step it "
    "lists, and that the two are one run. It did not make the comparison: bluefire-lab "
    "compare did."
)
SHIPPED_PAIR_NOTE = (
    "Shipped with BlueFire, with both of its recordings. This repository's lab workflow made "
    "the two runs side by side, and this comparison of them, in the CI run at {run_url}. "
    "BlueFire checked that the comparison follows the delta format and names both recordings "
    "by the SHA-256 of their files, with every step it lists. It did not make the comparison: "
    "bluefire-lab compare did."
)


def _texts(check: _Checker, parent: Mapping[str, Any], key: str, where: str) -> list[str]:
    value = parent.get(key)
    if not isinstance(value, list) or len(value) > _LIST:
        check.fail(f"{where}.{key}" if where else key, f"must be a list of at most {_LIST} texts.")
        return []
    texts = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip() or len(item) > _LINE:
            check.fail(f"{where}.{key}[{index}]" if where else f"{key}[{index}]",
                       "must be non-empty text.")  # fmt: skip
        else:
            texts.append(item)
    return texts


def _fields(check: _Checker, parent: Mapping[str, Any], key: str, where: str) -> None:
    for item in _texts(check, parent, key, where):
        if item not in FIELDS:
            check.fail(f"{where}.{key}", "must name fields among: " + ", ".join(FIELDS) + ".")
            return


def _side(check: _Checker, value: Any, where: str) -> None:
    side = check.obj(value, where)
    sha = side.get("sha256")
    if not isinstance(sha, str) or not _SHA256.fullmatch(sha):
        check.fail(f"{where}.sha256", "must be the SHA-256 of the recording's file, 64 hex digits.")
    if not isinstance(side.get("id"), str) or not _ID.fullmatch(side["id"]):
        check.fail(f"{where}.id", "must be 1 to 64 letters, digits, '-' or '_'.")
    for key in ("run_url", "environment", "commit", "defense_commit", "lab_rules_commit"):
        check.text(side, key, where, required=False, limit=_LINE)
    check.time(side, "started", where, required=False)


def _outcomes(check: _Checker, value: Any, where: str) -> None:
    side = check.obj(value, where)
    check.text(side, "happened", where, choices=_HAPPENED)
    check.text(side, "recorded", where, choices=_RECORDED)
    check.text(side, "outcome", where, choices=_OUTCOMES)
    check.text(side, "outcome_with_lab_rules", where, choices=_OUTCOMES)


def _listed(check: _Checker, value: Any, where: str) -> None:
    for index, step in enumerate(check.items(value, where, MAX_STEPS)):
        for key in ("id", "role", "title", "technique"):
            check.text(step, key, f"{where}[{index}]", limit=500)


def _limit(check: _Checker, value: Any) -> Mapping[str, Any] | None:
    """The limit of a verdict on two runners that differed, or None when it is like with like."""

    if value is None:
        return None
    limit = check.obj(value, "limit")
    for key in ("why", "credits"):
        check.text(limit, key, "limit", limit=_LINE)
    _texts(check, limit, "differences", "limit")
    if isinstance(limit.get("differences"), list) and not limit["differences"]:
        check.fail("limit.differences", "must name what differed between the runners.")
    for key in ("credited", "not_attributable"):
        check.count(limit, key, "limit", required=True)
    return limit


def _mark(check: _Checker, value: Any, where: str) -> None:
    mark = check.obj(value, where)
    check.text(mark, "run", where, choices=("before", "after"))
    keys = _texts(check, mark, "keys", where)
    if isinstance(mark.get("keys"), list) and not keys:
        check.fail(f"{where}.keys", "must name the audit keys of the mark.")
    check.count(mark, "events", where, required=True)
    if mark.get("events") == 0:
        check.fail(f"{where}.events", "must be at least 1: a mark is events of the change's own.")


def _records(check: _Checker, value: Any, where: str) -> None:
    records = check.obj(value, where)
    check.text(records, "sensor", where)
    for key in ("new", "gone"):
        part = check.obj(records.get(key), f"{where}.{key}")
        check.count(part, "count", f"{where}.{key}", required=True)
        lines = _texts(check, part, "lines", f"{where}.{key}")
        if len(lines) > _RECORDS_LINES:
            check.fail(f"{where}.{key}.lines", f"holds at most the first {_RECORDS_LINES} lines.")
        if isinstance(part.get("count"), int) and part["count"] < len(lines):
            check.fail(f"{where}.{key}.count", "must not be less than the lines it gives.")


def _audit_keys(check: _Checker, value: Any, limited: bool) -> None:
    """The audit keys only one run's events carry. Under a limit each says whether its events can
    carry the change's own mark, and why not when they cannot; without one, neither."""

    if value is None:
        return
    found = check.obj(value, "audit_keys")
    for side in ("only_before", "only_after"):
        keys = check.obj(found.get(side), f"audit_keys.{side}")
        if len(keys) > 500:
            check.fail(f"audit_keys.{side}", "names at most 500 audit keys.")
            continue
        for key, entry in keys.items():
            where = f"audit_keys.{side}.{key[:80]}"
            if not key.strip() or len(key) > 500:
                check.fail(f"audit_keys.{side}", "names an audit key that is empty or too long.")
            fields = check.obj(entry, where)
            check.count(fields, "events", where, required=True)
            _texts(check, fields, "steps", where)
            for name in sorted(set(fields) - {"events", "steps", "mark", "no_mark"}):
                check.fail(f"{where}.{name[:80]}", "is not a key of an audit key's entry.")
            if not limited:
                for name in ("mark", "no_mark"):
                    if name in fields:
                        check.fail(f"{where}.{name}", "is given only under a limit: whether a key "
                                   "can carry the change's own mark is asked only on two runners "
                                   "that differed.")  # fmt: skip
                continue
            check.flag(fields, "mark", where, required=True)
            mark = fields.get("mark")
            if mark is False:
                check.text(fields, "no_mark", where, limit=_LINE)
            elif mark is True and "no_mark" in fields:
                check.fail(f"{where}.no_mark", "is given only when mark is false.")


def _judged(declared: Any) -> tuple[str, ...]:
    """The fields a declared change can move, as the format gives them; the rest is control."""

    if not isinstance(declared, str):
        return ()
    if declared == LAB_RULES:
        return ("outcome_with_lab_rules",)
    if declared.startswith("detectors:"):
        return ("outcome", "outcome_with_lab_rules")
    return ("recorded", "outcome", "outcome_with_lab_rules")


def _lab_rules(check: _Checker, value: Mapping[str, Any]) -> None:
    """The lab's rules that differ, each with how each evaluation judged it: only for a
    change of the lab's rules, each side as its recording's verdicts give it."""

    rows = value.get("lab_rules")
    if rows is None:
        return
    if value.get("declared_change") != LAB_RULES:
        check.fail("lab_rules", f"is given only when the declared change is {LAB_RULES}.")
    seen: set[str] = set()
    for index, row in enumerate(check.items(rows, "lab_rules", 500)):
        where = f"lab_rules[{index}]"
        rule = check.text(row, "rule", where, limit=500)
        check.text(row, "title", where, limit=500)
        change = check.text(row, "change", where, choices=_LAB_RULE_CHANGES)
        if rule is not None:
            if rule in seen:
                check.fail(f"{where}.rule", "names a rule another row names.")
            seen.add(rule)
        sides: dict[str, Mapping[str, Any] | None] = {}
        for side in ("before", "after"):
            if side not in row:
                check.fail(f"{where}.{side}", "is missing.")
                continue
            if row[side] is None:
                sides[side] = None
                continue
            judged = check.obj(row[side], f"{where}.{side}")
            check.flag(judged, "accepted", f"{where}.{side}", required=True)
            check.text(judged, "reason", f"{where}.{side}", required=False, limit=_LINE)
            check.text(judged, "file", f"{where}.{side}", required=False, limit=500)
            for name in sorted(set(judged) - {"accepted", "reason", "file"}):
                check.fail(f"{where}.{side}.{name[:80]}", "is not a key of how a run judged a rule.")
            sides[side] = judged
        if len(sides) < 2 or change is None:
            continue
        there = {side: sides[side] is not None for side in sides}
        expected = {"new": (False, True), "gone": (True, False)}.get(change, (True, True))
        if (there["before"], there["after"]) != expected:
            check.fail(where, f"is {change}, so the rule must be in "
                       + {(False, True): "the after evaluation only", (True, False):
                          "the before evaluation only"}.get(expected, "both evaluations")
                       + ".")  # fmt: skip
        before, after = sides["before"], sides["after"]
        if change == "moved" and before is not None and after is not None:
            if before.get("file") is None or before.get("file") == after.get("file"):
                check.fail(where, "is moved, so the rule's file must differ between the two.")


def _one_run(check: _Checker, value: Mapping[str, Any]) -> None:
    """What one run evaluated twice promises of a delta's own keys. The recordings are
    checked against it on import (``one_run_problems``)."""

    once = value.get("one_run")
    claim = value.get("claim")
    # A delta without one_run is of a pair of runs, as the lab wrote before it knew one run.
    if isinstance(claim, str) and (claim == ONE_RUN) != (once is True):
        check.fail("claim", f"must be {ONE_RUN!r} exactly when one_run is true, and {CLAIM!r} "
                   "otherwise.")  # fmt: skip
    if once is not True:
        return
    if value.get("declared_change") != LAB_RULES:
        check.fail("one_run", f"is true only for a change of the lab's rules ({LAB_RULES}): only "
                   "rules run after a run can evaluate its telemetry again.")  # fmt: skip
    for key in ("runners", "limit", "audit_keys"):
        if value.get(key) is not None:
            check.fail(key, "is not given for one run evaluated twice: it ran on one runner, "
                       "with one set of audit rules.")  # fmt: skip
    sides: list[Mapping[str, Any]] = [
        part if isinstance(part, Mapping) else {}
        for part in (value.get("before"), value.get("after"))
    ]
    if sides[0].get("id") != sides[1].get("id"):
        check.fail("after.id", "must be the before recording's id: one run has one id.")
    if not sides[0].get("run_url") or sides[0].get("run_url") != sides[1].get("run_url"):
        check.fail("after.run_url", "must name the CI run the before recording names: one run "
                   "was made in one CI run.")  # fmt: skip
    if sides[0].get("sha256") is not None and sides[0].get("sha256") == sides[1].get("sha256"):
        check.fail("after.sha256", "names the before recording's file: one run evaluated twice "
                   "is two files.")  # fmt: skip
    if value.get("comparable") is True:
        control = value.get("control")
        if isinstance(control, Mapping) and control.get("varied"):
            check.fail("control.varied", "must be empty: one run evaluated twice has no run "
                       "variation, and a step whose control moved means two runs.")  # fmt: skip
        counts = value.get("counts")
        for result in ("without cause", "not attributable"):
            if isinstance(counts, Mapping) and counts.get(result):
                check.fail(f"counts.{result}", "must be 0: one run evaluated twice has no run "
                           "variation, and every lab rule whose file is the same in both is "
                           "judged the same.")  # fmt: skip
        if value.get("lab_rules") is None:
            check.fail("lab_rules", "must list the lab's rules that differ: one run evaluated "
                       "twice is compared only when both recordings say how they judged them.")  # fmt: skip


def validate_delta(value: Any) -> Mapping[str, Any]:
    """Return the delta unchanged, or raise ``RecordingError`` naming each problem.

    It checks the shape of every key the app reads, and that the delta agrees with
    itself where the format ties its keys together (a step's result, fields and
    price; the counts; the refusal). It does not check what the delta says of the
    two runs: that is ``bluefire-lab compare``'s to compute.
    """

    check = _Checker()
    if not isinstance(value, Mapping):
        raise RecordingError(["A delta must be one JSON object."])
    if value.get("schema") != DELTA_SCHEMA:
        raise RecordingError([f"schema must be {DELTA_SCHEMA!r}."])
    _walk(value, check, "A delta")
    for key in sorted(set(value) - _TOP_LEVEL - _OPTIONAL):
        check.fail(key, "is not a key of the delta format.")
    for key in sorted(_TOP_LEVEL - set(value)):
        check.fail(key, "is missing.")
    check.text(value, "claim", "delta", choices=(CLAIM, ONE_RUN))
    _side(check, value.get("before"), "before")
    _side(check, value.get("after"), "after")
    check.text(value, "declared_change", "delta", required=False, null=True)
    check.flag(value, "one_run", "delta", required=False)
    _lab_rules(check, value)
    _one_run(check, value)
    runners = value.get("runners")
    if runners is not None and (isinstance(runners, bool) or runners != 2):
        check.fail("runners", "must be 2 or null.")
    limit = _limit(check, value.get("limit"))
    _audit_keys(check, value.get("audit_keys"), limit is not None)
    check.flag(value, "comparable", "delta", required=True)
    refusals = _texts(check, value, "refused_because", "")
    if isinstance(value.get("comparable"), bool) and value["comparable"] == bool(refusals):
        check.fail("comparable", "must be true exactly when refused_because is empty.")
    for index, difference in enumerate(check.items(value.get("differences"), "differences", 500)):
        where = f"differences[{index}]"
        check.text(difference, "what", where)
        for key in ("before", "after"):
            if key not in difference:
                check.fail(f"{where}.{key}", "is missing.")
            else:
                check.text(difference, key, where, required=False, limit=_LINE, null=True)
        if "declared" in difference and difference["declared"] is not True:
            check.fail(f"{where}.declared", "must be true, or left out.")
    _texts(check, value, "same_in_both", "")
    code = check.obj(value.get("lab_code"), "lab_code")
    for key in ("before", "after"):
        if key not in code:
            check.fail(f"lab_code.{key}", "is missing.")
        else:
            check.text(code, key, "lab_code", required=False, limit=_LINE, null=True)
    check.flag(code, "same", "lab_code", required=True)
    _fields(check, value, "judged", "")
    control = check.obj(value.get("control"), "control")
    _fields(check, control, "fields", "control")
    # What a declared change can move is the format's, not the delta's to choose.
    judged = _judged(value.get("declared_change"))
    if isinstance(value.get("judged"), list) and value["judged"] != list(judged):
        check.fail("judged", "must be the fields the declared change can move: "
                   + (", ".join(judged) or "none, since nothing was declared") + ".")  # fmt: skip
    rest = [field for field in FIELDS if field not in judged]
    if isinstance(control.get("fields"), list) and control["fields"] != rest:
        check.fail("control.fields", "must be the fields the declared change cannot move: "
                   + ", ".join(rest) + ".")  # fmt: skip
    check.count(control, "same", "control", required=True)
    check.count(control, "of", "control", required=True)
    _texts(check, control, "varied", "control")
    counts = check.obj(value.get("counts"), "counts")
    for key in ("paired", *RESULTS, "new", "gone"):
        check.count(counts, key, "counts", required=True)
    # A delta of two alike runners may leave it out; under a limit it says how many steps
    # the change's mark alone credits.
    check.count(counts, "by_mark", "counts", required=limit is not None)
    _texts(check, value, "unexplained", "")
    results: dict[str, int] = {}
    marked = 0
    for index, step in enumerate(check.items(value.get("steps"), "steps", MAX_STEPS)):
        where = f"steps[{index}]"
        check.text(step, "id", where, limit=500)
        check.text(step, "before_id", where, required=False, limit=500)
        for key in ("role", "title", "technique"):
            check.text(step, key, where, limit=500)
        check.text(step, "paired_by", where, choices=_PAIRED_BY)
        _outcomes(check, step.get("before"), f"{where}.before")
        _outcomes(check, step.get("after"), f"{where}.after")
        _fields(check, step, "changed", where)
        _texts(check, step, "underneath", where)
        result = check.text(step, "result", where, choices=RESULTS)
        verdict = check.text(step, "verdict", where, limit=_LINE * 2)
        price = check.text(step, "price", where, required=result == "better", limit=_LINE * 2)
        if "procedures" in step:
            procedures = check.obj(step["procedures"], f"{where}.procedures")
            check.count(procedures, "better", f"{where}.procedures", required=True)
            check.count(procedures, "of", f"{where}.procedures", required=True)
        if "mark" in step:
            _mark(check, step["mark"], f"{where}.mark")
            marked += 1
        if "records" in step:
            _records(check, step["records"], f"{where}.records")
        _step_agrees(check, step, where, result, verdict, price, value.get("comparable"))
        _step_under_limit(check, value, limit, step, where, result, verdict, price)
        if result is not None:
            results[result] = results.get(result, 0) + 1
    _listed(check, value.get("new"), "new")
    _listed(check, value.get("gone"), "gone")
    _counts_agree(check, value, results)
    _limit_agrees(check, value, limit, results, marked)
    race = check.obj(value.get("race"), "race")
    if "why" in race:
        check.text(race, "why", "race", limit=_LINE)
    elif isinstance(value.get("race"), Mapping):
        # Without a reason there is a race: both sides, each with the numbers it has.
        for side in ("before", "after"):
            times = check.obj(race.get(side), f"race.{side}")
            for key in ("first_alert_seconds", "goal_seconds"):
                check.seconds(times, key, f"race.{side}")
    if check.problems:
        raise RecordingError(check.problems)
    return value


def _step_agrees(
    check: _Checker,
    step: Mapping[str, Any],
    where: str,
    result: str | None,
    verdict: str | None,
    price: str | None,
    comparable: Any,
) -> None:
    """What the format says of one step holds within it; nothing is computed or corrected."""

    before, after, changed = step.get("before"), step.get("after"), step.get("changed")
    if isinstance(before, Mapping) and isinstance(after, Mapping) and isinstance(changed, list):
        differing = [field for field in FIELDS if before.get(field) != after.get(field)]
        if changed != differing:
            check.fail(f"{where}.changed", "must name exactly the fields whose values differ.")
        if result is not None and (result == "same") != (not differing):
            check.fail(f"{where}.result", "must be same exactly when no field differs.")
    if price is not None and verdict is not None and price not in verdict:
        check.fail(f"{where}.verdict", "must hold the step's price.")
    if comparable is False and result not in (None, "same", "no verdict"):
        check.fail(f"{where}.result", "must be same or no verdict: the comparison is refused.")
    if comparable is True and result == "no verdict":
        check.fail(f"{where}.result", "must not be no verdict: the comparison has a verdict.")


def _counts_agree(check: _Checker, value: Mapping[str, Any], results: Mapping[str, int]) -> None:
    """The counts, the declared change and the steps say the same of the delta."""

    counts, steps = value.get("counts"), value.get("steps")
    # Counted only when every step's result could be read: a bad one is reported already.
    if (
        isinstance(counts, Mapping)
        and isinstance(steps, list)
        and sum(results.values()) == len(steps)
    ):
        given = {
            "paired": len(steps),
            "new": len(value["new"]) if isinstance(value.get("new"), list) else None,
            "gone": len(value["gone"]) if isinstance(value.get("gone"), list) else None,
            **{result: results.get(result, 0) for result in RESULTS},
        }
        for key, number in given.items():
            if number is not None and isinstance(counts.get(key), int) and counts[key] != number:
                check.fail(f"counts.{key}", f"is {counts[key]}, but the delta lists {number}.")
    declared, differences = value.get("declared_change"), value.get("differences")
    if (
        value.get("comparable") is True
        and isinstance(declared, str)
        and isinstance(differences, list)
    ):
        if not any(
            isinstance(item, Mapping) and item.get("what") == declared for item in differences
        ):
            check.fail("declared_change", "must be one of the differences when there is a verdict.")


def _step_under_limit(
    check: _Checker,
    value: Mapping[str, Any],
    limit: Mapping[str, Any] | None,
    step: Mapping[str, Any],
    where: str,
    result: str | None,
    verdict: str | None,
    price: str | None,
) -> None:
    """A step's mark, records and price say no more than the delta's limit and change allow."""

    mark, records = step.get("mark"), step.get("records")
    if mark is not None and limit is None:
        check.fail(f"{where}.mark", "is given only under a limit: a step is credited by the "
                   "change's own mark only on two runners that differed.")  # fmt: skip
    if mark is not None and result is not None and result not in _CREDITED:
        check.fail(f"{where}.mark", "is on a step whose result is not better, worse or changed.")
    if isinstance(mark, Mapping) and result in _CREDITED and verdict is not None:
        lead = _MARK_LEAD.format(result=result)
        if not verdict.startswith(lead):
            check.fail(f"{where}.verdict", f"must start with {lead!r}: the step is credited by "
                       "the change's own mark.")  # fmt: skip
        # What the mark rests on is held by its keys, its events and the step's records, which
        # are checked below; the verdict's own words around them are the lab's to improve.
        keys = mark.get("keys")
        for key in keys if isinstance(keys, list) else []:
            if isinstance(key, str) and f"`{key}`" not in verdict:
                check.fail(f"{where}.verdict", f"must name the audit key {key[:80]!r} its mark "
                           "rests on.")  # fmt: skip
    if limit is not None and result in _CREDITED and mark is None:
        check.fail(f"{where}.result", f"is {result} under a limit without the change's own mark: "
                   "on two runners that differed only a step that carries it is credited.")  # fmt: skip
    if limit is not None and price is not None and not price.startswith(_UNKNOWN_PRICE):
        check.fail(f"{where}.price", f"must be {_UNKNOWN_PRICE!r} under a limit: each run counted "
                   "its ordinary activity on a runner of its own.")  # fmt: skip
    if isinstance(mark, Mapping) and mark.get("run") in ("before", "after"):
        run = mark["run"]
        other = "before" if run == "after" else "after"
        marked, unmarked = step.get(run), step.get(other)
        # The run without the mark holds nothing of the step and says no sensor recorded it.
        if (
            isinstance(marked, Mapping)
            and isinstance(unmarked, Mapping)
            and (
                marked.get("recorded") == "no telemetry"
                or unmarked.get("recorded") != "no telemetry"
            )
        ):
            check.fail(f"{where}.mark", f"says the {run} run carries the mark, so the {other} side "
                       f"must be no telemetry and the {run} side not.")  # fmt: skip
        audit = value.get("audit_keys")
        only = audit.get(f"only_{run}") if isinstance(audit, Mapping) else None
        elsewhere = audit.get(f"only_{other}") if isinstance(audit, Mapping) else None
        keys = mark.get("keys")
        if not isinstance(only, Mapping):
            check.fail(f"{where}.mark", f"needs audit_keys.only_{run}, the keys only its run's "
                       "events carry.")  # fmt: skip
        elif isinstance(keys, list):
            step_id = step.get("id") if run == "after" else step.get("before_id", step.get("id"))
            listed, unlisted = 0, False
            for key in keys:
                if not isinstance(key, str):
                    continue
                entry = only.get(key)
                if isinstance(elsewhere, Mapping) and key in elsewhere:
                    check.fail(f"{where}.mark.keys", f"names {key[:80]!r}, which audit_keys lists "
                               f"among the keys only the {other} run's events carry.")  # fmt: skip
                if entry is None:
                    # A key that can carry the mark and whose name the other run's events carry
                    # too, on other rules, is not listed; the recordings say it is its run's.
                    unlisted = True
                elif isinstance(entry, Mapping):
                    if entry.get("mark") is False:
                        check.fail(f"{where}.mark.keys", f"names {key[:80]!r}, which audit_keys "
                                   "says can carry no mark of the change's own.")  # fmt: skip
                    steps = entry.get("steps")
                    if isinstance(steps, list) and step_id not in steps:
                        check.fail(f"{where}.mark.keys", f"names {key[:80]!r}, whose entry in "
                                   f"audit_keys.only_{run} does not list the step.")  # fmt: skip
                    if isinstance(entry.get("events"), int):
                        listed += entry["events"]
            events = mark.get("events")
            if isinstance(events, int) and not unlisted and listed < events:
                check.fail(f"{where}.mark.events", f"is {events}, but audit_keys gives its keys "
                           f"only {listed} events in the {run} run.")  # fmt: skip
        if records is None:
            check.fail(f"{where}.records", "is missing: a step credited by the change's own mark "
                       "says what the sensor recorded of it.")  # fmt: skip
        part = records.get("new" if run == "after" else "gone") if isinstance(records, Mapping) else None
        if (
            isinstance(part, Mapping)
            and isinstance(part.get("count"), int)
            and isinstance(mark.get("events"), int)
            and part["count"] != mark["events"]
        ):
            check.fail(f"{where}.mark.events", "must be the number of events the step's records "
                       "give for the run that carries the mark.")  # fmt: skip
    if records is not None:
        declared = value.get("declared_change")
        if not isinstance(declared, str) or not declared.startswith("sensors:"):
            check.fail(f"{where}.records", "is given only when the declared change is a sensor's "
                       "settings.")  # fmt: skip
        elif isinstance(records, Mapping) and records.get("sensor") != declared.partition(":")[2]:
            check.fail(f"{where}.records.sensor", "must be the sensor of the declared change.")
        if not step.get("changed"):
            check.fail(f"{where}.records", "is given only on a step that changed.")


def _limit_agrees(
    check: _Checker,
    value: Mapping[str, Any],
    limit: Mapping[str, Any] | None,
    results: Mapping[str, int],
    marked: int,
) -> None:
    """The limit, the counts of marks and the differences say the same of the delta."""

    if value.get("audit_keys") is not None and value.get("declared_change") != "sensors:auditd":
        check.fail("audit_keys", "is given only when the declared change is sensors:auditd.")
    counts = value.get("counts")
    by_mark = counts.get("by_mark") if isinstance(counts, Mapping) else None
    if isinstance(by_mark, int) and not isinstance(by_mark, bool) and by_mark != marked:
        check.fail("counts.by_mark", f"is {by_mark}, but the delta lists {marked} steps with a mark.")
    differences = value.get("differences")
    # A row whose `what` is not text is reported already; only text can name a difference.
    rows = (
        [row for row in differences if isinstance(row, Mapping) and isinstance(row.get("what"), str)]
        if isinstance(differences, list)
        else []
    )
    named = limit.get("differences") if limit is not None else None
    runner_names = {name for name in named if isinstance(name, str)} if isinstance(named, list) else set()
    if value.get("comparable") is True:
        # A verdict holds only when every difference is the declared change, part of it, or
        # the runners' difference that a limit names.
        for index, row in enumerate(rows):
            what = row.get("what")
            if what != value.get("declared_change") and row.get("declared") is not True and (
                what not in runner_names
            ):
                check.fail(f"differences[{index}]", f"({str(what)[:80]}) differs and is neither the "
                           "declared change nor named by a limit, so there can be no verdict.")  # fmt: skip
    if value.get("runners") == 2:
        sides = [value.get(side) for side in ("before", "after")]
        urls = [side.get("run_url") if isinstance(side, Mapping) else None for side in sides]
        if not urls[0] or urls[0] != urls[1]:
            check.fail("runners", "is 2 only when both recordings name the same CI run (run_url): "
                       "two runs side by side in one CI run.")  # fmt: skip
    if limit is None:
        return
    if value.get("runners") != 2:
        check.fail("limit", "is given only for two runs side by side on two runners (runners 2).")
    if value.get("comparable") is not True:
        check.fail("limit", "is given only with a verdict: comparable must be true.")
    if value.get("declared_change") not in _MARKED_CHANGES:
        check.fail("limit", "is given only for a declared change that leaves a mark of its own: "
                   + ", ".join(_MARKED_CHANGES) + ".")  # fmt: skip
    by_what = {row.get("what"): row for row in rows}
    for name in sorted(runner_names):
        if not name.startswith(_RUNNER_NAMES):
            check.fail("limit.differences", f"names {name[:80]!r}, which is not a runner's image or "
                       "kernel.")  # fmt: skip
        elif name not in by_what:
            check.fail("limit.differences", f"names {name[:80]!r}, which is not among the differences.")
        elif by_what[name].get("declared") is True or name == value.get("declared_change"):
            check.fail("limit.differences", f"names {name[:80]!r}, which is part of the declared change.")
        elif by_what[name].get("before") is None or by_what[name].get("after") is None:
            check.fail("limit.differences", f"names {name[:80]!r}, which is not recorded in both runs.")
        elif by_what[name].get("before") == by_what[name].get("after"):
            check.fail("limit.differences", f"names {name[:80]!r}, which is the same in both runs.")
    if isinstance(limit.get("credited"), int) and limit["credited"] != marked:
        check.fail("limit.credited", f"is {limit['credited']}, but the delta lists {marked} steps with a mark.")
    unattributed = results.get("not attributable", 0)
    if isinstance(limit.get("not_attributable"), int) and limit["not_attributable"] != unattributed:
        check.fail("limit.not_attributable", f"is {limit['not_attributable']}, but the delta lists "
                   f"{unattributed} steps not attributable.")  # fmt: skip


def _audit_watches(recording: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """What the run's audit rules watch under each audit key, as its auditd sensor says, or None
    when it does not say: a recording written before it said, which may name the keys alone."""

    sensors = recording.get("network", {}).get("sensors", [])
    for sensor in sensors if isinstance(sensors, list) else []:
        if isinstance(sensor, Mapping) and sensor.get("id") == "auditd":
            watches = sensor.get("audit_watches")
            return watches if isinstance(watches, Mapping) else None
    return None


def _watched_keys(delta: Mapping[str, Any], kept: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Under a limit, the mark rests on what each run's audit rules watch, which its recording
    must say; every key said to carry the mark is a key of its run's rules."""

    problems: list[str] = []
    watches = {side: _audit_watches(kept[side]) for side in ("before", "after")}
    for side, found in watches.items():
        if found is None:
            problems.append(
                f"the {side} recording does not say what its audit rules watch under each audit "
                "key (audit_watches on its sensor auditd), so no step can carry the change's own "
                "mark: a key's name alone is no mark. The recording is written again from its "
                "run's folder by bluefire-lab recording, or the pair is run again."
            )
    claimed: list[tuple[str, str, str]] = []
    for part, side in (("only_before", "before"), ("only_after", "after")):
        for key, entry in (delta.get("audit_keys") or {}).get(part, {}).items():
            if entry.get("mark") is True:
                claimed.append((side, key, f"audit_keys.{part}.{key[:80]}.mark"))
    for index, step in enumerate(delta["steps"]):
        mark = step.get("mark")
        if isinstance(mark, Mapping):
            for key in mark["keys"]:
                claimed.append((mark["run"], key, f"steps[{index}].mark.keys"))
    for side, key, where in claimed:
        found = watches[side]
        if found is not None and key not in found and len(problems) < 20:
            problems.append(
                f"{where} says the audit key {key[:80]!r} can carry the change's own mark, but "
                f"the {side} recording's audit rules have no rule under it."
            )
    return problems


def _value(step: Mapping[str, Any], field: str) -> Any:
    """A step's value of one field a delta compares, as the format defines it."""

    if field == "happened":
        return step["happened"]["answer"]
    if field == "recorded":
        answer = step["visibility"]["answer"]
        if answer == "no telemetry":
            return answer
        return "recorded" if answer in ("alert", "telemetry only") else "not known"
    return step.get(field, step["outcome"])


def _steps_agree(delta: Mapping[str, Any], kept: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Each step's values in the delta are those of its step in each recording."""

    problems: list[str] = []
    steps = {side: {step["id"]: step for step in kept[side]["steps"]} for side in kept}
    for index, row in enumerate(delta["steps"]):
        for side, step_id in (("before", row.get("before_id", row["id"])), ("after", row["id"])):
            step = steps[side].get(step_id)
            if step is None:
                continue
            for field in FIELDS:
                said, there = row[side][field], _value(step, field)
                if said != there and len(problems) < 20:
                    problems.append(
                        f"steps[{index}].{side}.{field} is {said!r}, but the {side} recording's "
                        f"step {step_id!r} says {there!r}."
                    )
    return problems


def _lab(recording: Mapping[str, Any]) -> Mapping[str, Any]:
    found: Mapping[str, Any] = next(
        (detector for detector in recording["network"]["detectors"] if detector["id"] == "lab"), {}
    )
    return found


def _verdicts(recording: Mapping[str, Any]) -> dict[str, Mapping[str, Any]] | None:
    """How the run judged each of the lab's rules, by rule id; None when it does not say."""

    lab = _lab(recording)
    return {item["rule"]: item for item in lab["verdicts"]} if "verdicts" in lab else None


def _lab_matches(recording: Mapping[str, Any]) -> dict[str, set[str]]:
    """The steps each rule of the lab's own matched, a match on the launcher's start left out."""

    found: dict[str, set[str]] = {}
    for alert in recording["alerts"]:
        if alert["rule"]["origin"] == "lab" and not alert.get("launcher_only"):
            found.setdefault(alert["rule"]["id"], set()).add(alert["step"])
    return found


def one_run_problems(delta: Mapping[str, Any], kept: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Why the two kept recordings of a delta of one run evaluated twice are not one run, or
    do not say what the delta says of the lab's rules: empty when they are and do. Everything a
    change of the lab's rules cannot move must be the same, not only alike, as
    ``bluefire-lab compare --one-run`` checked before it wrote the delta: the run's source, its
    steps with what happened, whether a sensor recorded each and the published rules' outcome,
    its events, the published rules' alerts and the ordinary activity, and the judgement and
    matches of every lab rule whose file is the same in both."""

    before, after = kept["before"], kept["after"]
    problems: list[str] = []

    def say(text: str) -> None:
        if len(problems) < 20:
            problems.append(f"one run evaluated twice: {text}")

    if before["source"] != after["source"]:
        say("the two recordings' source differ, so they are not of one run.")
    old_steps, new_steps = before["steps"], after["steps"]
    if [step["id"] for step in old_steps] != [step["id"] for step in new_steps]:
        say("the two recordings do not hold the same steps in the same order.")
    else:
        for old, new in zip(old_steps, new_steps, strict=True):
            fields = [field for field in ("happened", "recorded", "outcome") if _value(old, field) != _value(new, field)]
            fields += [
                key
                for key in ("first_event", "first_alert", "started", "ended")
                if old.get(key) != new.get(key)
            ]
            if old["visibility"].get("events") != new["visibility"].get("events"):
                fields.append("visibility.events")
            if fields:
                say(f"step {new['id']!r} differs in {', '.join(fields)}.")
    events = [{event["id"]: event for event in recording["events"]} for recording in (before, after)]
    cited = [
        {found for alert in recording["alerts"] if alert["rule"]["origin"] == "lab" for found in alert.get("events", [])}
        for recording in (before, after)
    ]
    unlike = [name for name in events[0].keys() & events[1].keys() if events[0][name] != events[1][name]]
    alone = [
        name
        for number in (0, 1)
        for name in events[number].keys() - events[1 - number].keys()
        if name not in cited[number]
    ]
    if unlike or alone:
        say(f"the events differ: {len(unlike)} held by both differ, and {len(alone)} held by one "
            "only are not kept for an alert of the lab's rules.")  # fmt: skip

    def published(recording: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        return sorted(
            (
                alert["step"],
                alert["rule"]["id"],
                alert.get("time", ""),
                tuple(alert.get("events", [])),
                bool(alert.get("launcher_only")),
            )
            for alert in recording["alerts"]
            if alert["rule"]["origin"] != "lab"
        )

    if published(before) != published(after):
        say("the published rules' alerts differ.")
    if before.get("ordinary") != after.get("ordinary"):
        say("the ordinary activity, or what the published rules matched in it, differs.")
    judged_before, judged_after = _verdicts(before), _verdicts(after)
    if judged_before is None or judged_after is None:
        say("a recording does not say how its run judged each of the lab's rules (verdicts of "
            "its detector lab).")  # fmt: skip
        return problems
    verdicts = (judged_before, judged_after)
    matched = (_lab_matches(before), _lab_matches(after))
    differing: set[str] = set()
    for rule in judged_before.keys() | judged_after.keys():
        old, new = judged_before.get(rule), judged_after.get(rule)
        if old is None or new is None or old.get("digest") is None or old.get("digest") != new.get("digest"):
            differing.add(rule)
            continue
        if old.get("file") != new.get("file"):
            differing.add(rule)
        if (old["accepted"], old.get("reason")) != (new["accepted"], new.get("reason")):
            say(f"the lab's rule {new['title']!r} is the same file in both recordings and was "
                "judged differently.")  # fmt: skip
        elif matched[0].get(rule, set()) != matched[1].get(rule, set()):
            say(f"the lab's rule {new['title']!r} is the same file in both recordings and "
                "matched other steps.")  # fmt: skip
    rows = delta.get("lab_rules") or []
    listed = {row["rule"] for row in rows}
    for name in sorted(differing - listed):
        title = (verdicts[1].get(name) or verdicts[0].get(name) or {}).get("title", name)
        say(f"the lab's rule {title!r} differs between the two recordings and lab_rules does not "
            "list it.")  # fmt: skip
    for index, row in enumerate(rows):
        where = f"lab_rules[{index}]"
        if row["rule"] not in differing:
            say(f"{where} lists the rule {row['title']!r}, which is the same file in both recordings.")
        for number, side in enumerate(("before", "after")):
            verdict, said = verdicts[number].get(row["rule"]), row[side]
            if (verdict is None) != (said is None):
                say(f"{where}.{side} says the rule is {'not ' if said is None else ''}in the {side} "
                    f"evaluation, but the {side} recording {'has' if verdict is not None else 'does not have'} "
                    "it.")  # fmt: skip
            elif verdict is not None and said is not None:
                for key in ("accepted", "reason", "file"):
                    if said.get(key) != verdict.get(key):
                        say(f"{where}.{side}.{key} is {said.get(key)!r}, but the {side} recording "
                            f"says {verdict.get(key)!r}.")  # fmt: skip
        if row["change"] == "changed" and all(row[side] is not None for side in ("before", "after")):
            old, new = verdicts[0].get(row["rule"]), verdicts[1].get(row["rule"])
            if old is not None and new is not None and old.get("digest") is not None and old.get("digest") == new.get("digest"):
                say(f"{where} says the rule's text changed, but both recordings give its file the same digest.")
    # A step credited to the change moved because a rule that changed matched it in one
    # evaluation only: the lab's own rules are all that differ.
    for index, row in enumerate(delta["steps"]):
        if row.get("result") not in _CREDITED:
            continue
        touched = {
            rule
            for rule in matched[0].keys() | matched[1].keys()
            if (row["id"] in matched[0].get(rule, set())) != (row["id"] in matched[1].get(rule, set()))
        }
        if not touched & listed:
            say(f"steps[{index}] is {row['result']}, but no rule that lab_rules lists matched it in "
                "one evaluation only.")  # fmt: skip
    return problems


def parse_delta_bytes(payload: bytes) -> Mapping[str, Any]:
    """Parse and check one delta file's bytes."""

    if len(payload) > MAX_DELTA_BYTES:
        raise RecordingError([f"A delta file is limited to {MAX_DELTA_BYTES} bytes."])
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RecordingError([f"The file is not UTF-8 JSON: {exc}"]) from None
    return validate_delta(value)


def invalid_delta(exc: RecordingError) -> APIError:
    return APIError(
        HTTPStatus.UNPROCESSABLE_ENTITY,
        "delta_invalid",
        f"The comparison was not imported: {exc}",
        {"problems": exc.problems},
    )


def delta_id(delta: Mapping[str, Any]) -> str:
    """A delta's id: the start of the SHA-256 of its canonical JSON."""

    return hashlib.sha256(canonical_json_bytes(delta)).hexdigest()[:16]


def _shipped_folder() -> Any:
    """The packaged folder of shipped deltas, a ``Traversable``; it may hold none."""

    return resources.files("bluefire.data").joinpath("recordings").joinpath("deltas")


class DeltaLibrary:
    """The deltas shipped with BlueFire, and those imported beside the recording store."""

    def __init__(self, recordings: RecordingLibrary) -> None:
        self.recordings = recordings
        self.root = recordings.root / "deltas"
        self._shipped_entries: dict[str, Mapping[str, Any]] | None = None
        self._read_files: dict[Path, tuple[tuple[int, int, int], Mapping[str, Any] | None]] = {}

    def _recording_entries(self, delta: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
        """The list entries of the delta's two recordings, by side, each of the very file the
        delta names: a run evaluated twice keeps two files under its one id. Checked at
        import, and again whenever it is served: a later release may ship another file under
        the same id."""

        entries: dict[str, Mapping[str, Any]] = {}
        for side in ("before", "after"):
            entry = self.recordings.kept_files(delta[side]["id"]).get(delta[side]["sha256"])
            if entry is None:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "delta_recording_replaced",
                    f"The {side} recording of this comparison is no longer kept as the file it "
                    "was made from, so the comparison is not shown.",
                )
            entries[side] = entry
        return entries

    def _summary(self, delta: Mapping[str, Any], shipped: bool) -> dict[str, Any]:
        recordings = self._recording_entries(delta)
        weaker = not shipped or any(
            entry["origin"]["kind"] != "shipped" for entry in recordings.values()
        )
        origin: dict[str, Any] = {"kind": "imported", "note": IMPORTED_DELTA_NOTE}
        if not weaker:
            origin = {"kind": "shipped", "note": SHIPPED_DELTA_NOTE}
            runs = {entry["origin"]["run_url"] for entry in recordings.values()}
            [run_url] = runs if len(runs) == 1 else [None]
            # Two runs side by side in one CI run, or one run evaluated twice: the lab compared
            # them in that run too.
            if run_url is not None and delta.get("one_run") is True:
                origin = {
                    "kind": "shipped",
                    "run_url": run_url,
                    "note": SHIPPED_ONE_RUN_NOTE.format(run_url=run_url),
                }
            elif run_url is not None and delta.get("runners") == 2:
                origin = {
                    "kind": "shipped",
                    "run_url": run_url,
                    "note": SHIPPED_PAIR_NOTE.format(run_url=run_url),
                }
        return {
            "id": delta_id(delta),
            "claim": delta["claim"],
            "declared_change": delta["declared_change"],
            "runners": delta.get("runners"),
            "one_run": delta.get("one_run") is True,
            "comparable": delta["comparable"],
            "limit": dict(delta["limit"]) if delta.get("limit") is not None else None,
            "lab_rules": [dict(row) for row in delta["lab_rules"]]
            if delta.get("lab_rules") is not None
            else None,
            "refused_because": list(delta["refused_because"]),
            "counts": dict(delta["counts"]),
            # What the change moved, for a list: each step it is credited with, at most 20.
            "moved": [
                {key: step[key] for key in ("id", "role", "title", "technique", "result", "before", "after")}
                for step in delta["steps"]
                if step["result"] in _CREDITED
            ][:20],
            "before": dict(delta["before"]),
            "after": dict(delta["after"]),
            "recordings": recordings,
            "origin": origin,
        }

    def _check_recordings(self, delta: Mapping[str, Any]) -> None:
        """Both recordings are kept, finished, as the files the delta names, with its steps."""

        problems: list[str] = []
        kept: dict[str, Mapping[str, Any]] = {}
        for side in ("before", "after"):
            named = delta[side]
            try:
                files = self.recordings.kept_files(named["id"])
            except APIError as exc:
                problems.append(f"the {side} recording {named['id']!r}: {exc.message}")
                continue
            if not files:
                problems.append(
                    f"the {side} recording {named['id']!r} is not kept here: import it first."
                )
                continue
            summary = files.get(named["sha256"])
            if summary is None:
                first = next(iter(files.values()))
                how = (
                    "shipped with BlueFire"
                    if first["origin"]["kind"] == "shipped"
                    else "imported earlier"
                )
                digests = (
                    f"the kept file's SHA-256 is {next(iter(files))}"
                    if len(files) == 1
                    else f"the kept files' SHA-256 are {', '.join(files)}"
                )
                problems.append(
                    f"the {side} recording {named['id']!r} is kept here from another file than "
                    f"the one this comparison was made from ({how}): {digests}, the comparison "
                    f"names {named['sha256']}. A kept recording that is finished is never "
                    "replaced, and another file of its id is kept beside it only with the same "
                    "source: another evaluation of the same run, or the same recording in other "
                    "bytes."
                )
                continue
            if summary["running"]:
                problems.append(
                    f"the {side} recording {named['id']!r} is still running; a comparison is "
                    "made of two finished runs."
                )
                continue
            recording = self.recordings.file(named["id"], named["sha256"])["recording"]
            for key in _SOURCE_FACTS:
                if named.get(key) != recording["source"].get(key):
                    problems.append(
                        f"{side}.{key} is not the {key} of the {side} recording's source."
                    )
            if named.get("lab_rules_commit") != _lab(recording).get("commit"):
                problems.append(
                    f"{side}.lab_rules_commit is not the commit of the {side} recording's "
                    "detector lab."
                )
            kept[side] = recording
        if len(kept) == 2:
            ids = {side: {step["id"] for step in kept[side]["steps"]} for side in kept}

            def has(side: str, step_id: str, where: str) -> None:
                if step_id not in ids[side] and len(problems) < 20:
                    problems.append(
                        f"{where} names step {step_id!r}, which the {side} recording does not have."
                    )

            for index, step in enumerate(delta["steps"]):
                has("after", step["id"], f"steps[{index}].id")
                has("before", step.get("before_id", step["id"]), f"steps[{index}]")
            for index, step in enumerate(delta["new"]):
                has("after", step["id"], f"new[{index}].id")
            for index, step in enumerate(delta["gone"]):
                has("before", step["id"], f"gone[{index}].id")
            for index, step_id in enumerate(delta["control"]["varied"]):
                has("after", step_id, f"control.varied[{index}]")
            for index, step_id in enumerate(delta["unexplained"]):
                has("after", step_id, f"unexplained[{index}]")
            for part, side in (("only_before", "before"), ("only_after", "after")):
                for key, entry in (delta.get("audit_keys") or {}).get(part, {}).items():
                    for index, step_id in enumerate(entry["steps"]):
                        has(side, step_id, f"audit_keys.{part}.{key}.steps[{index}]")
            if delta.get("limit") is not None:
                problems += _watched_keys(delta, kept)
            if delta.get("one_run") is True:
                problems += _steps_agree(delta, kept) + one_run_problems(delta, kept)
        if problems:
            raise RecordingError(problems)

    def _shipped(self) -> dict[str, Mapping[str, Any]]:
        """Read the packaged deltas once; each must hold for the shipped recordings."""

        if self._shipped_entries is None:
            folder = _shipped_folder()
            entries: dict[str, Mapping[str, Any]] = {}
            names = sorted(item.name for item in folder.iterdir()) if folder.is_dir() else []
            for name in names:
                if name.endswith(".json"):
                    delta = parse_delta_bytes(folder.joinpath(name).read_bytes())
                    self._check_recordings(delta)
                    entries[delta_id(delta)] = delta
            self._shipped_entries = entries
        return self._shipped_entries

    def _read(self, path: Path) -> Mapping[str, Any] | None:
        """An imported delta, or None when it is unreadable; read again only once replaced."""

        try:
            status = path.stat()
        except OSError:
            return None
        key = (status.st_ino, status.st_mtime_ns, status.st_size)
        cached = self._read_files.get(path)
        if cached is not None and cached[0] == key:
            return cached[1]
        try:
            with path.open("rb") as handle:
                delta: Mapping[str, Any] | None = parse_delta_bytes(
                    handle.read(MAX_DELTA_BYTES + 1)
                )
            if delta is not None and delta_id(delta) != path.stem:
                delta = None
        except (OSError, RecordingError):
            delta = None
        self._read_files[path] = (key, delta)
        return delta

    def _imported_paths(self) -> list[Path]:
        if not self.root.is_dir():
            return []
        return [
            path
            for path in sorted(self.root.glob("*.json"))
            if DELTA_ID.fullmatch(path.stem) and not path.is_symlink() and path.is_file()
        ]

    def list(self) -> Mapping[str, Any]:
        shipped = self._shipped()
        paths = [path for path in self._imported_paths() if path.stem not in shipped]
        found: list[tuple[Mapping[str, Any] | None, bool]] = [
            (delta, True) for delta in shipped.values()
        ]
        found += [(self._read(path), False) for path in paths[:MAX_LISTED]]
        entries: list[dict[str, Any]] = []
        unreadable = 0
        for delta, is_shipped in found:
            try:
                if delta is not None:
                    entries.append(self._summary(delta, is_shipped))
                    continue
            except APIError:
                # A recording it names can no longer be read, or is now another file.
                pass
            unreadable += 1
        return {
            "schema_version": "bluefire.delta-list.v1",
            "deltas": entries,
            "unreadable_count": unreadable,
            "omitted_count": max(0, len(paths) - MAX_LISTED),
        }

    def _path(self, value: Any) -> Path:
        if not isinstance(value, str) or not DELTA_ID.fullmatch(value):
            raise APIError(
                HTTPStatus.BAD_REQUEST, "invalid_delta_id", "Comparison identifier is invalid."
            )
        return self.root / f"{value}.json"

    def detail(self, value: str) -> Mapping[str, Any]:
        path = self._path(value)
        shipped = self._shipped().get(value)
        if shipped is not None:
            delta, is_shipped = shipped, True
        else:
            if not path.is_file() or path.is_symlink():
                raise APIError(HTTPStatus.NOT_FOUND, "delta_not_found", "Comparison was not found.")
            read = self._read(path)
            if read is None:
                raise APIError(
                    HTTPStatus.CONFLICT,
                    "delta_unreadable",
                    "The stored comparison could not be read or no longer follows the format.",
                )
            delta, is_shipped = read, False
        return {
            "schema_version": "bluefire.delta-entry.v1",
            "summary": self._summary(delta, is_shipped),
            "delta": delta,
        }

    def import_delta(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Store a delta whose two recordings are kept here; never compute or change it."""

        if set(request) != {"delta"}:
            raise APIError(
                HTTPStatus.BAD_REQUEST,
                "delta_import_invalid",
                'Send exactly one field, "delta", holding the delta.json object.',
            )
        try:
            delta = validate_delta(request["delta"])
            payload = canonical_json_bytes(delta) + b"\n"
            if len(payload) > MAX_DELTA_BYTES:
                raise RecordingError([f"A delta file is limited to {MAX_DELTA_BYTES} bytes."])
        except (RecordingError, ValueError) as exc:
            problems = exc.problems if isinstance(exc, RecordingError) else [str(exc)]
            raise invalid_delta(RecordingError(problems)) from None
        identifier = delta_id(delta)
        with self.recordings.import_lock():
            try:
                self._check_recordings(delta)
            except RecordingError as exc:
                raise invalid_delta(exc) from None
            target = self._path(identifier)
            created = False
            if identifier not in self._shipped() and not target.exists():
                self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
                try:
                    _write_atomically(self.root, target, payload, replace=False)
                    created = True
                except FileExistsError:
                    pass
            shipped = identifier in self._shipped()
        return {"created": created, "summary": self._summary(delta, shipped)}
