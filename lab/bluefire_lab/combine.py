"""Combine the results of the same list run on several runners into one set of answers.

One runner's answer can rest on something the sensor reports only sometimes: Sysmon for
Linux, for example, can miss the creation of a file. So the workflow runs the list on
several runners at once, and this takes each runner's results.json and gives one answer
for every run of a test: the answer all runners gave, or "unstable" when they differ.
An unstable answer counts in no total.

The combined results keep the first runner's evidence (its events and rule matches) for
the report, and say for every run of a test what each runner answered.
"""

from __future__ import annotations

import collections
import copy
import json
from pathlib import Path

from .compare import answers, identity
from .evaluate import summarize

ANSWERS = ("execution", "visibility", "with the lab's rules")
UNSTABLE = "unstable"


def by_identity(results: dict) -> dict[tuple, dict]:
    """The runs of tests in a results document, each under what names the same run on
    another runner: its role, test, input arguments and hardening change, and, for a test
    that runs more than once, such as the canary, which of its runs it is."""

    seen: collections.Counter = collections.Counter()
    found = {}
    for test in results["tests"]:
        key = identity(test)
        found[(*key, seen[key])] = test
        seen[key] += 1
    return found


def combine(runs: list[dict]) -> dict:
    """One results document from those of several runners, the first one's evidence kept."""

    keyed = [by_identity(run) for run in runs]
    combined = copy.deepcopy(runs[0])
    tests = by_identity(combined)
    # A run of a test that only another runner has, because their inventories differ, is unstable too.
    for other in keyed[1:]:
        for key, test in other.items():
            if key not in tests:
                tests[key] = added = copy.deepcopy(test)
                combined["tests"].append(added)
    for key, test in tests.items():
        given = [answers(found[key]) if key in found else ("not run",) * 3 for found in keyed]
        test["runners"] = [dict(zip(ANSWERS, answer, strict=True)) for answer in given]
        differing = [
            name for index, name in enumerate(ANSWERS) if len({answer[index] for answer in given}) > 1
        ]
        if not differing:
            continue
        test["unstable"] = differing
        for name in differing:
            said = ", ".join(runner[name] for runner in test["runners"])
            basis = f"the runners gave different answers: {said}"
            if name == "execution":
                test["execution"].update(answer=UNSTABLE, basis=basis)
            elif name == "visibility":
                test["visibility"].update(answer=UNSTABLE, basis=basis)
            else:
                test["visibility"].setdefault("with_lab_rules", {"rules": []})["answer"] = UNSTABLE

    # A rule of the lab's own counts as accepted when every runner accepted it.
    verdicts = [{rule["id"]: rule for rule in run.get("lab_rules", [])} for run in runs]
    for rule in combined.get("lab_rules", []):
        each = [verdict.get(rule["id"]) for verdict in verdicts]
        rule["runners"] = [
            {
                "accepted": bool(found and found["accepted"]),
                "reason": found["reason"] if found else "not judged",
            }
            for found in each
        ]
        rule["accepted"] = all(runner["accepted"] for runner in rule["runners"])
        refused = [
            f"runner {number}: {runner['reason']}"
            for number, runner in enumerate(rule["runners"], start=1)
            if not runner["accepted"]
        ]
        if refused and len(refused) < len(runs):
            rule["reason"] = "not accepted on every runner; " + "; ".join(refused)

    # A control passes when it passed on every runner.
    controls = []
    for check in combined["controls"]:
        each = [next((c for c in run["controls"] if c["name"] == check["name"]), None) for run in runs]
        failed = [
            f"runner {number}: {other['detail'] if other else 'the control is missing'}"
            for number, other in enumerate(each, start=1)
            if not (other and other["passed"])
        ]
        detail = "; ".join(failed) or f"on each of the {len(runs)} runners; on the first, {check['detail']}"
        controls.append({"name": check["name"], "passed": not failed, "detail": detail})
    combined["controls"] = controls
    combined["runners"] = [
        {
            "run": run["run"],
            "summary": run["summary"],
            "controls_passed": all(check["passed"] for check in run["controls"]),
        }
        for run in runs
    ]
    combined["summary"] = summarize(combined["tests"])
    return combined


def main(folder: Path) -> int:
    """Write folder/results.json from the results.json in each of its subfolders."""

    found = sorted(path for path in folder.iterdir() if (path / "results.json").is_file())
    if len(found) < 2:
        raise SystemExit(f"{folder} holds the results of {len(found)} runners: combining needs at least two")
    runs = [json.loads((path / "results.json").read_text(encoding="utf-8")) for path in found]
    combined = combine(runs)
    for runner, path in zip(combined["runners"], found, strict=True):
        runner["folder"] = path.name
    (folder / "results.json").write_text(json.dumps(combined, indent=1) + "\n", encoding="utf-8")
    summary = combined["summary"]
    print(
        f"{len(runs)} runners, {summary['tests']} tests: {summary['took_effect']} took effect on every runner, "
        f"{summary['alert']} alert, {summary['alert_with_lab_rules']} alert with the lab's rules too, "
        f"{summary['unstable']} unstable"
    )
    failed = [check for check in combined["controls"] if not check["passed"]]
    for check in combined["controls"]:
        print(("ok      " if check["passed"] else "FAILED  ") + f"{check['name']}: {check['detail']}")
    return 1 if failed else 0
