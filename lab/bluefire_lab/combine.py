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


def given(test: dict) -> dict[str, str]:
    """The answers one runner gave for a run of a test, by name."""

    return dict(zip(ANSWERS, answers(test), strict=True))


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
    # A run of a test that only another runner has, because their inventories differ, is unstable
    # too. It gets a number of its own after the first runner's, and the run it is compared with
    # is found again by what it is, because each runner numbers its own runs.
    last = max((test["order"] for test in combined["tests"]), default=0)
    for other in keyed[1:]:
        numbered = {test["order"]: key for key, test in other.items()}
        added = []
        for key, test in other.items():
            if key not in tests:
                last += 1
                tests[key] = copy.deepcopy(test)
                tests[key]["order"] = last
                combined["tests"].append(tests[key])
                added.append(tests[key])
        for test in added:
            if "compared_with" in test:
                test["compared_with"] = tests[numbered[test["compared_with"]]]["order"]
    for key, test in tests.items():
        names = list(given(test))
        test["runners"] = [
            given(found[key]) if key in found else dict.fromkeys(names, "not run") for found in keyed
        ]
        differing = [name for name in names if len({runner.get(name) for runner in test["runners"]}) > 1]
        if not differing:
            continue
        test["unstable"] = differing
        for name in differing:
            said = ", ".join(str(runner.get(name)) for runner in test["runners"])
            basis = f"the runners gave different answers: {said}"
            if name == "execution":
                test["execution"].update(answer=UNSTABLE, basis=basis)
            elif name == "visibility":
                test["visibility"].update(answer=UNSTABLE, basis=basis)
            else:
                test["visibility"].setdefault("with_lab_rules", {"rules": []})["answer"] = UNSTABLE

    # A rule of the lab's own counts as accepted when every runner accepted it. A rule only
    # another runner judged is listed too.
    verdicts = [{rule["id"]: rule for rule in run.get("lab_rules", [])} for run in runs]
    listed = {rule["id"] for rule in combined.get("lab_rules", [])}
    for verdict in verdicts[1:]:
        for rule_id, rule in verdict.items():
            if rule_id not in listed:
                listed.add(rule_id)
                combined.setdefault("lab_rules", []).append(copy.deepcopy(rule))
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
    # Where a rule is named with a test it matched, it is accepted or not as the runners together say.
    together = {rule["id"]: rule["accepted"] for rule in combined.get("lab_rules", [])}
    for test in combined["tests"]:
        for rule in test["visibility"].get("with_lab_rules", {}).get("rules", []):
            rule["accepted"] = together.get(rule["id"], False)

    # A control passes when it passed on every runner. A control only another runner has counts too.
    controls = []
    names = list(dict.fromkeys(check["name"] for run in runs for check in run["controls"]))
    for name in names:
        each = [next((c for c in run["controls"] if c["name"] == name), None) for run in runs]
        check = next(found for found in each if found)
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
    # Every test a runner left out, once, with the runners that left it out.
    left_out: dict[tuple, list[int]] = {}
    for number, run in enumerate(runs, start=1):
        for item in run.get("dropped", []):
            left_out.setdefault((item["technique"], item["name"], item["reason"]), []).append(number)
    combined["dropped"] = [
        {
            "technique": technique,
            "name": name,
            "reason": reason
            + ("" if len(numbers) == len(runs) else f" (on runner {', '.join(map(str, numbers))} only)"),
        }
        for (technique, name, reason), numbers in left_out.items()
    ]
    combined["summary"] = summarize(combined["tests"])
    return combined


def main(folder: Path) -> int:
    """Write folder/results.json from the results.json in each of its subfolders."""

    found = sorted(path for path in folder.iterdir() if path.is_dir())
    without = [path.name for path in found if not (path / "results.json").is_file()]
    if without:
        raise SystemExit(
            f"no results.json in {', '.join(without)}: that runner's run was not evaluated, so there is "
            "nothing to combine it with"
        )
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
