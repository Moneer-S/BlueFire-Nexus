"""Say which answers changed between two runs, and what changed underneath.

Takes the results.json of an earlier run and of a later one. A run of a test is
the same in both when it has the same role, GUID, input arguments and hardening
change; a test that runs twice, as the canary does, is matched in order. For
each whose answers differ, the comparison gives both answers and what changed
under them: the events that appeared or went when the telemetry did, the rules
that matched, a rule of the lab's own that is accepted now, and the basis of a
changed execution answer. For a rule of the lab's own it says how many
published procedures the rule covers, and for each hardening change how many
of the procedures it was tried on it blocked, because a fix that covers one
procedure has not shown that it covers the technique.
"""

from __future__ import annotations

import collections
import json
from pathlib import Path


def plural(number: int, noun: str) -> str:
    return f"{number} {noun}" + ("" if number == 1 else "s")


def identity(test: dict) -> tuple[str, str, str, str]:
    change = (test.get("defense") or {}).get("name", "")
    return test["role"], test["guid"], json.dumps(test.get("args") or {}, sort_keys=True), change


def answers(test: dict) -> tuple[str, str, str]:
    seen = test["visibility"]
    return (
        test["execution"]["answer"],
        seen["answer"],
        seen.get("with_lab_rules", {}).get("answer", seen["answer"]),
    )


def shown(answer: tuple[str, str, str]) -> str:
    execution, visibility, with_lab_rules = answer
    return f"{execution}, {visibility}" + (
        f" ({with_lab_rules} with the lab's rules)" if with_lab_rules != visibility else ""
    )


def matched(test: dict, lab: bool = False) -> set[str]:
    seen = test["visibility"]
    if lab:
        return {
            rule["title"] for rule in seen.get("with_lab_rules", {}).get("rules", []) if rule.get("accepted")
        }
    return {f"{rule['level']}: {rule['title']}" for rule in seen.get("rules", [])}


def underneath(before: dict, after: dict, procedures: dict[str, int]) -> list[str]:
    """What changed under the answers of one test, in plain words."""

    reasons = []
    old, new = before["visibility"], after["visibility"]
    if (old["answer"] == "no telemetry") != (new["answer"] == "no telemetry"):
        came = new if old["answer"] == "no telemetry" else old
        kinds = ", ".join(
            plural(number, kind + " event") for kind, number in came.get("events_by_kind", {}).items()
        )
        reasons.append(("recorded now: " if came is new else "no longer recorded: ") + (kinds or "nothing"))
    reasons += [f"{title} matches now" for title in sorted(matched(after) - matched(before))]
    reasons += [f"{title} no longer matches" for title in sorted(matched(before) - matched(after))]
    for title in sorted(matched(after, lab=True) - matched(before, lab=True)):
        covered = procedures.get(title, 1)
        reasons.append(
            f"the lab's rule {title} is accepted now, covering "
            + (plural(covered, "published procedure") if covered > 1 else "one published procedure only")
        )
    reasons += [
        f"the lab's rule {title} no longer counts"
        for title in sorted(matched(before, True) - matched(after, True))
    ]
    if before["execution"]["answer"] != after["execution"]["answer"]:
        reasons.append(f"execution: {after['execution'].get('basis', '')}")
    return reasons or ["no change in the events or rules behind it"]


def compare(before: dict, after: dict) -> dict:
    earlier: dict[tuple, list[dict]] = collections.defaultdict(list)
    for test in before["tests"]:
        earlier[identity(test)].append(test)
    procedures = {rule["title"]: rule.get("procedures", 1) for rule in after.get("lab_rules", [])}
    changed, same, new = [], 0, []
    for test in after["tests"]:
        matches = earlier.get(identity(test))
        old = matches.pop(0) if matches else None
        if old is None:
            new.append(test)
        elif answers(old) == answers(test):
            same += 1
        else:
            changed.append({"test": test, "before": answers(old), "after": answers(test),
                            "why": underneath(old, test, procedures)})  # fmt: skip
    gone = [test for tests in earlier.values() for test in tests]
    return {"changed": changed, "same": same, "new": new, "gone": gone}


def named(tests: list[dict]) -> str:
    """The runs of tests: a hardened run with its change and what it showed, the runs of a test
    with changed input arguments counted, and any other run with the arguments the list sets."""

    parts, varied = [], collections.Counter()
    for test in tests:
        title = f"{test['technique']} {test['name']}"
        change = (test.get("defense") or {}).get("title")
        if change:
            parts.append(f"{title}, with {change}: {test['execution']['answer']}")
        elif test["role"] == "variant":
            varied[title] += 1
        else:
            args = ", ".join(f"{key}={value}" for key, value in (test.get("args") or {}).items())
            parts.append(title + (f", with {args}" if args else ""))
    parts += [f"{title} with changed input arguments ({count}x)" for title, count in varied.items()]
    return "; ".join(parts)


def coverage(results: dict) -> list[str]:
    """For each hardening change in a run, the published procedures it was tried on and
    blocked, because a change that blocks one procedure has not shown it covers the technique."""

    runs: dict[str, list[dict]] = collections.defaultdict(list)
    for test in results["tests"]:
        if test.get("defense"):
            runs[test["defense"]["title"]].append(test)
    lines = []
    for title, tried in runs.items():
        open_ = [f"{test['technique']} {test['name']} ({test['execution']['answer']})" for test in tried
                 if test["execution"]["answer"] != "blocked"]  # fmt: skip
        blocked = len(tried) - len(open_)
        lines.append(
            f"- {title}: blocked {blocked} of the {plural(len(tried), 'published procedure')} it was tried on"
            + (f"; not {'; '.join(open_)}" if open_ else "")
        )
    return lines


def markdown(before: dict, after: dict) -> str:
    result = compare(before, after)

    def cell(text: object) -> str:
        return str(text).replace("|", "\\|")

    def name(test: dict) -> str:
        change = (test.get("defense") or {}).get("title")
        args = ", ".join(f"{key}={value}" for key, value in (test.get("args") or {}).items())
        extra = f", with {change}" if change else (f", with {args}" if args else "")
        return cell(f"{test['technique']} {test['name']}{extra}")

    run = before["run"]
    made = (run.get("tools") or {}).get("lab") or "an earlier version of the lab"
    lines = [
        "## Compared with an earlier run",
        "",
        f"Run `{run['id']}` of {run['started'][:10]}, made with `{made}`. "
        f"{plural(result['same'], 'run')} of a test gave the same answers, {len(result['changed'])} changed, "
        f"{len(result['new'])} are new and {len(result['gone'])} are gone.",
        "",
    ]
    if result["changed"]:
        lines += ["| Role | Test | Before | Now | What changed |", "|---|---|---|---|---|"]
        lines += [
            f"| {row['test']['role']} | {name(row['test'])} | {cell(shown(row['before']))} | "
            f"{cell(shown(row['after']))} | {cell('; '.join(row['why']))} |"
            for row in result["changed"]
        ]
        lines.append("")
    for label, tests in (("New", result["new"]), ("Gone", result["gone"])):
        if tests:
            lines += [f"{label}: {cell(named(tests))}.", ""]
    if coverage(after):
        lines += ["Hardening changes in this run:", "", *coverage(after), ""]
    return "\n".join(lines)


def main(before: Path, after: Path) -> int:
    earlier, later = (
        json.loads((folder / "results.json").read_text(encoding="utf-8")) for folder in (before, after)
    )
    text = markdown(earlier, later)
    (after / "compare.md").write_text(text, encoding="utf-8")
    print(text)
    return 0
