"""Write report.html and summary.md from results.json.

The report is one file that opens offline and requests nothing from the
network. The table comes first. The events and rules behind a row are one click
away.
"""

from __future__ import annotations

import html
import json
import re
from importlib import resources
from pathlib import Path

RECOMPUTE = "bluefire-lab evaluate <folder of the unpacked artifact> --engine <path to Zircolite>"

# What would make the page fetch something when it opens: an element with a source,
# style that imports or points at a file, a script that makes a request. A link that
# needs a click is fine. Text from telemetry is escaped, so it cannot match.
_FETCHING_ELEMENT = re.compile(
    r"<(?:script|img|link|iframe|frame|source|object|embed|video|audio|track|base|input|image|use)\b"
    r"[^>]*\b(?:src|href|data|srcset|poster)\s*=",
    re.IGNORECASE,
)
_FETCHING_STYLE = re.compile(r"url\s*\(|@import", re.IGNORECASE)
_FETCHING_SCRIPT = re.compile(r"\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|\bimport\s*\(")


def loads_anything(page: str) -> list[str]:
    """What in the page would fetch something from elsewhere when it opens."""

    style = "".join(re.findall(r"<style>(.*?)</style>", page, re.DOTALL))
    script = "".join(re.findall(r"<script>(.*?)</script>", page, re.DOTALL))
    return _FETCHING_ELEMENT.findall(page) + _FETCHING_STYLE.findall(style) + _FETCHING_SCRIPT.findall(script)


def e(value: object) -> str:
    return html.escape(str(value))


def count(number: int, noun: str, plural: str = "") -> str:
    return f"{number} {noun if number == 1 else plural or noun + 's'}"


def sentence(text: str) -> str:
    return text[:1].upper() + text[1:] + "."


def tone(test: dict, answer: str) -> str:
    """The colour of an answer. A test that did not take effect is no gap, so it gets none."""

    if answer == "blocked":
        return "good"
    if test["execution"]["answer"] != "took effect":
        return ""
    return {"alert": "good", "telemetry only": "warn", "no telemetry": "bad"}.get(answer, "")


def pill(test: dict, answer: str) -> str:
    return f'<span class="pill {tone(test, answer)}">{e(answer)}</span>'


# The name of the second visibility answer in what each runner answered (combine.ANSWERS).
LAB = "with the lab's rules"


def runners_note(test: dict, name: str) -> str:
    """What each runner answered, for an answer the runners did not agree on."""

    if name not in test.get("unstable", []):
        return ""
    return "runners: " + ", ".join(runner[name] for runner in test["runners"])


def lede(results: dict) -> str:
    summary, target = results["summary"], results["run"]["target"]
    runners = results.get("runners")
    where = f"{target['os']}, kernel {target['kernel']}"
    if target.get("runner_image"):
        where = f"a GitHub-hosted runner ({where}, image {target['runner_image']})"
    if runners:
        kernels = sorted({runner["run"]["target"]["kernel"] for runner in runners})
        where = (
            f"each of {len(runners)} GitHub-hosted runners ({target['os']}, "
            f"{'kernel' if len(kernels) == 1 else 'kernels'} {' and '.join(kernels)})"
        )
    text = (
        f"{count(summary['tests'], 'published attack test')} ran on {where} on "
        f"{results['run']['started'][:10]}. {summary['took_effect']} took effect"
        f"{' on every runner' if runners else ''}. Of those, "
        f"{summary['alert']} raised an alert, {summary['telemetry_only']} left telemetry but no alert, "
        f"and {summary['no_telemetry']} left no telemetry."
    )
    if summary.get("unstable") or summary.get("unstable_other_runs"):
        others = summary.get("unstable_other_runs", 0)
        text += (
            f" {count(summary.get('unstable', 0), 'test')} got different answers on different runners"
            + (
                f", and so did {count(others, 'run')} of another kind (with a hardening change, with changed "
                "input arguments, or a control run)"
                if others
                else ""
            )
            + ": such an answer is marked unstable and is in none of these counts."
        )
    if summary["inconclusive"]:
        text += f" {summary['inconclusive']} could not be measured."
    if results.get("lab_rules"):
        text += (
            f" With the lab's own rules as well, {summary['alert_with_lab_rules']} of the "
            f"{summary['took_effect']} raised an alert."
        )
    if summary.get("hardened"):
        text += (
            f" {count(summary['hardened'], 'test')} ran again with a hardening change in place, and "
            f"{summary['blocked']} of those changes blocked the technique."
        )
    return text


def lab_rule_names(test: dict) -> list[str]:
    """The lab's rules that matched the test. One that is not accepted is said to be so, and
    changes no answer."""

    return [
        f"{rule['level']}: {rule['title']}" + ("" if rule.get("accepted") else ", not accepted")
        for rule in test["visibility"].get("with_lab_rules", {}).get("rules", [])
    ]


def lab_rules_table(results: dict) -> str:
    rows = []
    for rule in results["lab_rules"]:
        fires = (
            "<br>".join(f"{e(test['technique'])} {e(test['name'])}" for test in rule["fires_on"]) or "none"
        )
        took = [variant for variant in rule["variants"] if variant["took_effect"]]
        variants = (
            f"alerted on {sum(variant['alerted'] for variant in took)} of {len(took)}" if took else "none ran"
        )
        ordinary = (
            f"matched {count(len(rule['ordinary_matches']), 'event')}"
            if rule["ordinary_matches"]
            else "quiet"
        )
        verdict = "accepted" if rule["accepted"] else "not accepted"
        rows.append(
            f'<tr><td class="wide">{e(rule["title"])}<span class="sub">{e(sentence(rule["reason"]))}</span>'
            f'<details class="inner"><summary>Rule text</summary><pre class="box">{e(rule["text"])}</pre></details></td>'
            f'<td>{e(rule["level"])}</td><td class="wide">{fires}'
            f'<span class="sub">{count(rule["procedures"], "published procedure")}</span></td>'
            f"<td>{e(variants)}</td><td>{e(ordinary)}</td>"
            f'<td><span class="pill {"good" if rule["accepted"] else "warn"}">{verdict}</span></td></tr>'
        )
    head = (
        "<tr><th>Rule</th><th>Level</th><th>Alerts on</th><th>Runs with changed input arguments</th>"
        "<th>Ordinary activity</th><th>Verdict</th></tr>"
    )
    return f'<div class="table-wrap"><table><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table></div>'


def ordinary_note(results: dict) -> str:
    ordinary = results.get("ordinary_activity")
    if not ordinary:
        return ""
    noisy = ", ".join(
        f"{rule['title']} ({rule['level']}, {rule['events']})" for rule in ordinary["pinned_rules"]
    )
    return (
        f"The baseline of ordinary activity left {count(ordinary['baseline_events'], 'event')}, and the runner's "
        f"own work outside the tests left {count(ordinary['system_events'], 'event')}. Pinned rules that matched "
        f"them: {noisy or 'none'}."
    )


def left_behind(results: dict) -> list[dict]:
    """The runs of a test whose cleanup did not undo what the test did."""

    return [test for test in results["tests"] if test.get("cleanup", {}).get("answer") == "left behind"]


def left_behind_table(results: dict) -> str:
    rows = "".join(
        f'<tr><td class="mono">{e(test["technique"])}</td>'
        f'<td><a href="#t{test["order"]}">{e(test["name"])}</a></td>'
        f'<td class="mono wide">{e(test["cleanup"]["check"]["command"])}</td>'
        f"<td>{'yes' if 'no cleanup command upstream' not in test['cleanup']['basis'] else 'no'}</td></tr>"
        for test in left_behind(results)
    )
    head = "<tr><th>Technique</th><th>Test</th><th>Still found after the cleanup</th><th>Cleanup upstream</th></tr>"
    return f'<div class="table-wrap"><table><thead>{head}</thead><tbody>{rows}</tbody></table></div>'


def unstable_runs(results: dict) -> list[dict]:
    """Every run of a test, of any kind, that the runners did not agree on."""

    return [test for test in results["tests"] if test.get("unstable")]


def run_kind(test: dict) -> str:
    """What kind of run of a test this is, in words."""

    if test["role"] == "hardened":
        return f"with {test['defense']['title']}"
    if test["role"] == "variant":
        return "with input arguments " + ", ".join(f"{k}={v}" for k, v in test.get("args", {}).items())
    return {"canary": "known-detected test", "control": "harmless command"}.get(test["role"], "")


def unstable_table(results: dict) -> str:
    rows = "".join(
        f'<tr><td class="mono">{e(test["technique"])}</td>'
        f'<td><a href="#t{test["order"]}">{e(test["name"])}</a>'
        + (f'<span class="sub">{e(run_kind(test))}</span>' if run_kind(test) else "")
        + f"</td><td>{e(name)}</td>"
        f'<td class="wide">{e(", ".join(str(runner.get(name)) for runner in test["runners"]))}</td></tr>'
        for test in unstable_runs(results)
        for name in test["unstable"]
    )
    head = (
        "<tr><th>Technique</th><th>Run of a test</th><th>Answer</th><th>What each runner answered</th></tr>"
    )
    return f'<div class="table-wrap"><table><thead>{head}</thead><tbody>{rows}</tbody></table></div>'


def hardened_runs(results: dict) -> list[dict]:
    return [test for test in results["tests"] if test["role"] == "hardened"]


def hardening_table(results: dict) -> str:
    by_order = {test["order"]: test for test in results["tests"]}
    rows = []
    for test in hardened_runs(results):
        without = by_order.get(test.get("compared_with"))
        rows.append(
            f'<tr><td class="mono">{e(test["technique"])}</td>'
            f'<td><a href="#t{test["order"]}">{e(test["name"])}</a></td>'
            f'<td class="wide">{e(test["defense"]["title"])}</td>'
            f"<td>{pill(without, without['execution']['answer']) if without else 'not run'}</td>"
            f"<td>{pill(test, test['execution']['answer'])}</td>"
            f"<td>{pill(test, test['visibility']['answer'])}</td></tr>"
        )
    head = (
        "<tr><th>Technique</th><th>Test</th><th>Hardening change</th><th>Without it</th>"
        "<th>With it</th><th>Visibility with it</th></tr>"
    )
    return f'<div class="table-wrap"><table><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table></div>'


def rule_names(test: dict, limit: int = 3) -> list[str]:
    rules = test["visibility"].get("rules", [])
    names = [f"{rule['level']}: {rule['title']}" for rule in rules[:limit]]
    if len(rules) > limit:
        names.append(f"and {len(rules) - limit} more")
    return names


def launcher_note(test: dict) -> str:
    """Rules that matched only the line that carries the whole test: shown, never counted."""

    rules = test["visibility"].get("launcher_only_rules", [])
    if not rules:
        return ""
    levels = ", ".join(sorted({rule["level"] for rule in rules}, key=LEVELS.index))
    return f"{count(len(rules), 'rule')} ({levels}) matched only the launcher line, not counted"


LEVELS = ["critical", "high", "medium", "low", "informational"]


def rule_link(rule: dict, results: dict) -> str:
    if rule.get("origin") == "lab":
        repository, _, commit = results["run"]["tools"].get("lab", "@").partition("@")
        return f"https://github.com/{repository}/blob/{commit}/lab/rules/{rule['file']}" if commit else "#"
    repository, _, commit = results["rules"]["source"].partition("@")
    return f"https://github.com/{repository}/blob/{commit}/rules/{rule['file']}"


def results_table(tests: list[dict], with_lab_rules: bool = False) -> str:
    rows = []
    for test in tests:
        seen = test["visibility"]
        lab = seen.get("with_lab_rules", {})
        notes = {
            name: f'<span class="sub">{e(runners_note(test, name))}</span>'
            if runners_note(test, name)
            else ""
            for name in ("execution", "visibility", LAB)
        }
        lab_cell = (
            f"<td>{pill(test, lab.get('answer', seen['answer']))}{notes[LAB]}"
            + "".join(f'<span class="sub">{e(name)}</span>' for name in lab_rule_names(test))
            + "</td>"
            if with_lab_rules
            else ""
        )
        rows.append(
            f'<tr><td class="mono">{e(test["technique"])}</td>'
            f'<td><a href="#t{test["order"]}">{e(test["name"])}</a>'
            f'<span class="sub">ran as {e(test["user"])}</span></td>'
            f"<td>{pill(test, test['execution']['answer'])}{notes['execution']}</td>"
            f"<td>{pill(test, seen['answer'])}{notes['visibility']}</td>"
            f'<td class="wide">{"<br>".join(map(e, rule_names(test))) or "none"}'
            + (f'<span class="sub">{e(launcher_note(test))}</span>' if launcher_note(test) else "")
            + "</td>"
            + lab_cell
            + f'<td class="num">{seen.get("events", 0)}</td></tr>'
        )
    head = (
        "<tr><th>Technique</th><th>Test</th><th>Execution</th><th>Visibility</th><th>Rules that matched</th>"
        + ("<th>With the lab's rules too</th>" if with_lab_rules else "")
        + '<th class="num">Events</th></tr>'
    )
    return f'<div class="table-wrap"><table><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table></div>'


def rules_table(rules: list[dict], results: dict) -> str:
    rows = []
    for rule in rules:
        rows.append(
            f"<tr><td>{e(rule['level'])}</td>"
            f'<td class="wide"><a href="{e(rule_link(rule, results))}">{e(rule["title"])}</a>'
            f'<span class="sub mono">{e(rule["id"])}</span>'
            f'<details class="inner"><summary>Rule text</summary><pre class="box">{e(rule["text"])}</pre></details></td>'
            f'<td class="wide">{e(rule["author"])}</td>'
            f'<td class="mono wide">{e(", ".join(map(str, rule["records"])))}</td></tr>'
        )
    head = "<tr><th>Level</th><th>Rule</th><th>Author</th><th>Event records</th></tr>"
    return f'<div class="table-wrap"><table><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table></div>'


def fields_table(fields: dict) -> str:
    rows = "".join(
        f'<tr><td>{e(name)}</td><td class="mono wide">{e(value)}</td></tr>' for name, value in fields.items()
    )
    return f'<table class="fields"><tbody>{rows}</tbody></table>'


def events_table(events: list[dict]) -> str:
    rows = []
    for event in events:
        rows.append(
            f'<tr><td class="mono">{e(event["time"][11:])}</td><td>{e(event["kind"])}</td>'
            f'<td class="mono">{e(event["image"])}</td>'
            f'<td class="mono wide">{e(event["detail"])}'
            f'<details class="inner"><summary>All fields of record {event["record"]}</summary>'
            f"{fields_table(event['fields'])}</details></td>"
            f"<td>{e(event['user'])}</td><td>{e(event['why'])}</td></tr>"
        )
    head = (
        "<tr><th>Time (UTC)</th><th>Kind</th><th>Image</th><th>Detail</th><th>User</th><th>Tied by</th></tr>"
    )
    return f'<div class="table-wrap"><table><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table></div>'


def evidence(test: dict, results: dict) -> str:
    done, seen = test["execution"], test["visibility"]
    exit_code = "not recorded" if done["exit_code"] is None else done["exit_code"]
    facts = [f"Prerequisites: {done['prerequisites']}.", f"Exit code of the test: {exit_code}."]
    if done.get("timed_out"):
        facts.append("The test ran into its time limit.")
    check = ""
    if "effect_check" in done:
        effect = done["effect_check"]
        check = (
            f"<p>Effect check, exit status {effect['exit_status']}:</p>"
            f'<pre class="box">{e(effect["command"])}'
            + (f"\n\n{e(effect['output'])}" if effect["output"] else "")
            + "</pre>"
        )
    undone = test.get("cleanup")
    if undone:
        check += f"<p>Cleanup: {e(undone['answer'])}. {e(sentence(undone['basis']))}</p>"
        if "check" in undone:
            check += f'<pre class="box">{e(undone["check"]["command"])}</pre>'
    parts = [
        '<div class="answers"><section>'
        f"<h3>Execution</h3><p>{pill(test, done['answer'])} {e(sentence(done['basis']))}</p>"
        f"<p>{e(' '.join(facts))}</p>{check}</section><section>"
        f"<h3>Visibility</h3><p>{pill(test, seen['answer'])} {e(sentence(seen['basis']))}</p>"
    ]
    if "window" in seen:
        parts.append(
            f"<p>Between the markers at {e(seen['window'][0][11:])} and {e(seen['window'][1][11:])} UTC.</p>"
        )
    if seen.get("events_by_kind"):
        kinds = ", ".join(f"{kind}: {number}" for kind, number in sorted(seen["events_by_kind"].items()))
        parts.append(f"<p>Events by kind. {e(sentence(kinds))}</p>")
    parts.append("</section></div>")
    if seen.get("rules"):
        parts.append(f"<h3>Rules that matched an event of the test</h3>{rules_table(seen['rules'], results)}")
    if seen.get("with_lab_rules", {}).get("rules"):
        parts.append(
            "<h3>The lab's own rules that matched an event of the test</h3>"
            + rules_table(seen["with_lab_rules"]["rules"], results)
        )
    if "launcher" in seen:
        parts.append(
            '<h3>Launcher</h3><p class="note">The executor starts the test as one shell process (sh -c or '
            "bash -c) whose command line is the whole test. Its own start and end are not counted as telemetry "
            "of the test; files it writes are.</p>"
            f'<pre class="box">{e(seen["launcher"]["detail"])}</pre>'
        )
    if seen.get("launcher_only_rules"):
        parts.append(
            '<h3>Rules that matched only the launcher</h3><p class="note">Reported, and not counted as a '
            f"detection.</p>{rules_table(seen['launcher_only_rules'], results)}"
        )
    if "defense" in test:
        change = test["defense"]
        state = "Put in place: " + ("yes" if change.get("applied") else "no")
        if "reverted" in change:
            state += ". Removed after the test: " + ("yes" if change["reverted"] else "no")
        parts.append(
            f"<h3>Hardening change</h3><p>{e(sentence(change['title']))} {e(change['why'])}</p>"
            f'<p>{e(state)}.</p><pre class="box">{e(change["apply"])}</pre>'
            f'<p class="note">Removed with:</p><pre class="box">{e(change["revert"])}</pre>'
            f'<h3>What the test printed</h3><pre class="box">{e(test.get("output") or "nothing")}</pre>'
        )
    if test["events"]:
        parts.append(f"<h3>Events of the test ({len(test['events'])})</h3>{events_table(test['events'])}")
    role = {
        "canary": "known-detected test",
        "control": "harmless command",
        "hardened": "with a hardening change",
        "variant": "input arguments "
        + ", ".join(f"{key}={value}" for key, value in test.get("args", {}).items()),
    }.get(test["role"], "")
    return (
        f'<details class="test" id="t{test["order"]}"><summary>'
        f'<span class="mono">{e(test["technique"])}</span><span class="name">{e(test["name"])}'
        + (f" ({role})" if role else "")
        + f"</span>{pill(test, done['answer'])}{pill(test, seen['answer'])}</summary>"
        f'<div class="evidence">{"".join(parts)}</div></details>'
    )


def fact(term: str, value: str) -> str:
    return f"<div><dt>{e(term)}</dt><dd>{value}</dd></div>"


def html_report(results: dict) -> str:
    package = resources.files("bluefire_lab")
    css = package.joinpath("report.css").read_text(encoding="utf-8")
    script = package.joinpath("report.js").read_text(encoding="utf-8")
    run, sensor, rules, tools = results["run"], results["sensor"], results["rules"], results["run"]["tools"]
    audit = results.get("audit")
    found = run.get("inventory")
    inventory_section = (
        '<h3 id="inventory">Inventory of the target</h3><p class="note">Read before the lab started its '
        "sensors, and the sensors' state after it did. A test that needs a program the target does not "
        'have is left out, with the reason, under <a href="#left-out">Tests left out</a>.</p>'
        '<div class="table-wrap"><table><tbody>'
        + "".join(
            f'<tr><td>{e(label)}</td><td class="mono wide">{e(value)}</td></tr>'
            for label, value in (
                ("Accounts that can log in", ", ".join(found["accounts"])),
                ("Running services", ", ".join(found["services"])),
                ("Listening addresses", ", ".join(found["listening"])),
                ("Sensors", ", ".join(f"{name} {state}" for name, state in found.get("sensors", {}).items())),
                (
                    "Programs the tests need",
                    ", ".join(f"{name} at {path or 'none'}" for name, path in found["programs"].items()),
                ),
            )
        )
        + "</tbody></table></div>"
        if found
        else ""
    )
    audit_configuration = (
        f'<p class="note">auditd, rules SHA-256 <span class="mono">{e(audit["rules_sha256"])}</span>:</p>'
        f'<pre class="box">{e(audit["rules_text"])}</pre>'
        if audit
        else ""
    )
    tests = [test for test in results["tests"] if test["role"] == "test"]
    hardened = hardened_runs(results)
    variants = [test for test in results["tests"] if test["role"] == "variant"]
    others = [test for test in results["tests"] if test["role"] in ("canary", "control")]
    lab_rules = (
        "<h2>The lab's own rules</h2>"
        + lab_rules_table(results)
        + '<p class="note">Rules this repository adds for gaps the pinned rules leave. A rule is accepted when it '
        "alerts on a test, still alerts when that test runs again with changed input arguments, and matches "
        "nothing in a baseline of ordinary use of the same tools or in the runner's own work. "
        + e(ordinary_note(results))
        + "</p>"
        if results.get("lab_rules")
        else ""
    )
    unstable = (
        '<h2 id="unstable">Answers the runners did not agree on</h2>'
        + unstable_table(results)
        + '<p class="note">Every run of a test, of any kind, for which the runners gave different answers. '
        "Such an answer counts in no total.</p>"
        if unstable_runs(results)
        else ""
    )
    failed = [check for check in results["controls"] if not check["passed"]]
    unstable_note = (
        "An answer is unstable when the runners, which ran the same list at the same time, did not all give "
        "the same one: it is shown with each runner's answer and counted in no total. "
        if results.get("runners")
        else ""
    )
    hardening = (
        "<h2>With a hardening change</h2>"
        + hardening_table(results)
        + '<p class="note">Each of these tests ran again later in the same run, with one change in place '
        "that a defender could deploy. Blocked means the test ran with its prerequisites met and did not "
        "take effect, while it took effect without the change. Select a test to see the change and what "
        "the test printed.</p>"
        if hardened
        else ""
    )

    behind = (
        '<h2 id="left-behind">Left behind after the cleanup</h2>'
        + left_behind_table(results)
        + '<p class="note">After each test\'s cleanup the lab looks again for what the test did: with the '
        "command the list names for it, or else with the test's effect check. These runs still had it. Some "
        "tests have no cleanup command upstream. A target that is thrown away, as a hosted runner is, takes no "
        "harm from that; the effect check also runs before every test, so a test that starts with its effect "
        "already in place is reported as not measured.</p>"
        if left_behind(results)
        else ""
    )
    facts = "".join(
        [
            fact("Run", f"{e(run['started'].replace('T', ' ').replace('Z', ' UTC'))}, id {e(run['id'])}"),
            fact(
                "Targets" if results.get("runners") else "Target",
                "; ".join(
                    f"{e(target['os'])}, kernel {e(target['kernel'])}"
                    + (f", runner image {e(target['runner_image'])}" if target.get("runner_image") else "")
                    for target in (
                        [runner["run"]["target"] for runner in results["runners"]]
                        if results.get("runners")
                        else [run["target"]]
                    )
                )
                + (
                    ". The events and rule matches shown below are the first runner's; the artifact holds each "
                    "runner's own files and report in a folder of its own."
                    if results.get("runners")
                    else ""
                ),
            ),
            fact(
                "Sensors" if audit else "Sensor",
                f"{e(sensor['name'])} {e(sensor['version'])}, {sensor['events']} events recorded"
                + (
                    f"; auditd {e(audit['version'])}, {audit['records']} records of {audit['events']} events"
                    if audit
                    else ""
                )
                + '. The <a href="#sensor">configuration</a> is below.',
            ),
            fact(
                "Tests",
                f'Atomic Red Team at commit <span class="mono">{e(tools["atomic-red-team"][:12])}</span>, run by '
                f'Invoke-AtomicRedTeam at <span class="mono">{e(tools["invoke-atomicredteam"][:12])}</span>',
            ),
            fact(
                "Rules",
                f"{e(rules['source'].partition('@')[0])} at commit "
                f'<span class="mono">{e(rules["source"].partition("@")[2][:12])}</span>: '
                + ", ".join(f"{number} {e(category)}" for category, number in rules["evaluated"].items())
                + f". Alert levels: {e(' and '.join(rules['alert_levels']))}.",
            ),
            fact("Rule engine", f"{e(results['engine']['name'])} {e(results['engine']['version'])}"),
            *(
                [
                    fact(
                        "Inventory",
                        f"{count(len(found['accounts']), 'account')} that can log in, "
                        f"{count(len(found['services']), 'running service')}, "
                        f"{count(len(found['listening']), 'listening address', 'listening addresses')}. "
                        'The <a href="#inventory">inventory</a> is below.',
                    )
                ]
                if found
                else []
            ),
        ]
    )
    controls = "".join(
        f"<li><strong>{e(check['name'])}</strong>"
        f'<span class="pill {"good" if check["passed"] else "bad"}">{"passed" if check["passed"] else "failed"}</span>'
        f'<span class="sub">{e(sentence(check["detail"]))}</span></li>'
        for check in results["controls"]
    )
    dropped = "".join(
        f'<tr><td class="mono">{e(item["technique"])}</td><td>{e(item["name"])}</td><td>{e(item["reason"])}</td></tr>'
        for item in results["dropped"]
    )
    dropped = (
        '<div class="table-wrap"><table><thead><tr><th>Technique</th><th>Test</th><th>Why it was left out</th>'
        f"</tr></thead><tbody>{dropped}</tbody></table></div>"
        if dropped
        else '<p class="note">No test was left out.</p>'
    )
    warning = (
        f'<p class="failed-run">{count(len(failed), "control")} failed, so this run does not support its '
        "results: " + e("; ".join(check["detail"] for check in failed)) + ".</p>"
        if failed or run.get("aborted")
        else ""
    )
    versions = "".join(
        f'<tr><td>{e(name)}</td><td class="mono wide">{e(value)}</td></tr>'
        for name, value in {**tools, "rules": rules["source"], "rule license": rules["license"]}.items()
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lab report {e(run["started"][:10])}</title>
<style>
{css}</style>
</head>
<body>
<main>
<header>
<div>
<h1>Lab report</h1>
<p class="lede">{e(lede(results))}</p>
</div>
<button id="theme" type="button">Light or dark</button>
</header>
{warning}
<dl class="facts">{facts}</dl>

<h2>Results</h2>
{results_table(tests, bool(results.get("lab_rules")))}
<p class="note">Execution says whether the technique took effect on the target. Visibility says what the
defense saw: an alert, telemetry without an alert, or nothing. An alert is a match of a Sigma rule whose
level is {e(" or ".join(rules["alert_levels"]))} on an event of the test. A test that took effect and left
telemetry but no alert is a gap that a rule could close; one that left no telemetry needs the sensor to
record more first. {e(unstable_note)}Select a test to see its events and rules.</p>
{lab_rules}
{hardening}
{behind}
{unstable}

<h2>Controls</h2>
<p class="note">These checks keep a broken measurement from looking like a finding. A run with a failed
control fails as a whole.</p>
<ul class="controls">{controls}</ul>

<h2>Evidence</h2>
{"".join(evidence(test, results) for test in tests)}
{"<h3>Runs with a hardening change</h3>" + "".join(evidence(test, results) for test in hardened) if hardened else ""}
{"<h3>Runs with changed input arguments</h3>" + "".join(evidence(test, results) for test in variants) if variants else ""}
<h3>Control runs</h3>
{"".join(evidence(test, results) for test in others)}

<h2 id="left-out">Tests left out</h2>
{dropped}

<h2>How this was measured</h2>
<p class="note">Each test is a published Atomic Red Team test, pinned by its GUID and run unchanged by the
upstream executor on the target, as an unprivileged account unless the test declares that it needs root.
A marker command runs before and after each test. Each step runs in a kernel audit session of its own,
and an event is tied to a test when its process is in the session of the test's attack step; an auditd
record, when the process that wrote it is one of the test's. What a test schedules runs outside its session,
so two rules go by time, between the test's markers: what cron starts for the test account belongs to a test
run as that account, and what systemd starts belongs to a test run as root, unless the same command also ran
outside every test's window. A late step of systemd for an earlier test can still land in such a window.
What the executor and the lab's own driver run for themselves, systemd's own steps, and the test's cleanup
are left out, and so is a hardening change, which root puts in place and removes in sessions of its own.
The sensors' own timestamps are used throughout.</p>
<p class="note">The answers can be computed again from the files of the run's artifact:</p>
<pre class="box">{e(RECOMPUTE)}</pre>
<h3 id="sensor">Sensor configuration</h3>
<p class="note">"No telemetry" means none under this configuration. Sysmon for Linux, SHA-256
<span class="mono">{e(sensor["configuration_sha256"])}</span>:</p>
<pre class="box">{e(sensor["configuration_text"])}</pre>
{audit_configuration}
{inventory_section}
<h3>Pinned versions</h3>
<div class="table-wrap"><table><tbody>{versions}</tbody></table></div>
<p class="note">Sigma rules are the work of their authors, named with each rule above, and are used under
the Detection Rule License 1.1.</p>
</main>
<script>
{script}</script>
</body>
</html>
"""


def markdown_summary(results: dict) -> str:
    def cell(text: object) -> str:
        return str(text).replace("|", "\\|")

    lines = ["## Lab report", "", lede(results), ""]
    failed = [check for check in results["controls"] if not check["passed"]]
    if failed:
        lines += [
            f"**{count(len(failed), 'control')} failed, so this run does not support its results.**",
            "",
        ]
    lines += [
        "| Technique | Test | Execution | Visibility | Rules that matched | "
        + ("With the lab's rules too | " if results.get("lab_rules") else "")
        + "Events |",
        "|---|---|---|---|---|" + ("---|" if results.get("lab_rules") else "") + "---:|",
    ]

    def said(test: dict, name: str, answer: str) -> str:
        return cell(answer + (f" ({runners_note(test, name)})" if runners_note(test, name) else ""))

    for test in results["tests"]:
        if test["role"] == "test":
            seen = test["visibility"]
            lab = seen.get("with_lab_rules", {})
            lab_cell = (
                f" {said(test, LAB, lab.get('answer', seen['answer']))}"
                + (f" ({cell('; '.join(lab_rule_names(test)))})" if lab_rule_names(test) else "")
                + " |"
                if results.get("lab_rules")
                else ""
            )
            lines.append(
                f"| {cell(test['technique'])} | {cell(test['name'])} | "
                f"{said(test, 'execution', test['execution']['answer'])} | "
                f"{said(test, 'visibility', seen['answer'])} | {cell('; '.join(rule_names(test)) or 'none')}"
                + (f" ({cell(launcher_note(test))})" if launcher_note(test) else "")
                + " |"
                + lab_cell
                + f" {seen.get('events', 0)} |"
            )
    if results.get("lab_rules"):
        lines += ["", "| The lab's rule | Level | Alerts on | Runs with changed input arguments | Verdict |"]
        lines.append("|---|---|---|---|---|")
        for rule in results["lab_rules"]:
            took = [variant for variant in rule["variants"] if variant["took_effect"]]
            alerted = f"{sum(variant['alerted'] for variant in took)} of {len(took)}" if took else "none ran"
            fires = "; ".join(f"{test['technique']} {test['name']}" for test in rule["fires_on"]) or "none"
            verdict = ("accepted: " if rule["accepted"] else "not accepted: ") + rule["reason"]
            lines.append(
                f"| {cell(rule['title'])} | {cell(rule['level'])} | {cell(fires)} | {alerted} | {cell(verdict)} |"
            )
    by_order = {test["order"]: test for test in results["tests"]}
    if hardened_runs(results):
        lines += [
            "",
            "| Technique | Test | Hardening change | Without it | With it | Visibility with it |",
            "|---|---|---|---|---|---|",
        ]
        for test in hardened_runs(results):
            without = by_order.get(test.get("compared_with"))
            lines.append(
                f"| {cell(test['technique'])} | {cell(test['name'])} | {cell(test['defense']['title'])} | "
                f"{cell(without['execution']['answer']) if without else 'not run'} | "
                f"{cell(test['execution']['answer'])} | {cell(test['visibility']['answer'])} |"
            )
    if left_behind(results):
        lines += ["", "| Technique | Test | Still found after the cleanup |", "|---|---|---|"]
        for test in left_behind(results):
            role = "" if test["role"] == "test" else f" ({test['role']})"
            lines.append(
                f"| {cell(test['technique'])} | {cell(test['name'] + role)} | "
                f"`{cell(test['cleanup']['check']['command'])}` |"
            )
    if unstable_runs(results):
        lines += [
            "",
            "| Technique | Run of a test the runners did not agree on | Answer | What each runner answered |",
            "|---|---|---|---|",
        ]
        for test in unstable_runs(results):
            kind = f" ({run_kind(test)})" if run_kind(test) else ""
            for name in test["unstable"]:
                said = ", ".join(str(runner.get(name)) for runner in test["runners"])
                lines.append(
                    f"| {cell(test['technique'])} | {cell(test['name'] + kind)} | {cell(name)} | {cell(said)} |"
                )
    if results["dropped"]:
        lines += ["", "| Technique | Test left out | Why |", "|---|---|---|"]
        for item in results["dropped"]:
            lines.append(f"| {cell(item['technique'])} | {cell(item['name'])} | {cell(item['reason'])} |")
    lines += ["", "| Control | Result | Detail |", "|---|---|---|"]
    for check in results["controls"]:
        lines.append(
            f"| {cell(check['name'])} | {'passed' if check['passed'] else '**failed**'} | {cell(check['detail'])} |"
        )
    levels = " or ".join(results["rules"]["alert_levels"])
    lines += [
        "",
        f"An alert is a match of a Sigma rule of level {levels} on an event of the test. "
        "The file `report.html` in this run's artifact shows the events and rules behind each row.",
        "",
    ]
    return "\n".join(lines)


def main(run_dir: Path) -> int:
    results = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    page = html_report(results)
    if loads_anything(page):
        raise SystemExit(f"the report would fetch {loads_anything(page)} when opened: put it in the page")
    (run_dir / "report.html").write_text(page, encoding="utf-8")
    (run_dir / "summary.md").write_text(markdown_summary(results), encoding="utf-8")
    return 0
