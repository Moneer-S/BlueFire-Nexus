"""Make a host's Wazuh configuration from the stock file its package installed.

The lab does not write an ossec.conf of its own. It takes the stock file that
the pinned agent package or the pinned manager image installed and makes a
short list of edits to it, each with a label: `lab addition` (something the lab
collects that the stock file does not), `removed` (a stock feature the lab
switches off) or `startup` (a setting that lets the range start quickly and
without a person). Every edit must find exactly the text it expects in the
stock file, or the build stops: a Wazuh version that changes the file cannot
change the range's configuration unnoticed.

The image build runs this file with the Python inside the pinned manager image,
so it uses the standard library only:

    python3 ossec.py <settings.json> <stock manager ossec.conf> <stock agent ossec.conf> <out folder>

The engine makes the same edits again on the stock files it copies out of the
range, to check the files the hosts ran with and to label their diff.
"""

from __future__ import annotations

import difflib
import json
import re
import sys
from pathlib import Path

LAB = "lab addition"
REMOVED = "removed"
STARTUP = "startup"
LABELS = (LAB, REMOVED, STARTUP)


class ConfError(ValueError):
    """The stock file does not hold the text an edit expects."""


def _once(pattern: str, text: str, what: str) -> re.Match:
    found = list(re.finditer(pattern, text, re.S))
    if len(found) != 1:
        raise ConfError(
            f"the stock ossec.conf has {len(found)} {what}, and the lab's edit expects exactly one"
        )
    return found[0]


def _blocks(text: str, opening: str) -> list[re.Match]:
    """The blocks that start with the line `opening`, each up to its closing tag at the same depth."""

    tag = re.match(r"<([a-z_-]+)", opening).group(1)
    return list(re.finditer(r"\n  " + re.escape(opening) + r"\n.*?\n  </" + tag + r">\n", text, re.S))


def _block(text: str, opening: str, what: str) -> re.Match:
    found = _blocks(text, opening)
    if len(found) != 1:
        raise ConfError(
            f"the stock ossec.conf has {len(found)} {what}, and the lab's edit expects exactly one"
        )
    return found[0]


def _set(text: str, opening: str, tag: str, old: str, new: str) -> str:
    """Change `<tag>old</tag>` to `<tag>new</tag>` in the one block, of those that start with `opening`, that has it."""

    line = f"    <{tag}>{old}</{tag}>\n"
    found = [block for block in _blocks(text, opening) if block.group(0).count(line) == 1]
    if len(found) != 1:
        raise ConfError(
            f"the stock ossec.conf has {len(found)} blocks {opening} with {line.strip()}, "
            "and the lab's edit expects exactly one"
        )
    block = found[0]
    inside = block.group(0).replace(line, f"    <{tag}>{new}</{tag}>\n")
    return text[: block.start()] + inside + text[block.end() :]


def _remove_commands(text: str) -> tuple[str, list[str]]:
    """Take out every command monitor: the localfile blocks that run a command on a timer."""

    pattern = (
        r"(?<=\n)  <localfile>\n    <log_format>(?:command|full_command)</log_format>\n"
        r"    <command>([^\n]*)</command>\n(?:    [^\n]*\n)*?  </localfile>\n\n?"
    )
    commands = [found.group(1) for found in re.finditer(pattern, text)]
    if not commands:
        raise ConfError("the stock ossec.conf has no command monitor, which the lab's edit expects")
    return re.sub(pattern, "", text), commands


def _off(text: str, off: list[str], reason: str) -> tuple[str, list[dict]]:
    changes = []
    if "command_monitoring" in off:
        text, commands = _remove_commands(text)
        changes.append(
            {
                "label": REMOVED,
                "change": "command monitoring: the commands the stock file runs on a timer ("
                + ", ".join(command.split(" | ")[0] for command in commands)
                + f"), {reason}",
            }
        )
    if "sca" in off:
        text = _set(text, "<sca>", "enabled", "yes", "no")
        changes.append({"label": REMOVED, "change": f"security configuration assessment (sca), {reason}"})
    if "rootcheck" in off:
        text = _set(text, "<rootcheck>", "disabled", "no", "yes")
        changes.append({"label": REMOVED, "change": f"rootcheck, {reason}"})
    if "syscollector" in off:
        text = _set(text, '<wodle name="syscollector">', "disabled", "no", "yes")
        changes.append({"label": REMOVED, "change": f"syscollector, the inventory of the system, {reason}"})
    return text, changes


def agent(stock: str, settings: dict) -> tuple[str, list[dict]]:
    """The agent's ossec.conf, and its labelled changes.

    `settings` holds the agent's `name`, the `manager` it reports to (a name on
    the range network), the `logs` it collects (path and format), the folders
    it watches in real time (`fim_realtime`) and the features switched `off`.
    """

    text, changes = stock, []
    text = _set(text, "<client>", "address", "MANAGER_IP", settings["manager"])
    changes.append(
        {
            "label": STARTUP,
            "change": f"the agent reports to {settings['manager']}, the manager's name in the range",
        }
    )
    text = _set(text, "<client>", "auto_restart", "yes", "no")
    changes.append(
        {
            "label": STARTUP,
            "change": "auto_restart no: the agent does not restart itself when the manager sends it the shared "
            "configuration after its first connection",
        }
    )
    anchor = _once(r"\n    <crypto_method>aes</crypto_method>\n", text, "crypto_method lines in client")
    enrollment = (
        "    <enrollment>\n"
        "      <enabled>yes</enabled>\n"
        f"      <agent_name>{settings['name']}</agent_name>\n"
        "      <delay_after_enrollment>1</delay_after_enrollment>\n"
        "    </enrollment>\n"
    )
    text = text[: anchor.end()] + enrollment + text[anchor.end() :]
    changes.append(
        {
            "label": STARTUP,
            "change": f"enrollment: the agent asks the manager for its key on port 1515 as {settings['name']}, "
            "and waits 1 s after enrolling instead of 20",
        }
    )
    text, removed = _off(text, settings["off"], "not live telemetry of what happens on the host")
    changes += removed

    added = []
    for log in settings["logs"]:
        stock_entry = f"<log_format>{log['format']}</log_format>\n    <location>{log['path']}</location>"
        if stock_entry in stock:
            continue
        added.append(
            "  <localfile>\n"
            f"    <log_format>{log['format']}</log_format>\n"
            f"    <location>{log['path']}</location>\n"
            "  </localfile>\n"
        )
        changes.append({"label": LAB, "change": f"collects {log['path']} ({log['format']})"})
    if added:
        last = text.rindex("\n</ossec_config>")
        text = text[: last + 1] + "\n".join(added) + "\n" + text[last + 1 :]

    folders = settings["fim_realtime"]
    if folders:
        syscheck = _block(text, "<syscheck>", "syscheck blocks")
        inside = syscheck.group(0)
        scheduled = []

        def without_ours(found: re.Match) -> str:
            kept = [f for f in found.group(1).split(",") if f not in folders]
            scheduled.extend(f for f in found.group(1).split(",") if f in folders)
            return f"<directories>{','.join(kept)}</directories>" if kept else ""

        inside = re.sub(r"<directories>([^<]*)</directories>", without_ours, inside)
        inside = re.sub(r"\n    \n", "\n", inside)
        lines = list(re.finditer(r"\n    <directories[^\n]*</directories>", inside))
        if not lines:
            raise ConfError(
                "the stock ossec.conf has no directories line in syscheck, which the lab's edit expects"
            )
        line = f'\n    <directories realtime="yes">{",".join(folders)}</directories>'
        inside = inside[: lines[-1].end()] + line + inside[lines[-1].end() :]
        text = text[: syscheck.start()] + inside + text[syscheck.end() :]
        note = (
            f" ({', '.join(scheduled)} moved from the stock file's scan every 12 hours)" if scheduled else ""
        )
        changes.append(
            {
                "label": LAB,
                "change": f"file integrity monitoring in real time (inotify) on {', '.join(folders)}{note}",
            }
        )
    return text, changes


def manager(stock: str) -> tuple[str, list[dict]]:
    """The manager's ossec.conf, and its labelled changes."""

    text, changes = stock, []
    text = _set(text, "<global>", "logall_json", "no", "yes")
    changes.append(
        {
            "label": LAB,
            "change": "logall_json: every event the manager receives is written to logs/archives/archives.json, "
            "whether or not a rule matched",
        }
    )
    text = _set(text, "<global>", "update_check", "yes", "no")
    changes.append(
        {"label": REMOVED, "change": "the check for a newer Wazuh version, which needs the internet"}
    )
    text = _set(text, "<vulnerability-detection>", "enabled", "yes", "no")
    changes.append(
        {
            "label": REMOVED,
            "change": "vulnerability detection, which needs an indexer and a feed from the internet",
        }
    )
    text = _set(text, "<indexer>", "enabled", "yes", "no")
    changes.append({"label": REMOVED, "change": "the indexer connection: the range has no indexer"})
    reason = "on the manager itself: the manager's own container is not a defended host"
    text, removed = _off(text, ["command_monitoring", "sca", "rootcheck", "syscollector"], reason)
    changes += removed
    text = _set(text, "<syscheck>", "disabled", "no", "yes")
    changes.append({"label": REMOVED, "change": f"file integrity monitoring {reason}"})
    return text, changes


def diff(stock: str, rendered: str, name: str = "ossec.conf") -> str:
    return "".join(
        difflib.unified_diff(
            stock.splitlines(keepends=True),
            rendered.splitlines(keepends=True),
            fromfile=f"{name} (stock)",
            tofile=f"{name} (range)",
        )
    )


def main(arguments: list[str]) -> int:
    settings_path, manager_stock, agent_stock, out = arguments
    settings = json.loads(Path(settings_path).read_text(encoding="utf-8"))
    try:
        rendered = {settings["manager"]: manager(Path(manager_stock).read_text(encoding="utf-8"))[0]}
        stock = Path(agent_stock).read_text(encoding="utf-8")
        for name, agent_settings in settings["agents"].items():
            rendered[name] = agent(stock, agent_settings)[0]
    except ConfError as error:
        print(f"ossec.py: {error}", file=sys.stderr)
        return 1
    for name, text in rendered.items():
        folder = Path(out) / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "ossec.conf").write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
