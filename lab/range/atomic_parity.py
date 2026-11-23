"""Compare the lab's argument vectors with what Invoke-AtomicRedTeam starts, byte for byte.

For every step of the path, the upstream executor runs the attack, -CheckPrereqs and
-Cleanup with the step's input arguments. PATH holds only a folder with two stand-ins
named sh and bash (argv_stub.py), which write the vector they were started with and run
nothing. .NET resolves a bare program name in the folder of the pwsh executable, then in
pwsh's working folder, then in PATH (ResolvePath in Process.Unix.cs), so this script first
makes sure the first two hold no sh or bash. Any difference, a stand-in not reached where
a vector was expected, or a start that was not expected fails the comparison.

Usage: python3 atomic_parity.py --expected <file from bluefire-lab atomic argv>
       --executor <Invoke-AtomicRedTeam checkout> --work <empty folder> [--summary <file>]
Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SHELLS = ("sh", "bash")
INTERPRETER = [b"/usr/bin/python3", b"-I"]
PHASES = {"attack": [], "prereq": ["-CheckPrereqs"], "cleanup": ["-Cleanup"]}
DRIVER = r"""
param([string]$Phase, [string]$Technique, [string]$Guid, [string]$Atomics, [string]$Executor, [string]$ArgsFile)
$ProgressPreference = 'SilentlyContinue'
$PSStyle.OutputRendering = 'PlainText'
Import-Module (Join-Path $Executor 'Invoke-AtomicRedTeam.psd1') -Force
$inputArgs = @{}
foreach ($pair in (Get-Content -Raw -LiteralPath $ArgsFile | ConvertFrom-Json).PSObject.Properties) {
    $inputArgs[$pair.Name] = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($pair.Value))
}
$common = @{ TestGuids = $Guid; PathToAtomicsFolder = $Atomics; InputArgs = $inputArgs; NoExecutionLog = $true }
switch ($Phase) {
    'attack' { Invoke-AtomicTest $Technique @common }
    'prereq' { Invoke-AtomicTest $Technique @common -CheckPrereqs }
    'cleanup' { Invoke-AtomicTest $Technique @common -Cleanup }
}
"""


def stand_ins(work: Path, pwsh: Path, executor: Path) -> Path:
    """The folder that is PATH for the executor, holding only the two stand-ins.

    Public/config.ps1 of the executor runs privateConfig.ps1 from the folder above its
    checkout when that file exists, so it must not.
    """

    if (executor.parent / "privateConfig.ps1").exists():
        raise SystemExit(f"{executor.parent / 'privateConfig.ps1'} exists, and the executor would run it")
    for place in (pwsh.parent, work / "empty"):
        found = [name for name in SHELLS if (place / name).exists()]
        if found:
            raise SystemExit(f"{place} holds {', '.join(found)}, which .NET would start before PATH")
    stubs = work / "stubs"
    stubs.mkdir()
    for name in SHELLS:
        shutil.copyfile(Path(__file__).with_name("argv_stub.py"), stubs / name)
        (stubs / name).chmod(0o755)
    return stubs


def started(calls: Path, stubs: Path) -> list[list[bytes]]:
    """The vectors the stand-ins recorded, in order, as the program name and its arguments."""

    vectors = []
    for record in sorted(calls.iterdir()):
        cmdline = [bytes.fromhex(element) for element in json.loads(record.read_text())["cmdline"]]
        script = cmdline[2] if len(cmdline) > 2 else b""
        if cmdline[:2] != INTERPRETER or script not in [os.fsencode(stubs / name) for name in SHELLS]:
            raise SystemExit(f"{record}: not a vector a stand-in wrote: {cmdline!r}")
        vectors.append([os.fsencode(Path(os.fsdecode(script)).name), *cmdline[3:]])
    return vectors


def shown(vector: list[bytes] | None) -> str:
    if vector is None:
        return "(none)"
    text = json.dumps([element.decode("utf-8", "backslashreplace") for element in vector])
    return "<code>" + html.escape(text).replace("|", "&#124;") + "</code>"


def compare(expected: list[list[bytes]], got: list[list[bytes]]) -> list[tuple[str, str, str]]:
    """One row per vector: whether it is identical, and both vectors when it is not."""

    rows = []
    for index in range(max(len(expected), len(got))):
        want = expected[index] if index < len(expected) else None
        have = got[index] if index < len(got) else None
        if want == have:
            rows.append(("identical", "", ""))
        elif have is None:
            rows.append(("different: the stand-in was not reached", shown(want), shown(have)))
        elif want is None:
            rows.append(("different: a start the parser does not give", shown(want), shown(have)))
        else:
            rows.append(("different", shown(want), shown(have)))
    return rows or [("identical (nothing to start, nothing started)", "", "")]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--executor", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--pwsh", default=shutil.which("pwsh"))
    options = parser.parse_args()
    if not options.pwsh:
        raise SystemExit("pwsh is not installed")
    document = json.loads(options.expected.read_text(encoding="ascii"))
    work = options.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    if any(work.iterdir()):
        raise SystemExit(f"{work} is not empty")
    (work / "empty").mkdir()
    executor = options.executor.resolve()
    stubs = stand_ins(work, Path(os.path.realpath(options.pwsh)), executor)
    (work / "driver.ps1").write_text(DRIVER, encoding="utf-8")
    environment = {
        **os.environ,
        "PATH": str(stubs),
        # The culture the lab's merge of PathToAtomicsFolder follows, whatever the runner's locale.
        "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT": "1",
        "POWERSHELL_TELEMETRY_OPTOUT": "1",
        "POWERSHELL_UPDATECHECK": "Off",
    }
    table = ["| Step | Command | Identical | Parser | Upstream |", "|---|---|---|---|---|"]
    failed = 0
    for step in document["steps"]:
        arguments = work / f"{step['id']}-args.json"
        encoded = {
            name: base64.b64encode(value.encode("utf-8")).decode() for name, value in step["args"].items()
        }
        arguments.write_text(json.dumps(encoded), encoding="ascii")
        expected = {"attack": [step["attack"]], "prereq": step["prereqs"], "cleanup": [step["cleanup"]]}
        for phase in PHASES:
            calls = work / f"{step['id']}-{phase}"
            calls.mkdir()
            command = [
                options.pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(work / "driver.ps1"),
                "-Phase", phase, "-Technique", step["technique"], "-Guid", step["guid"],
                "-Atomics", document["atomics_path"], "-Executor", str(executor),
                "-ArgsFile", str(arguments),
            ]  # fmt: skip
            done = subprocess.run(
                command,
                cwd=work / "empty",
                env={**environment, "BLUEFIRE_PARITY_CALLS": str(calls)},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=300,
                check=False,
            )
            want = [[element.encode("utf-8") for element in vector] for vector in expected[phase]]
            rows = compare(want, started(calls, stubs))
            for status, mine, theirs in rows:
                table.append(f"| {step['id']} | {phase} | {status} | {mine} | {theirs} |")
            differ = sum(not status.startswith("identical") for status, _, _ in rows)
            if differ:
                # What the executor printed, as the job's log shows nothing else of it.
                print(f"--- {step['id']} {phase}: pwsh exit code {done.returncode}")
                print((done.stdout + done.stderr).decode("utf-8", "replace"))
            failed += differ
    verdict = "every vector is identical" if not failed else f"{failed} vectors differ"
    text = "\n".join([f"### Atomic argument vectors against Invoke-AtomicRedTeam: {verdict}", "", *table, ""])
    print(text)
    if options.summary:
        with open(options.summary, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
