"""Command line of the lab: run, evaluate, combine, report, compare."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import combine, compare, evaluate, report, run, target


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bluefire-lab", description=__import__("bluefire_lab").__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    running = commands.add_parser("run", help="run the pinned tests on this machine, a disposable CI runner")
    running.add_argument("--tests", type=Path, required=True, help="the list of pinned tests")
    running.add_argument("--atomics", type=Path, required=True, help="atomics folder of Atomic Red Team")
    running.add_argument("--executor", type=Path, required=True, help="checkout of Invoke-AtomicRedTeam")
    running.add_argument("--sensor-config", type=Path, required=True, help="Sysmon configuration file")
    running.add_argument("--audit-rules", type=Path, required=True, help="the lab's own auditd rules")
    running.add_argument(
        "--instrument",
        type=Path,
        required=True,
        help="the auditd rules the lab itself needs, loaded after whichever settings are under test",
    )
    running.add_argument(
        "--given-settings",
        type=Path,
        help="folder with sensor settings to test in place of the lab's own: sysmon.xml, audit.rules, or both",
    )
    running.add_argument("--account", default="bluefire-lab", help="unprivileged account the tests run as")
    running.add_argument("--out", type=Path, required=True, help="folder for run.json and sysmon.txt")

    running.add_argument(
        "--image",
        help="run the tests inside a container the lab starts from this image, on a network with no way out",
    )

    leashing = commands.add_parser(
        "leash", help="check that a container has no way out: its settings, and probes from its network"
    )
    leashing.add_argument("container", help="name of the container")
    leashing.add_argument("--network", required=True, help="the one network the container may be on")

    evaluating = commands.add_parser("evaluate", help="compute results.json from the files of a run")
    evaluating.add_argument(
        "folder",
        type=Path,
        help="folder with run.json, sysmon.txt and rules/, or a folder that holds one such folder for each runner",
    )
    evaluating.add_argument("--engine", type=Path, required=True, help="the Zircolite program")

    combining = commands.add_parser(
        "combine", help="give one answer for every test from the results of several runners"
    )
    combining.add_argument(
        "folder", type=Path, help="folder that holds one folder with results.json for each runner"
    )

    reporting = commands.add_parser("report", help="write report.html and summary.md from results.json")
    reporting.add_argument("folder", type=Path, help="folder with results.json")

    comparing = commands.add_parser("compare", help="say which answers changed since an earlier run, and why")
    comparing.add_argument("before", type=Path, help="folder with the earlier run's results.json")
    comparing.add_argument(
        "after", type=Path, help="folder with the later run's results.json; gets compare.md"
    )

    options = parser.parse_args(arguments)
    if options.command == "run":
        # Attack tests run only where the machine is thrown away afterwards.
        if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
            parser.error(
                "this machine is not a GitHub-hosted runner, and the tests are real attack tests: "
                "start the lab workflow instead (see lab/README.md)"
            )
        return run.main(
            options.tests,
            options.atomics,
            options.executor,
            options.sensor_config,
            options.out,
            options.account,
            options.audit_rules,
            options.instrument,
            options.given_settings,
            options.image,
        )
    if options.command == "leash":
        found = target.leash({"container": options.container, "network": options.network, "read_only": []})
        for reason in found["refused"]:
            print(f"refused: {reason}")
        for probe in found["probes"]:
            outcome = "succeeded" if probe["succeeded"] else "failed"
            print(
                f"{'ok     ' if probe['held'] else 'WRONG  '} {probe['probe']}: {outcome}, expected: {probe['expected']}"
            )
        print(
            "the container is held" if found["held"] else "the container is NOT held: no test may run in it"
        )
        return 0 if found["held"] else 1
    if options.command == "evaluate":
        if (options.folder / "run.json").is_file():
            return evaluate.main(options.folder, options.engine)
        # The runs of several runners: evaluate each, then combine their answers.
        runs = sorted(path for path in options.folder.iterdir() if (path / "run.json").is_file())
        failed = [evaluate.main(path, options.engine) for path in runs]
        return max([combine.main(options.folder), *failed])
    if options.command == "combine":
        return combine.main(options.folder)
    if options.command == "compare":
        return compare.main(options.before, options.after)
    return report.main(options.folder)


if __name__ == "__main__":
    sys.exit(main())
