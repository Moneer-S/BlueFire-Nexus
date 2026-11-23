"""Command line of the lab: run, evaluate, report, recording, compare, atomic, range."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import atomic, compare, evaluate, recording, report, run
from .range import engine as range_engine


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bluefire-lab", description=__import__("bluefire_lab").__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    running = commands.add_parser("run", help="run the pinned tests on this machine, a disposable CI runner")
    running.add_argument("--tests", type=Path, required=True, help="the list of pinned tests")
    running.add_argument("--atomics", type=Path, required=True, help="atomics folder of Atomic Red Team")
    running.add_argument("--executor", type=Path, required=True, help="checkout of Invoke-AtomicRedTeam")
    running.add_argument("--sensor-config", type=Path, required=True, help="Sysmon configuration file")
    running.add_argument("--audit-rules", type=Path, help="auditd rules to load, so that auditd records too")
    running.add_argument("--account", default="bluefire-lab", help="unprivileged account the tests run as")
    running.add_argument("--out", type=Path, required=True, help="folder for run.json and sysmon.txt")

    evaluating = commands.add_parser("evaluate", help="compute results.json from the files of a run")
    evaluating.add_argument("folder", type=Path, help="folder with run.json, sysmon.txt and rules/")
    evaluating.add_argument("--engine", type=Path, required=True, help="the Zircolite program")

    reporting = commands.add_parser("report", help="write report.html and summary.md from results.json")
    reporting.add_argument("folder", type=Path, help="folder with results.json")

    replaying = commands.add_parser(
        "recording", help="write recording.json, the run as one file that can be replayed"
    )
    replaying.add_argument("folder", type=Path, help="folder with run.json and results.json")
    replaying.add_argument("--run-url", help="address of the CI run that made the files")
    replaying.add_argument(
        "--tests", type=Path, help="the list of pinned tests, for a run made before it recorded plain words"
    )

    comparing = commands.add_parser("compare", help="say which answers changed since an earlier run, and why")
    comparing.add_argument("before", type=Path, help="folder with the earlier run's results.json")
    comparing.add_argument(
        "after", type=Path, help="folder with the later run's results.json; gets compare.md"
    )

    atomic_tests = commands.add_parser("atomic", help="read published Atomic Red Team tests as upstream does")
    atomic_commands = atomic_tests.add_subparsers(dest="atomic_command", required=True)
    vectors = atomic_commands.add_parser(
        "argv", help="write the argument vectors upstream starts for every step of a range's path"
    )
    vectors.add_argument("spec", type=Path, help="the range's spec file, such as lab/range/range-one.yaml")
    vectors.add_argument(
        "--atomics", type=Path, required=True, help="atomics folder of Atomic Red Team at the spec's commit"
    )
    vectors.add_argument("--out", type=Path, required=True, help="the JSON file to write")

    ranging = commands.add_parser(
        "range", help="bring a range up from its spec file, seal it, and take it down"
    )
    actions = ranging.add_subparsers(dest="action", required=True)
    bringing = actions.add_parser(
        "run", help="create the range, prove it is sealed, and take it down again (exit 3: the seal failed)"
    )
    bringing.add_argument(
        "spec", type=Path, help="the range's spec file, for example lab/range/seal-check.yaml"
    )
    bringing.add_argument(
        "--out", type=Path, required=True, help="new folder for seal.json and manifest.json"
    )
    bringing.add_argument(
        "--hold",
        type=float,
        default=0,
        help="seconds to keep the sealed range up where the path will run, before the seal is checked again",
    )
    bringing.add_argument(
        "--plant",
        choices=range_engine.PLANTS,
        help="plant one break, to show that the seal catches it; the run then fails",
    )
    removing = actions.add_parser(
        "down",
        help="remove the containers and networks that carry both the spec's prefix and its range label",
    )
    removing.add_argument("spec", type=Path, help="the range's spec file")
    rendering = actions.add_parser(
        "render", help="write the Dockerfile and bake file that build the range's images, and build nothing"
    )
    rendering.add_argument("spec", type=Path, help="the range's spec file")
    rendering.add_argument("--out", type=Path, required=True, help="folder for the build context")

    options = parser.parse_args(arguments)
    if options.command == "range":
        if options.action == "down":
            return range_engine.down(options.spec)
        if options.action == "render":
            return range_engine.render(options.spec, options.out)
        return range_engine.run(options.spec, options.out, options.plant, options.hold)
    if options.command == "atomic":
        return atomic.write(options.spec, options.atomics, options.out)
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
        )
    if options.command == "evaluate":
        return evaluate.main(options.folder, options.engine)
    if options.command == "compare":
        return compare.main(options.before, options.after)
    if options.command == "recording":
        return recording.main(options.folder, options.run_url, options.tests)
    return report.main(options.folder)


if __name__ == "__main__":
    sys.exit(main())
