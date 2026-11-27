"""Command line of the lab: run, evaluate, report, recording, replay, compare, pair, atomic, range."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import atomic, compare, evaluate, pair, recording, replay, report, run
from .range import engine as range_engine
from .range import retained as range_retained


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

    paging = commands.add_parser(
        "replay", help="write the single replay page of a recording, from the app's page template"
    )
    paging.add_argument("recording", type=Path, help="the recording.json a run of the lab wrote")
    paging.add_argument(
        "--template", type=Path, required=True, help="the app's page template, bluefire/ui/replay.html"
    )
    paging.add_argument(
        "--out", type=Path, required=True, help="the page to write, a file that does not exist"
    )

    comparing = commands.add_parser(
        "compare", help="say what differs between two recordings, and whether one declared change explains it"
    )
    comparing.add_argument("before", type=Path, help="the recording.json of the run before the change")
    comparing.add_argument("after", type=Path, help="the recording.json of the run after it")
    comparing.add_argument("--out", type=Path, required=True, help="folder for delta.json and delta.md")
    comparing.add_argument(
        "--change",
        help="the one thing changed between the runs: sensors:<sensor id> for a sensor's settings, "
        "or detectors:<detector id> for a rule set, such as detectors:lab; leave out, or give it empty, "
        "when nothing was",
    )
    comparing.add_argument(
        "--two-runners",
        action="store_true",
        help="the two runs were made side by side in one CI run, each on a fresh runner of its own",
    )
    comparing.add_argument(
        "--one-run",
        action="store_true",
        help="the two recordings are of one run, its telemetry evaluated twice with two sets of the lab's "
        "rules; refused unless everything else in them is the same",
    )

    pairing = commands.add_parser(
        "pair",
        help="say whether the defense a run loads differs from the base commit's and how the change is "
        "shown: pair=no, rules (one run evaluated twice) or runs (two runs), the sides to run and the one "
        "change to declare, as name=value lines",
    )
    pairing.add_argument(
        "--base",
        type=Path,
        help="the lab folder of a checkout of the base commit; leave out when there is none",
    )
    pairing.add_argument("head", type=Path, help="the lab folder of the commit under test")

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
        "range",
        help="bring a range up from its spec file, seal it, run its path of published tests, and take it down",
    )
    actions = ranging.add_subparsers(dest="action", required=True)
    bringing = actions.add_parser(
        "run",
        help="create the range, prove it is sealed, run the spec's path of published tests inside it when the "
        "spec has one and score what the defense saw, then take it down again (exit 1: refused, not ready, an "
        "engine error or plants not in place; 3: the seal failed; 4: the run was made invalid)",
    )
    bringing.add_argument(
        "spec", type=Path, help="the range's spec file, for example lab/range/seal-check.yaml"
    )
    bringing.add_argument(
        "--out",
        type=Path,
        required=True,
        help="new folder for seal.json and manifest.json; with a defense also score.md, and with a path "
        "path.md and, when it can be written, recording.json",
    )
    bringing.add_argument(
        "--hold",
        type=float,
        default=0,
        help="seconds to keep the sealed range up after the path, before the seal is checked again",
    )
    bringing.add_argument(
        "--plant",
        choices=range_engine.PLANTS,
        help="plant one break, to show that the seal catches it; the run then fails",
    )
    bringing.add_argument(
        "--engine",
        type=Path,
        help="the Zircolite program: with it, the rule sets of the spec's defenses judge the run after it; "
        "without it those defenses are not judged, and score.md says so",
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
    locking = actions.add_parser(
        "lock",
        help="fetch the published files the spec's hosts carry and the files of its public rule sets, each at "
        "its commit, and write their SHA-256 to the spec's locks",
    )
    locking.add_argument("spec", type=Path, help="the range's spec file")
    fetching = actions.add_parser(
        "rules",
        help="fetch a spec's public rule sets by their lock into a folder's rules/, as a run does into its own, "
        "so that a run folder made without them can be judged by them",
    )
    fetching.add_argument("spec", type=Path, help="the range's spec file")
    fetching.add_argument("--out", type=Path, required=True, help="the folder to fetch into, a run's folder")
    scoring = actions.add_parser(
        "score",
        help="write a run folder's ECS lines, score and recording.json again from its own files; "
        "starts nothing",
    )
    scoring.add_argument("folder", type=Path, help="the folder a run of `range run` wrote")
    scoring.add_argument(
        "--engine",
        type=Path,
        help="the Zircolite program, which evaluates the rule sets in the run's folder; without it the "
        "defenses that run them are not judged",
    )
    scoring.add_argument(
        "--defenses",
        type=Path,
        help="a spec file whose defenses and rule sets judge the run in place of those of the spec it ran, "
        "as for a run made before its spec named any",
    )
    rejudging = actions.add_parser(
        "rejudge",
        help="verify a retained CI run, copy its raw files, judge the copy by another spec, and write replay.html",
    )
    rejudging.add_argument("retained", type=Path, help="folder with provenance.json and the retained files")
    rejudging.add_argument(
        "--defenses", type=Path, required=True, help="spec whose defenses and rule sets judge the copied run"
    )
    rejudging.add_argument(
        "--engine", type=Path, help="the Zircolite program; required when the judging spec has rule sets"
    )
    rejudging.add_argument(
        "--template", type=Path, required=True, help="the app's page template, bluefire/ui/replay.html"
    )
    rejudging.add_argument(
        "--out", type=Path, required=True, help="new folder for the rejudged run and replay"
    )

    options = parser.parse_args(arguments)
    if options.command == "range":
        if options.action == "down":
            return range_engine.down(options.spec)
        if options.action == "score":
            return range_engine.rescore(options.folder, options.engine, options.defenses)
        if options.action == "rejudge":
            return range_retained.rejudge(
                options.retained, options.defenses, options.out, options.template, options.engine
            )
        if options.action == "render":
            return range_engine.render(options.spec, options.out)
        if options.action == "lock":
            return range_engine.lock(options.spec)
        if options.action == "rules":
            return range_engine.rules(options.spec, options.out)
        return range_engine.run(options.spec, options.out, options.plant, options.hold, options.engine)
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
        if options.one_run and options.two_runners:
            parser.error("--one-run and --two-runners say two different things: give one of them")
        return compare.main(
            options.before,
            options.after,
            options.out,
            options.change or None,
            options.two_runners,
            options.one_run,
        )
    if options.command == "pair":
        return pair.main(options.base, options.head)
    if options.command == "recording":
        return recording.main(options.folder, options.run_url, options.tests)
    if options.command == "replay":
        return replay.main(options.recording, options.template, options.out)
    return report.main(options.folder)


if __name__ == "__main__":
    sys.exit(main())
