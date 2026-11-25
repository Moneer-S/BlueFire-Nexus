# Documentation

These are the documents of BlueFire Nexus: how to watch a recorded attack run, how to see what a change to the defense did, how the runs are made on real machines, and how to install and use the rest of the workspace.

## Watch a run

- [The live view](LIVE_VIEW.md): what the player shows for each step of a run, what it never shows, its two modes and its keys.
- [Recorded runs in the app](USER_GUIDE.md#recorded-runs): the Runs screen, how to open a recorded run, its address, and how to import a recording.
- [The attack path's page](live-view/attack-path.html): the attack path through a network of seven hosts, in a single HTML file. Download it and open it in any browser, offline.
- [The replay page](live-view/replay.html): the run of published tests on one Linux machine, in a single HTML file, opened the same way.
- [The run on the front page](LIVE_VIEW.md#the-run-on-the-front-page): what that attack path was and where it was made, and [the run on one Linux machine](LIVE_VIEW.md#the-run-on-one-linux-machine).

## Change a defense and see before and after

- [Before against after in the app](USER_GUIDE.md#recorded-runs): the pairs of runs the app lists, and what the page of a pair shows.
- [The defender loop](../lab/README.md#the-defender-loop-so-far): the one unseen test, followed through a sensor change and then a new rule.
- [A pair of runs for a change to the defense](../lab/README.md#a-pair-of-runs-for-a-change-to-the-defense): how a pull request that changes a sensor's settings gets a fresh run before and after.
- [One run evaluated with two rule sets](../lab/README.md#a-change-of-the-labs-rules-one-run-evaluated-twice): how a change to the lab's own rules is shown without running the tests again.

## How the real runs are made

- [The lab](../lab/README.md): runs published attack tests on a throwaway machine, records what its sensors saw, and evaluates published rules over that.
- [The range](../lab/README.md#a-range-and-its-seal): a small network of throwaway containers with no route out, and how the lab proves it is sealed.
- [Range one](../lab/README.md#range-one-its-hosts): a shop's servers, its ordinary work, and a path of published tests through them.
- [The recording](RECORDING.md): the format of the one file that holds a run, and of the comparison of two runs.

## Use the workspace

- [The tour](WORKSPACE.md): building an experiment, following its run, testing a defense, improving a detection, and working with a model.
- [The operator guide](OPERATOR_GUIDE.md): one experiment from first edit to Simulate, Execute, a detection and a replay, step by step.
- [Detection Lab](DETECTION_LAB.md): writing and testing detection rules against what a run observed.
- [Replay and compare](REPLAY_COMPARE.md): running an experiment again with one change, and comparing the results.
- [The assistant](contextual-assistance.md): what the assistant can do from the saved work you selected, and how to start and stop it.

## Install and run it

- [Install](INSTALLATION.md): look at the source with Docker, or install a published package and open the app.
- [The user guide](USER_GUIDE.md): starting the app and using each of its screens.
- [Troubleshooting](TROUBLESHOOTING.md): what to do when the app will not open, a run cannot start, evidence is missing or cleanup fails.

## Reference

- [Command line](CLI.md): every `bluefire` command.
- [API](API.md): the local HTTP API behind the app and the command line.
- [Configuration](CONFIGURATION.md): the two modes, runner profiles, and where secrets and settings are kept.
- [Architecture](ARCHITECTURE.md): how planning is kept apart from the part that acts on a machine.

## What is in scope

- [Scope](SCOPE.md): what BlueFire Nexus covers, what it does not, and its license.
- [Responsible use](RESPONSIBLE_USE.md): use it only on systems you own or may test, and what to settle before an experiment.
- [Threat model](THREAT_MODEL.md): what the design protects against, and how.

## Everything else

The rest of the folder is reference for single features:

- Running experiments: [the two modes](EXECUTION_MODEL.md), [writing behaviors and scenarios](BEHAVIOR_AUTHORING.md), [letting a step choose among reviewed methods](ADAPTIVE_EXECUTION.md), [what a runner may do](RUNNER_PROFILES.md), [installing the runner](RUNNER_DEPLOYMENT.md), [time limits of a managed runner](managed-runner-deadlines.md), [reading a file right after the step that wrote it](managed_filesystem_observation.md), [where each record comes from](EVIDENCE_MODEL.md), [downloading a run](RUN_EXPORTS.md), [carrying a result into the next attempt](RETAINED_RESULTS.md), [new attempts within an installed set of methods](capability-composition.md), [which build is running](build-identity.md).
- The assistant and models: [how a model's proposals are used](AI_PLANNER.md), [allowing data to go to a model](AI_PROVIDER_AUTHORIZATION.md), [reaching a model from a prepared lab](AI_BROKER_ACCESS.md), [one workflow from question to retest](AI_FIRST_PROGRAM.md), [running a saved experiment with the assistant](assisted-runs.md), [proposals for an experiment's steps](contextual-graph-assistance.md), [a first rule from a completed run](initial-detection-creation.md), [the assistant in a receiver test](receiver-assistance-contract.md), [comparing two methods of one step](ai_method_comparison.md).
- Detections: [evaluating a rule over a finished run](detection_run_evaluations.md).
- Single methods and tools: [changing file permissions](ATOMIC_CHMOD.md), [collecting files with gzip](ATOMIC_GZIP.md), [how outside tools are wired in](TOOL_ADAPTERS.md), [which installed tool a method uses](NATIVE_TOOL_INSTALLATIONS.md), [the tool builds the runner accepts](REVIEWED_NATIVE_BUILDS.md), [inspecting an installed service](OWNED_SERVICE_INSTALLATIONS.md), [groundwork for a user service](OWNED_USER_SERVICES.md), [observing collected records](collection_semantics_observer.md), [collection with and without redaction](compatible_collection_experiment.md).
- Single workspaces: [testing a receiver's redaction policy](receiver-control-test.md), [the receiver's content policy](receiver_content_policy.md), [a file share on a Windows server](AD_SMB_ACCESS.md), [hardening access to an S3 object](S3_ACCESS.md), [the S3 access workspace](s3-access-review.md), [file access on macOS](MACOS_FILE_ACCESS.md), [file access on Windows](WINDOWS_FILE_ACCESS_BASELINE.md), [a Linux lab prepared from Windows](PREPARED_LINUX_LAB.md).
- Extending it: [plugins and action packages](EXTENSIONS.md), [the plugin manifest](PLUGIN_SDK.md), [the action contracts](ACTION_SDK.md), [taking in public security projects](SOURCE_INTAKE.md).
- The project: [working on the code](DEVELOPMENT.md), [moving from the old Python modules](MIGRATION.md), [what the release ships](RELEASE_CAPABILITIES.md), [an earlier map of the product](PRE_RELEASE_BASELINE.md), [suggested text for the GitHub page](GITHUB_METADATA.md).
