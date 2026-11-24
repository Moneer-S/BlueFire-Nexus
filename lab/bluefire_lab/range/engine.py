"""Bring a range up from its spec, seal it, watch it and take it down again.

The engine calls the plain Docker CLI and writes every flag itself. Every
object is addressed by the full ID Docker returned when the engine created it.
A watch on Docker's events runs from before the first create to the end of the
teardown, and any event on the range that the engine did not cause breaks the
seal. The run writes `seal.json`, `seal.md` and `manifest.json` on every exit
path, and takes the range down on every exit path after the first create.

The seal comes in phases. The static seal reads `docker inspect` of what the
engine created, before any container starts. Right after the start, before
the engine waits for anything in the range, the phase "no way out" proves from
inside each container that nothing can leave: routes, forwarding, no Docker
socket, the resolver, addresses outside that must not answer and the host
canary, with a positive control that needs no service of the range. Then the
ready gate waits for each host's services (and, for a range with a defense,
for the defense). The phase "segmentation" then adds the probes between the
hosts and the check of their listening ports, and repeats everything else.
The phase "after path" repeats it all where the path ends.

Hosts without a pinned image are built from the spec (see `build`). A range
with a defense also has the engine's
harmless marks before the path, and, on every exit path after the
start, the collection of what Wazuh recorded into `raw/`, the configuration
diff, the delivery counts and `defense.md`. A range with ordinary activity
starts its jobs after the plant checks and lets them run a warm-up before the
place of the path and a tail after it, then stops them; after the collection
it counts each job's runs and archive events into the manifest and
`activity.md`. A range with a path runs its published tests after the marks,
between the warm-up and the tail, and writes `path.md` (see `path`). Last,
every line of the manager's archive and alerts is written
as an ECS line, with its origin, into `events.ecs.ndjson` and
`alerts.ecs.ndjson`, and the ordinary day is scored into the manifest and
`score.md` (see `score`).

Exit codes: 0 the range was sealed and still was at the end; 1 refused before
anything was created, an engine error, or a range that was not ready in time
and whose seal held; 3 the seal failed before the place of the path: in the
static seal, before the ready gate (the engine had run nothing in the range
but its probes), after the ready gate (the ready gate's own checks had run), or
when the range was not ready; 4 the run was made invalid (the seal failed
after the point where the path runs, something the engine did not do happened
to the range, or the conversion to ECS failed).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import tarfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import activity, atomics, build, ossec, plants, score, seal, wazuh
from . import path as range_path
from .spec import Spec, SpecError, load

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_SEAL = 3
EXIT_INVALID = 4
MEMORY = "256m"
# The Wazuh manager needs about a gigabyte.
MEMORY_DEFENSE = "1g"
PIDS_LIMIT = "1024"
WATCH_SECONDS = 15
READY_SECONDS = 30
# For a range with a defense: the manager's ports, each agent connected with its real-time file
# monitoring started, the manager listing each agent, and a nonce from each agent host in the archive.
DEFENSE_READY_SECONDS = 180
MARK_SECONDS = 60
POLL_SECONDS = 1.0
BUILD_SECONDS = 3600
# Breaks planted on purpose, to show that the seal catches each one. A run with a plant always fails.
PLANTS = ("not-internal", "no-isolated-gateway", "published-port", "bind-mount")
# With this plant only, the run starts the containers although the static seal failed, so that
# the phase "no way out", before the ready gate, shows the host canary catching the same break.
# Its networks are internal.
GOES_ON = {"no-isolated-gateway": {"network: gateway mode"}}


class EngineError(RuntimeError):
    """A Docker command failed, or the engine was stopped."""


class NotReady(RuntimeError):
    """A part of the range was not ready in time; the message says which and what to look at."""


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def docker(*arguments: str, timeout: float = 300, check: bool = True) -> subprocess.CompletedProcess:
    try:
        done = subprocess.run(
            ["docker", *arguments],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as late:
        raise EngineError(f"docker {arguments[0]} took longer than {timeout} s") from late
    if check and done.returncode != 0:
        raise EngineError(f"docker {' '.join(arguments[:2])} failed: {done.stderr.strip()[:500]}")
    return done


def inspect(*arguments: str) -> list[dict]:
    return json.loads(docker(*arguments).stdout)


def inspect_present(*arguments: str) -> list[dict]:
    """Inspect objects that are not the range's own, leaving out any that vanished meanwhile.

    Docker prints the objects it found and exits non-zero when one of them is gone.
    """

    done = docker(*arguments, check=False)
    try:
        return json.loads(done.stdout or "[]")
    except ValueError as error:
        raise EngineError(f"docker {' '.join(arguments[:2])} failed: {done.stderr.strip()[:500]}") from error


def inspect_one(identifier: str) -> dict | None:
    try:
        found = inspect_present("inspect", identifier)
    except EngineError:
        return None
    return found[0] if found else None


def write_json(path: Path, data: object) -> None:
    """Write a file whole, so that a reader never sees half of it."""

    partial = path.with_name(path.name + ".partial")
    partial.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(partial, path)


def untar(stream, folder: Path) -> list[str]:
    """Write the folders and regular files of a tar stream under `folder`; return what was left out, and why.

    Nothing but a folder or a regular file is written, and no path leaves `folder`.
    """

    refused = []
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if not name.parts:
                continue
            if name.is_absolute() or ".." in name.parts:
                refused.append(f"{member.name}: a path outside the copy")
                continue
            target = folder.joinpath(*name.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isreg():
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as out:
                    shutil.copyfileobj(archive.extractfile(member), out)
            elif member.issym() or member.islnk():
                refused.append(f"{member.name}: a link to {member.linkname}")
            else:
                refused.append(f"{member.name}: not a regular file")
    return refused


class Watch:
    """Docker's events on the range, each matched to an action the engine announced.

    Before each action the engine announces the events it will cause. An event
    on a range object (by ID, or by a name with the prefix) that matches no
    announcement is a finding. So is the create or start of any other container
    that shares a namespace with a range container: `inspect` reads such a
    container's `docker inspect`, since its events do not name the range. While
    the range has containers, the create or start of any container that is gone
    before `inspect` could read it is a finding as well.
    """

    def __init__(self, prefix: str, raw: Path, inspect=inspect_one):
        self.prefix = prefix + "-"
        self.raw = raw
        self.containers: set[str] = set()
        self.networks: set[str] = set()
        self.allowed: list[dict] = []
        self.required: set[int] = set()
        self.findings: list[dict] = []
        self.events = 0
        self.alive = False
        self.lock = threading.Lock()
        self.process: subprocess.Popen | None = None
        self.counter = 0
        self.inspect = inspect
        # Each exec on a range container, by Docker's exec ID: its command and the daemon's times.
        self.execs: dict[str, dict] = {}

    def start(self, since: str) -> None:
        self.process = subprocess.Popen(
            [
                "docker",
                "events",
                "--since",
                since,
                "--format",
                "{{json .}}",
                "--filter",
                "type=container",
                "--filter",
                "type=network",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self.alive = True
        threading.Thread(target=self._read, daemon=True).start()

    def expect(self, kind: str, action: str, required: bool = False, **identity: str) -> None:
        with self.lock:
            self.counter += 1
            self.allowed.append({"token": self.counter, "type": kind, "action": action, **identity})
            if required:
                self.required.add(self.counter)

    def _relevant(self, event: dict) -> bool:
        actor = event.get("Actor") or {}
        attributes = actor.get("Attributes") or {}
        return (
            actor.get("ID") in self.containers | self.networks
            or attributes.get("container") in self.containers
            or attributes.get("name", "").startswith(self.prefix)
        )

    def _match(self, event: dict) -> bool:
        actor = event.get("Actor") or {}
        attributes = actor.get("Attributes") or {}
        matching = [
            index
            for index, allowed in enumerate(self.allowed)
            if allowed["type"] == event.get("Type")
            and allowed["action"] == event.get("Action")
            and allowed.get("id", actor.get("ID")) == actor.get("ID")
            and allowed.get("name", attributes.get("name")) == attributes.get("name")
            and allowed.get("container", attributes.get("container")) == attributes.get("container")
        ]
        if not matching:
            return False
        # An event that an announcement waits for is matched to it before one that may never come,
        # such as the end of a command that runs until the teardown.
        index = next((i for i in matching if self.allowed[i]["token"] in self.required), matching[0])
        self.required.discard(self.allowed[index]["token"])
        del self.allowed[index]
        return True

    def _record(self, event: dict) -> None:
        """Keep the daemon's time of an exec's start and end, and its command and exit code."""

        actor = event.get("Actor") or {}
        attributes = actor.get("Attributes") or {}
        action = event.get("Action") or ""
        exec_id = attributes.get("execID")
        if not exec_id or not (action.startswith("exec_start: ") or action == "exec_die"):
            return
        entry = self.execs.setdefault(exec_id, {"exec_id": exec_id, "container": actor.get("ID")})
        if action == "exec_die":
            entry["die"] = event.get("timeNano")
            entry["exit_code"] = attributes.get("exitCode")
        else:
            entry["command"] = action.removeprefix("exec_start: ")
            entry["start"] = event.get("timeNano")

    def exec_of(self, container: str, command: str, claimed: set[str]) -> dict | None:
        """The first exec on a container with this command whose start Docker reported, and not yet claimed."""

        with self.lock:
            for entry in self.execs.values():
                if (
                    entry["exec_id"] not in claimed
                    and entry.get("container") == container
                    and entry.get("command") == command
                ):
                    return dict(entry)
        return None

    def _finding(self, event: dict, **more) -> dict:
        actor = event.get("Actor") or {}
        attributes = actor.get("Attributes") or {}
        return {
            "time_nano": event.get("timeNano"),
            "type": event.get("Type"),
            "action": (event.get("Action") or "")[:200],
            "id": actor.get("ID"),
            "name": attributes.get("name"),
            "container": attributes.get("container"),
            **more,
        }

    def feed(self, lines) -> None:
        """Take Docker's events, one JSON object per line, and record what they show."""

        with self.raw.open("a", encoding="utf-8") as raw:
            for line in lines:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                with self.lock:
                    relevant = self._relevant(event)
                    if relevant:
                        raw.write(line)
                        raw.flush()
                        self.events += 1
                        self._record(event)
                        if not self._match(event):
                            self.findings.append(self._finding(event))
                        continue
                    targets = set(self.containers)
                if (
                    not targets
                    or event.get("Type") != "container"
                    or event.get("Action") not in ("create", "start")
                ):
                    continue
                inspected = self.inspect((event.get("Actor") or {}).get("ID", ""))
                # A container that is gone before the watch could read it might have joined a range
                # container's namespace: that cannot be ruled out, so it is a finding too.
                shared = (
                    seal.joins(inspected, targets) if inspected is not None else {"inspect": "gone before it"}
                )
                if shared:
                    with self.lock:
                        raw.write(line)
                        raw.flush()
                        self.events += 1
                        self.findings.append(self._finding(event, joins=shared))

    def _read(self) -> None:
        assert self.process and self.process.stdout
        self.feed(self.process.stdout)
        self.alive = False

    def settle(self, seconds: float = WATCH_SECONDS) -> list[str]:
        """Wait until every event the engine required has been reported; return those still missing."""

        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            with self.lock:
                if not self.required:
                    return []
            time.sleep(0.1)
        with self.lock:
            return [
                f"{a['type']} {a['action'][:80]} {a.get('id') or a.get('name')}"
                for a in self.allowed
                if a["token"] in self.required
            ]

    def check(self, command: str) -> dict:
        missing = self.settle()
        with self.lock:
            findings = list(self.findings)
            observed = {
                "events": self.events,
                "not caused by the engine": findings,
                "not reported by Docker in time": missing,
                "watching": self.alive,
            }
        return seal.check(
            "event watch",
            "range",
            command,
            observed,
            "every event on the range caused by the engine",
            self.alive and not findings and not missing,
        )

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()


class Canary:
    """A TCP listener on the Docker host, for the seal's duration: any connection to it breaks the seal."""

    def __init__(self):
        self.peers: list[str] = []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("0.0.0.0", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self) -> None:
        while not self.stopped.is_set():
            try:
                connection, peer = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.peers.append(peer[0])
            connection.close()

    def close(self) -> list[str]:
        self.stopped.set()
        self.thread.join(timeout=5)
        self.listener.close()
        return list(self.peers)


class Run:
    def __init__(self, spec: Spec, spec_name: str, out: Path, plant: str | None, hold: float):
        self.spec = spec
        self.out = out
        self.plant = plant
        self.hold = hold
        self.run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
        self.networks: dict[str, str] = {}
        self.containers: dict[str, str] = {}
        self.images: dict[str, dict] = {}
        self.phases: list[dict] = []
        self.created = False
        self.started = False
        self.started_at = time.monotonic()
        self.rootless = False
        self.platform = "linux/amd64"
        # Per built host: the image its Dockerfile pins by digest, and that image's layers.
        self.parents: dict[str, dict] = {}
        self.tails: list[subprocess.Popen] = []
        # Per agent host: the nonces it logged, and the line counts of its logs read just before each.
        self.nonces: dict[str, dict[str, str]] = {}
        self.windows: dict[str, dict[str, dict[str, int]]] = {}
        # The path of published tests, read once its technique YAMLs are fetched and checked.
        self.plan: range_path.Plan | None = None
        self.watch = Watch(spec.prefix, out / "docker-events.ndjson")
        github = os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        run_url = None
        if github and all(
            os.environ.get(k) for k in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID")
        ):
            run_url = "{}/{}/actions/runs/{}".format(
                os.environ["GITHUB_SERVER_URL"], os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_RUN_ID"]
            )
        self.manifest: dict = {
            "range": spec.range,
            "version": spec.version,
            "prefix": spec.prefix,
            "run_id": self.run_id,
            "spec": {"file": spec_name, "sha256": spec.sha256, "text": spec.text},
            "environment": "GitHub-hosted runner" if github else "containers on a developer machine",
            "run_url": run_url,
            "plant": plant,
            "hold_seconds": hold,
            "docker": {},
            "build": None,
            "images": {},
            "networks": {},
            "containers": {},
            "ready": {},
            "defense": None,
            "atomic_red_team": None,
            "weaknesses": plants.weaknesses(spec),
            "plants": None,
            "path": None,
            "result": "incomplete",
            "reason": None,
            "exit_code": None,
            "teardown": [],
            "engine_clock": {
                "started": now(),
                "ended": None,
                "note": "the engine's own clock; no result uses it",
            },
        }
        if spec.wazuh:
            self.manifest["defense"] = {
                # The pinned version; the seal checks the version the manager and each agent report.
                "wazuh_version": spec.wazuh.version,
                "manager_image": spec.wazuh.manager_image,
                "agent_deb": {"version": spec.wazuh.agent_version, "sha512": spec.wazuh.agent_sha512},
                "alert_level": spec.wazuh.alert_level,
                "alert_level_note": (
                    "the level from which a Wazuh alert counts as an alert when a step is scored; the manager "
                    "keeps the stock log_alert_level 3, so alerts.json also holds the matches below it"
                ),
                "off": list(spec.wazuh.off),
                "snoopy_decoder_sha256": hashlib.sha256(build.SNOOPY_DECODER.encode()).hexdigest(),
                "manager": spec.manager,
                "agents": spec.agents,
                "configuration": {},
                "manager_files": list(build.MANAGER_FILES),
                "ready": {},
                "marks": [],
                "snoopy_tag": None,
                "delivery": {},
                "delivery_gap": None,
                "drops": {},
                "live": {
                    "files": ["live/archives.json", "live/alerts.json"],
                    "note": "followed while the run lasts, for a live view; no result is computed from them",
                },
            }
        # The archive and alerts as ECS lines, and the ordinary day's score: written after the collection.
        self.manifest["ecs"] = None
        self.manifest["score"] = None
        self.manifest["activity"] = None
        if spec.activity:
            self.manifest["activity"] = {
                "seed": spec.activity.seed,
                "warmup_seconds": spec.activity.warmup_seconds,
                "tail_seconds": spec.activity.tail_seconds,
                "schedule": activity.schedule(spec.activity),
                # Container times, from the command that wrote or removed the go on each host.
                "go": {},
                "stop": {},
                "started": None,
                "minutes": None,
                "jobs": {},
                "note": (
                    "runs are counted from the logs of the host each job acts on, archived runs from those "
                    "lines in the archive, and archive events by the job's tag, its host's address, its "
                    "account and the files it writes, from the go to the stop of its host and "
                    f"{activity.GRACE} s after; an event counts for one job at most, and the engine's mark "
                    "files for none; cron's session lines of a cron job's account are counted apart"
                ),
            }

    # Outputs

    def write(self) -> None:
        write_json(self.out / "manifest.json", self.manifest)
        record = {
            "range": self.spec.range,
            "run_id": self.run_id,
            "plant": self.plant,
            # True only for a run that ended sealed: never while it runs, and never for a run that was
            # stopped, made invalid or ended in an error after its recorded phases had passed.
            "passed": self.manifest["result"] == "sealed" and all(phase["passed"] for phase in self.phases),
            "phases": self.phases,
            "watch": {"events": self.watch.events, "findings": list(self.watch.findings)},
        }
        write_json(self.out / "seal.json", record)
        (self.out / "seal.md").write_text(summary(record, self.manifest), encoding="utf-8")
        if self.manifest["defense"] is not None:
            (self.out / "defense.md").write_text(
                wazuh.summary(self.manifest, record["passed"]), encoding="utf-8"
            )
        if self.manifest["weaknesses"] or self.manifest["plants"] or self.manifest["ready"].get("plants"):
            (self.out / "plants.md").write_text(plants.summary(self.manifest), encoding="utf-8")
        if self.manifest["activity"] is not None:
            (self.out / "activity.md").write_text(activity.summary(self.manifest), encoding="utf-8")
        if self.manifest["path"] is not None:
            (self.out / "path.md").write_text(range_path.summary(self.manifest), encoding="utf-8")
        if self.manifest["ecs"] is not None:
            (self.out / "score.md").write_text(score.summary(self.manifest), encoding="utf-8")

    def phase(self, name: str, checks: list[dict]) -> bool:
        self.phases.append({"phase": name, "passed": seal.passed(checks), "checks": checks})
        self.write()
        return seal.passed(checks)

    # The sequence

    def preflight(self) -> None:
        version = json.loads(docker("version", "--format", "{{json .}}").stdout)
        server = (version.get("Server") or {}).get("Version", "")
        info = json.loads(docker("info", "--format", "{{json .}}").stdout)
        self.rootless = any("name=rootless" in option for option in info.get("SecurityOptions") or [])
        endpoint = os.environ.get("DOCKER_HOST")
        if not endpoint:
            contexts = json.loads(docker("context", "inspect").stdout)
            endpoint = ((contexts[0].get("Endpoints") or {}).get("docker") or {}).get("Host", "")
        scheme = endpoint.split("://", 1)[0] if "://" in endpoint else ""
        self.platform = "{}/{}".format(
            (version.get("Server") or {}).get("Os") or "linux",
            (version.get("Server") or {}).get("Arch") or "amd64",
        )
        self.manifest["docker"] = {
            "server": server,
            "platform": self.platform,
            "api": (version.get("Server") or {}).get("ApiVersion"),
            "rootless": self.rootless,
            "endpoint": scheme,
            # Whether the daemon confines containers with AppArmor (name=apparmor) shows here.
            "security_options": info.get("SecurityOptions") or [],
        }
        try:
            major = int(server.split(".")[0])
        except ValueError:
            major = 0
        if major < self.spec.min_engine:
            raise SpecError(
                f"Docker Engine {server or 'unknown'} is older than {self.spec.min_engine}, which the range needs"
            )
        if scheme not in ("unix", "npipe"):
            raise SpecError(
                f"the Docker endpoint is {scheme or 'unknown'}://, and a range runs only on a local engine "
                "(unix:// or npipe://)"
            )
        stale = self.prefixed()
        if stale:
            names = ", ".join(sorted(name for _, name in stale))
            raise SpecError(
                f"objects named with {self.spec.prefix}- exist already ({names}): remove them with "
                f"bluefire-lab range down <spec>"
            )

    def prefixed(self) -> list[tuple[str, str]]:
        pattern = f"name={self.spec.prefix}-"
        found = []
        for line in docker(
            "ps", "-a", "--no-trunc", "--filter", pattern, "--format", "{{.ID}}\t{{.Names}}"
        ).stdout.splitlines():
            identifier, _, name = line.partition("\t")
            if name.startswith(self.spec.prefix + "-"):
                found.append((identifier, name))
        for line in docker(
            "network", "ls", "--no-trunc", "--filter", pattern, "--format", "{{.ID}}\t{{.Name}}"
        ).stdout.splitlines():
            identifier, _, name = line.partition("\t")
            if name.startswith(self.spec.prefix + "-"):
                found.append((identifier, name))
        return found

    def prepare_images(self) -> None:
        """Pull the pinned images, and build the others from the rendered spec unless all their tags exist.

        The path is read here, before any container exists: against the technique YAMLs the
        build fetched and checked, and refused for a spec that builds no host.
        """

        if not any(host.built for host in self.spec.hosts.values()):
            self.plan = range_path.plan(self.spec, None)
        for host in self.spec.hosts.values():
            if host.built:
                continue
            reference = host.image
            if docker("image", "inspect", reference, check=False).returncode != 0:
                docker("pull", "--quiet", reference, timeout=900)
            image = inspect("image", "inspect", reference)[0]
            self.images[host.name] = {"reference": reference, "id": image["Id"], "digest": host.digest}
        if any(host.built for host in self.spec.hosts.values()):
            rendered = build.render(self.spec, self.out / "build")
            self.plan = range_path.plan(self.spec, rendered.folder)
            if self.spec.atomics and self.spec.atomics.lock:
                locked = atomics.read_lock(
                    atomics.lock_path(self.spec).read_text(encoding="utf-8"), self.spec
                )
                self.manifest["atomic_red_team"] = {
                    "repo": self.spec.atomics.repo,
                    "commit": self.spec.atomics.commit,
                    "lock": locked,
                    "note": "every file was fetched at the commit and had the lock's SHA-256; the images carry the "
                    "src folders and served files as data, and no build step runs published text",
                }
            layers_of: dict[str, list[str]] = {}
            for host in rendered.tags:
                image = self.spec.wazuh.manager_image if self.spec.hosts[host].kind == "defense" else None
                image = image or self.spec.base.image
                if image not in layers_of:
                    layers_of[image] = self.registry_layers(image)
                self.parents[host] = {"image": image, "layers": layers_of[image]}

            def present(host: str, tag: str) -> bool:
                # A tag counts only on an image built on the pinned image; any other is built again.
                done = docker("image", "inspect", tag, check=False)
                if done.returncode != 0:
                    return False
                layers = (json.loads(done.stdout)[0].get("RootFS") or {}).get("Layers") or []
                return seal.built_on(layers, self.parents[host]["layers"])

            missing = [tag for host, tag in rendered.tags.items() if not present(host, tag)]
            started = time.monotonic()
            if missing:
                print(f"building {', '.join(missing)} with docker buildx bake", flush=True)
                try:
                    done = subprocess.run(
                        ["docker", "buildx", "bake", "--file", build.BAKE, "--load"],
                        cwd=rendered.folder,
                        timeout=BUILD_SECONDS,
                        check=False,
                    )
                except subprocess.TimeoutExpired as late:
                    raise EngineError(f"the image build took longer than {BUILD_SECONDS} s") from late
                if done.returncode != 0:
                    raise EngineError(
                        f"docker buildx bake failed with exit code {done.returncode}: its output is above"
                    )
            self.manifest["build"] = {
                "folder": "build",
                "context_sha256": rendered.digest,
                "built_now": bool(missing),
                "seconds": round(time.monotonic() - started, 1),
                "note": "an image found under the tag of this build context, built on the pinned image, is not "
                "built again: the lab trusts that the local image under that tag was built from the context",
            }
            for host, tag in rendered.tags.items():
                image = inspect("image", "inspect", tag)[0]
                self.images[host] = {
                    "tag": tag,
                    "id": image["Id"],
                    "built_on": self.parents[host]["image"],
                    "built_on_layers": len(self.parents[host]["layers"]),
                }
                if not seal.built_on(
                    (image.get("RootFS") or {}).get("Layers") or [], self.parents[host]["layers"]
                ):
                    raise EngineError(
                        f"the image built under {tag} is not built on {self.parents[host]['image']}"
                    )
        self.manifest["images"] = self.images
        self.write()

    def registry_layers(self, image: str) -> list[str]:
        """The layers of a pinned image for the daemon's platform, read from its registry without pulling it."""

        done = docker(
            "buildx", "imagetools", "inspect", image, "--format", "{{json .Image}}", timeout=120, check=False
        )
        try:
            config = json.loads(done.stdout)
        except ValueError:
            config = None
        if isinstance(config, dict) and "rootfs" not in config:
            config = config.get(self.platform)
        layers = ((config or {}).get("rootfs") or {}).get("diff_ids") if isinstance(config, dict) else None
        if done.returncode != 0 or not layers:
            raise EngineError(
                f"could not read the layers of {image} for {self.platform} from its registry: "
                f"{done.stderr.strip()[:300]}"
            )
        return layers

    def create_networks(self) -> None:
        for network in self.spec.networks:
            name = self.spec.network_name(network)
            flags = ["--driver", "bridge"]
            if self.plant != "not-internal":
                flags.append("--internal")
            # Docker refuses the isolated gateway mode on a network that is not internal.
            if self.plant not in ("not-internal", "no-isolated-gateway"):
                flags += ["-o", f"{seal.GATEWAY_MODE}=isolated"]
            self.watch.expect("network", "create", required=True, name=name)
            self.created = True
            identifier = docker("network", "create", *flags, *self.labels(), name).stdout.strip()
            self.networks[network] = identifier
            self.watch.networks.add(identifier)
            inspected = inspect("network", "inspect", identifier)[0]
            subnets = [entry.get("Subnet") for entry in (inspected.get("IPAM") or {}).get("Config") or []]
            self.manifest["networks"][network] = {"name": name, "id": identifier, "subnets": subnets}
        self.write()

    def labels(self) -> list[str]:
        return [
            "--label",
            f"{seal.LABEL_RUN}={self.run_id}",
            "--label",
            f"{seal.LABEL_RANGE}={self.spec.range}",
        ]

    def create_containers(self) -> None:
        first = next(iter(self.spec.hosts))
        for host in self.spec.hosts.values():
            name = self.spec.container_name(host.name)
            image_id = self.images[host.name]["id"]
            # Hosts built from base run a plain start script, so a small init reaps their processes.
            # The manager keeps its image's own init.
            init = ["--init"] if host.built and host.kind != "defense" else []
            planted = []
            if host.name == first and self.plant == "published-port":
                planted = ["-p", f"127.0.0.1::{host.listens[0] if host.listens else 80}"]
            if host.name == first and self.plant == "bind-mount":
                source = (self.out / "plant-mount").resolve()
                source.mkdir(exist_ok=True)
                planted = ["--mount", f"type=bind,source={source},target=/plant,readonly"]
            self.watch.expect("container", "create", required=True, name=name)
            self.created = True
            identifier = docker(
                "create",
                "--pull",
                "never",
                "--name",
                name,
                "--hostname",
                host.name,
                *self.labels(),
                "--network",
                self.networks[host.networks[0]],
                "--network-alias",
                host.name,
                "--dns-search",
                ".",
                "--sysctl",
                "net.ipv4.ip_forward=0",
                "--pids-limit",
                PIDS_LIMIT,
                "--memory",
                MEMORY_DEFENSE if host.kind == "defense" else MEMORY,
                *init,
                *planted,
                image_id,
            ).stdout.strip()
            self.containers[host.name] = identifier
            self.watch.containers.add(identifier)
            for network in host.networks[1:]:
                docker("network", "connect", "--alias", host.name, self.networks[network], identifier)
            self.manifest["containers"][host.name] = {"name": name, "id": identifier, "image_id": image_id}
        self.write()

    def start(self) -> None:
        """Start the containers, the manager first, so that agents find it."""

        hosts = sorted(self.spec.hosts.values(), key=lambda host: host.kind != "defense")
        for host in hosts:
            identifier = self.containers[host.name]
            for network in host.networks:
                self.watch.expect("network", "connect", id=self.networks[network], container=identifier)
            self.watch.expect("container", "start", required=True, id=identifier)
            self.started = True
            docker("start", identifier)
        self.started_at = time.monotonic()

    def execute(
        self, identifier: str, script: str, timeout: float, tag: str = "engine:seal", user: str = "root"
    ) -> subprocess.CompletedProcess:
        """Run a script of the engine's own in a range container, as root unless told, and announce its events.

        The process carries BLUEFIRE_TAG, so that snoopy's lines name it as the engine's.
        """

        if identifier not in self.containers.values():
            raise EngineError("the engine runs commands only in the range's own containers")
        action = f"bash -c {script}"
        self.watch.expect("container", f"exec_create: {action}", id=identifier)
        self.watch.expect("container", f"exec_start: {action}", id=identifier)
        self.watch.expect("container", "exec_die", required=True, id=identifier)
        return docker(
            "exec",
            "-u",
            user,
            "--env",
            f"BLUEFIRE_TAG={tag}",
            identifier,
            "bash",
            "-c",
            script,
            timeout=timeout,
            check=False,
        )

    def poll(self, host: str, script: str, deadline: float, tag: str = "engine:ready"):
        """Run a check of bash builtins in a host once a second until it exits 0; None when time ran out.

        Each try is a command of its own, so that no program but bash starts in the
        host and snoopy logs nothing for the checks. A check that exits 2 has seen
        something that waiting does not mend, and its result is returned at once.
        """

        while True:
            done = self.execute(self.containers[host], script, 30, tag)
            if done.returncode in (0, 2):
                return done
            if time.monotonic() + POLL_SECONDS > deadline:
                return None
            time.sleep(POLL_SECONDS)

    def ready(self) -> None:
        """Wait until each host's own service listens, so that the seal's controls can reach it.

        A range with a defense waits too until its defense is ready: see `defense_ready`.
        """

        budget = DEFENSE_READY_SECONDS if self.spec.wazuh else READY_SECONDS
        deadline = self.started_at + budget
        for host in self.spec.hosts.values():
            if not host.listens:
                continue
            ports = " ".join(str(port) for port in host.listens)
            script = f"for port in {ports}; do (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null || exit 1; done"
            done = self.poll(host.name, script, deadline)
            self.manifest["ready"][host.name] = {
                "listening": done is not None,
                "seconds": round(time.monotonic() - self.started_at, 1),
            }
            self.write()
            if done is None:
                what = (
                    f"look at raw/hosts/{host.name}/var/ossec/logs/ossec.log"
                    if host.kind == "defense"
                    else "look at the host's start script and its service logs under raw/hosts/"
                )
                raise NotReady(
                    f"host {host.name}: port {ports} did not answer within {budget} s of the start; {what}"
                )
        if self.spec.wazuh:
            self.defense_ready(deadline, budget)
        checks = self.run_checks(plants.ready_checks(self.spec), "engine:ready")
        self.manifest["ready"]["plants"] = checks
        self.write()
        failed = [f"{item['check']} ({item['subject']})" for item in checks if not item["pass"]]
        if failed:
            raise NotReady(
                f"{'; '.join(failed)}: see ready.plants in manifest.json for what each command printed"
            )

    def run_checks(self, checks: list[plants.Check], tag: str) -> list[dict]:
        """Run each plant check's commands in order, as its accounts, and judge what they printed."""

        results = []
        for item in checks:
            outputs = []
            for command in item.commands:
                done = self.execute(self.containers[command.host], command.script, 120, tag, command.user)
                outputs.append((done.returncode, done.stdout))
            observed, good = item.judge(outputs)
            where = "; ".join(f"{c.host} as {c.user}: {c.script}" for c in item.commands)
            results.append(seal.check(item.name, item.subject, where, observed, item.expected, good))
        return results

    def plant_checks(self) -> None:
        """Check, with the engine's own commands, that what the spec plants is in place the way the path needs it."""

        locked = (
            atomics.read_lock(atomics.lock_path(self.spec).read_text(encoding="utf-8"), self.spec)
            if (self.spec.atomics and self.spec.atomics.lock)
            else {}
        )
        addresses = {host: entry.get("addresses", {}) for host, entry in self.manifest["containers"].items()}
        results = self.run_checks(plants.checks(self.spec, locked, addresses), "engine:plant")
        self.manifest["plants"] = {
            "passed": all(item["pass"] for item in results),
            "checks": results,
            "note": "each check uses what is planted once, with the engine's own commands (tag engine:plant); "
            "none runs a published test",
        }
        self.write()

    def defense_ready(self, deadline: float, budget: int) -> None:
        """The ready gate of the defense, within the same budget as the ports.

        Each agent is connected and its real-time file monitoring has started; the
        manager lists each agent active at the pinned version; and a nonce the
        engine logs on each agent host reaches the manager's archives.json.
        """

        spec, manager = self.spec, self.spec.manager
        ready = self.manifest["defense"]["ready"]
        parts = ready.setdefault("parts", {})
        parts["manager ports"] = self.manifest["ready"][manager]["seconds"]
        errors = " ".join(f"'{error}'" for error in wazuh.REALTIME_ERRORS)
        agent_check = (
            f"log=$(< {wazuh.OSSEC_LOG}) || exit 1; "
            f'for error in {errors}; do [[ $log == *"$error"* ]] && exit 2; done; '
            f"state=$(< {wazuh.AGENT_STATE}) && [[ $state == *\"status='connected'\"* ]] && "
            f"[[ $log == *'{wazuh.REALTIME_STARTED}'* ]]"
        )
        for host in spec.agents:
            done = self.poll(host, agent_check, deadline)
            good = done is not None and done.returncode == 0
            parts[f"{host}: agent connected, real-time file monitoring started"] = (
                round(time.monotonic() - self.started_at, 1) if good else None
            )
            self.write()
            if done is not None and done.returncode == 2:
                raise NotReady(
                    f"the agent on {host} could not watch every folder in real time: its log has one of the "
                    f"errors {', '.join(e.strip() for e in wazuh.REALTIME_ERRORS)} (inotify could not start, or "
                    f"its watch limit was reached): look at raw/hosts/{host}/var/ossec/logs/ossec.log. On a "
                    "developer machine, raise fs.inotify.max_user_watches"
                )
            if done is None:
                raise NotReady(
                    f"the agent on {host} is not connected, or its real-time file monitoring has not started, "
                    f"within {budget} s: look at raw/hosts/{host}/var/ossec/logs/ossec.log and "
                    f"raw/hosts/{host}/var/ossec/var/run/wazuh-agentd.state"
                )
        listed: dict = {}
        while True:
            listed, outputs = self.listing("engine:ready")
            ready["agent_control"] = outputs
            good = all(
                (listed.get(host) or {}).get("status") == "Active"
                and (listed.get(host) or {}).get("version") == spec.wazuh.version
                for host in spec.agents
            )
            if good or time.monotonic() + POLL_SECONDS > deadline:
                break
            time.sleep(POLL_SECONDS)
        ready["manager lists"] = listed
        parts["manager lists every agent active at the pinned version"] = (
            round(time.monotonic() - self.started_at, 1) if good else None
        )
        self.write()
        if not good:
            raise NotReady(
                f"agent_control -l on the manager does not list every agent active at Wazuh {spec.wazuh.version} "
                f"within {budget} s (it lists {listed}): look at raw/hosts/{manager}/var/ossec/logs/ossec.log"
            )
        nonces = ready.setdefault("nonces", {})
        for host in spec.agents:
            nonce = f"bluefire-ready-{self.run_id}-{host}"
            logged = self.nonce(host, nonce, "ready", "engine:ready")
            found = self.wait_archived(nonce, host, "/var/log/auth.log", deadline)
            delay = round(wazuh.timestamp(found["timestamp"]) - logged, 3) if found and logged else None
            nonces[host] = {
                "nonce": nonce,
                "logged": logged,
                "archived": found["timestamp"] if found else None,
                "delay_seconds": delay,
            }
            self.write()
            if not found:
                raise NotReady(
                    f"the nonce logged on {host} did not reach the manager's archives.json within {budget} s: "
                    f"look at raw/hosts/{host}/var/log/auth.log, raw/hosts/{host}/var/ossec/logs/ossec.log and "
                    f"raw/hosts/{manager}/var/ossec/logs/ossec.log"
                )
        parts["a nonce from every agent host in the archive"] = round(time.monotonic() - self.started_at, 1)

    def listing(self, tag: str) -> tuple[dict, dict]:
        """What the manager's agent_control says now: each agent's ID, status and version, and the manager's own.

        The manager is listed under its host name, from `agent_control -i 000`.
        """

        identifier = self.containers[self.spec.manager]
        done = self.execute(identifier, "/var/ossec/bin/agent_control -l", 30, tag)
        listed = wazuh.agents(done.stdout)
        outputs = {"agent_control -l": done.stdout}
        for host in self.spec.agents:
            if (listed.get(host) or {}).get("status") == "Active":
                command = f"/var/ossec/bin/agent_control -i {listed[host]['id']}"
                info = self.execute(identifier, command, 30, tag)
                listed[host].update(wazuh.agent_info(info.stdout))
                outputs[f"agent_control -i {listed[host]['id']}"] = info.stdout
        info = self.execute(identifier, "/var/ossec/bin/agent_control -i 000", 30, tag)
        listed[self.spec.manager] = {"id": "000", **wazuh.agent_info(info.stdout)}
        outputs["agent_control -i 000"] = info.stdout
        return listed, outputs

    def nonce(self, host: str, nonce: str, which: str, tag: str) -> float | None:
        """Read the line counts of the host's watched logs, then log a nonce to syslog; return when.

        The time is the container's clock, which is the kernel's, like the
        manager's. The counts open and close the window of the delivery count.
        """

        logs = [log.path for log in self.spec.watch_for(host).logs]
        script = (
            f"for f in {' '.join(logs)}; do n=0; "
            'if [ -e "$f" ]; then while IFS= read -r line; do n=$((n+1)); done < "$f"; fi; '
            'printf \'lines\\t%s\\t%s\\n\' "$f" "$n"; done; '
            "printf 'time\\t%s\\n' \"$EPOCHREALTIME\"; "
            f"logger -p authpriv.info -t bluefire-{which} {nonce}"
        )
        done = self.execute(self.containers[host], script, 60, tag)
        if done.returncode != 0:
            raise EngineError(f"logging the {which} nonce on {host} failed: {done.stderr.strip()[:300]}")
        counts, logged = wazuh.window_counts(done.stdout)
        self.nonces.setdefault(host, {})[which] = nonce
        self.windows.setdefault(host, {})[which] = counts
        return logged

    def archived(self, text: str) -> list[dict]:
        """The manager's archive events that hold `text`, read with grep in the manager."""

        if not all(c.isalnum() or c in "-_./:" for c in text):
            raise EngineError("the engine searches the archive only for plain nonces")
        return self.grep_archive(text)

    def grep_archive(self, text: str) -> list[dict]:
        done = self.execute(
            self.containers[self.spec.manager], f"grep -h -F -- '{text}' {wazuh.ARCHIVES}", 30, "engine:ready"
        )
        found = []
        for line in done.stdout.splitlines():
            try:
                found.append(json.loads(line))
            except ValueError:
                continue
        return found

    def wait_archived(self, text: str, host: str, location: str, deadline: float) -> dict | None:
        while True:
            found = wazuh.find(self.archived(text), text, host, location)
            if found:
                return found[0]
            if time.monotonic() + POLL_SECONDS > deadline:
                return None
            time.sleep(POLL_SECONDS)

    def follow(self) -> None:
        """Follow the manager's archives.json and alerts.json into the run folder while the run lasts.

        Two long-running commands of the engine's own, for a live view. No result
        is computed from what they write.
        """

        live = self.out / "live"
        live.mkdir(exist_ok=True)
        identifier = self.containers[self.spec.manager]
        for path, name in ((wazuh.ARCHIVES, "archives.json"), (wazuh.ALERTS, "alerts.json")):
            action = f"tail -n +1 -F {path}"
            self.watch.expect("container", f"exec_create: {action}", id=identifier)
            self.watch.expect("container", f"exec_start: {action}", id=identifier)
            self.watch.expect("container", "exec_die", id=identifier)
            with (live / name).open("wb") as target:
                self.tails.append(
                    subprocess.Popen(
                        [
                            "docker",
                            "exec",
                            "--env",
                            "BLUEFIRE_TAG=engine:live",
                            identifier,
                            *action.split(" "),
                        ],
                        stdout=target,
                        stderr=subprocess.DEVNULL,
                    )
                )

    def mark(self) -> None:
        """Harmless marks on each agent host, where the path will run, so that delivery is counted on real lines.

        On each agent host: three lines sent to syslog, a file created and then
        changed in each folder watched in real time, so that a folder whose watch
        failed shows, and one program start that snoopy records. Then the engine
        waits until each has reached the archive.
        """

        marks = self.manifest["defense"]["marks"]
        token = self.run_id
        sent = []
        for host in self.spec.agents:
            identifier = self.containers[host]
            for number in (1, 2, 3):
                text = f"bluefire-mark-{number}-{token}"
                done = self.execute(
                    identifier,
                    f"printf '%s' \"$EPOCHREALTIME\"; logger -p authpriv.notice -t bluefire-mark {text}",
                    30,
                    "engine:mark",
                )
                sent.append((host, f"logger line {number}", "/var/log/auth.log", text, done))
            folders = self.spec.watch_for(host).fim_realtime
            for step, (write, what, event) in enumerate(
                ((">", "file created", "added"), (">>", "file changed", "modified"))
            ):
                if step and folders:
                    # Apart in time, so that the change is not one event with the create.
                    time.sleep(2)
                for folder in folders:
                    path = f"{folder.rstrip('/')}/bluefire-mark-{token}.txt"
                    done = self.execute(
                        identifier,
                        f"printf '%s' \"$EPOCHREALTIME\"; printf '{what}\\n' {write} {path}",
                        30,
                        "engine:mark",
                    )
                    sent.append((host, f"{what} in {folder}", "syscheck", f"File '{path}' {event}", done))
            text = f"bluefire-mark-program-{token}"
            done = self.execute(
                identifier, f"printf '%s' \"$EPOCHREALTIME\"; /bin/echo {text} > /dev/null", 30, "engine:mark"
            )
            sent.append((host, "program start", "/var/log/snoopy.log", text, done))
        deadline = time.monotonic() + MARK_SECONDS
        for host, mark, location, text, done in sent:
            try:
                logged = float(done.stdout.strip()) if done.returncode == 0 else None
            except ValueError:
                logged = None
            while True:
                search = text.split("'")[1] if "'" in text else text
                found = [event for event in wazuh.find(self.archived(search), text, host, location)]
                if found or time.monotonic() + POLL_SECONDS > deadline:
                    break
                time.sleep(POLL_SECONDS)
            event = found[0] if found else None
            marks.append(
                {
                    "host": host,
                    "mark": mark,
                    "source": location,
                    "made": done.returncode == 0,
                    "archived": event is not None,
                    "delay_seconds": round(wazuh.timestamp(event["timestamp"]) - logged, 3)
                    if event and logged
                    else None,
                }
            )
            if mark == "program start" and event:
                seen = (event.get("data") or {}).get("tag")
                self.manifest["defense"]["snoopy_tag"] = {
                    "expected": "engine:mark",
                    "seen": seen,
                    "works": seen == "engine:mark",
                }
        self.write()

    def end(self) -> None:
        """Close the delivery window: log an end nonce on each agent host and wait for it in the archive.

        Then, since logcollector reads each file on its own, wait until each
        watched log has as many events in the archive as its window has lines
        (see `in_flight`), so that a line still on its way is not counted lost.
        """

        deadline = time.monotonic() + MARK_SECONDS
        for host in self.spec.agents:
            nonce = f"bluefire-end-{self.run_id}-{host}"
            logged = self.nonce(host, nonce, "end", "engine:end")
            found = self.wait_archived(nonce, host, "/var/log/auth.log", deadline)
            waited = self.in_flight(host, deadline)
            self.manifest["defense"]["ready"].setdefault("end", {})[host] = {
                "nonce": nonce,
                "logged": logged,
                "archived": found["timestamp"] if found else None,
                "every log caught up": waited,
            }
        self.write()

    def in_flight(self, host: str, deadline: float) -> dict:
        """Wait until the archive holds, for each watched log of a host, an event for each line of its window.

        Counted per location from the first event there that holds the ready
        nonce (or, for a log that never holds it, the first event anywhere that
        does), leaving out the end nonce's own lines. This only decides how long
        to wait; the delivery count is made later from the copied files.
        """

        ready, end = self.windows[host]["ready"], self.windows[host]["end"]
        wanted = {path: end.get(path, 0) - ready.get(path, 0) for path in end}
        first, last = self.nonces[host]["ready"], self.nonces[host]["end"]
        started = time.monotonic()
        while True:
            # The archive's events of this agent: grep for its name, then keep those whose agent it is.
            ordered = [
                event
                for event in self.grep_archive(f'"name":"{host}"')
                if (event.get("agent") or {}).get("name") == host
            ]
            holds = [i for i, event in enumerate(ordered) if first in (event.get("full_log") or "")]
            counts = {}
            for path in wanted:
                here = [i for i in holds if ordered[i].get("location") == path]
                start = (here or holds or [len(ordered)])[0]
                counts[path] = sum(
                    1
                    for event in ordered[start:]
                    if event.get("location") == path and last not in (event.get("full_log") or "")
                )
            caught_up = all(counts[path] >= number for path, number in wanted.items())
            if caught_up or time.monotonic() + POLL_SECONDS > deadline:
                return {
                    "caught up": caught_up,
                    "seconds": round(time.monotonic() - started, 1),
                    "lines in the window": wanted,
                    "archive events": counts,
                }
            time.sleep(POLL_SECONDS)

    def copy_out(self, host: str, path: str) -> dict:
        """Copy a file or folder out of a range container by ID, into raw/hosts/<host>/<path>.

        Docker streams it as a tar archive, and only its folders and regular
        files are written. A link, or anything else, is left out and listed under
        `refused`: a link that something in the container planted must not make
        the lab read a file of the machine that runs it.
        """

        identifier = self.containers[host]
        folder = self.out / "raw" / "hosts" / host / path.lstrip("/")
        folder = folder.parent
        folder.mkdir(parents=True, exist_ok=True)
        self.watch.expect("container", "archive-path", id=identifier)
        process = subprocess.Popen(
            ["docker", "cp", f"{identifier}:{path}", "-"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        refused = []
        try:
            refused = untar(process.stdout, folder)
        except (tarfile.TarError, OSError) as error:
            refused.append(f"the archive could not be read: {error}"[:300])
        finally:
            process.stdout.close()
            try:
                error_output = process.communicate(timeout=300)[1]
            except subprocess.TimeoutExpired:
                process.kill()
                error_output = process.communicate()[1]
        result: dict = {"copied": process.returncode == 0}
        if process.returncode != 0:
            result["error"] = error_output.decode(errors="replace").strip()[:300]
        if refused:
            result["refused"] = refused
        return result

    def collect(self) -> None:
        """Copy out what the defense recorded, and gzip the manager's archive and alerts."""

        defense = self.manifest["defense"]
        copied = defense.setdefault("collected", {})
        manager = self.spec.manager
        paths = {
            manager: [
                "/var/ossec/logs/archives",
                "/var/ossec/logs/alerts",
                wazuh.OSSEC_LOG,
                "/var/ossec/logs/active-responses.log",
                "/var/ossec/var/run",
                build.OSSEC_CONF,
                build.STOCK,
            ]
        }
        for host in self.spec.agents:
            paths[host] = [log.path for log in self.spec.watch_for(host).logs] + [
                "/var/log/syslog",
                wazuh.OSSEC_LOG,
                "/var/ossec/var/run",
                build.OSSEC_CONF,
                build.STOCK,
            ]
        for host in self.spec.hosts.values():
            if "inet-server" in host.services:
                # The stand-in internet's access log and what was uploaded to it.
                paths[host.name] = ["/var/log/inet", build.INET_UPLOADS]
        for host in self.spec.activity.hosts if self.spec.activity else []:
            # Each job's own state and the output of its last run.
            paths.setdefault(host, []).append(activity.STATE)
        for host, wanted in paths.items():
            copied[host] = {path: self.copy_out(host, path) for path in wanted}
        for kind in ("archives", "alerts"):
            # archives.json and alerts.json are links to the current day's file, so the copy left them
            # out (they are listed as refused) and kept the daily files.
            folder = self.out / "raw" / "hosts" / manager / "var" / "ossec" / "logs" / kind
            if not folder.exists():
                continue
            for path in sorted(folder.rglob("*.json")):
                with path.open("rb") as source, gzip.open(path.with_name(path.name + ".gz"), "wb") as target:
                    shutil.copyfileobj(source, target)
                path.unlink()
        self.write()

    def analyse(self) -> None:
        """The configuration diff of every ossec.conf, the delivery counts and Wazuh's own drop counters.

        Everything here is read from the files copied out of the range.
        """

        defense = self.manifest["defense"]
        raw = self.out / "raw" / "hosts"
        settings = build.conf_settings(self.spec)

        def text(host: str, path: str) -> str | None:
            file = raw / host / path.lstrip("/")
            return file.read_text(encoding="utf-8", errors="replace") if file.is_file() else None

        for host in [self.spec.manager, *self.spec.agents]:
            stock, running = text(host, build.STOCK), text(host, build.OSSEC_CONF)
            if stock is None or running is None:
                defense["configuration"][host] = {
                    "error": "ossec.conf or ossec.conf.stock was not copied out"
                }
                continue
            try:
                if host == self.spec.manager:
                    expected, changes = ossec.manager(stock)
                else:
                    expected, changes = ossec.agent(stock, settings["agents"][host])
            except ossec.ConfError as error:
                defense["configuration"][host] = {"error": str(error)}
                continue
            defense["configuration"][host] = {
                "file": build.OSSEC_CONF,
                "matches_the_lab_edits": running == expected,
                "changes": changes,
                "diff": ossec.diff(stock, running),
            }

        archive = raw / self.spec.manager / "var" / "ossec" / "logs" / "archives"
        found = wazuh.events(wazuh.daily_files(archive)) if archive.exists() else []
        # The line counts read just before each nonce, so that the counts can be made again from raw/.
        defense["windows"] = self.windows
        findings, uncounted = [], []
        for host in self.spec.agents:
            windows = self.windows.get(host, {})
            if "ready" not in windows or "end" not in windows:
                uncounted.append(f"{host}: the run did not reach its end nonce")
                continue
            logs = {}
            for log in self.spec.watch_for(host).logs:
                content = text(host, log.path)
                logs[log.path] = wazuh.lines_of(content) if content is not None else None
            spans = {
                path: (windows["ready"][path], windows["end"][path])
                if path in windows["ready"] and path in windows["end"]
                else None
                for path in logs
            }
            rows = wazuh.delivery(host, logs, spans, found)
            defense["delivery"][host] = rows
            findings += [
                f"{host}: {row['missing']} lines of {row['source']} missing" for row in rows if row["missing"]
            ]
            uncounted += [f"{host}: {row['source']} not counted" for row in rows if row["missing"] is None]
        for mark in defense["marks"]:
            if mark["made"] and not mark["archived"]:
                findings.append(f"{mark['host']}: the mark '{mark['mark']}' did not reach the archive")
            elif not mark["made"]:
                uncounted.append(f"{mark['host']}: the mark '{mark['mark']}' was not made")

        states = {}
        for host in [self.spec.manager, *self.spec.agents]:
            folder = raw / host / "var" / "ossec" / "var" / "run"
            for file in sorted(folder.glob("*.state")) if folder.exists() else []:
                states[f"{host}: {file.name}"] = wazuh.state(
                    file.read_text(encoding="utf-8", errors="replace")
                )
        defense["states"] = states
        drops = wazuh.drops(states)
        end = self.manifest["defense"]["ready"].get("end") or {}
        for host in self.spec.agents:
            # logcollector writes its counters once a minute: say whether they reach the end of the window.
            name = f"{host}: wazuh-logcollector.state"
            until = wazuh.state_time((drops.get(name) or {}).get("counted until", ""))
            closed = (end.get(host) or {}).get("archived")
            if name not in drops:
                drops[name] = {"counted until": "not written yet"}
            elif until is not None and closed:
                covers = until >= wazuh.timestamp(closed)
                drops[name]["covers the window"] = (
                    "yes" if covers else "no, it was written before the end nonce"
                )
            log = text(host, wazuh.OSSEC_LOG)
            if log is not None:
                drops[f"{host}: ossec.log"] = wazuh.lost_warnings(log)
        defense["drops"] = drops
        dropped = wazuh.dropped(drops)
        defense["wazuh_counted_drops"] = dropped
        if dropped:
            findings.append("one of Wazuh's own counters of lost events is above zero")
        # A lost event is a property of the defense under test: the run is flagged, not failed.
        defense["delivery_findings"] = findings or uncounted
        defense["delivery_gap"] = True if findings else (None if uncounted else False)
        self.write()
        if self.spec.activity:
            self.count_activity()

    def static_checks(self, started: bool) -> list[dict]:
        """Checks a, b and c."""

        spec = self.spec
        labelled_containers, labelled_networks = self.labelled()
        checks = seal.objects(
            spec,
            labelled_containers,
            labelled_networks,
            self.prefixed(),
            self.containers,
            self.networks,
            self.run_id,
        )
        everything = docker("ps", "-a", "--no-trunc", "-q").stdout.split()
        checks.append(
            seal.joiners(inspect_present("inspect", *everything) if everything else [], self.containers, spec)
        )
        for network, identifier in self.networks.items():
            inspected = inspect("network", "inspect", identifier)[0]
            members = {host: self.containers[host] for host in spec.members(network)} if started else None
            checks += seal.network(spec, network, identifier, inspected, members)
        for host, identifier in self.containers.items():
            inspected = inspect("inspect", identifier)[0]
            image_id = self.images[host]["id"]
            checks += seal.container(spec, host, identifier, inspected, image_id, self.networks, started)
        return checks

    def dynamic_checks(self, services_up: bool = True) -> list[dict]:
        """Checks d, e and f, on the running containers.

        With `services_up` false, before the ready gate, only what needs no
        service of the range: see `seal.plan_for`.
        """

        spec = self.spec
        inspected = {host: inspect("inspect", identifier)[0] for host, identifier in self.containers.items()}
        by_host = {host: seal.addresses(data, spec) for host, data in inspected.items()}
        for host, found in by_host.items():
            self.manifest["containers"][host]["addresses"] = found
        subnets = {network: self.manifest["networks"][network]["subnets"] for network in self.networks}
        all_networks = docker("network", "ls", "--no-trunc", "-q").stdout.split()
        daemon_networks = inspect_present("network", "inspect", *all_networks) if all_networks else []
        range_subnets = [subnet for found in subnets.values() for subnet in found]
        held = {address for found in by_host.values() for address in found.values()}
        canary = Canary()
        checks: list[dict] = []
        try:
            targets = seal.canary_targets(daemon_networks, range_subnets, held, self.rootless)
            plans = {
                host: seal.plan_for(spec, host, by_host, subnets, (targets, canary.port), services_up)
                for host in spec.hosts
            }
            results: dict[str, tuple[list[str], subprocess.CompletedProcess | None]] = {}

            def probe(host: str) -> None:
                script = seal.script_for(plans[host])
                identifier = self.containers[host]
                command = [
                    "docker",
                    "exec",
                    "-u",
                    "root",
                    "--env",
                    "BLUEFIRE_TAG=engine:seal",
                    identifier,
                    "bash",
                    "-c",
                    "<probe script>",
                ]
                try:
                    results[host] = (command, self.execute(identifier, script, 180))
                except EngineError:
                    results[host] = (command, None)

            threads = [threading.Thread(target=probe, args=(host,)) for host in spec.hosts]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            peers = canary.close()
        for host in spec.hosts:
            command, done = results[host]
            code = done.returncode if done else -1
            output = done.stdout if done else ""
            checks += seal.inside(spec, host, command, code, output, plans[host])
        checks.append(
            seal.check(
                "host canary",
                "Docker host",
                f"listener on 0.0.0.0:{canary.port} during the probes",
                peers,
                "no connection",
                not peers,
            )
        )
        for host, data in inspected.items():
            image = inspect("image", "inspect", data.get("Image", ""))[0]
            if spec.hosts[host].built:
                checks.append(
                    seal.built_image(
                        host, self.images[host]["tag"], self.images[host]["id"], image, self.parents[host]
                    )
                )
            else:
                checks.append(seal.image(host, spec.hosts[host].image, spec.hosts[host].digest, image))
        for host, settings in spec.hosts.items():
            if settings.atomics_src:
                script = f'printf "%s" "$(< {build.COMMIT_FILE})"'
                done = self.execute(self.containers[host], script, 30)
                checks.append(
                    seal.check(
                        "pins: published files",
                        f"container {host}",
                        f"docker exec -u root --env BLUEFIRE_TAG=engine:seal {self.containers[host]} "
                        f"bash -c {shlex.quote(script)}",
                        done.stdout.strip(),
                        spec.atomics.commit,
                        done.returncode == 0 and done.stdout.strip() == spec.atomics.commit,
                    )
                )
        return checks

    def wazuh_pins(self) -> list[dict]:
        """The version each Wazuh piece reports to the manager now; only once the agents have enrolled."""

        spec = self.spec
        checks: list[dict] = []
        listed, _ = self.listing("engine:seal")
        for host in [spec.manager, *spec.agents]:
            identifier = (listed.get(host) or {}).get("id", "<id>")
            checks.append(
                seal.check(
                    "pins: manager version" if host == spec.manager else "pins: agent version",
                    f"container {host}",
                    f"docker exec {self.containers[spec.manager]} /var/ossec/bin/agent_control -i {identifier}",
                    listed.get(host),
                    {"status": "Active", "version": spec.wazuh.version},
                    (listed.get(host) or {}).get("version") == spec.wazuh.version
                    # The manager reports itself as Active/Local.
                    and str((listed.get(host) or {}).get("status")).split("/")[0] == "Active",
                )
            )
        return checks

    def sealed_checks(self, watch_command: str, services_up: bool) -> list[dict]:
        """The static checks on the started range, the checks inside it, and the event watch.

        The Wazuh versions are read again in every phase after the ready gate, and never before it.
        """

        return (
            self.static_checks(started=True)
            + self.dynamic_checks(services_up)
            + (self.wazuh_pins() if self.spec.wazuh and services_up else [])
            + [self.watch.check(watch_command)]
        )

    def run_path(self) -> None:
        """Run the path's published tests in the sealed range, on a range whose plants are in place.

        Each `{ip:<host>@<network>}` of a check is filled in from `docker inspect` of the started containers.
        """

        record: dict = {
            "planned": [step.id for step in self.plan.steps],
            "steps": [],
            "goal": None,
            "stopped": None,
            "notes": list(range_path.NOTES),
        }
        self.manifest["path"] = record
        if not (self.manifest.get("plants") or {}).get("passed"):
            record["skipped"] = "a plant check failed, so the range is not the one its spec describes"
            self.write()
            return
        addresses = {
            host: seal.addresses(inspect("inspect", identifier)[0], self.spec)
            for host, identifier in self.containers.items()
        }
        range_path.Executor(self, self.plan, addresses).run_path()

    def hold_window(self) -> None:
        """After the path: keep the sealed range up for --hold seconds, and stop at once on a finding of the watch."""

        deadline = time.monotonic() + self.hold
        while time.monotonic() < deadline:
            with self.watch.lock:
                if self.watch.findings:
                    return
            time.sleep(0.5)

    def pause(self, seconds: float) -> None:
        """Wait, and stop waiting at once on a finding of the watch."""

        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            with self.watch.lock:
                if self.watch.findings:
                    return
            time.sleep(0.5)

    def activity_go(self) -> None:
        """Start the ordinary activity: write the go on each host that runs a job, and record when."""

        record = self.manifest["activity"]
        # A log time to the second is compared with the go taken down to its second (nginx, dpkg and
        # MariaDB write whole seconds): the go starts a new second, so that no line the engine caused
        # before it, a plant check's request say, carries the go's own second.
        time.sleep(1.05 - time.time() % 1)
        for host in self.spec.activity.hosts:
            done = self.execute(
                self.containers[host],
                f"touch {activity.GO} && printf '%s' \"$EPOCHREALTIME\"",
                30,
                "engine:go",
            )
            if done.returncode != 0:
                raise EngineError(
                    f"writing the go of the ordinary activity on {host} failed: {done.stderr[:300]}"
                )
            record["go"][host] = float(done.stdout.strip())
        record["started"] = activity.started(record["go"])
        self.write()

    def activity_tail(self) -> None:
        """Let the ordinary activity run its tail after the path, then stop it on each host, and record when."""

        record = self.manifest["activity"]
        self.pause(self.spec.activity.tail_seconds)
        for host in self.spec.activity.hosts:
            done = self.execute(
                self.containers[host],
                f"rm -f {activity.GO} && printf '%s' \"$EPOCHREALTIME\"",
                30,
                "engine:stop",
            )
            if done.returncode != 0:
                raise EngineError(f"stopping the ordinary activity on {host} failed: {done.stderr[:300]}")
            record["stop"][host] = float(done.stdout.strip())
        record["minutes"] = activity.minutes(record["go"], record["stop"])
        self.write()
        # A job's window runs to GRACE seconds after its stop: what the engine does next (the seal's
        # probes) starts after every window has closed, so that none of it can be sorted to a job.
        self.pause(activity.GRACE)

    def count_activity(self) -> None:
        """Each job's runs and its events in the archive, from the files copied out of the range."""

        record = self.manifest["activity"]
        if not record["go"]:
            return
        raw = self.out / "raw" / "hosts"
        logs = {}
        for job in self.spec.activity.jobs:
            host, path = activity.counted_from(job)
            file = raw / host / path.lstrip("/")
            logs[(host, path)] = (
                wazuh.lines_of(file.read_text(encoding="utf-8", errors="replace")) if file.is_file() else None
            )
        archive = raw / self.spec.manager / "var" / "ossec" / "logs" / "archives"
        found = wazuh.events(wazuh.daily_files(archive)) if archive.exists() else []
        record["jobs"] = activity.count(
            self.spec.activity, logs, found, self.addresses(), record["go"], record["stop"]
        )
        self.write()

    def addresses(self) -> dict[str, list[str]]:
        """Each host's addresses in the range, as the seal's last phase inside the containers read them."""

        return {
            host: list((entry.get("addresses") or {}).values())
            for host, entry in self.manifest["containers"].items()
        }

    def record_ecs(self) -> None:
        """Write the manager's archive and alerts as ECS lines with their origins, and score the ordinary day."""

        logs = self.out / "raw" / "hosts" / self.spec.manager / "var" / "ossec" / "logs"
        self.manifest["ecs"], self.manifest["score"] = score.record(
            self.out,
            logs,
            self.run_id,
            self.spec.wazuh.alert_level,
            self.spec.activity,
            self.manifest["activity"],
            self.addresses(),
        )
        self.write()

    def labelled(self) -> tuple[list[str], list[str]]:
        """The IDs of the containers and networks that carry this run's label."""

        label = f"label={seal.LABEL_RUN}={self.run_id}"
        containers = docker("ps", "-a", "--no-trunc", "-q", "--filter", label).stdout.split()
        networks = docker("network", "ls", "--no-trunc", "-q", "--filter", label).stdout.split()
        return containers, networks

    def remove(self, what: str, identifier: str, *command: str) -> None:
        try:
            done = docker(*command, identifier, timeout=120, check=False)
            removed, error = done.returncode == 0, done.stderr.strip()[:300] or None
        except EngineError as late:
            removed, error = False, str(late)
        self.manifest["teardown"].append(
            {"object": what, "id": identifier, "removed": removed, "error": error}
        )

    def teardown(self) -> bool:
        """Remove every object of this run by ID; true when none carries the run's label afterwards.

        Objects that carry the run's label but were never recorded (the engine was stopped while
        Docker created them) are removed too.
        """

        try:
            labelled_containers, labelled_networks = self.labelled()
        except EngineError as error:
            labelled_containers, labelled_networks = [], []
            self.manifest["teardown"].append({"object": "listing", "error": str(error)[:300]})
        containers = [(f"container {host}", i, host) for host, i in reversed(list(self.containers.items()))]
        containers += [
            ("container (not recorded)", i, None)
            for i in labelled_containers
            if i not in self.containers.values()
        ]
        networks = [(f"network {network}", i) for network, i in reversed(list(self.networks.items()))]
        networks += [
            ("network (not recorded)", i) for i in labelled_networks if i not in self.networks.values()
        ]
        for what, identifier, host in containers:
            self.watch.containers.add(identifier)
            for action in ("kill", "die", "stop"):
                self.watch.expect("container", action, id=identifier)
            joined = self.spec.hosts[host].networks if host else self.networks
            for network in joined:
                if network in self.networks:
                    self.watch.expect(
                        "network", "disconnect", id=self.networks[network], container=identifier
                    )
            self.watch.expect("container", "destroy", required=True, id=identifier)
            self.remove(what, identifier, "rm", "-f", "-v")
        for what, identifier in networks:
            self.watch.networks.add(identifier)
            self.watch.expect("network", "destroy", required=True, id=identifier)
            self.remove(what, identifier, "network", "rm")
        try:
            left = [i for found in self.labelled() for i in found]
        except EngineError as error:
            self.manifest["teardown"].append({"object": "listing", "error": str(error)[:300]})
            return False
        if left:
            self.manifest["teardown"].append({"object": "left behind", "ids": left})
        return not left

    def run(self) -> int:
        code, result, reason = EXIT_REFUSED, "refused", None
        sealed = False
        watch_command = "docker events --filter type=container --filter type=network"
        try:
            self.preflight()
            self.prepare_images()
            since = docker("info", "--format", "{{.SystemTime}}").stdout.strip()
            self.watch.start(since)
            code, result = EXIT_REFUSED, "engine error"
            self.create_networks()
            self.create_containers()
            static = self.static_checks(started=False) + [self.watch.check(watch_command)]
            self.phase("static", static)
            exempt = GOES_ON.get(self.plant or "", set())
            blocking = [item["check"] for item in static if not item["pass"] and item["check"] not in exempt]
            if blocking or not seal.passed(static):
                code, result = EXIT_SEAL, "seal failed"
                reason = "static seal failed: " + failing(static)
                if blocking:
                    return code
            self.start()
            # Before the engine waits for anything in the range: nothing can leave it.
            way_out = self.sealed_checks(watch_command, services_up=False)
            if not self.phase("no way out", way_out) or code == EXIT_SEAL:
                code, result = EXIT_SEAL, "seal failed"
                reason = (
                    (reason + "; " if reason else "")
                    + "seal failed before the ready gate: "
                    + failing(way_out)
                )
                return code
            if self.spec.wazuh:
                self.follow()
            self.ready()
            # The services listen now: the segmentation between the hosts, with everything above again.
            segmentation = self.sealed_checks(watch_command, services_up=True)
            if not self.phase("segmentation", segmentation):
                code, result = EXIT_SEAL, "seal failed"
                reason = "seal failed after the ready gate: " + failing(segmentation)
                return code
            sealed = True
            code, result = EXIT_INVALID, "invalid"
            self.plant_checks()
            if self.spec.activity:
                self.activity_go()
                self.pause(self.spec.activity.warmup_seconds)
            # A range with a defense gets the engine's harmless marks, so that delivery is counted on real lines.
            if self.spec.wazuh:
                self.mark()
            # The path of published tests, beside the ordinary activity, between the warm-up and the tail.
            if self.plan and self.plan.steps:
                self.run_path()
            self.hold_window()
            if self.spec.activity:
                self.activity_tail()
            after = self.sealed_checks(watch_command, services_up=True)
            if not self.phase("after path", after):
                reason = "the seal failed after the path: " + failing(after)
                return code
            if self.spec.wazuh:
                self.end()
            code, result = EXIT_OK, "sealed"
            return code
        except NotReady as error:
            # The seal is judged once more, so that a range that is not ready and not sealed either
            # is reported as not sealed.
            stopped = False
            try:
                again = self.sealed_checks(watch_command, services_up=False)
            except KeyboardInterrupt:
                stopped = True
                again = [
                    seal.check("seal judged", "range", "the seal's checks", "stopped", "they ran", False)
                ]
            except Exception as late:  # noqa: BLE001 - a seal that could not be judged did not hold
                again = [
                    seal.check(
                        "seal judged", "range", "the seal's checks", str(late)[:300], "they ran", False
                    )
                ]
            judged = self.phase("no way out, not ready", again)
            if stopped:
                code, result = EXIT_REFUSED, "engine error"
                reason = f"stopped while the seal was judged again; not ready: {error}"
            elif not judged:
                code, result = EXIT_SEAL, "seal failed"
                reason = f"seal failed while the range was not ready: {failing(again)}; not ready: {error}"
            else:
                code, result, reason = EXIT_REFUSED, "not ready", str(error)
            return code
        except SpecError as error:
            reason = str(error)
            if self.created:
                code, result = EXIT_REFUSED, "engine error"
            return code
        except (EngineError, KeyboardInterrupt) as error:
            code = EXIT_INVALID if sealed else EXIT_REFUSED
            result = "invalid" if sealed else "engine error"
            reason = str(error) or "stopped"
            return code
        except Exception as error:  # noqa: BLE001 - the manifest's exit code is the process's
            code = EXIT_INVALID if sealed else EXIT_REFUSED
            result = "invalid" if sealed else "engine error"
            reason = f"{type(error).__name__}: {error}"
            return code
        finally:
            # A second Ctrl-C, or a SIGTERM after a SIGINT, must not cut the teardown or the last write short.
            held = hold_signals()
            try:
                complete = True
                if self.started and self.spec.wazuh:
                    try:
                        self.collect()
                        self.analyse()
                    except Exception as error:  # noqa: BLE001 - every exit path writes its outputs
                        self.manifest["defense"]["collect_error"] = f"{type(error).__name__}: {error}"[:500]
                    try:
                        self.record_ecs()
                    except Exception as error:  # noqa: BLE001 - every exit path writes its outputs
                        self.manifest["ecs"] = {
                            "error": f"{type(error).__name__}: {error}"[:500],
                            "files": {},
                        }
                if self.created:
                    try:
                        complete = self.teardown()
                    except Exception as error:  # noqa: BLE001 - every exit path writes its outputs
                        complete = False
                        self.manifest["teardown"].append({"object": "teardown", "error": str(error)[:300]})
                for tail in self.tails:
                    # The container is gone, so the command's output has ended; the client is stopped too.
                    try:
                        tail.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        tail.kill()
                self.manifest["teardown_complete"] = complete
                watched = None
                if self.watch.process:
                    # The watch runs to the end of the teardown: what it saw there is the seal's last phase.
                    final = self.watch.check(watch_command)
                    self.watch.stop()
                    watched = final["pass"]
                    if self.phases:
                        self.phases.append({"phase": "teardown", "passed": final["pass"], "checks": [final]})
                code, result, reason = outcome(
                    (code, result, reason),
                    complete,
                    watched,
                    self.manifest.get("plants"),
                    (self.manifest.get("ecs") or {}).get("error"),
                )
                self.manifest.update({"result": result, "reason": reason, "exit_code": code})
                self.manifest["engine_clock"]["ended"] = now()
                self.write()
            finally:
                for number, handler in held.items():
                    signal.signal(number, handler)


def failing(checks: list[dict]) -> str:
    """The names of the checks that failed, for a run's reason."""

    return ", ".join(sorted({item["check"] for item in checks if not item["pass"]}))


def outcome(
    reached: tuple[int, str, str | None],
    teardown_complete: bool,
    watch_passed: bool | None,
    planted: dict | None,
    conversion_error: str | None = None,
) -> tuple[int, str, str | None]:
    """A run's exit code, result and reason once its teardown is over.

    `reached` is what the run had reached before the teardown. A range that was
    not ready and whose event watch failed during the teardown ends with a
    failed seal, so that "not ready" never hides one. Otherwise only a run that
    ended sealed changes here: a teardown that left objects behind makes it an
    engine error, a failed event watch during the teardown or a failed
    conversion of the archive and alerts to ECS makes it invalid, and only then
    failed plant checks make it "plants not in place", so that this softer
    result never hides one of the others.
    """

    code, result, reason = reached
    if result == "not ready" and watch_passed is False:
        watch = "the event watch failed during the teardown: see seal.json"
        return EXIT_SEAL, "seal failed", f"{watch}; not ready: {reason}"
    if code != EXIT_OK:
        return reached
    if not teardown_complete:
        return EXIT_REFUSED, "engine error", "the teardown left objects behind: see teardown in manifest.json"
    if watch_passed is False:
        return EXIT_INVALID, "invalid", "the event watch failed during the teardown: see seal.json"
    if conversion_error:
        return EXIT_INVALID, "invalid", f"the conversion to ECS failed: {conversion_error}"
    if planted and not planted.get("passed"):
        # The range was sealed, and not the range its spec describes: the path could not run in it.
        failed = [
            f"{item['check']} ({item['subject']})" for item in planted.get("checks") or [] if not item["pass"]
        ]
        return EXIT_REFUSED, "plants not in place", "plant checks failed: " + ", ".join(failed)
    return reached


def summary(record: dict, manifest: dict) -> str:
    """The seal as Markdown, for a CI job's summary: the failed checks first, then every check."""

    def cell(value) -> str:
        text = value if isinstance(value, str) else json.dumps(value)
        text = text.replace("|", "\\|").replace("\n", " ")
        return text if len(text) <= 120 else text[:117] + "..."

    title = "passed" if record["passed"] else "failed"
    lines = [f"### Seal of {record['range']}: {title}", ""]
    if manifest.get("plant"):
        lines += [f"Planted break: `{manifest['plant']}`.", ""]
    lines += [
        f"Result: {manifest.get('result')} (exit code {manifest.get('exit_code')}). "
        f"{manifest.get('environment')}, Docker {manifest.get('docker', {}).get('server', '?')}.",
        "",
    ]
    if manifest.get("reason"):
        lines += [f"Reason: {manifest['reason']}", ""]
    failed = [
        (phase["phase"], item) for phase in record["phases"] for item in phase["checks"] if not item["pass"]
    ]
    if failed:
        lines += ["| Phase | Check | Subject | Observed |", "|---|---|---|---|"]
        lines += [f"| {p} | {i['check']} | {cell(i['subject'])} | {cell(i['observed'])} |" for p, i in failed]
        lines.append("")
    for phase in record["phases"]:
        total = len(phase["checks"])
        good = sum(1 for item in phase["checks"] if item["pass"])
        lines += [
            "<details>",
            f"<summary>{phase['phase']}: {good} of {total} checks passed</summary>",
            "",
            "| Check | Subject | Observed | Result |",
            "|---|---|---|---|",
        ]
        lines += [
            f"| {i['check']} | {cell(i['subject'])} | {cell(i['observed'])} | {'pass' if i['pass'] else 'FAIL'} |"
            for i in phase["checks"]
        ]
        lines += ["", "</details>", ""]
    return "\n".join(lines)


def hold_signals() -> dict:
    """Ignore SIGINT and SIGTERM; return the handlers to put back."""

    held = {}
    for number in (signal.SIGINT, signal.SIGTERM):
        try:
            held[number] = signal.signal(number, signal.SIG_IGN)
        except ValueError:  # not the main thread
            pass
    return held


def run(spec_path: Path, out: Path, plant: str | None = None, hold: float = 0) -> int:
    try:
        spec = load(spec_path)
    except (OSError, SpecError) as error:
        print(f"bluefire-lab range: {error}")
        return EXIT_REFUSED
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    if (out / "seal.json").exists():
        print(f"bluefire-lab range: {out} holds a run already; give a new folder")
        return EXIT_REFUSED

    def stop(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, stop)
    try:
        engine = Run(spec, Path(spec_path).name, out, plant, hold)
        engine.run()
        # The teardown can still change the outcome after the sequence returned.
        code = engine.manifest["exit_code"]
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(f"range {spec.range}: {engine.manifest['result']} (exit {code})")
    if engine.manifest.get("reason"):
        print(engine.manifest["reason"])
    return code


def render(spec_path: Path, out: Path) -> int:
    """Write the build context of the range's images, and print the tags they will carry."""

    try:
        spec = load(spec_path)
    except (OSError, SpecError) as error:
        print(f"bluefire-lab range: {error}")
        return EXIT_REFUSED
    if not any(host.built for host in spec.hosts.values()):
        print(
            f"bluefire-lab range: every host of {spec.range} runs a pinned image, so there is nothing to build"
        )
        return EXIT_OK
    try:
        rendered = build.render(spec, Path(out))
    except SpecError as error:
        print(f"bluefire-lab range: {error}")
        return EXIT_REFUSED
    for host, tag in rendered.tags.items():
        print(f"{host}: {tag}")
    return EXIT_OK


def lock(spec_path: Path) -> int:
    """Write the lock of the published files the spec's hosts carry."""

    try:
        spec = load(spec_path)
        written = atomics.lock(spec)
    except (OSError, SpecError, ValueError) as error:
        print(f"bluefire-lab range: {error}")
        return EXIT_REFUSED
    print(f"{written}: {len(written.read_text(encoding='utf-8').splitlines()) - 1} files")
    return EXIT_OK


def down(spec_path: Path) -> int:
    """Remove the containers and networks that carry both the spec's prefix and its range label."""

    try:
        spec = load(spec_path)
    except (OSError, SpecError) as error:
        print(f"bluefire-lab range: {error}")
        return EXIT_REFUSED
    label = f"label={seal.LABEL_RANGE}={spec.range}"
    failed = False
    try:
        listed = docker("ps", "-a", "--no-trunc", "--filter", label, "--format", "{{.ID}}\t{{.Names}}").stdout
        for line in listed.splitlines():
            identifier, _, name = line.partition("\t")
            if name.startswith(spec.prefix + "-"):
                done = docker("rm", "-f", "-v", identifier, check=False)
                failed |= done.returncode != 0
                print(f"container {name}: {'removed' if done.returncode == 0 else done.stderr.strip()}")
        listed = docker(
            "network", "ls", "--no-trunc", "--filter", label, "--format", "{{.ID}}\t{{.Name}}"
        ).stdout
        for line in listed.splitlines():
            identifier, _, name = line.partition("\t")
            if name.startswith(spec.prefix + "-"):
                done = docker("network", "rm", identifier, check=False)
                failed |= done.returncode != 0
                print(f"network {name}: {'removed' if done.returncode == 0 else done.stderr.strip()}")
    except EngineError as error:
        print(f"bluefire-lab range: {error}")
        return EXIT_REFUSED
    return EXIT_REFUSED if failed else EXIT_OK
