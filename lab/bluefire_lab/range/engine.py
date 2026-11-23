"""Bring a range up from its spec, seal it, watch it and take it down again.

The engine calls the plain Docker CLI and writes every flag itself. Every
object is addressed by the full ID Docker returned when the engine created it.
A watch on Docker's events runs from before the first create to the end of the
teardown, and any event on the range that the engine did not cause breaks the
seal. The run writes `seal.json`, `seal.md` and `manifest.json` on every exit
path, and takes the range down on every exit path after the first create.

Exit codes: 0 the range was sealed and still was at the end; 1 refused before
anything was created, or an engine error; 3 the seal failed and nothing ran in
the range; 4 the run was made invalid (the seal failed after the point where the
path runs, or something the engine did not do happened to the range).
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import seal
from .spec import Spec, SpecError, load

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_SEAL = 3
EXIT_INVALID = 4
MEMORY = "256m"
PIDS_LIMIT = "1024"
WATCH_SECONDS = 15
READY_SECONDS = 30
# Breaks planted on purpose, to show that the seal catches each one. A run with a plant always fails.
PLANTS = ("not-internal", "no-isolated-gateway", "published-port", "bind-mount")
# With this plant only, the run starts the containers although the static seal failed, so that
# the dynamic seal shows the host canary catching the same break. Its networks are internal.
GOES_ON = {"no-isolated-gateway": {"network: gateway mode"}}


class EngineError(RuntimeError):
    """A Docker command failed, or the engine was stopped."""


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


class Watch:
    """Docker's events on the range, each matched to an action the engine announced.

    Before each action the engine announces the events it will cause. An event
    on a range object (by ID, or by a name with the prefix) that matches no
    announcement is a finding. So is the create or start of any other container
    that shares a namespace with a range container: `inspect` reads such a
    container's `docker inspect`, since its events do not name the range.
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
        for index, allowed in enumerate(self.allowed):
            if (
                allowed["type"] == event.get("Type")
                and allowed["action"] == event.get("Action")
                and allowed.get("id", actor.get("ID")) == actor.get("ID")
                and allowed.get("name", attributes.get("name")) == attributes.get("name")
                and allowed.get("container", attributes.get("container")) == attributes.get("container")
            ):
                del self.allowed[index]
                self.required.discard(allowed["token"])
                return True
        return False

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
                shared = seal.joins(inspected or {}, targets)
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
        self.rootless = False
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
            "images": {},
            "networks": {},
            "containers": {},
            "ready": {},
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

    # Outputs

    def write(self) -> None:
        write_json(self.out / "manifest.json", self.manifest)
        record = {
            "range": self.spec.range,
            "run_id": self.run_id,
            "plant": self.plant,
            "passed": bool(self.phases) and all(phase["passed"] for phase in self.phases),
            "phases": self.phases,
            "watch": {"events": self.watch.events, "findings": list(self.watch.findings)},
        }
        write_json(self.out / "seal.json", record)
        (self.out / "seal.md").write_text(summary(record, self.manifest), encoding="utf-8")

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
        self.manifest["docker"] = {
            "server": server,
            "api": (version.get("Server") or {}).get("ApiVersion"),
            "rootless": self.rootless,
            "endpoint": scheme,
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
        missing = [host.name for host in self.spec.hosts.values() if not host.image]
        if missing:
            raise SpecError(
                f"hosts {', '.join(missing)} have no image: building images from a host's plant keys is not in "
                "the lab yet, so every host needs an image pinned by digest"
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

    def pull(self) -> None:
        for host in self.spec.hosts.values():
            reference = host.image
            if reference in self.images:
                continue
            if docker("image", "inspect", reference, check=False).returncode != 0:
                docker("pull", "--quiet", reference, timeout=900)
            image = inspect("image", "inspect", reference)[0]
            self.images[reference] = {"id": image["Id"], "digest": host.digest}
        self.manifest["images"] = self.images

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
            image_id = self.images[host.image]["id"]
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
                MEMORY,
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
        for host in self.spec.hosts.values():
            identifier = self.containers[host.name]
            for network in host.networks:
                self.watch.expect("network", "connect", id=self.networks[network], container=identifier)
            self.watch.expect("container", "start", required=True, id=identifier)
            docker("start", identifier)

    def execute(self, identifier: str, script: str, timeout: float) -> subprocess.CompletedProcess:
        """Run a script of the engine's own as root in a range container, and announce its events."""

        if identifier not in self.containers.values():
            raise EngineError("the engine runs commands only in the range's own containers")
        action = f"bash -c {script}"
        self.watch.expect("container", f"exec_create: {action}", id=identifier)
        self.watch.expect("container", f"exec_start: {action}", id=identifier)
        self.watch.expect("container", "exec_die", required=True, id=identifier)
        return docker(
            "exec",
            "-u",
            "root",
            "--env",
            "BLUEFIRE_TAG=engine:seal",
            identifier,
            "bash",
            "-c",
            script,
            timeout=timeout,
            check=False,
        )

    def ready(self) -> None:
        """Wait until each host's own service listens, so that the seal's controls can reach it."""

        for host in self.spec.hosts.values():
            if not host.listens:
                continue
            ports = " ".join(str(port) for port in host.listens)
            script = (
                f"for port in {ports}; do ok=; for i in $(seq 1 {READY_SECONDS * 2}); do "
                "if (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; then ok=1; break; fi; sleep 0.5; done; "
                '[ -n "$ok" ] || exit 1; done'
            )
            started = time.monotonic()
            done = self.execute(self.containers[host.name], script, READY_SECONDS + 30)
            self.manifest["ready"][host.name] = {
                "listening": done.returncode == 0,
                "seconds": round(time.monotonic() - started, 1),
            }
        self.write()

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
            image_id = self.images[spec.hosts[host].image]["id"]
            checks += seal.container(spec, host, identifier, inspected, image_id, self.networks, started)
        return checks

    def dynamic_checks(self) -> list[dict]:
        """Checks d, e and f, on the running containers."""

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
                host: seal.plan_for(spec, host, by_host, subnets, (targets, canary.port))
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
            reference = spec.hosts[host].image
            image = inspect("image", "inspect", data.get("Image", ""))[0]
            checks.append(seal.image(host, reference, spec.hosts[host].digest, image))
        return checks

    def hold_window(self) -> None:
        """Where the path will run: keep the sealed range up, and stop at once on a finding of the watch."""

        deadline = time.monotonic() + self.hold
        while time.monotonic() < deadline:
            with self.watch.lock:
                if self.watch.findings:
                    return
            time.sleep(0.5)

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
            self.pull()
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
                reason = "static seal failed: " + ", ".join(
                    sorted({item["check"] for item in static if not item["pass"]})
                )
                if blocking:
                    return code
            self.start()
            self.ready()
            dynamic = (
                self.static_checks(started=True) + self.dynamic_checks() + [self.watch.check(watch_command)]
            )
            if not self.phase("dynamic", dynamic) or code == EXIT_SEAL:
                code, result = EXIT_SEAL, "seal failed"
                reason = (
                    (reason + "; " if reason else "")
                    + "dynamic seal failed: "
                    + ", ".join(sorted({item["check"] for item in dynamic if not item["pass"]}))
                )
                return code
            sealed = True
            code, result = EXIT_INVALID, "invalid"
            # The path of published tests runs here in a later version of the lab.
            self.hold_window()
            after = (
                self.static_checks(started=True) + self.dynamic_checks() + [self.watch.check(watch_command)]
            )
            if not self.phase("after path", after):
                reason = "the seal failed after the path: " + ", ".join(
                    sorted({item["check"] for item in after if not item["pass"]})
                )
                return code
            code, result = EXIT_OK, "sealed"
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
                if self.created:
                    try:
                        complete = self.teardown()
                    except Exception as error:  # noqa: BLE001 - every exit path writes its outputs
                        complete = False
                        self.manifest["teardown"].append({"object": "teardown", "error": str(error)[:300]})
                if self.watch.process:
                    missing = self.watch.settle()
                    self.watch.stop()
                    if self.watch.findings and code == EXIT_OK:
                        code, result = EXIT_INVALID, "invalid"
                        reason = "the event watch saw an event on the range that the engine did not cause"
                    if missing:
                        self.manifest["teardown"].append(
                            {"object": "event watch", "error": "not reported: " + "; ".join(missing)}
                        )
                self.manifest["teardown_complete"] = complete
                if not complete and code == EXIT_OK:
                    code, result = EXIT_REFUSED, "engine error"
                    reason = "the teardown left objects behind: see teardown in manifest.json"
                self.manifest.update({"result": result, "reason": reason, "exit_code": code})
                self.manifest["engine_clock"]["ended"] = now()
                self.write()
            finally:
                for number, handler in held.items():
                    signal.signal(number, handler)


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
