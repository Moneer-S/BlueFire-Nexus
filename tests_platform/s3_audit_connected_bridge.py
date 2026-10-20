"""Explicit opt-in test bridge. Never imported by a production worker entrypoint.

The owner supplies a pinned tools JSON, not executable paths in a worker request:
schema_version=bluefire.s3-connected-test-tools.v1; python/native/helper each have
absolute path and sha256; source_root is the reviewed checkout; source_files is
the exact relative .py path -> sha256 inventory for imported local modules.
BLUEFIRE_S3_CONNECTED_TOOLS_SHA256 pins that complete JSON. Nothing builds here.
This proves neither protected installation, mutual TLS, AWS, nor log integrity.
"""

import ctypes
import hashlib
import importlib.abc
import importlib.machinery
import json
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

LIMIT = 256 * 1024
MAX_SOURCE_FILE_BYTES = 512 * 1024
READ_CHUNK_BYTES = 64 * 1024
NATIVE_TEST = "s3_reservation::connected_tests::application_worker_bridge"
_LAUNCH_LOCK = threading.Lock()
MAX_PROCESSES = 4096
MAX_OWNED = 32
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37


def subreaper(value=None):
    library = ctypes.CDLL(None, use_errno=True)
    prctl = library.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    current = ctypes.c_int()
    if prctl(PR_GET_CHILD_SUBREAPER, ctypes.addressof(current), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "test subreaper state unavailable")
    if value is not None and prctl(PR_SET_CHILD_SUBREAPER, int(value), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "test subreaper state change failed")
    return current.value


class OwnedSession:
    """Test-only cleanup of one unreaped private session, including adopted children."""

    def __init__(self, directory):
        from bluefire.runner_linux_containment import LinuxPrivateProcessContainment

        if sys.platform != "linux" or not LinuxPrivateProcessContainment.available():
            raise RuntimeError("connected test requires Linux pidfd containment")
        self.containment = LinuxPrivateProcessContainment
        self.directory = directory
        self.process = None
        self.leader = None
        self.previous_subreaper = None
        self.locked = False
        self.reaped_members = 0
        self.observed_members = {}

    def __enter__(self):
        if not _LAUNCH_LOCK.acquire(blocking=False):
            raise RuntimeError("connected native test launches must be serialized")
        self.locked = True
        try:
            self.previous_subreaper = subreaper()
            subreaper(1)
            if subreaper() != 1:
                raise RuntimeError("test subreaper state was not established")
        except BaseException:
            try:
                if self.previous_subreaper is not None:
                    subreaper(self.previous_subreaper)
            finally:
                _LAUNCH_LOCK.release()
                self.locked = False
            raise
        return self

    def spawn(self, command, environment):
        # Store the Child before any identity/pipe setup can fail.
        self.process = subprocess.Popen(
            command,
            cwd="/",
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.pin_leader()
        return self.process

    def pin_leader(self):
        identity = self.containment.process_identity(self.process.pid)
        if identity[2:] != (self.process.pid, self.process.pid):
            raise RuntimeError("native test did not retain its private session")
        if self.leader is not None and identity != self.leader:
            raise RuntimeError("native test identity changed before cleanup")
        self.leader = identity
        return identity

    def exited(self):
        self.pin_leader()
        status = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if status is not None and status.si_pid != self.process.pid:
            raise RuntimeError("native test exit identity changed")
        return status is not None

    def members(self, deadline):
        self.pin_leader()
        result = []
        with os.scandir("/proc") as entries:
            for count, entry in enumerate(entries, 1):
                if count > MAX_PROCESSES or time.monotonic() >= deadline:
                    raise RuntimeError("test process inventory exceeded finite bound")
                if not entry.name.isdecimal():
                    continue
                try:
                    identity = self.containment.process_identity(int(entry.name))
                    if identity[3] != self.leader[3]:
                        continue
                    if entry.stat(follow_symlinks=False).st_uid != os.getuid():
                        raise RuntimeError("test session contains an unowned process")
                except ProcessLookupError:
                    continue
                except FileNotFoundError:
                    continue
                result.append(identity)
                self.observed_members[identity[:2]] = identity
                if len(result) > MAX_OWNED or len(self.observed_members) > MAX_OWNED:
                    raise RuntimeError("test session member bound exceeded")
        if self.leader not in result:
            raise RuntimeError("native test was reaped before owned cleanup")
        return result

    def reap_member(self, identity):
        try:
            if self.containment.process_identity(identity[0]) != identity:
                raise RuntimeError("test descendant identity changed before reap")
            pid, _status = os.waitpid(identity[0], os.WNOHANG)
        except ProcessLookupError:
            return
        except ChildProcessError:
            # Its immediate parent may still be exiting; never reap another PID.
            return
        if pid not in (0, identity[0]):
            raise RuntimeError("test descendant reap identity changed")
        if pid:
            self.reaped_members += 1

    def cleanup(self):
        if self.process is None:
            return True
        deadline = time.monotonic() + 2
        try:
            self.pin_leader()
            if not self.containment._signal_identity(self.leader, signal.SIGKILL):
                return False
            while time.monotonic() < deadline:
                exited = self.exited()
                targets = [row for row in self.members(deadline) if row != self.leader]
                for identity in targets:
                    if not self.containment._signal_identity(identity, signal.SIGKILL):
                        return False
                    if exited:
                        self.reap_member(identity)
                if exited and not targets:
                    # The unreaped leader pins the session number until its last member is gone.
                    self.process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    return self.process.returncode is not None
                time.sleep(0.005)
        except Exception:
            return False
        return False

    def __exit__(self, kind, _value, _traceback):
        clean = False
        restored = False
        try:
            clean = self.cleanup()
        finally:
            try:
                if self.previous_subreaper is not None:
                    subreaper(self.previous_subreaper)
                    restored = subreaper() == self.previous_subreaper
            except Exception:
                restored = False
            finally:
                try:
                    if self.process is not None:
                        for pipe in (self.process.stdout, self.process.stderr):
                            if pipe is not None:
                                pipe.close()
                except Exception:
                    clean = False
                finally:
                    if self.locked:
                        _LAUNCH_LOCK.release()
                        self.locked = False
        create_json(
            self.directory / "parent-cleanup.json",
            {
                "schema_version": "bluefire.s3-connected-parent-cleanup.v2",
                "cleanup": "verified" if clean and restored else "unknown",
                "native_reaped": self.process is None or self.process.returncode is not None,
                "native_identity": self.leader,
                "observed_members": sorted(self.observed_members.values()),
                "live_owned_members": [] if clean and restored else None,
                "adopted_members_reaped": self.reaped_members,
                "subreaper_restored": restored,
                "body_failed": kind is not None,
            },
        )
        if not clean or not restored:
            raise RuntimeError(
                "connected native test cleanup is unknown; retained result is not accepted"
            )


def _read_chunks(path, maximum):
    path = Path(path)
    if not path.is_absolute() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("test input must be an absolute non-symlink path")
    remaining = maximum + 1
    with path.open("rb") as stream:
        # A large pin ceiling must not become a single worker-sized allocation.
        while remaining:
            piece = stream.read(min(remaining, READ_CHUNK_BYTES))
            if not piece:
                break
            remaining -= len(piece)
            if not remaining:
                raise ValueError("test input exceeds finite bound")
            yield piece


def read_file(path, maximum=LIMIT):
    return b"".join(_read_chunks(path, maximum))


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def pinned(row, maximum=LIMIT):
    if set(row) != {"path", "sha256"}:
        raise ValueError("test executable/source pin differs")
    hasher = hashlib.sha256()
    for piece in _read_chunks(row["path"], maximum):
        hasher.update(piece)
    if "sha256:" + hasher.hexdigest() != row["sha256"]:
        raise ValueError("test executable/source pin differs")
    return Path(row["path"])


def load_tools(path, expected):
    raw = read_file(path)
    if digest(raw) != expected:
        raise ValueError("test tools packet differs")
    value = json.loads(raw)
    if set(value) != {
        "schema_version",
        "python",
        "native",
        "helper",
        "source_root",
        "source_files",
    }:
        raise ValueError("test tools packet shape differs")
    if value["schema_version"] != "bluefire.s3-connected-test-tools.v1":
        raise ValueError("test tools schema differs")
    root = Path(value["source_root"])
    if not root.is_absolute() or root.resolve() != Path(__file__).resolve().parents[1]:
        raise ValueError("test tools must reference this reviewed checkout")
    if pinned(value["helper"]) != Path(__file__).resolve():
        raise ValueError("test helper path differs")
    pinned(value["python"], 128 * 1024 * 1024)
    pinned(value["native"], 512 * 1024 * 1024)
    sources = value["source_files"]
    if not isinstance(sources, dict) or not 1 <= len(sources) <= 1024:
        raise ValueError("test source inventory exceeds finite bound")
    for name, expected_hash in sources.items():
        part = Path(name)
        if part.is_absolute() or ".." in part.parts or part.suffix != ".py":
            raise ValueError("test source inventory path invalid")
        if digest(read_file(root / part, MAX_SOURCE_FILE_BYTES)) != expected_hash:
            raise ValueError("test source inventory changed")
    return value


def create_json(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if len(raw) > LIMIT:
        raise ValueError("test output exceeds finite bound")
    with Path(path).open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class LocalSourcePins(importlib.abc.MetaPathFinder):
    def __init__(self, tools):
        self.root = Path(tools["source_root"])
        self.sources = tools["source_files"]

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] not in {"bluefire", "tests_platform"}:
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        if spec is None or spec.origin is None:
            return spec
        source = Path(spec.origin)
        name = source.relative_to(self.root).as_posix()
        validated_source = read_file(source, MAX_SOURCE_FILE_BYTES)
        if digest(validated_source) != self.sources.get(name):
            raise ImportError("local test import is not in the frozen source inventory")
        # Ignore bytecode even if the checkout contains a historical cache.
        spec.loader = importlib.machinery.SourceFileLoader(fullname, str(source))
        spec.loader.get_code = lambda _name: compile(validated_source, str(source), "exec")
        return spec


def invoke_native(tools_path, tools_hash, case_dir, packet):
    """Only the explicit opt-in fixture calls this bounded ignored test binary."""
    tools = load_tools(tools_path, tools_hash)
    case_dir = Path(case_dir)
    case_dir.mkdir(mode=0o700)
    input_path = case_dir / "input.json"
    create_json(input_path, packet)
    environment = {
        "LC_ALL": "C",
        "BLUEFIRE_S3_CONNECTED_TOOLS": str(tools_path),
        "BLUEFIRE_S3_CONNECTED_TOOLS_SHA256": tools_hash,
        "BLUEFIRE_S3_CONNECTED_INPUT": str(input_path),
    }
    # Drain both diagnostic pipes with finite memory, file and lifetime bounds.
    with (
        (case_dir / "native.stdout").open("xb") as output,
        (case_dir / "native.stderr").open("xb") as errors,
    ):
        with OwnedSession(case_dir) as owner:
            process = owner.spawn(
                [
                    tools["native"]["path"],
                    "--exact",
                    NATIVE_TEST,
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ],
                environment,
            )
            selector = None
            try:
                end = time.monotonic() + 25
                selector = selectors.DefaultSelector()
                for pipe, destination in ((process.stdout, output), (process.stderr, errors)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, destination)
                while selector.get_map() or not owner.exited():
                    if time.monotonic() >= end:
                        raise TimeoutError("test native bridge exceeded its finite lifecycle")
                    for key, _events in selector.select(timeout=0.02):
                        data = os.read(key.fd, 4096)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        if key.data.tell() + len(data) > LIMIT:
                            raise ValueError("test native bridge diagnostics exceeded finite bound")
                        key.data.write(data)
            finally:
                if selector is not None:
                    selector.close()
                process.stdout.close()
                process.stderr.close()
        if process.returncode != 0:
            raise RuntimeError(
                "test native bridge failed; retained bounded diagnostics identify the failure"
            )
    result = json.loads(read_file(case_dir / "result.json"))
    if result["task_id"] != packet["task_id"] or result["request_hash"] != packet["request_hash"]:
        raise ValueError("native retained result changed original identity")
    if result["child_reaped"] is not True or result["group_absent"] is not True:
        raise ValueError("native test worker cleanup is not verified")
    return result


def worker(tools_path, tools_hash, input_path):
    def deny_network(event, _arguments):
        if event.startswith("socket.") or event in {
            "subprocess.Popen",
            "os.system",
            "os.exec",
            "os.posix_spawn",
            "os.fork",
            "os.forkpty",
        }:
            raise RuntimeError(
                "network and child launch are disabled for the connected test worker"
            )

    sys.addaudithook(deny_network)
    tools = load_tools(tools_path, tools_hash)
    sys.path.insert(0, tools["source_root"])
    sys.meta_path.insert(0, LocalSourcePins(tools))
    from bluefire.s3_access_contract import timestamp
    from bluefire.s3_access_wire import S3WorkerRequest
    from bluefire.s3_access_worker import run_worker
    from tests_platform.test_s3_access_sdk import FakeFactory, FakeServiceError
    from tests_platform.test_s3_audit_sdk import FakeAuditFactory

    packet = json.loads(read_file(input_path))
    request = packet["manifest"]["params"]["worker_request"]
    state = Path(input_path).parent.parent / "sdk-policy.json"
    trace = Path(input_path).parent / "sdk-trace.jsonl"

    def record(operation):
        data = (json.dumps({"operation": operation}, separators=(",", ":")) + "\n").encode()
        with trace.open("ab") as output:
            if output.tell() + len(data) > 4096:
                raise ValueError("inert SDK trace bound exceeded")
            output.write(data)
            output.flush()
            os.fsync(output.fileno())

    class Business(FakeFactory):
        def __init__(self, row):
            super().__init__(S3WorkerRequest.from_mapping(row))
            self.policy = json.loads(read_file(state))

        def invoke(self, service, operation, role, guard, parameters):
            value = super().invoke(service, operation, role, guard, parameters)
            record(operation)
            value["ResponseMetadata"][
                "RequestId"
            ] = f"CONNECTED-{request['request_id'][:16]}-{len(self.calls)}"
            if operation == "PutBucketPolicy":
                temporary = state.with_name("sdk-policy-next.json")
                create_json(temporary, self.policy)
                os.replace(temporary, state)
            if operation == "GetObject" and role == "probe":
                sid = request["scope"]["policy"]["probe_sid"]
                if not any(item.get("Sid") == sid for item in self.policy["Statement"]):
                    value["Body"].close()
                    raise FakeServiceError(
                        {
                            "Error": {"Code": "AccessDenied"},
                            "ResponseMetadata": {
                                **value["ResponseMetadata"],
                                "HTTPStatusCode": 403,
                            },
                        }
                    )
            return value

    class Audit(FakeAuditFactory):
        def _invoke(self, session, transport, guard, service, role, operation, parameters):
            value = super()._invoke(session, transport, guard, service, role, operation, parameters)
            record(operation)
            return value

    factory = Audit(request) if request["operation"] == "collect_audit" else Business(request)
    stat = read_file(Path(f"/proc/{os.getpid()}/stat"), 4096).decode()
    ticks = stat[stat.rfind(")") + 2 :].split()[19]
    return run_worker(
        sys.stdin.buffer,
        sys.stdout.buffer,
        factory=factory,
        clock=lambda: timestamp(packet["now"]),
        process_id=os.getpid(),
        creation_identity=ticks,
        nonce="a" * 64,
        expected_runtime_digest=request["runtime_digest"],
        expected_worker_generation=request["worker_generation"],
    )


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "--worker":
        raise SystemExit("explicit native-owned test worker invocation required")
    raise SystemExit(worker(*sys.argv[2:]))
