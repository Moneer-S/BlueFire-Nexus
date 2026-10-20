"""Original host/controller plumbing with fake processes and sockets only.

No Darwin ABI, credential drop, service launch, or installed-host proof is made.
"""

import ctypes
import errno
import sys
import threading
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from bluefire import macos_file_access_endpoint as original_endpoint
from bluefire import macos_file_access_workspace as workspace
from bluefire import macos_file_access_workspace_bootstrap as bootstrap
from bluefire.macos_file_access_contract import MacOSFileAccessContractError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_macos_file_access_contract import binding


class Stream:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.close_calls = 0
        self.fail_close = False
        self.raw = bytearray()
        self.output = bytearray()
        self.ancillary = []
        self.flags = 0

    def fileno(self):
        return self.descriptor

    def close(self):
        self.close_calls += 1
        if self.fail_close:
            raise OSError("fake uncertain descriptor close")

    def set_inheritable(self, value):
        assert value is False

    def settimeout(self, value):
        assert value > 0

    def getpeername(self):
        return ""

    def send(self, raw):
        count = min(7, len(raw))
        self.output.extend(raw[:count])
        return count

    def recvmsg(self, size, _ancillary):
        count = min(7, size, len(self.raw))
        result = bytes(self.raw[:count])
        del self.raw[:count]
        return result, self.ancillary, self.flags, ""


class Pins:
    def __init__(self):
        self.close_calls = 0

    def enter_context(self, context):
        return context.__enter__()

    def close(self):
        self.close_calls += 1


@pytest.fixture
def fake(monkeypatch):
    state = dict(
        wall=1000,
        monotonic=1000,
        mode="normal",
        release=True,
        releases=0,
        sent=[],
        received=0,
        observed=0,
        launch_objects=[],
        import_checks=[],
    )
    value = object.__new__(workspace.MacOSWorkspaceOwner)
    value._binding = binding()
    value._creator = object()
    value._pins = Pins()
    value._files = []
    value._directories = {}
    value._stream = value._child_stream = None
    value._stream_closed = value._child_closed = False
    value._cleanup_unknown = value._creation_unknown = False
    value._process = value._launch = value._owned = value._consistency = None
    value._started = False
    value._state = "prepared"
    value._clock = (0, 0)
    value._lock = threading.Lock()
    value._fork_guard = threading.Lock()
    value._channel_lock = threading.RLock()
    value._bridge = None
    value._creator_pid = 100
    value._recipe = dict(
        binding=value._binding,
        binding_digest=content_hash(value._binding),
        python="/fixed/python",
        python_sha256="1" * 64,
        package_root="/fixed/site",
        workspace_root="/fixed/generated",
        runner_binary="/fixed/native",
        pycache_root="/fixed/root-cache",
        creator_pid=100,
        creator_start=[12, 34],
        port=0,
        runtime_import_roots=["/fixed/stdlib"],
        runtime_sha256={"/fixed/stdlib/module.py": "2" * 64},
        source_sha256={"bluefire/macos_file_access_workspace_bootstrap.py": "3" * 64},
    )
    parent, child = Stream(10), Stream(11)

    class Process:
        def __new__(cls):
            result = object.__new__(cls)
            state["launch_objects"].append(result)
            return result

        def __init__(self, argv, **options):
            assert value._process is self
            state["argv"], state["options"] = argv, options
            state["recipe"] = workspace.json.loads(argv[-1])
            if state["mode"] == "constructor_error":
                raise OSError("fake ambiguous constructor")
            self.pid = 123
            self.returncode = None
            if state["mode"] == "late_constructor":
                state["monotonic"] = state["recipe"]["handshake_deadline_ns"]

    @contextmanager
    def pinned(path, digest):
        assert path == Path("/fixed/python") and digest == "sha256:" + "1" * 64
        yield "/fixed/pinned-python", ()

    def retain(launch, pid):
        assert launch.process is value._process and pid == launch.process.pid
        return SimpleNamespace(launcher=launch.process)

    def observe(process, **options):
        assert process is value._process
        assert options["expected_ids"] == {
            key: value._binding["owner"][key] for key in workspace._IDS
        }
        state["observed"] += 1
        return SimpleNamespace(start=(12, 34))

    def receive(stream, guard):
        assert stream is parent
        guard()
        state["received"] += 1
        recipe = state["recipe"]
        if state["received"] == 1:
            result = dict(
                schema_version="bluefire.macos-workspace-ready.v1",
                nonce=recipe["nonce"],
                binding_digest=recipe["binding_digest"],
                pid=value._process.pid,
                owner=value._binding["owner"],
                handshake_deadline_ns=recipe["handshake_deadline_ns"],
            )
            if state["mode"] == "wrong_ready":
                result["pid"] += 1
            return result
        if state["received"] == 2:
            result = dict(
                schema_version="bluefire.macos-workspace-handshake-complete.v1",
                nonce=recipe["nonce"],
                binding_digest=recipe["binding_digest"],
            )
            if state["mode"] == "wrong_ack":
                result["nonce"] = "9" * 64
            return result
        result = dict(
            schema_version="bluefire.macos-workspace-ui-ready.v1",
            nonce=recipe["nonce"],
            binding_digest=recipe["binding_digest"],
            host="127.0.0.1",
            port=49152,
            browser_bootstrap_capability="A" * 64,
        )
        if state["mode"] == "late_ui":
            state["monotonic"] = recipe["handshake_deadline_ns"]
        elif state["mode"] == "wrong_ui":
            result["host"] = "0.0.0.0"
        elif state["mode"] == "no_ui":
            raise OSError("fake service never became ready")
        return result

    def send(stream, document, guard):
        assert stream is parent
        guard()
        state["sent"].append(document)

    def release(launch):
        assert launch.process is value._process
        state["releases"] += 1
        return state["release"]

    monkeypatch.setattr(workspace, "_root", lambda: None)
    start_bridge = workspace._start_bridge
    monkeypatch.setattr(workspace, "_start_bridge", lambda _owner, _factory: None)
    monkeypatch.setattr(workspace, "os", SimpleNamespace(getpid=lambda: 100))
    monkeypatch.setattr(
        workspace,
        "_query_bsd",
        lambda _pid: SimpleNamespace(
            start_seconds=12,
            start_microseconds=34,
            uid=0,
            real_uid=0,
            saved_uid=0,
            gid=0,
            real_gid=0,
            saved_gid=0,
        ),
    )
    monkeypatch.setattr(
        workspace, "time", SimpleNamespace(time_ns=lambda: state["wall"] * 1_000_000)
    )
    monkeypatch.setattr(workspace, "darwin_clock_ns", lambda: state["monotonic"])
    monkeypatch.setattr(
        workspace,
        "socket",
        SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, socketpair=lambda *_args: (parent, child)),
    )
    monkeypatch.setattr(workspace, "subprocess", SimpleNamespace(Popen=Process, DEVNULL=-3))
    monkeypatch.setattr(workspace, "secrets", SimpleNamespace(token_hex=lambda _size: "5" * 64))
    monkeypatch.setattr(
        workspace,
        "host",
        SimpleNamespace(
            _LaunchProcess=lambda **fields: SimpleNamespace(**fields),
            _retain_owned_host_process=retain,
            _launch_exited_without_reap=lambda _launch: False,
            _terminate_contained_launch=release,
        ),
    )
    monkeypatch.setattr(workspace, "_pinned_launch_file", pinned)
    monkeypatch.setattr(workspace, "observe_owned_child", observe)
    monkeypatch.setattr(workspace, "_receive", receive)
    monkeypatch.setattr(workspace, "_send", send)
    monkeypatch.setattr(
        workspace.validation,
        "_import_inventory",
        lambda roots, hashes: state["import_checks"].append((roots, hashes)),
    )
    return SimpleNamespace(
        owner=value,
        state=state,
        parent=parent,
        child=child,
        bridge_factory=lambda _owner: None,
        start_bridge=start_bridge,
    )


def test_documents_cannot_construct_original_workspace():
    with pytest.raises(TypeError):
        workspace.MacOSWorkspaceOwner(binding())
    with pytest.raises(TypeError):
        original_endpoint.OriginalWorkspaceEndpoint(binding())


def test_fixed_original_host_launch_and_closed_handshake(fake, monkeypatch):
    from enum import IntEnum

    class Family(IntEnum):
        LOCAL = 1

    monkeypatch.setattr(workspace.socket, "AF_UNIX", Family.LOCAL)
    monkeypatch.setattr(bootstrap, "socket", SimpleNamespace(AF_UNIX=Family.LOCAL))
    assert workspace._socket_constant("AF_UNIX") is Family.LOCAL
    assert bootstrap._socket_constant("AF_UNIX") is Family.LOCAL
    fake.owner.start(bridge_factory=fake.bridge_factory)
    selected = fake.owner._binding["owner"]
    assert fake.owner._state == "active"
    assert fake.owner._owned.launcher is fake.owner._process
    assert fake.state["argv"][:4] == ["/fixed/pinned-python", "-I", "-S", "-B"]
    assert fake.state["argv"][4:8] == [
        "-X",
        "pycache_prefix=/fixed/root-cache",
        str(Path("/fixed/site/bluefire/macos_file_access_workspace_bootstrap.py")),
        "11",
    ]
    options = fake.state["options"]
    assert options == dict(
        stdin=-3,
        stdout=-3,
        stderr=-3,
        shell=False,
        close_fds=True,
        start_new_session=True,
        pass_fds=(11,),
        user=selected["effective_uid"],
        group=selected["effective_gid"],
        extra_groups=selected["groups"],
        umask=0o077,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": "/fixed/generated",
            "BLUEFIRE_MACOS_RUNNER": "/fixed/native",
            "BLUEFIRE_MACOS_SANDBOX": str(Path("/fixed/generated") / "sandbox"),
        },
        cwd="/fixed/generated",
    )
    assert fake.child.close_calls == 1 and fake.parent.close_calls == 0
    assert len(fake.state["sent"]) == 1 and fake.state["received"] == 3
    assert fake.state["sent"][0]["schema_version"] == "bluefire.macos-workspace-go.v1"
    assert fake.state["recipe"]["handshake_deadline_ns"] == 5_000_001_000
    assert fake.state["observed"] >= 2
    assert fake.state["import_checks"] == [
        (["/fixed/stdlib"], {"/fixed/stdlib/module.py": "2" * 64}),
        (
            ["/fixed/site"],
            {str(Path("/fixed/site/bluefire/macos_file_access_workspace_bootstrap.py")): "3" * 64},
        ),
    ]
    assert fake.owner.ui_readiness()["port"] == 49152
    assert fake.owner.ui_readiness()["browser_bootstrap_capability"] == "A" * 64


@pytest.mark.parametrize(
    "mode",
    [
        "constructor_error",
        "late_constructor",
        "wrong_ready",
        "wrong_ack",
        "late_ui",
        "wrong_ui",
        "no_ui",
    ],
)
def test_uncertain_or_late_launch_closes_go_and_retains_original(fake, mode):
    fake.state["mode"] = mode
    with pytest.raises((MacOSFileAccessContractError, OSError)):
        fake.owner.start(bridge_factory=fake.bridge_factory)
    assert fake.owner._state == "unknown"
    assert fake.owner._process is fake.state["launch_objects"][0]
    assert fake.parent.close_calls == fake.child.close_calls == 1
    assert fake.state["releases"] == 0
    if mode in ("constructor_error", "late_constructor", "wrong_ready"):
        assert fake.state["sent"] == []
    assert fake.owner._creation_unknown is (mode == "constructor_error")


def test_ambiguous_constructor_never_uses_inferred_pid_cleanup(fake):
    fake.state["mode"] = "constructor_error"
    with pytest.raises(OSError):
        fake.owner.start(bridge_factory=fake.bridge_factory)
    result = fake.owner.close()
    assert result["creation_unknown"] and not result["host_closed"]
    assert result["process_creation_hard_bound"] is False
    assert fake.state["releases"] == fake.owner._pins.close_calls == 0


@pytest.mark.parametrize("child", [False, True])
def test_endpoint_close_uncertainty_is_sticky_and_not_retried(fake, child):
    fake.owner._stream, fake.owner._child_stream = fake.parent, fake.child
    stream = fake.child if child else fake.parent
    stream.fail_close = True
    first = fake.owner.close()
    stream.fail_close = False
    second = fake.owner.close()
    assert first["descriptor_cleanup_unknown"] and second["descriptor_cleanup_unknown"]
    assert stream.close_calls == 1
    assert not second["whole_setup_cleanup_proven"] and not second["task_cleanup_proven"]


def test_child_endpoint_close_failure_still_retains_and_releases_host(fake):
    fake.child.fail_close = True
    with pytest.raises(OSError):
        fake.owner.start(bridge_factory=fake.bridge_factory)
    assert fake.state["sent"] == []
    result = fake.owner.close()
    assert result["host_closed"] and result["descriptor_cleanup_unknown"]
    assert fake.state["releases"] == 1 and fake.child.close_calls == 1


def test_workspace_launch_is_once_only(fake):
    fake.owner.start(bridge_factory=fake.bridge_factory)
    with pytest.raises(MacOSFileAccessContractError):
        fake.owner.start(bridge_factory=fake.bridge_factory)
    assert len(fake.state["launch_objects"]) == 1


@pytest.mark.parametrize(
    "field,value", [("wall", 999), ("wall", 901000), ("monotonic", 900000001000)]
)
def test_original_lifetime_refuses_equality_and_rollback(fake, field, value):
    fake.owner._guard()
    fake.state[field] = value
    with pytest.raises(MacOSFileAccessContractError):
        fake.owner._guard()


def test_cleanup_refusal_cannot_publish_whole_setup_closure(fake):
    fake.owner.start(bridge_factory=fake.bridge_factory)
    fake.state["release"] = False
    result = fake.owner.close()
    assert not result["host_closed"]
    assert fake.owner._pins.close_calls == 0
    assert not result["task_cleanup_proven"] and not result["whole_setup_cleanup_proven"]
    assert not result["fixture_removed"]


def test_wire_real_framing_progress_and_original_guard():
    stream = Stream(10)
    document = dict(schema_version="fixed", nonce="5" * 64)
    raw = canonical_json_bytes(document)
    stream.raw.extend(len(raw).to_bytes(4, "little") + raw)
    checks = []

    def guard():
        checks.append(True)
        return 1.0

    assert workspace._receive(stream, guard) == document
    workspace._send(stream, document, guard)
    assert bytes(stream.output) == len(raw).to_bytes(4, "little") + raw
    assert len(checks) > 4


@pytest.mark.parametrize(
    "raw", [b'{"a":1,"a":1}', b'{"a":NaN}', b'{"a":Infinity}', b'{ "a":1}', b"[]"]
)
def test_wire_rejects_noncanonical_or_ambiguous_documents(raw):
    with pytest.raises((MacOSFileAccessContractError, ValueError)):
        workspace._decode(raw)


@pytest.mark.parametrize("fault", ["empty", "ancillary", "flags", "oversize"])
def test_wire_refuses_eof_ancillary_flags_and_bound(fault):
    stream = Stream(10)
    stream.raw.extend((1).to_bytes(4, "little") + b"x")
    if fault == "empty":
        stream.raw.clear()
    elif fault == "ancillary":
        stream.ancillary = [object()]
    elif fault == "flags":
        stream.flags = 1
    else:
        stream.raw[:] = (workspace.FRAME_MAX + 1).to_bytes(4, "little")
    with pytest.raises(MacOSFileAccessContractError):
        workspace._receive(stream, lambda: 1.0)


def test_wire_short_wait_preserves_partial_frame_without_renewing_guard():
    stream = Stream(10)
    document = {"schema_version": "fixed"}
    raw = canonical_json_bytes(document)
    stream.raw.extend(len(raw).to_bytes(4, "little") + raw)
    receive = stream.recvmsg
    calls = []

    def intermittent(size, ancillary):
        calls.append(True)
        if len(calls) == 2:
            raise TimeoutError("fake bounded socket wait")
        return receive(size, ancillary)

    stream.recvmsg = intermittent
    assert workspace._receive(stream, lambda: 0.025) == document
    assert len(calls) > 2


@pytest.fixture
def endpoint(monkeypatch):
    state = dict(wall=1000, monotonic=1000, parent=100, uid=0, child=123)
    value = object.__new__(original_endpoint.OriginalWorkspaceEndpoint)
    value._closed = value._poisoned = value.local_cleanup_unknown = False
    value._clock = (0, 0)
    value._child_pid = 123
    value._fork_guard = threading.Lock()
    value._io_lock = threading.RLock()
    value._sequence = 0
    value._parent_guard = bootstrap._parent_current
    value._stream = Stream(10)
    value._recipe = dict(
        binding=binding(),
        creator_pid=100,
        creator_start=[12, 34],
        python="/fixed/python",
        handshake_deadline_ns=5_000_001_000,
    )

    def parent(_pid):
        bootstrap._refuse(state["uid"] == 0)

    value._api = SimpleNamespace(darwin_clock_ns=lambda: state["monotonic"])
    monkeypatch.setattr(
        original_endpoint, "time", SimpleNamespace(time_ns=lambda: state["wall"] * 1_000_000)
    )
    process = SimpleNamespace(getppid=lambda: state["parent"], getpid=lambda: state["child"])
    monkeypatch.setattr(original_endpoint, "os", process)
    monkeypatch.setattr(
        bootstrap,
        "os",
        process,
    )
    monkeypatch.setattr(bootstrap, "_parent_image", lambda *_args: None)
    monkeypatch.setattr(bootstrap, "_short_parent", parent)
    monkeypatch.setattr(bootstrap, "_peer_root", lambda _stream: None)
    return SimpleNamespace(value=value, state=state)


@pytest.mark.parametrize(
    "field,value",
    [("wall", 901000), ("monotonic", 900000001000), ("parent", 101), ("uid", 501), ("child", 124)],
)
def test_child_original_endpoint_poisoned_on_parent_or_lifetime_drift(endpoint, field, value):
    endpoint.value.assert_current()
    endpoint.state[field] = value
    with pytest.raises(RuntimeError):
        endpoint.value.assert_current()
    assert endpoint.value._poisoned
    endpoint.state[field] = 1000
    with pytest.raises(RuntimeError):
        endpoint.value.assert_current()


def test_child_handshake_cannot_renew_original_lifetime(endpoint):
    assert endpoint.value.assert_current(handshake=True) == 5.0
    endpoint.state["monotonic"] = 5_000_001_000
    with pytest.raises(RuntimeError):
        endpoint.value.assert_current(handshake=True)
    assert endpoint.value._poisoned


def test_child_endpoint_close_failure_is_once_and_sticky(endpoint):
    endpoint.value._stream.fail_close = True
    with pytest.raises(OSError):
        endpoint.value.close()
    endpoint.value._stream.fail_close = False
    endpoint.value.close()
    assert endpoint.value.local_cleanup_unknown and endpoint.value._poisoned
    assert endpoint.value._stream.close_calls == 1


def test_recipe_preserves_exact_closed_schema():
    document = dict.fromkeys(
        {
            "schema_version",
            "binding",
            "binding_digest",
            "python",
            "python_sha256",
            "package_root",
            "source_sha256",
            "workspace_root",
            "runner_binary",
            "runner_sha256",
            "config",
            "port",
            "creator_pid",
            "creator_start",
            "nonce",
            "handshake_deadline_ns",
            "runtime_import_roots",
            "runtime_sha256",
            "pycache_root",
        },
        None,
    )
    document["schema_version"] = "bluefire.macos-workspace-bootstrap.v1"
    assert bootstrap._recipe(canonical_json_bytes(document).decode()) == document
    changed = deepcopy(document)
    changed["command"] = "not permitted"
    with pytest.raises(RuntimeError):
        bootstrap._recipe(canonical_json_bytes(changed).decode())
    with pytest.raises(RuntimeError):
        bootstrap._recipe('{"schema_version":"x","schema_version":"x"}')


@pytest.mark.parametrize(
    "mode", ["absent", "empty", "entry", "unproven", "free_error", "ignore_ownership"]
)
def test_positive_acl_policy_and_release_with_fake_public_api(monkeypatch, mode):
    state = dict(error=0, freed=0)

    class Function:
        def __init__(self, callback):
            self.callback = callback

        def __call__(self, *args):
            return self.callback(*args)

    def filesystem(_descriptor, pointer):
        pointer._obj.f_flags = 0x00200000 if mode == "ignore_ownership" else 0
        return 0

    def acl(_descriptor, flavor):
        assert flavor == 0x100
        state["error"] = errno.ENOENT if mode == "absent" else errno.EACCES
        return None if mode in ("absent", "unproven") else 123

    def entry(_acl, ordinal, pointer):
        assert ordinal == 0
        if mode == "entry":
            pointer._obj.value = 456
            return 0
        state["error"] = errno.EINVAL
        return -1

    def release(_acl):
        state["freed"] += 1
        return -1 if mode == "free_error" else 0

    library = SimpleNamespace(
        fstatfs=Function(filesystem),
        acl_get_fd_np=Function(acl),
        acl_get_entry=Function(entry),
        acl_free=Function(release),
    )
    view = SimpleNamespace(
        **{
            name: getattr(ctypes, name)
            for name in ("sizeof", "POINTER", "c_int", "c_void_p", "byref")
        }
    )
    view.CDLL = lambda *_args, **_options: library
    view.set_errno = lambda number: state.update(error=number)
    view.get_errno = lambda: state["error"]
    monkeypatch.setattr(bootstrap, "ctypes", view)
    monkeypatch.setattr(bootstrap, "sys", SimpleNamespace(platform="darwin"))
    if mode in ("absent", "empty"):
        bootstrap._descriptor_security(10)
    else:
        with pytest.raises(RuntimeError):
            bootstrap._descriptor_security(10)
    assert state["freed"] == (1 if mode in ("empty", "entry", "free_error") else 0)


@pytest.mark.parametrize("mode", ["exact", "unlisted_source", "unlisted_bytecode", "extra_pin"])
def test_installed_import_inventory_is_exact_before_application_import(monkeypatch, mode):
    checked = []

    class InstalledPath(PurePosixPath):
        def lstat(self):
            return SimpleNamespace(st_size=10)

        def is_file(self):
            return False

    leaves = ["module.py", "native.so"]
    expected = {"/fixed/site/module.py": "1" * 64, "/fixed/site/native.so": "2" * 64}
    if mode == "unlisted_source":
        leaves.append("unlisted.py")
    elif mode == "unlisted_bytecode":
        leaves.append("unlisted.pyc")
    elif mode == "extra_pin":
        expected["/fixed/site/missing.py"] = "3" * 64
    monkeypatch.setattr(bootstrap, "Path", InstalledPath)
    monkeypatch.setattr(bootstrap, "_parents", lambda _path: None)
    monkeypatch.setattr(bootstrap, "_directory", lambda _path: None)
    monkeypatch.setattr(
        bootstrap, "_protected_file", lambda path, digest: checked.append((str(path), digest))
    )
    monkeypatch.setattr(
        bootstrap,
        "os",
        SimpleNamespace(walk=lambda *_args, **_options: [("/fixed/site", [], leaves)]),
    )
    if mode == "exact":
        bootstrap._import_inventory(["/fixed/site"], expected)
        assert dict(checked) == expected
    else:
        with pytest.raises(RuntimeError):
            bootstrap._import_inventory(["/fixed/site"], expected)


@pytest.mark.parametrize("mode", ["normal", "pin_failure"])
def test_parent_preparation_lock_precedes_retention_and_resource_pins(fake, monkeypatch, mode):
    from bluefire.macos_file_access_creator import MacOSFileAccessCreator

    retained = []
    checked = []
    original = binding()

    class PreparedPath(PurePosixPath):
        def lstat(self):
            return SimpleNamespace(st_mode=0o40700, st_uid=501)

        def stat(self):
            return self.lstat()

    class Config:
        def to_dict(self):
            return {}

    creator = object.__new__(MacOSFileAccessCreator)
    creator._runtime = SimpleNamespace(
        runner_binary=PreparedPath("/fixed/native"), runner_binary_digest="sha256:" + "1" * 64
    )
    monkeypatch.setattr(
        MacOSFileAccessCreator, "review_context", lambda *_args: {"binding": original}
    )
    monkeypatch.setattr(workspace, "BlueFireConfig", Config)
    monkeypatch.setattr(workspace, "Path", PreparedPath)
    monkeypatch.setattr(workspace, "WORKSPACE_PARENT", PreparedPath("/fixed/workspaces"))
    monkeypatch.setattr(workspace, "_config", lambda *_args: None)
    fork_callbacks = {}
    monkeypatch.setattr(
        workspace,
        "os",
        SimpleNamespace(
            getpid=lambda: 100,
            register_at_fork=lambda **callbacks: fork_callbacks.update(callbacks),
            listdir=lambda path: (
                ["runs"] if str(path) == "/fixed/workspaces/" + original["generation"] else []
            ),
            path=SimpleNamespace(samestat=lambda *_args: True),
        ),
    )

    def protection(*_args, **_options):
        assert len(retained) == 1
        assert retained[0]._state == "preparing" and retained[0]._lock.locked()
        with pytest.raises(MacOSFileAccessContractError):
            retained[0].close()
        checked.append(True)

    monkeypatch.setattr(workspace, "_parents", protection)
    monkeypatch.setattr(workspace, "_directory", protection)
    monkeypatch.setattr(workspace.validation, "_import_inventory", protection)

    def file_pin(path, digest, *_args, **_options):
        if mode == "pin_failure":
            raise OSError("fake incomplete resource pin")
        return dict(path=str(path), sha256=digest, identity=[1, 2, 3, 4, 5, 10, 7], fd=20)

    monkeypatch.setattr(workspace, "_file", file_pin)
    names = {
        name: "2" * 64
        for name in (
            "bluefire/__init__.py",
            "bluefire/macos_file_access_workspace.py",
            "bluefire/macos_file_access_workspace_bootstrap.py",
            "bluefire/macos_file_access_workspace_validation.py",
            "bluefire/macos_file_access_endpoint.py",
            "bluefire/service.py",
            "bluefire/api.py",
        )
    }
    options = dict(
        python=PreparedPath("/fixed/python"),
        python_sha256="1" * 64,
        package_root=PreparedPath("/fixed/site"),
        source_sha256=names,
        runtime_import_roots=["/fixed/stdlib"],
        runtime_sha256={"/fixed/stdlib/module.py": "3" * 64},
        workspace_root=workspace.WORKSPACE_PARENT / original["generation"],
        config=Config(),
        retained=retained,
    )
    if mode == "pin_failure":
        with pytest.raises(OSError):
            workspace.MacOSWorkspaceOwner.prepare(creator, **options)
        owner = retained[0]
        assert owner._state == "unknown" and owner._cleanup_unknown
    else:
        owner = workspace.MacOSWorkspaceOwner.prepare(creator, **options)
        assert owner._state == "prepared"
    assert checked and owner is retained[0]
    assert not owner._lock.locked() and owner._pins is not fake.owner._pins
    assert set(fork_callbacks) == {"before", "after_in_parent", "after_in_child"}
    if mode == "normal":
        assert len(owner._files) == 3


@pytest.mark.parametrize(
    "mode", ["normal", "late_ui", "wrong_address", "endpoint_close_error", "server_close_error"]
)
def test_normal_entry_typed_postbind_ui_and_nested_local_settlement(monkeypatch, mode):
    state = dict(
        guards=0,
        guard_kinds=[],
        mkdirs=[],
        frames=[],
        joined=0,
        service_closed=0,
        endpoint_closed=0,
    )

    class WorkspacePath(type(Path())):
        def mkdir(self, mode=0o777, parents=False, exist_ok=False):
            assert self == Path("/fixed/workspace/sandbox")
            assert (mode, parents, exist_ok) == (0o700, False, False)
            assert state["guard_kinds"] == [True, False]
            state["mkdirs"].append(self)

    class Event:
        def __init__(self):
            self.value = False

        def set(self):
            self.value = True

        def is_set(self):
            return self.value

        def wait(self, _timeout):
            return True

    class Thread:
        def __init__(self, *, target, **_options):
            self.target = target

        def start(self):
            self.target()

        def join(self, *, timeout):
            assert timeout == 1
            state["joined"] += 1

    class Service:
        def __init__(self, *, config, runs_dir):
            assert config == "validated" and runs_dir == Path("/fixed/workspace/runs")
            assert state["mkdirs"] == [Path("/fixed/workspace/sandbox")]

        def close(self):
            state["service_closed"] += 1

    class Endpoint:
        _recipe = dict(
            config={},
            workspace_root="/fixed/workspace",
            port=0,
            nonce="5" * 64,
            binding_digest="sha256:" + "6" * 64,
        )
        _stream = object()
        _poisoned = False

        def assert_current(self, handshake=False):
            assert handshake is (len(state["guard_kinds"]) != 1)
            state["guard_kinds"].append(handshake)
            if handshake:
                state["guards"] += 1
                if mode == "late_ui" and state["guards"] >= 2:
                    raise RuntimeError("fake original startup expiry")
            return 1.0

        def close(self):
            state["endpoint_closed"] += 1
            if mode == "endpoint_close_error":
                raise OSError("fake endpoint close failure")

    def send(_stream, document, guard):
        guard()
        state["frames"].append(document)

    value = Endpoint()
    value._api = SimpleNamespace(_config=lambda *_args: "validated", _send=send)

    def serve(service, **options):
        assert options["host"] == "127.0.0.1" and options["port"] == 0
        assert options["browser_bootstrap_capability"] == "A" * 64
        address = ("0.0.0.0", 49152) if mode == "wrong_address" else ("127.0.0.1", 49152)
        options["on_ready"](SimpleNamespace(server_address=address))
        if mode == "server_close_error":
            raise OSError("fake serve server-close failure")
        service.close()

    monkeypatch.setitem(
        sys.modules,
        "bluefire.api",
        SimpleNamespace(generate_browser_bootstrap_capability=lambda: "A" * 64, serve=serve),
    )
    monkeypatch.setitem(sys.modules, "bluefire.service", SimpleNamespace(BlueFireService=Service))
    monkeypatch.setattr(bootstrap, "Path", WorkspacePath)
    monkeypatch.setattr(bootstrap, "threading", SimpleNamespace(Event=Event, Thread=Thread))
    if mode == "normal":
        bootstrap._normal_entry(value)
    else:
        with pytest.raises((RuntimeError, OSError)):
            bootstrap._normal_entry(value)
    assert state["service_closed"] >= 1 and state["endpoint_closed"] == 1
    assert state["guard_kinds"][:2] == [True, False]
    assert state["mkdirs"] == [Path("/fixed/workspace/sandbox")]
    if mode in ("late_ui", "wrong_address"):
        assert state["frames"] == [] and state["joined"] == 0
    else:
        assert state["joined"] == 1
        assert state["frames"] == [
            dict(
                schema_version="bluefire.macos-workspace-ui-ready.v1",
                nonce="5" * 64,
                binding_digest="sha256:" + "6" * 64,
                host="127.0.0.1",
                port=49152,
                browser_bootstrap_capability="A" * 64,
            )
        ]


@pytest.mark.parametrize("failure", ["eof", "deadline"])
@pytest.mark.parametrize("close_error", [False, True])
def test_normal_entry_monitor_poison_shutdown_and_settlement(
    endpoint, monkeypatch, failure, close_error
):
    from enum import IntFlag

    class Flags(IntFlag):
        PEEK = 2
        DONTWAIT = 4

    state = dict(
        waited=0,
        selected=0,
        received=0,
        shutdown=0,
        joined=0,
        service_closed=0,
        mkdirs=[],
        frames=[],
    )

    class WorkspacePath(type(Path())):
        def mkdir(self, mode=0o777, parents=False, exist_ok=False):
            assert self == Path("/fixed/workspace/sandbox")
            assert (mode, parents, exist_ok) == (0o700, False, False)
            state["mkdirs"].append(self)

    events = []
    value = endpoint.value
    value._recipe.update(
        config={},
        workspace_root="/fixed/workspace",
        port=0,
        nonce="5" * 64,
        binding_digest="sha256:" + "6" * 64,
    )
    value._stream.fail_close = close_error

    class Event:
        def __init__(self):
            self.value = False
            events.append(self)

        def set(self):
            self.value = True

        def is_set(self):
            return self.value

        def wait(self, timeout):
            assert self is events[0] and timeout == 0.025
            state["waited"] += 1
            assert state["waited"] <= 2
            return self.value or state["waited"] > 1

    class Thread:
        def __init__(self, *, target, name, daemon):
            assert name == "macos-workspace-original-lease" and daemon is True
            self.target = target

        def start(self):
            if failure == "deadline":
                endpoint.state["monotonic"] = value._recipe["binding"]["original_deadline_ns"]
            self.target()

        def join(self, *, timeout):
            assert timeout == 1 and events[1].is_set()
            state["joined"] += 1

    class Service:
        def __init__(self, *, config, runs_dir):
            assert config == "validated" and runs_dir == Path("/fixed/workspace/runs")
            assert state["mkdirs"] == [Path("/fixed/workspace/sandbox")]

        def close(self):
            state["service_closed"] += 1

    def receive(size, flags):
        assert failure == "eof" and size == 1 and flags == 6
        state["received"] += 1
        return b""

    def select(read, write, error, timeout):
        assert read == [value._stream] and write == error == [] and timeout == 0
        state["selected"] += 1
        return read, [], []

    def shutdown():
        assert value._poisoned
        state["shutdown"] += 1

    def send(stream, document, guard):
        assert stream is value._stream
        guard()
        state["frames"].append(document)

    def serve(service, **options):
        assert options["host"] == "127.0.0.1" and options["port"] == 0
        options["on_ready"](SimpleNamespace(server_address=("127.0.0.1", 49152), shutdown=shutdown))
        assert state["shutdown"] == 1 and events[1].is_set()

    value._stream.recv = receive
    value._api._config = lambda *_args: "validated"
    value._api._send = send
    monkeypatch.setitem(
        sys.modules,
        "bluefire.api",
        SimpleNamespace(generate_browser_bootstrap_capability=lambda: "A" * 64, serve=serve),
    )
    monkeypatch.setitem(sys.modules, "bluefire.service", SimpleNamespace(BlueFireService=Service))
    monkeypatch.setattr(bootstrap, "Path", WorkspacePath)
    monkeypatch.setattr(bootstrap, "threading", SimpleNamespace(Event=Event, Thread=Thread))
    monkeypatch.setattr(original_endpoint, "select", SimpleNamespace(select=select))
    monkeypatch.setattr(
        original_endpoint,
        "socket",
        SimpleNamespace(MSG_PEEK=Flags.PEEK, MSG_DONTWAIT=Flags.DONTWAIT),
    )
    if close_error:
        with pytest.raises(OSError, match="fake uncertain descriptor close"):
            bootstrap._normal_entry(value)
    else:
        bootstrap._normal_entry(value)
    assert value._poisoned and value._closed and value.local_cleanup_unknown is close_error
    assert state["mkdirs"] == [Path("/fixed/workspace/sandbox")]
    assert (
        value._stream.close_calls
        == state["shutdown"]
        == state["joined"]
        == state["service_closed"]
        == 1
    )
    assert state["waited"] == 1 and all(event.is_set() for event in events)
    assert state["selected"] == state["received"] == (1 if failure == "eof" else 0)
    assert len(state["frames"]) == 1
    assert state["frames"][0]["schema_version"] == "bluefire.macos-workspace-ui-ready.v1"


@pytest.mark.parametrize(
    "mode", ["normal", "short_result", "wrong_pid", "zombie", "traced", "uid", "saved_gid"]
)
def test_public_short_parent_identity_without_starttime_claim(monkeypatch, mode):
    calls = []

    class Query:
        def __call__(self, parent, flavor, argument, pointer, size):
            calls.append((parent, flavor, argument, size))
            facts = pointer._obj
            facts.pid, facts.status, facts.flags = 100, 2, 0x10
            if mode == "wrong_pid":
                facts.pid = 101
            elif mode == "zombie":
                facts.status = 5
            elif mode == "traced":
                facts.flags |= 2
            elif mode == "uid":
                facts.uid = 501
            elif mode == "saved_gid":
                facts.saved_gid = 501
            return 63 if mode == "short_result" else 64

    view = SimpleNamespace(
        **{
            name: getattr(ctypes, name)
            for name in ("sizeof", "c_int", "c_uint64", "c_void_p", "byref")
        }
    )
    view.CDLL = lambda *_args, **_options: SimpleNamespace(proc_pidinfo=Query())
    monkeypatch.setattr(bootstrap, "ctypes", view)
    if mode == "normal":
        bootstrap._short_parent(100)
    else:
        with pytest.raises(RuntimeError):
            bootstrap._short_parent(100)
    assert calls == [(100, 13, 0, 64)]
    assert not hasattr(bootstrap._ShortBSD, "start_seconds")


def test_original_parent_relation_is_rechecked_after_image_lookup(monkeypatch):
    state = dict(parent=100, observations=[])
    monkeypatch.setattr(bootstrap, "os", SimpleNamespace(getppid=lambda: state["parent"]))
    monkeypatch.setattr(
        bootstrap, "_short_parent", lambda parent: state["observations"].append(parent)
    )
    monkeypatch.setattr(bootstrap, "_peer_root", lambda _stream: None)
    monkeypatch.setattr(bootstrap, "_parent_image", lambda *_args: state.update(parent=1))
    with pytest.raises(RuntimeError):
        bootstrap._parent_current(dict(creator_pid=100, python="/fixed/python"), Stream(10))
    assert state["observations"] == [100, 100]


def test_sequential_descendant_pin_closes_immediately_not_in_retained_stack(monkeypatch):
    import hashlib
    from contextlib import ExitStack

    raw = b"fixed installed source"
    details = SimpleNamespace(
        st_dev=1,
        st_ino=2,
        st_mode=0o100444,
        st_uid=0,
        st_gid=0,
        st_size=len(raw),
        st_mtime_ns=3,
        st_nlink=1,
    )
    state = dict(closed=[], reads=0, checked=[])

    class InstalledPath(PurePosixPath):
        def lstat(self):
            return details

    def read(descriptor, _size):
        assert descriptor == 20
        state["reads"] += 1
        return raw if state["reads"] == 1 else b""

    view = SimpleNamespace(
        open=lambda *_args: 20,
        fstat=lambda _fd: details,
        read=read,
        close=state["closed"].append,
        O_RDONLY=0,
        O_NOFOLLOW=1,
        O_CLOEXEC=2,
        path=SimpleNamespace(samestat=lambda first, second: first is second),
    )
    monkeypatch.setattr(workspace, "os", view)
    monkeypatch.setattr(workspace, "_validate_darwin_descriptor_security", state["checked"].append)
    monkeypatch.setattr(workspace.validation, "_parents", lambda _path: None)
    retained = ExitStack()
    result = workspace._file(
        InstalledPath("/fixed/site/module.py"),
        hashlib.sha256(raw).hexdigest(),
        retained,
        {},
        retain=False,
    )
    assert result["fd"] is None and state["closed"] == [20] and state["checked"] == [20]
    retained.close()
    assert state["closed"] == [20]


def test_retained_root_directory_budget_refuses_before_open():
    from contextlib import ExitStack

    with pytest.raises(MacOSFileAccessContractError):
        workspace._directory(
            Path("/fixed/another-root"),
            ExitStack(),
            {str(index): {} for index in range(workspace.HELD_DIRECTORY_MAX)},
        )


def test_prelaunch_inventory_failure_cannot_create_or_send_go(fake, monkeypatch):
    def changed(*_args):
        raise RuntimeError("fake installation changed before launch")

    monkeypatch.setattr(workspace.validation, "_import_inventory", changed)
    with pytest.raises(RuntimeError):
        fake.owner.start(bridge_factory=fake.bridge_factory)
    assert fake.state["launch_objects"] == fake.state["sent"] == []
    assert fake.owner._state == "unknown"


@pytest.mark.parametrize("mode", ["different_pid", "different_start"])
def test_root_original_generation_not_reconstituted_from_recipe(fake, monkeypatch, mode):
    if mode == "different_pid":
        monkeypatch.setattr(workspace, "os", SimpleNamespace(getpid=lambda: 101))
    else:
        monkeypatch.setattr(
            workspace,
            "_query_bsd",
            lambda _pid: SimpleNamespace(
                start_seconds=12,
                start_microseconds=35,
                uid=0,
                real_uid=0,
                saved_uid=0,
                gid=0,
                real_gid=0,
                saved_gid=0,
            ),
        )
    with pytest.raises(MacOSFileAccessContractError):
        fake.owner.start(bridge_factory=fake.bridge_factory)
    assert fake.state["launch_objects"] == fake.state["sent"] == []


def test_parent_current_uncertainty_is_sticky_not_reconnectable(fake, monkeypatch):
    fake.owner.start(bridge_factory=fake.bridge_factory)
    original = workspace.observe_owned_child

    def failed(*_args, **_options):
        raise OSError("fake original child observation uncertainty")

    monkeypatch.setattr(workspace, "observe_owned_child", failed)
    with pytest.raises(OSError):
        fake.owner.assert_current()
    monkeypatch.setattr(workspace, "observe_owned_child", original)
    with pytest.raises(MacOSFileAccessContractError):
        fake.owner.assert_current()
    assert fake.owner._state == "unknown" and fake.parent.close_calls == fake.child.close_calls == 1


def test_child_clock_api_uncertainty_poisoned_before_any_retry(endpoint):
    def failed():
        raise OSError("fake original clock observation uncertainty")

    endpoint.value._api.darwin_clock_ns = failed
    with pytest.raises(OSError):
        endpoint.value.assert_current()
    endpoint.value._api.darwin_clock_ns = lambda: 1000
    with pytest.raises(RuntimeError):
        endpoint.value.assert_current()
    assert endpoint.value._poisoned


def test_original_setup_is_detached_inactive_history(endpoint):
    first = endpoint.value.current_setup()
    first["binding"]["control_revision"] = 99
    assert endpoint.value.current_setup()["binding"]["control_revision"] == 1
    assert first["schema_version"] == "bluefire.macos-file-access-setup.v1"


@pytest.mark.parametrize("failure", ["wrong_response", "cancelled_wait", "lost_channel"])
def test_original_child_exchange_serializes_sequence_and_poisoned_loss(
    endpoint, monkeypatch, failure
):
    from bluefire import macos_file_access_bridge as bridge

    value = endpoint.value
    monkeypatch.setattr(
        bridge, "time", SimpleNamespace(time_ns=lambda: endpoint.state["wall"] * 1_000_000)
    )
    cancelled = threading.Event()
    sent = []

    def send(stream, document, guard):
        assert stream is value._stream and value._io_lock._is_owned()
        guard()
        sent.append(document)

    def receive(stream, guard):
        assert stream is value._stream and value._io_lock._is_owned()
        if failure == "cancelled_wait":
            cancelled.set()
            guard()
        if failure == "lost_channel":
            raise OSError("fake original channel loss")
        response = {
            "schema_version": "bluefire.macos-workspace-response.v1",
            "sequence": 2,
            "operation": "review_context",
            "request_digest": content_hash(sent[0]),
            "payload": {},
        }
        return response

    value._api._send = send
    value._api._receive = receive
    with pytest.raises((MacOSFileAccessContractError, OSError)):
        bridge.exchange(value, "review_context", {"operation": "baseline"}, cancelled)
    assert len(sent) == value._sequence == 1
    assert value._poisoned and value._closed and value._stream.close_calls == 1
    with pytest.raises(RuntimeError):
        value.assert_current()


@pytest.mark.parametrize("failure", ["slow_chunks", "truncated", "cancelled"])
def test_original_child_frame_five_second_bound_survives_short_socket_waits(
    endpoint, monkeypatch, failure
):
    from bluefire import macos_file_access_bridge as bridge

    value = endpoint.value
    cancelled = threading.Event()
    state = dict(reads=0, sent=[])
    monotonic_start = endpoint.state["monotonic"]
    monkeypatch.setattr(
        bridge, "time", SimpleNamespace(time_ns=lambda: endpoint.state["wall"] * 1_000_000)
    )

    def send(stream, request, guard):
        guard()
        state["sent"].append(request)
        response = {
            "schema_version": "bluefire.macos-workspace-response.v1",
            "sequence": 1,
            "operation": "review_context",
            "request_digest": content_hash(request),
            "payload": {"review": "inactive"},
        }
        raw = canonical_json_bytes(response)
        stream.raw.extend(len(raw).to_bytes(4, "little") + raw)
        if failure == "truncated":
            stream.raw[:] = stream.raw[:2]

    receive = value._stream.recvmsg

    def delayed(size, ancillary):
        state["reads"] += 1
        endpoint.state["monotonic"] += 25_000_000
        if failure == "cancelled" and state["reads"] == 3:
            cancelled.set()
        if state["reads"] <= 4 or (failure == "truncated" and not value._stream.raw):
            raise TimeoutError("fake short poll; original deadline stays fixed")
        return receive(size, ancillary)

    value._stream.recvmsg = delayed
    value._api._send = send
    value._api._receive = workspace._receive
    if failure == "slow_chunks":
        assert bridge.exchange(value, "review_context", {"operation": "baseline"}, cancelled) == {
            "review": "inactive"
        }
        assert endpoint.state["monotonic"] - monotonic_start > 25_000_000
        assert not value._poisoned and value._stream.close_calls == 0
    else:
        with pytest.raises(MacOSFileAccessContractError):
            bridge.exchange(value, "review_context", {"operation": "baseline"}, cancelled)
        assert value._poisoned and value._closed and value._stream.close_calls == 1
        if failure == "truncated":
            assert endpoint.state["monotonic"] == monotonic_start + 5_000_000_000
    assert len(state["sent"]) == 1 and value._sequence == 1


def test_copied_parent_owner_closes_only_its_endpoint_copies(fake, monkeypatch):
    fake.owner.start(bridge_factory=fake.bridge_factory)
    fake.owner._before_fork()
    fake.owner._after_fork_child()
    assert fake.owner._state == "unknown" and fake.owner._creation_unknown
    assert fake.parent.close_calls == fake.child.close_calls == 1
    assert not fake.owner._fork_guard.locked() and not fake.owner._lock.locked()
    assert fake.state["releases"] == fake.owner._pins.close_calls == 0
    monkeypatch.setattr(workspace, "os", SimpleNamespace(getpid=lambda: 101))
    with pytest.raises(MacOSFileAccessContractError):
        fake.owner.close()
    assert fake.state["releases"] == fake.owner._pins.close_calls == 0


@pytest.mark.parametrize("fail_close", [False, True])
def test_copied_child_endpoint_is_poisoned_and_closed_without_inherited_mutex(endpoint, fail_close):
    endpoint.value._stream.fail_close = fail_close
    endpoint.value._before_fork()
    endpoint.value._after_fork_child()
    assert endpoint.value._poisoned and endpoint.value._closed
    assert endpoint.value._stream.close_calls == 1
    assert endpoint.value.local_cleanup_unknown is fail_close
    assert not endpoint.value._fork_guard.locked()
    with pytest.raises(RuntimeError):
        endpoint.value.assert_current()


def test_parent_fork_callback_releases_only_its_guard(fake, endpoint):
    for value in (fake.owner, endpoint.value):
        value._before_fork()
        assert value._fork_guard.locked()
        value._after_fork_parent()
        assert not value._fork_guard.locked()
    assert fake.owner._state == "prepared" and not endpoint.value._poisoned


def test_import_inventory_walk_error_cannot_be_silently_skipped(monkeypatch):
    class InstalledPath(PurePosixPath):
        def lstat(self):
            return SimpleNamespace(st_size=10)

        def is_file(self):
            return False

    def walk(_root, *, followlinks, onerror):
        assert followlinks is False
        onerror(PermissionError("fake unreadable import descendant"))
        return []

    monkeypatch.setattr(bootstrap, "Path", InstalledPath)
    monkeypatch.setattr(bootstrap, "_parents", lambda _path: None)
    monkeypatch.setattr(bootstrap, "_directory", lambda _path: None)
    monkeypatch.setattr(bootstrap, "os", SimpleNamespace(walk=walk))
    with pytest.raises(PermissionError):
        bootstrap._import_inventory(["/fixed/site"], {"/fixed/site/module.py": "1" * 64})


@pytest.mark.parametrize("mode", ["omitted", "none", "non_callable"])
def test_missing_bridge_factory_refuses_before_any_host_launch(fake, mode):
    options = {} if mode == "omitted" else {"bridge_factory": None if mode == "none" else False}
    with pytest.raises(MacOSFileAccessContractError):
        fake.owner.start(**options)
    assert fake.state["launch_objects"] == fake.state["sent"] == []
    assert fake.owner._state == "unknown" and fake.owner._bridge is None
    with pytest.raises(MacOSFileAccessContractError):
        fake.owner.start(bridge_factory=fake.bridge_factory)
    assert fake.state["launch_objects"] == fake.state["sent"] == []


def test_bridge_factory_failure_keeps_existing_unknown_startup_cleanup(fake, monkeypatch):
    events = []

    class Bridge:
        def start(self):
            events.append("start")
            raise RuntimeError("fake original bridge start failed")

        def close(self):
            events.append("close")

        def join(self):
            events.append("join")

    retained = Bridge()

    def factory(owner):
        assert owner is fake.owner and owner._state == "active"
        assert owner._ui_ready["port"] == 49152
        assert owner._lock.locked()
        events.append("attach")
        return retained

    monkeypatch.setattr(workspace, "_start_bridge", fake.start_bridge)
    with pytest.raises(RuntimeError, match="fake original bridge start failed"):
        fake.owner.start(bridge_factory=factory)
    assert events == ["attach", "start"]
    assert fake.owner._bridge is retained and fake.owner._state == "unknown"
    assert fake.parent.close_calls == fake.child.close_calls == 1
    with pytest.raises(MacOSFileAccessContractError):
        fake.owner.start(bridge_factory=factory)
    assert events == ["attach", "start"]


def test_injected_bridge_starts_only_after_original_ui_ready_while_owner_is_locked(
    fake, monkeypatch
):
    events = []
    retained = SimpleNamespace(
        start=lambda: events.append("start"),
        close=lambda: events.append("close"),
        join=lambda: events.append("join"),
    )

    def factory(owner):
        assert owner is fake.owner and owner._state == "active"
        assert owner._ui_ready["port"] == 49152 and owner._lock.locked()
        events.append("attach")
        return retained

    monkeypatch.setattr(workspace, "_start_bridge", fake.start_bridge)
    fake.owner.start(bridge_factory=factory)
    assert fake.owner._bridge is retained and fake.owner._state == "active"
    assert events == ["attach", "start"]
