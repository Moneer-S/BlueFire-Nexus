"""Fake privileged boundary only: no actual SAM, token, ACL, DPAPI or setup calls."""

from __future__ import annotations

import copy
import ctypes
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import _windows_file_access_setup_native as write
from bluefire import secret_store
from bluefire import windows_file_access_enrollment_setup as setup
from bluefire import windows_file_access_setup_process as process
from bluefire.util import canonical_json_bytes
from bluefire.windows_session_facts import WindowsPrincipalFacts
from tests_platform.test_windows_file_access_enrollment import declared_candidate

GENERATION = "0123456789abcdef0123456789abcdef"
ISSUED = 1_700_000_000_000


def source_facts():
    image = declared_candidate()["native_image"]
    digest = "sha256:" + "a" * 64
    transport = {
        "schema_version": "bluefire.runner-transport-identity.v1",
        "runner_id": "bluefire-rust-runner.v1",
        "client_id": "synthetic-client",
        "transport": "mutual-tls-loopback",
        "tls": "TLSv1.3",
        "server_fingerprint": digest,
        "client_fingerprint": digest,
        "authenticated_peer_fingerprint": digest,
        "enrollment_generation": digest,
        "runner_binary_digest": image["sha256"],
        "inventory_digest": digest,
    }
    capability = {
        "schema_version": "bluefire.windows-file-worker-capability.v1",
        "runner_id": "bluefire-rust-runner.v1",
        "runner_version": "0.1.0",
        "platform": "windows",
        "architecture": "x86_64",
        "supported": True,
        "worker_command": "windows-file-worker",
        "worker_schema": setup.contract.REQUEST_SCHEMA,
        "read_schema": setup.contract.PROOF_SCHEMA,
        "scope": "protocol_support_only",
    }
    return {
        "source_profile_id": "existing-source",
        "source_enrollment_generation": digest,
        "transport": transport,
        "native_image": image,
        "capability": capability,
    }


class FakeGate:
    fail = False

    def check(self):
        if self.fail:
            raise RuntimeError("synthetic stopped")


class FakeCredential:
    def __init__(self, backend):
        self.backend, self.wiped = backend, False

    def protect(self, purpose):
        self.backend.events.append("protect")
        self.backend.purpose = purpose
        if self.backend.fail == "protect":
            raise RuntimeError("private input must not escape")
        return b"synthetic opaque ciphertext"

    def wipe(self):
        self.wiped = True


class FakeBackend:
    def __init__(self, gate):
        self.gate = gate
        row = declared_candidate()["resource"]
        self.owner = WindowsPrincipalFacts(71, 72, row["owner_sid"], 73, 74, 75, 1, True)
        self.reader = row["reader_sid"]
        self.files, self.directories, self.identities = {}, set(), {}
        self.events, self.fail, self.after = [], None, None
        self.credentials = []
        self.closed = 0

    def current(self):
        self.gate.check()

    def _event(self, label):
        self.events.append(label)
        if self.after:
            self.after(label)
        if self.fail == label:
            raise RuntimeError("synthetic failure containing private input")

    def observe(self, path, *, directory, protected=True):
        if path not in self.identities:
            index = len(self.identities) + 1
            self.identities[path] = {
                "volume_serial": "fedcba9876543210",
                "file_id": index.to_bytes(16, "little").hex(),
            }
        return {
            "identity": self.identities[path],
            "size": 0 if directory else len(self.files[path]),
        }

    def absent(self, path, *, directory):
        self._event("absent:" + path)
        if path in self.directories or path in self.files:
            raise RuntimeError("preexisting synthetic object")

    def directory(self, path, policy=None):
        assert path not in self.directories
        self.directories.add(path)
        self._event("directory:" + path)
        return self.observe(path, directory=True)

    def publish(self, path, raw, policy=None):
        assert path not in self.files
        self.files[path] = raw
        self._event("publish:" + path)
        return self.observe(path, directory=False)

    def missing_account(self, generation):
        assert generation == GENERATION
        self._event("missing_account")

    def account(self, generation, credential, expires):
        assert setup._INTENT_PATH in self.files and expires == (ISSUED + 900000) // 1000
        self._event("account")
        return self.reader

    def verify_account(self, generation, reader, expires):
        assert reader == self.reader and expires == (ISSUED + 900000) // 1000
        self._event("verify_account")

    def verify_all(self):
        self._event("verify_all")

    def read_public(self, path, maximum):
        assert len(self.files[path]) <= maximum
        return self.files[path]

    def close(self):
        self.closed += 1
        if self.fail == "cleanup":
            raise RuntimeError("cleanup unknown")


@pytest.fixture
def lifecycle(monkeypatch):
    gate = FakeGate()
    backend = FakeBackend(gate)
    monkeypatch.setattr(setup.time, "time_ns", lambda: ISSUED * 1000000)

    def credential():
        item = FakeCredential(backend)
        backend.credentials.append(item)
        return item

    monkeypatch.setattr(write, "_Credential", credential)
    return backend, gate


def run(backend, gate):
    return setup._run_setup(
        backend, source_facts(), backend.owner, gate, generation=GENERATION, issued=ISSUED
    )


def test_fake_original_lifecycle_creates_receipt_record_anchor_in_order(lifecycle):
    backend, gate = lifecycle
    result = run(backend, gate)
    assert result["publication"] == "complete" and result["context_available"] is False
    assert result["settled"] is False and result["account_cleanup_required"] is True
    assert result["external_hard_deadline_required"] is True
    events = backend.events
    assert events.index("publish:" + setup._INTENT_PATH) < events.index("account")
    assert events.index("publish:" + setup._RECEIPT_PATH) < events.index(
        "publish:" + setup.enrollment.ANCHOR_PATH
    )
    assert events.index("publish:" + setup.enrollment.ANCHOR_PATH) < events.index(
        "publish:" + setup._anchor_paths(GENERATION)[-1]
    )
    record = backend.files[setup.enrollment.ANCHOR_PATH]
    row = setup.enrollment._document(record)
    assert row["setup_receipt_digest"] == result["setup_receipt_digest"]
    assert row["credential_reference"]["purpose_digest"] == backend.purpose
    assert backend.credentials[0].wiped and backend.closed == 2
    assert setup._load_receipt(backend) == backend.files[setup._RECEIPT_PATH]


@pytest.mark.parametrize("fault", ["missing_account", "absent:C:\\BlueFire"])
def test_preexisting_account_or_resource_refused_before_original_intent(lifecycle, fault):
    backend, gate = lifecycle
    backend.fail = fault
    with pytest.raises(setup.WindowsFileSetupError) as caught:
        run(backend, gate)
    assert not caught.value.bootstrap_mutated and not caught.value.intent_persisted
    assert "account" not in backend.events and not backend.files


@pytest.mark.parametrize(
    "fault,stage",
    [
        ("directory:" + setup._METADATA_ROOT, "bootstrap_storage"),
        ("publish:" + setup._INTENT_PATH, "original_intent"),
        ("account", "account_creation"),
        ("protect", "credential_protection"),
        ("publish:" + setup._RECEIPT_PATH, "protected_receipt"),
        ("publish:" + setup.enrollment.ANCHOR_PATH, "enrollment_publication"),
        ("publish:" + setup._anchor_paths(GENERATION)[-1], "anchor_publication"),
        ("verify_all", "protected_receipt"),
        ("cleanup", "cleanup"),
    ],
)
def test_partial_lifecycle_never_repairs_replays_or_claims_complete(lifecycle, fault, stage):
    backend, gate = lifecycle
    backend.fail = fault
    with pytest.raises(setup.WindowsFileSetupError) as caught:
        run(backend, gate)
    assert caught.value.stage == stage and caught.value.bootstrap_mutated
    assert caught.value.intent_persisted == (stage not in ("bootstrap_storage", "original_intent"))
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    assert "private input" not in str(caught.value)
    assert all(item.wiped for item in backend.credentials)
    assert backend.closed >= 1


def test_distinct_local_sid_authority_drift_after_account_is_incomplete(lifecycle):
    backend, gate = lifecycle
    backend.reader = "S-1-5-21-444-555-666-1002"
    with pytest.raises(setup.WindowsFileSetupError) as caught:
        run(backend, gate)
    assert caught.value.stage == "account_creation" and caught.value.intent_persisted
    assert setup._ACCOUNT_PATH not in backend.files and backend.credentials[0].wiped


@pytest.mark.parametrize("rollback", [False, True])
def test_original_deadline_or_wall_rollback_after_intent_prevents_account(
    lifecycle, monkeypatch, rollback
):
    backend, gate = lifecycle

    def stop(label):
        if label == "publish:" + setup._INTENT_PATH:
            if rollback:
                monkeypatch.setattr(setup.time, "time_ns", lambda: (ISSUED - 1) * 1000000)
            else:
                gate.fail = True

    backend.after = stop
    with pytest.raises(setup.WindowsFileSetupError) as caught:
        run(backend, gate)
    assert caught.value.intent_persisted and "account" not in backend.events


@pytest.mark.parametrize(
    "name", ["source_profile_id", "source_enrollment_generation", "transport", "private_profile"]
)
def test_protected_receipt_original_linkage_corruption_refused(lifecycle, name):
    backend, gate = lifecycle
    run(backend, gate)
    receipt = setup.contract._document(backend.files[setup._RECEIPT_PATH])
    if name == "private_profile":
        receipt[name]["allowed_actions"] = ["filesystem.read"]
    else:
        receipt["source"][name] = "changed"
    backend.files[setup._RECEIPT_PATH] = canonical_json_bytes(receipt)
    with pytest.raises(setup.contract.NativeWireError):
        setup._load_receipt(backend)


@pytest.mark.parametrize(
    "field,value",
    [
        ("supported", False),
        ("supported", 1),
        ("platform", "linux"),
        ("architecture", "aarch64"),
        ("scope", "ready"),
        ("worker_command", "arbitrary-command"),
        ("read_schema", "changed"),
    ],
)
def test_genuine_binary_capability_shape_is_closed_and_protocol_only(field, value):
    row = source_facts()["capability"]
    row[field] = value
    with pytest.raises(setup.contract.NativeWireError):
        setup._capability(canonical_json_bytes(row), "0.1.0")


def test_normal_profile_is_not_resealed_or_registered(lifecycle):
    original = source_facts()
    untouched = copy.deepcopy(original)
    backend, gate = lifecycle
    run(backend, gate)
    assert original == untouched
    private = setup.contract._document(backend.files[setup._PROFILE_PATH])
    assert private["allowed_actions"] == [setup.contract.ACTION]
    assert private["profile_id"] != original["source_profile_id"]
    assert private["sandbox_root"] == "C:\\BlueFire\\EndpointAccess\\" + GENERATION


def test_caller_assertions_do_not_enable_no_argument_publisher():
    with pytest.raises(setup.enrollment.WindowsEnrollmentUnavailable):
        setup.publish_windows_file_access_setup()
    with pytest.raises(TypeError):
        setup.publish_windows_file_access_setup(verified=True)
    with pytest.raises(TypeError):
        process.setup_windows_file_access_local("existing-source", owner_sid="S-1-5-21-1-2-3-1000")


@pytest.mark.parametrize("native_result", [True, False, "raise"])
def test_dpapi_owned_native_buffers_wiped_and_output_freed_on_all_paths(native_result, monkeypatch):
    provider = object.__new__(secret_store.WindowsDPAPISecretProvider)
    retained = {}
    buffers = []
    original = secret_store._blob_from_bytes

    def owned(value):
        blob, buffer = original(value)
        buffers.append(buffer)
        return blob, buffer

    monkeypatch.setattr(secret_store, "_blob_from_bytes", owned)
    output = ctypes.create_string_buffer(b"synthetic-output")

    def operation(input_ptr, description, entropy_ptr, reserved, prompt, flags, output_ptr):
        input_blob = ctypes.cast(input_ptr, ctypes.POINTER(secret_store._DataBlob)).contents
        entropy_blob = ctypes.cast(entropy_ptr, ctypes.POINTER(secret_store._DataBlob)).contents
        retained["input"] = (input_blob.pbData, input_blob.cbData)
        retained["entropy"] = (entropy_blob.pbData, entropy_blob.cbData)
        result = ctypes.cast(output_ptr, ctypes.POINTER(secret_store._DataBlob)).contents
        result.pbData = ctypes.cast(output, ctypes.POINTER(ctypes.c_ubyte))
        result.cbData = len(output) - 1
        if native_result == "raise":
            raise OSError("synthetic private native failure")
        return native_result

    def free(pointer):
        assert not any(output.raw[:-1])
        retained["freed"] = True
        return None

    provider._local_free = free
    if native_result is True:
        assert (
            provider._call_dpapi(operation, b"synthetic-input", b"purpose", protecting=True)
            == b"synthetic-output"
        )
    else:
        with pytest.raises(secret_store.SecretStoreError):
            provider._call_dpapi(operation, b"synthetic-input", b"purpose", protecting=True)
    assert retained["freed"]
    # Backing arrays are deliberately retained by the fake; never dereference a
    # pointer after its production buffer lifetime has ended.
    for name in ("input", "entropy"):
        pointer, size = retained[name]
        assert ctypes.string_at(pointer, size) == b"\0" * size


@pytest.mark.parametrize("throw", [False, True])
def test_dpapi_local_free_failure_never_claims_success(throw):
    provider = object.__new__(secret_store.WindowsDPAPISecretProvider)
    output = ctypes.create_string_buffer(b"opaque")

    def operation(*args):
        result = ctypes.cast(args[-1], ctypes.POINTER(secret_store._DataBlob)).contents
        result.pbData = ctypes.cast(output, ctypes.POINTER(ctypes.c_ubyte))
        result.cbData = 6
        return True

    def free(pointer):
        if throw:
            raise RuntimeError("private cleanup failure")
        return 1

    provider._local_free = free
    with pytest.raises(secret_store.SecretStoreError, match="buffer cleanup failed"):
        provider._call_dpapi(operation, b"input", b"purpose", protecting=True)


def test_native_credential_owns_utf16_and_wipes_without_password_repr():
    credential = write._Credential()
    assert credential.length == 64 and credential.buffer[64] == 0
    assert "credential" in repr(credential) and len(repr(credential)) < 64
    credential.wipe()
    assert not any(credential.buffer)


@pytest.mark.parametrize("status", [0, 2224, 5])
def test_real_backend_net_user_add_uses_fixed_name_owned_buffer_and_finite_expiry(
    monkeypatch, status
):
    backend = object.__new__(write._NativeSetup)
    backend.owner = SimpleNamespace(user_sid="S-1-5-21-101-202-303-1001")
    backend.gate = FakeGate()
    backend.current = lambda: None
    monkeypatch.setattr(write, "_require_local_machine", lambda gate: None)
    calls = []

    def add(server, level, pointer, error):
        assert server is None and level == 2
        info = ctypes.cast(pointer, ctypes.POINTER(write._UserInfo2)).contents
        assert ctypes.wstring_at(info.name) == "bf_0123456789abcdef"
        assert info.flags == 0x10241 and info.priv == 1 and info.expires == 1700000900
        assert info.password == ctypes.addressof(credential.buffer)
        calls.append("add")
        return status

    backend.sam = SimpleNamespace(NetUserAdd=add)
    backend.verify_account = lambda generation, sid, expiry: calls.append("fresh-expiry")
    monkeypatch.setattr(write, "_local_account", lambda api, name: "S-1-5-21-101-202-303-1002")
    credential = write._Credential()
    try:
        if status:
            with pytest.raises(write.native.WindowsEnrollmentNativeError):
                backend.account(GENERATION, credential, 1700000900)
            assert calls == ["add"]  # Existing account is never adopted.
        else:
            assert backend.account(GENERATION, credential, 1700000900).endswith("-1002")
            assert calls == ["add", "fresh-expiry"]
    finally:
        credential.wipe()


@pytest.mark.parametrize("fault", [None, "expiry", "flags", "priv", "sid", "free", "size"])
def test_real_backend_fresh_local_account_expiry_and_cleanup_are_required(monkeypatch, fault):
    backend = object.__new__(write._NativeSetup)
    backend.current = lambda: None
    buffer = write._UserInfo2()
    buffer.expires, buffer.flags, buffer.priv = 1700000900, 0x10241, 1
    if fault in ("expiry", "flags", "priv"):
        setattr(buffer, {"expiry": "expires", "flags": "flags", "priv": "priv"}[fault], 0)
    freed = []

    def get(server, name, level, output):
        assert server is None and name == "bf_0123456789abcdef" and level == 2
        output._obj.value = ctypes.addressof(buffer)
        return 0

    def size(pointer, output):
        output._obj.value = ctypes.sizeof(buffer) - (1 if fault == "size" else 0)
        return 0

    def free(pointer):
        freed.append(True)
        return 1 if fault == "free" else 0

    backend.sam = SimpleNamespace(NetUserGetInfo=get, NetApiBufferSize=size, NetApiBufferFree=free)
    monkeypatch.setattr(
        write,
        "_local_account",
        lambda api, name: "S-1-5-21-101-202-303-" + ("1003" if fault == "sid" else "1002"),
    )
    if fault:
        with pytest.raises(write.native.WindowsEnrollmentNativeError):
            backend.verify_account(GENERATION, "S-1-5-21-101-202-303-1002", 1700000900)
    else:
        backend.verify_account(GENERATION, "S-1-5-21-101-202-303-1002", 1700000900)
    assert freed == ([] if fault == "sid" else [True])


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "not_elevated",
        "linked_sid",
        "linked_elevated",
        "local_sid",
        "close",
        "linked_missing",
        "drift",
    ],
)
def test_actual_linked_token_boundary_requires_same_primary_limited_local_owner(monkeypatch, fault):
    sid = "S-1-5-21-101-202-303-1001"
    owner = WindowsPrincipalFacts(91, 92, sid, 93, 94, 95, 1, fault != "not_elevated")
    closes = []

    def close(token):
        closes.append(token.value)
        return fault != "close"

    def linked(token, kind, output, capacity, length):
        assert token == 100 and kind == 19
        output._obj.value = None if fault == "linked_missing" else 200
        length._obj.value = ctypes.sizeof(ctypes.c_void_p)
        return True

    class Api:
        kernel = SimpleNamespace(CloseHandle=close)
        security = SimpleNamespace(GetTokenInformation=linked)

        @contextmanager
        def process_token(self):
            yield 100

        def statistics(self, token):
            assert token == 200
            return (1, 2, 3)

        def user_sid(self, token):
            return sid if fault != "linked_sid" else "S-1-5-21-101-202-303-1002"

        def dword(self, token, kind):
            assert kind == 20
            return 1 if fault == "linked_elevated" else 0

    observations = []

    def observe(api):
        observations.append(True)
        if fault == "drift" and len(observations) > 1:
            return WindowsPrincipalFacts(91, 92, sid, 96, 94, 95, 1, True)
        return owner

    def name(buffer, length):
        buffer.value = "synthetic-owner"
        length._obj.value = len(buffer.value) + 1
        return True

    monkeypatch.setattr(write.session, "_WindowsApi", Api)
    monkeypatch.setattr(write, "_require_local_machine", lambda gate: None)
    monkeypatch.setattr(write.session, "_observe", observe)
    monkeypatch.setattr(
        write.ctypes,
        "WinDLL",
        lambda *args, **kwargs: SimpleNamespace(GetUserNameW=name),
        raising=False,
    )
    monkeypatch.setattr(write.native, "_sam_api", lambda: object())
    monkeypatch.setattr(
        write,
        "_local_account",
        lambda api, value: sid if fault != "local_sid" else "S-1-5-21-444-555-666-1001",
    )
    if fault:
        with pytest.raises(write.native.WindowsEnrollmentNativeError):
            write._elevated_owner(FakeGate())
    else:
        assert write._elevated_owner(FakeGate()) == owner
    assert closes == ([] if fault in ("not_elevated", "linked_missing") else [200])


def test_actual_local_sam_sid_is_derived_from_bounded_allocation_not_caller(monkeypatch):
    from tests_platform.test_windows_file_access_enrollment_native import READER, SamFake

    api = SamFake()
    assert write._local_account(api, "bf_0123456789abcdef") == READER
    assert api.freed == 1
    api.info.sid = api.start + api.length - 4
    with pytest.raises(write.native.WindowsEnrollmentNativeError):
        write._local_account(api, "bf_0123456789abcdef")
    assert api.freed == 2


@pytest.mark.parametrize(
    "role,flags,allowed",
    [
        (0, 0, True),
        (1, 0x1000000, True),
        (2, 0, True),
        (3, 0, True),
        (4, 0, False),
        (5, 0, False),
        (6, 0, False),
        (0, 1, False),
        (3, 8, False),
        (0, 4, False),
    ],
)
def test_machine_role_refuses_dc_and_directory_service_before_account_calls(
    monkeypatch, role, flags, allowed
):
    buffer = (ctypes.c_uint32 * 2)(role, flags)
    freed = []

    def observe(server, level, output):
        assert server is None and level == 1
        output._obj.value = ctypes.addressof(buffer)
        return 0

    def free(pointer):
        freed.append(pointer.value)

    api = SimpleNamespace(DsRoleGetPrimaryDomainInformation=observe, DsRoleFreeMemory=free)
    monkeypatch.setattr(write.ctypes, "WinDLL", lambda *args, **kwargs: api, raising=False)
    if allowed:
        write._require_local_machine(FakeGate())
    else:
        with pytest.raises(write.native.WindowsEnrollmentNativeError):
            write._require_local_machine(FakeGate())
    assert freed == [ctypes.addressof(buffer)]


def test_existing_cli_requires_explicit_confirmation_and_passes_only_profile(monkeypatch):
    from bluefire import cli

    with pytest.raises(SystemExit):
        cli._parser().parse_args(["runner", "windows-file-setup", "--profile", "existing-source"])
    args = cli._parser().parse_args(
        [
            "runner",
            "windows-file-setup",
            "--profile",
            "existing-source",
            "--confirm-create-local-reader",
        ]
    )
    monkeypatch.setattr(cli, "_service", lambda args: pytest.fail("No ordinary service required"))
    calls = []

    def invoke(profile):
        calls.append(profile)
        return {"context_available": False}

    monkeypatch.setattr(process, "setup_windows_file_access_local", invoke)
    assert cli._execute(args) == {"context_available": False}
    assert calls == ["existing-source"]


@pytest.mark.parametrize(
    "fault", [None, "write", "flush", "close", "close_exception", "free", "late", "late_descriptor"]
)
def test_actual_create_wrapper_is_exclusive_flushes_and_attempts_all_cleanup(fault):
    backend = object.__new__(write._NativeSetup)
    gate = FakeGate()
    backend.current = gate.check
    allocation = ctypes.create_string_buffer(32)
    calls = []

    def convert(sddl, revision, output, length):
        assert revision == 1
        output._obj.value = ctypes.addressof(allocation)
        calls.append("descriptor")
        if fault == "late_descriptor":
            gate.fail = True
        return True

    def create(path, access, share, attributes, disposition, flags, template):
        assert path == "synthetic-only" and access == 0x40000000 and share == 1 and disposition == 1
        assert not attributes._obj.inherit and attributes._obj.descriptor == ctypes.addressof(
            allocation
        )
        calls.append("create-new")
        if fault == "late":
            gate.fail = True
        return 100

    def write_file(handle, data, size, written, overlap):
        assert handle == 100 and ctypes.string_at(data, size) == b"public-fixture"
        calls.append("write")
        written._obj.value = size
        return fault != "write"

    def flush(handle):
        calls.append("flush")
        return fault != "flush"

    def close(handle):
        calls.append("close")
        if fault == "close_exception":
            raise RuntimeError("synthetic close exception")
        return fault != "close"

    def free(pointer):
        calls.append("free")
        return 1 if fault == "free" else None

    backend.security = SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptorW=convert)
    backend.kernel = SimpleNamespace(
        CreateFileW=create,
        WriteFile=write_file,
        FlushFileBuffers=flush,
        CloseHandle=close,
        LocalFree=free,
    )
    if fault:
        with pytest.raises((write.native.WindowsEnrollmentNativeError, RuntimeError)):
            backend._create("synthetic-only", b"public-fixture", "synthetic finite recipe")
    else:
        backend._create("synthetic-only", b"public-fixture", "synthetic finite recipe")
        assert calls == ["descriptor", "create-new", "write", "flush", "close", "free"]
    assert calls[-2:] == (
        ["descriptor", "free"] if fault == "late_descriptor" else ["close", "free"]
    )
    if fault == "late_descriptor":
        assert "create-new" not in calls
    if fault == "late":
        assert "write" not in calls and "flush" not in calls


def test_private_deriving_child_cleanup_failure_preserves_partial_state(lifecycle, monkeypatch):
    backend, gate = lifecycle
    backend.fail = "cleanup"
    monkeypatch.setattr(write, "_elevated_owner", lambda gate: backend.owner)
    monkeypatch.setattr(write, "_NativeSetup", lambda *args: backend)
    monkeypatch.setattr(setup, "_source", lambda *args: source_facts())
    monkeypatch.setattr(setup.secrets, "token_hex", lambda length: GENERATION)
    monkeypatch.setattr(write.native, "_Gate", lambda *args: gate)
    with pytest.raises(setup.WindowsFileSetupError) as caught:
        setup._run_local_setup_child(
            "existing-source",
            lifecycle=object(),
            original_issued_at_ms=ISSUED,
            original_deadline=100.0,
        )
    assert (
        caught.value.stage == "cleanup"
        and caught.value.bootstrap_mutated
        and caught.value.intent_persisted
    )
    assert setup._anchor_paths(GENERATION)[-1] in backend.files


def test_public_cli_setup_only_delegates_to_owned_hard_worker(monkeypatch):
    from bluefire import windows_file_access_setup_process as process

    def forbidden(*args, **kwargs):
        pytest.fail("public setup must not observe or mutate native state itself")

    monkeypatch.setattr(write, "_elevated_owner", forbidden)
    monkeypatch.setattr(write, "_NativeSetup", forbidden)
    calls = []

    def run(profile, *, cancellation_event):
        calls.append(profile)
        assert not cancellation_event.is_set()
        return process.SetupProcessOutcome(None, "not_started", "verified", "cancelled", None)

    monkeypatch.setattr(process, "run_setup_process", run)
    result = process.setup_windows_file_access_local("existing-source")
    assert calls == ["existing-source"]
    assert result["publication"] == "not_established" and result["dispatch"] == "not_started"
    assert result["context_available"] is False and result["settled"] is False


@pytest.mark.parametrize(
    "issued,deadline", [(ISSUED - 5000, 100.0), (ISSUED + 1, 100.0), (True, 100.0), (ISSUED, 100)]
)
def test_private_child_original_clocks_are_not_renewed_or_inferred(monkeypatch, issued, deadline):
    monkeypatch.setattr(setup.time, "time_ns", lambda: ISSUED * 1000000)

    def forbidden(*args):
        pytest.fail("stale/invalid original clock must refuse before native authority")

    monkeypatch.setattr(write, "_elevated_owner", forbidden)
    with pytest.raises(setup.WindowsFileSetupError) as caught:
        setup._run_local_setup_child(
            "existing-source",
            lifecycle=object(),
            original_issued_at_ms=issued,
            original_deadline=deadline,
        )
    assert caught.value.stage == "authority" and not caught.value.bootstrap_mutated


@pytest.mark.parametrize(
    "fault",
    [None, "old_binary", "override", "channel_drift", "unsupported", "stderr", "image_drift"],
)
def test_concrete_source_checks_real_boundary_interfaces_before_setup_effects(
    lifecycle, monkeypatch, tmp_path, fault
):
    import hashlib

    from bluefire import runner_bootstrap
    from bluefire.runner_lifecycle import ManagedRunnerLifecycle

    backend, gate = lifecycle
    payload = b"synthetic packaged image bytes"
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    source = source_facts()
    source["transport"]["runner_binary_digest"] = digest
    image = tmp_path / "synthetic" / "bluefire-runner.exe"
    backend.files[str(image)] = payload
    backend.held = [777]
    observations = []
    original_observe = backend.observe

    def observe(*args, **kwargs):
        result = original_observe(*args, **kwargs)
        observations.append(result)
        if fault == "image_drift" and len(observations) > 1:
            return dict(result, size=result["size"] + 1)
        return result

    backend.observe = observe
    chunks = [payload, b""]
    monkeypatch.setattr(setup.os, "read", lambda descriptor, size: chunks.pop(0))
    client_calls = []

    def transport():
        client_calls.append(True)
        row = copy.deepcopy(source["transport"])
        if fault == "channel_drift" and len(client_calls) > 1:
            row["inventory_digest"] = "sha256:" + "b" * 64
        return row

    controller = object.__new__(ManagedRunnerLifecycle)
    controller._load_active_enrollment = lambda: object()
    bootstrap = SimpleNamespace(
        source="override" if fault == "override" else "packaged",
        managed_binary=True,
        binary_digest=digest,
        binary_path=image,
        runner_version="0.1.0",
    )
    controller._load_bootstrap = lambda enrollment: bootstrap
    controller.client_for_profile = lambda profile: (
        SimpleNamespace(transport_identity=transport),
        Path("synthetic-sandbox"),
    )
    manifest = SimpleNamespace(
        sha256="0" * 64 if fault == "old_binary" else digest[7:],
        size=len(payload),
        runner_version="0.1.0",
    )
    monkeypatch.setattr(runner_bootstrap, "load_runner_manifest", lambda **kwargs: manifest)

    def query(command, **kwargs):
        assert command == [str(image), "windows-file-worker-capability"]
        assert kwargs["shell"] is False and kwargs["stdin"] == setup.subprocess.DEVNULL
        record = copy.deepcopy(source["capability"])
        if fault == "unsupported":
            record["supported"] = False
        kwargs["stdout"].write(canonical_json_bytes(record) + b"\n")
        if fault == "stderr":
            kwargs["stderr"].write(b"private output not retained")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup.subprocess, "run", query)
    gate.deadline = 105.0
    monkeypatch.setattr(setup.time, "monotonic", lambda: 100.0)
    if fault:
        with pytest.raises(setup.contract.NativeWireError):
            setup._source(controller, "existing-source", backend, gate)
    else:
        result = setup._source(controller, "existing-source", backend, gate)
        assert result["native_image"]["sha256"] == digest and len(client_calls) == 2
    assert "account" not in backend.events and setup._INTENT_PATH not in backend.files


def test_win32_setup_structure_geometry_is_exact_on_current_pointer_width():
    width = ctypes.sizeof(ctypes.c_void_p)
    assert write._UserInfo2.expires.offset == (104 if width == 8 else 60)
    assert ctypes.sizeof(write._UserInfo2) == (152 if width == 8 else 96)
    assert ctypes.sizeof(write._SecurityAttributes) == (24 if width == 8 else 12)


def synthetic_query_capability(protocol):
    row = copy.deepcopy(source_facts()["capability"])
    if protocol is setup.enrollment._PAIR_SETUP:
        row.update(
            schema_version="bluefire.windows-file-worker-capability.v2",
            worker_command="windows-file-baseline-worker",
            worker_schema="bluefire.windows-file-worker-request.v2",
            read_schema="bluefire.windows-fixed-read-pair.v2",
            action_id="private.windows.file_read_pair.v2",
            capability="windows_file_read_pair",
            max_data_opens=2,
            max_bytes_per_read=1048576,
            max_total_read_bytes=2097152,
            max_execution_ms=5000,
        )
    return row


@pytest.mark.parametrize("protocol", [setup.enrollment._READER_SETUP, setup.enrollment._PAIR_SETUP])
@pytest.mark.parametrize(
    "fault", [None, "exit", "stderr", "unsupported", "malformed", "oversize", "raise", "late"]
)
def test_shared_readonly_capability_query_preserves_protocol_deadline_and_stream_cleanup(
    monkeypatch, protocol, fault
):
    streams, calls = [], []
    ticks = iter([100.0, 105.0 if fault == "late" else 100.5])
    monkeypatch.setattr(setup.time, "monotonic", lambda: next(ticks))

    def query(command, **kwargs):
        calls.append(command)
        assert command == ["synthetic-installed.exe", protocol.command + "-capability"]
        assert kwargs["stdin"] == setup.subprocess.DEVNULL
        assert kwargs["shell"] is False and kwargs["check"] is False
        assert kwargs["timeout"] == 5.0 and kwargs["creationflags"] == 0x08000000
        streams.extend([kwargs["stdout"], kwargs["stderr"]])
        if fault == "raise":
            raise OSError("synthetic private query failure")
        row = synthetic_query_capability(protocol)
        if fault == "unsupported":
            row["supported"] = False
        raw = canonical_json_bytes(row)
        kwargs["stdout"].write(
            b"not JSON" if fault == "malformed" else (b"x" * 1025 if fault == "oversize" else raw)
        )
        if fault == "stderr":
            kwargs["stderr"].write(b"synthetic private stderr")
        return SimpleNamespace(returncode=4 if fault == "exit" else 0)

    monkeypatch.setattr(setup.subprocess, "run", query)
    if fault:
        with pytest.raises(OSError if fault == "raise" else setup.contract.NativeWireError):
            setup._query_capability_for("synthetic-installed.exe", "0.1.0", 105.0, protocol)
    else:
        assert setup._query_capability_for("synthetic-installed.exe", "0.1.0", 105.0, protocol) == (
            synthetic_query_capability(protocol)
        )
    assert len(calls) == 1 and len(streams) == 2 and all(stream.closed for stream in streams)


@pytest.mark.parametrize("deadline", [True, 105, float("nan"), float("inf"), 100.0, 106.0])
def test_shared_readonly_query_refuses_invalid_or_renewed_deadline_before_subprocess(
    monkeypatch, deadline
):
    monkeypatch.setattr(setup.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(setup.subprocess, "run", lambda *a, **k: pytest.fail("query must not run"))
    with pytest.raises(setup.contract.NativeWireError):
        setup._query_capability_for(
            "synthetic-installed.exe", "0.1.0", deadline, setup.enrollment._PAIR_SETUP
        )
