"""One-shot Darwin workspace custody checks with inert store/creator fakes."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
from threading import RLock
from types import SimpleNamespace

import pytest

from bluefire import composition_macos_file_access as composition
from bluefire import product_store_macos_workspace as workspace_store
from bluefire.capability_packs import MACOS_FILE_ACCESS_PACK
from bluefire.product_store_errors import ProductStoreError
from bluefire.util import content_hash

ATTEMPT_ID = "attempt-" + "a" * 32
LEASE_DIGEST = content_hash("lease")
COMPILED_DIGEST = content_hash("compiled")
WORKSPACE_PATH = "synthetic-workspace/attempt"
WORKSPACE_PATH_DIGEST = content_hash({"sandbox_root": WORKSPACE_PATH})
WORKSPACE_IDENTITY_DIGEST = content_hash("workspace-identity")


class FakeCursor:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class FakeConnection:
    def __init__(self, store):
        self.store = store

    def execute(self, statement, parameters=()):
        attempt_id = parameters[0]
        if "capability_macos_workspace_claims" in statement:
            rows = self.store.claims
        elif "capability_workspace_bindings" in statement:
            rows = self.store.legacy_workspace_bindings
        else:
            raise AssertionError("unexpected fake SQL")
        return FakeCursor((1,) if attempt_id in rows else None)


class FakeStore(workspace_store.MacOSWorkspaceStoreMixin):
    def __init__(self, *, claims=None, legacy_workspace_bindings=None):
        self.claims = {} if claims is None else claims
        self.legacy_workspace_bindings = (
            set() if legacy_workspace_bindings is None else legacy_workspace_bindings
        )
        self._macos_attempt_workspaces = {}
        self._macos_workspace_claims = {}
        self._macos_workspace_pid = workspace_store.os.getpid()
        self.in_transaction = False
        self.commits = 0
        self._lock = RLock()
        self.workspace = {
            "attempt_id": ATTEMPT_ID,
            "lease_digest": LEASE_DIGEST,
            "workspace_path_digest": WORKSPACE_PATH_DIGEST,
        }

    @contextmanager
    def _connection(self, *, write=False):
        assert write
        self.in_transaction = True
        try:
            yield FakeConnection(self)
            self.commits += 1
        finally:
            self.in_transaction = False

    def _capability_workspace_at(self, connection, attempt_id, lease):
        assert attempt_id == ATTEMPT_ID
        assert lease["lease_digest"] == LEASE_DIGEST
        return dict(self.workspace)


class FakeGuard:
    def __init__(self, workspace, *, attempt_id, lease_digest, compiled_digest):
        self.workspace = workspace
        self.attempt_id = attempt_id
        self.lease_digest = lease_digest
        self.compiled_digest = compiled_digest
        self.closed = False
        self.phases = []
        self.binding_checks = []

    def validate_binding(self, workspace, *, attempt_id, lease_digest, compiled_digest):
        self.binding_checks.append((workspace, attempt_id, lease_digest, compiled_digest))
        if self.closed or (workspace, attempt_id, lease_digest, compiled_digest) != (
            self.workspace,
            self.attempt_id,
            self.lease_digest,
            self.compiled_digest,
        ):
            raise ProductStoreError("original Darwin workspace binding changed")

    def attest(self, phase):
        if self.closed:
            raise ProductStoreError("original Darwin workspace guard is closed")
        self.phases.append(phase)
        return {
            "schema_version": "bluefire.macos-file-access-empty-workspace.v1",
            "attempt_id": self.attempt_id,
            "lease_digest": self.lease_digest,
            "compiled_digest": self.compiled_digest,
            "workspace_path_digest": WORKSPACE_PATH_DIGEST,
            "workspace_identity_digest": WORKSPACE_IDENTITY_DIGEST,
            "phase": phase,
            "entry_count": 0,
            "state": "verified_empty",
        }

    def close(self):
        self.closed = True


@pytest.fixture
def setup_workspace(monkeypatch):
    process = {"pid": 701}
    monkeypatch.setattr(workspace_store, "os", SimpleNamespace(getpid=lambda: process["pid"]))
    store = FakeStore()
    lease = {"lease_digest": LEASE_DIGEST, "grant_id": "grant-" + "b" * 32}
    compiled = {"compiled_digest": COMPILED_DIGEST}
    grant = {
        "schema_version": "bluefire.capability-grant.v2",
        "pack": MACOS_FILE_ACCESS_PACK,
        "snapshot": {"pack": MACOS_FILE_ACCESS_PACK},
    }
    monkeypatch.setattr(
        workspace_store,
        "_attempt_live",
        lambda *args, **kwargs: (None, lease, compiled),
    )
    monkeypatch.setattr(workspace_store, "_claim_at", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        workspace_store,
        "_grant_at",
        lambda connection, grant_id: (None, grant, None),
    )

    def insert_document(connection, statement, attempt_id, document):
        assert "capability_macos_workspace_claims" in statement
        connection.store.claims[attempt_id] = dict(document)

    monkeypatch.setattr(workspace_store, "_insert_document", insert_document)
    monkeypatch.setattr(workspace_store, "MacOSAttemptWorkspaceGuard", FakeGuard)
    monkeypatch.setattr(composition, "MacOSAttemptWorkspaceGuard", FakeGuard)

    creator = {"function": lambda _root, _attempt: WORKSPACE_PATH, "calls": []}

    def isolated_owned_sandbox(root, attempt_id):
        creator["calls"].append((root, attempt_id))
        return creator["function"](root, attempt_id)

    return {
        "store": store,
        "lease": lease,
        "compiled": compiled,
        "creator": creator,
        "configured_root": "synthetic-root",
        "service": SimpleNamespace(_isolated_owned_sandbox=isolated_owned_sandbox),
        "process": process,
    }


def _create(state):
    return composition.create_workspace(
        SimpleNamespace(store=state["store"], service=state["service"], clock=lambda: 4_000),
        ATTEMPT_ID,
        {"sandbox": state["configured_root"], "current_environment": {"environment": "current"}},
    )


def test_claim_is_committed_before_any_workspace_creation(setup_workspace):
    state = setup_workspace
    observed = []

    def create(root, attempt_id):
        assert not state["store"].in_transaction and state["store"].commits == 1
        claim = state["store"].claims[attempt_id]
        observed.append((root, attempt_id, dict(claim)))
        return WORKSPACE_PATH

    state["creator"]["function"] = create
    assert _create(state) == WORKSPACE_PATH
    assert len(observed) == 1
    claim = observed[0][2]
    assert set(claim) == {
        "schema_version",
        "attempt_id",
        "lease_digest",
        "compiled_digest",
        "configured_root_digest",
        "claimed_at_ms",
    }
    assert claim["schema_version"] == "bluefire.macos-attempt-workspace-claim.v1"
    assert claim["configured_root_digest"] == content_hash({"configured_root": "synthetic-root"})
    assert not {"guard", "workspace_path", "workspace_identity"} & set(claim)
    guard = state["store"]._macos_attempt_workspaces[ATTEMPT_ID]
    assert guard.binding_checks == [(WORKSPACE_PATH, ATTEMPT_ID, LEASE_DIGEST, COMPILED_DIGEST)]
    assert guard.phases == []
    assert state["store"]._macos_workspace_claims == {}


def test_uncertain_creation_keeps_one_shot_claim_and_cannot_retry(setup_workspace):
    state = setup_workspace

    def uncertain_create(_root, attempt_id):
        assert attempt_id in state["store"].claims
        raise OSError("synthetic uncertain creation")

    state["creator"]["function"] = uncertain_create
    with pytest.raises(OSError, match="uncertain"):
        _create(state)
    assert ATTEMPT_ID in state["store"].claims
    assert state["store"]._macos_workspace_claims == {}
    assert len(state["creator"]["calls"]) == 1
    with pytest.raises(ProductStoreError, match="already claimed"):
        _create(state)
    assert len(state["creator"]["calls"]) == 1


def test_released_or_reopened_claim_cannot_be_adopted_again(setup_workspace):
    state = setup_workspace
    _create(state)
    guard = state["store"]._macos_attempt_workspaces[ATTEMPT_ID]
    state["store"].release_macos_attempt_workspace(ATTEMPT_ID)
    assert guard.closed
    with pytest.raises(ProductStoreError, match="already claimed"):
        _create(state)
    assert len(state["creator"]["calls"]) == 1

    reopened = FakeStore(claims=state["store"].claims)
    state["store"] = reopened
    with pytest.raises(ProductStoreError, match="already claimed"):
        _create(state)
    assert not reopened._macos_attempt_workspaces
    assert len(state["creator"]["calls"]) == 1


def _claim(state):
    return state["store"].claim_macos_attempt_workspace(
        ATTEMPT_ID,
        state["configured_root"],
        now_ms=4_000,
        current_environment={"environment": "current"},
    )


def _guard():
    return FakeGuard(
        WORKSPACE_PATH,
        attempt_id=ATTEMPT_ID,
        lease_digest=LEASE_DIGEST,
        compiled_digest=COMPILED_DIGEST,
    )


def test_original_frozen_claim_attaches_once_without_advancing_inventory(setup_workspace):
    state = setup_workspace
    claim = _claim(state)
    assert state["store"].commits == 1 and state["creator"]["calls"] == []
    with pytest.raises(FrozenInstanceError):
        claim.pid = 999
    retained = _guard()
    state["store"].attach_macos_attempt_workspace_guard(
        claim, state["configured_root"], WORKSPACE_PATH, retained
    )
    assert state["store"]._macos_attempt_workspaces[ATTEMPT_ID] is retained
    assert retained.phases == [] and not retained.closed
    second = _guard()
    with pytest.raises(ProductStoreError, match="claim is unavailable"):
        state["store"].attach_macos_attempt_workspace_guard(
            claim, state["configured_root"], WORKSPACE_PATH, second
        )
    assert second.closed and not retained.closed and second.phases == []


@pytest.mark.parametrize("kind", ["copy", "document", "reopened", "fork", "token_pid"])
def test_forged_reopened_or_fork_claim_never_attaches_a_guard(setup_workspace, kind):
    state = setup_workspace
    claim = _claim(state)
    target = state["store"]
    if kind == "copy":
        claim = replace(claim)
    elif kind == "document":
        claim = dict(vars(claim))
    elif kind == "reopened":
        target = FakeStore(claims=target.claims)
    elif kind == "token_pid":
        claim = replace(claim, pid=state["process"]["pid"] + 1)
    else:
        state["process"]["pid"] += 1
    retained = _guard()
    with pytest.raises(ProductStoreError, match="claim is unavailable"):
        target.attach_macos_attempt_workspace_guard(
            claim, state["configured_root"], WORKSPACE_PATH, retained
        )
    assert retained.closed and retained.binding_checks == [] and retained.phases == []
    assert target._macos_attempt_workspaces == {} and ATTEMPT_ID in target.claims
    with pytest.raises(
        ProductStoreError, match="process is unavailable" if kind == "fork" else "already claimed"
    ):
        target.claim_macos_attempt_workspace(
            ATTEMPT_ID, state["configured_root"], now_ms=4_000, current_environment={}
        )


@pytest.mark.parametrize(
    "field", ["attempt", "lease", "compiled", "workspace", "root", "guard_type"]
)
def test_wrong_guard_binding_consumes_original_claim_without_attestation(setup_workspace, field):
    state = setup_workspace
    claim = _claim(state)
    retained = _guard()
    root = state["configured_root"]
    if field == "attempt":
        retained.attempt_id = "attempt-" + "d" * 32
    elif field == "lease":
        retained.lease_digest = content_hash("another lease")
    elif field == "compiled":
        retained.compiled_digest = content_hash("another compiled graph")
    elif field == "workspace":
        retained.workspace = "another-workspace"
    elif field == "root":
        root = "another-root"
    else:
        retained = SimpleNamespace(
            close=lambda: pytest.fail("unknown guard must not receive authority")
        )
    with pytest.raises(ProductStoreError, match="binding changed|claim is unavailable"):
        state["store"].attach_macos_attempt_workspace_guard(claim, root, WORKSPACE_PATH, retained)
    assert (
        state["store"]._macos_workspace_claims == {}
        and state["store"]._macos_attempt_workspaces == {}
    )
    if type(retained) is FakeGuard:
        assert retained.closed and retained.phases == []


def test_guard_constructor_failure_releases_token_but_not_durable_one_shot_claim(
    setup_workspace, monkeypatch
):
    state = setup_workspace

    class FailedGuard:
        def __init__(self, *args, **kwargs):
            raise OSError("synthetic guard pin failure")

    monkeypatch.setattr(composition, "MacOSAttemptWorkspaceGuard", FailedGuard)
    with pytest.raises(OSError, match="guard pin failure"):
        _create(state)
    assert (
        state["store"]._macos_workspace_claims == {}
        and state["store"]._macos_attempt_workspaces == {}
    )
    assert ATTEMPT_ID in state["store"].claims and len(state["creator"]["calls"]) == 1
    with pytest.raises(ProductStoreError, match="already claimed"):
        _create(state)
    assert len(state["creator"]["calls"]) == 1


@pytest.mark.parametrize("operation", ["claim", "attach", "release"])
def test_fork_workspace_operations_refuse_before_inherited_store_lock(setup_workspace, operation):
    state = setup_workspace
    store = state["store"]
    claim = _claim(state)
    retained = _guard()

    class InheritedLock:
        def __enter__(self):
            pytest.fail("fork copy entered an inherited store lock")

        def __exit__(self, *args):
            return False

    store._lock = InheritedLock()
    store._connection = lambda *args, **kwargs: pytest.fail("fork copy opened the owner database")
    state["process"]["pid"] += 1
    if operation == "claim":
        with pytest.raises(ProductStoreError, match="process is unavailable"):
            _claim(state)
    elif operation == "attach":
        with pytest.raises(ProductStoreError, match="claim is unavailable"):
            store.attach_macos_attempt_workspace_guard(
                claim, state["configured_root"], WORKSPACE_PATH, retained
            )
        assert retained.closed and retained.binding_checks == [] and retained.phases == []
        store.release_macos_attempt_workspace(ATTEMPT_ID)
        assert store._macos_workspace_claims == {}
    else:
        store._macos_attempt_workspaces[ATTEMPT_ID] = retained
        store.release_macos_attempt_workspace(ATTEMPT_ID)
        store.release_macos_attempt_workspace(ATTEMPT_ID)
        assert retained.closed and retained.phases == []
        assert store._macos_workspace_claims == {} and store._macos_attempt_workspaces == {}
    assert ATTEMPT_ID in store.claims and len(state["creator"]["calls"]) == 0


def test_existing_legacy_workspace_binding_prevents_adoption(setup_workspace):
    state = setup_workspace
    state["store"].legacy_workspace_bindings.add(ATTEMPT_ID)
    with pytest.raises(ProductStoreError, match="already claimed"):
        _create(state)
    assert ATTEMPT_ID not in state["store"].claims
    assert not state["creator"]["calls"]

    reopened = FakeStore(
        claims=state["store"].claims,
        legacy_workspace_bindings=state["store"].legacy_workspace_bindings,
    )
    state["store"] = reopened
    with pytest.raises(ProductStoreError, match="already claimed"):
        _create(state)
    assert not reopened._macos_attempt_workspaces
    assert not state["creator"]["calls"]


def test_unavailable_live_guard_cannot_be_restored_from_durable_claim(setup_workspace):
    state = setup_workspace
    _create(state)
    reopened = FakeStore(claims=state["store"].claims)
    with pytest.raises(ProductStoreError, match="live macOS attempt workspace"):
        reopened._validate_macos_workspace_attestation(
            FakeConnection(reopened),
            ATTEMPT_ID,
            state["lease"],
            state["compiled"],
            phase="reserve",
            proof=None,
        )


def test_attestation_joins_exact_attempt_pins_path_and_phase(setup_workspace):
    state = setup_workspace
    _create(state)
    guard = state["store"]._macos_attempt_workspaces[ATTEMPT_ID]
    proof = state["store"]._validate_macos_workspace_attestation(
        FakeConnection(state["store"]),
        ATTEMPT_ID,
        state["lease"],
        state["compiled"],
        phase="reserve",
        proof=None,
    )
    assert guard.phases == ["reserve"]
    assert proof["attempt_id"] == ATTEMPT_ID
    assert proof["lease_digest"] == LEASE_DIGEST
    assert proof["compiled_digest"] == COMPILED_DIGEST
    assert proof["workspace_path_digest"] == WORKSPACE_PATH_DIGEST
    assert proof["workspace_identity_digest"] == WORKSPACE_IDENTITY_DIGEST
    assert proof["phase"] == "reserve"
    assert proof["entry_count"] == 0
    assert proof["state"] == "verified_empty"


@pytest.mark.parametrize("mismatch", ["phase", "attempt", "lease", "compiled", "workspace_path"])
def test_mismatched_workspace_attestation_closes_live_guard(setup_workspace, mismatch):
    state = setup_workspace
    _create(state)
    guard = state["store"]._macos_attempt_workspaces[ATTEMPT_ID]
    proof = guard.attest("reserve")
    if mismatch == "phase":
        proof["phase"] = "post_close"
    elif mismatch == "attempt":
        proof["attempt_id"] = "attempt-" + "d" * 32
    elif mismatch == "lease":
        proof["lease_digest"] = content_hash("another-lease")
    elif mismatch == "compiled":
        proof["compiled_digest"] = content_hash("another-compiled")
    else:
        state["store"].workspace["workspace_path_digest"] = content_hash(
            {"sandbox_root": "another-workspace"}
        )
        proof = None
    with pytest.raises(ProductStoreError, match="inventory changed"):
        state["store"]._validate_macos_workspace_attestation(
            FakeConnection(state["store"]),
            ATTEMPT_ID,
            state["lease"],
            state["compiled"],
            phase="reserve",
            proof=proof,
        )
    assert guard.closed
