"""Reopen real test-owned lease files; all WSL and guest seams are simulated."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from bluefire import prepared_lab as lab


def _lease(tmp_path, monkeypatch, *, legacy=False, historical_location=False):
    state = tmp_path / "state"
    state.mkdir()
    store = tmp_path / "managed-storage"
    store.mkdir()
    token = "0123456789abcdef"
    install = (state if historical_location else store) / ("wsl-distribution-" + token)
    install.mkdir()
    (state / "management.lock").touch()
    monkeypatch.setattr(lab, "_distribution_storage_parent", lambda **_kwargs: store)
    monkeypatch.setattr(lab, "registration", lambda _name: ("original-guid", install))
    monkeypatch.setattr(lab, "_trusted_wsl_executable", lambda: Path(sys.executable))
    document = {
        "schema_version": lab.LEGACY_SCHEMA if legacy else lab.SCHEMA,
        "distribution_name": "BlueFire-Gate11-Run-" + token,
        "state_identity": list(lab.identity(state, directory=True)),
        "install_identity": list(lab.identity(install, directory=True)),
        "lock_identity": list(lab.identity(state / "management.lock", directory=False)),
        "registration_id": "original-guid",
    }
    if not legacy:
        document.update(install_root=str(install), identity_format=lab.identity_format())
    (state / "lease.json").write_text(json.dumps(document), encoding="utf-8")
    return state, install, document


@pytest.mark.parametrize("legacy,historical", [(False, False), (True, False), (True, True)])
def test_reopen_exact_saved_lease_without_rewriting_evidence(
    tmp_path, monkeypatch, legacy, historical
):
    state, install, document = _lease(
        tmp_path, monkeypatch, legacy=legacy, historical_location=historical
    )
    original = (state / "lease.json").read_bytes()
    with lab.owned(state) as (lease, decoded):
        assert lease.install_root == install
        assert lease.install_identity == tuple(document["install_identity"])
        assert lease.registration_id == "original-guid"
        assert decoded == document
    assert (state / "lease.json").read_bytes() == original


@pytest.mark.parametrize("fault", ["registration", "path", "volume", "format", "field", "boolean"])
def test_reopen_refuses_changed_binding_before_yield(tmp_path, monkeypatch, fault):
    state, install, document = _lease(tmp_path, monkeypatch)
    if fault == "registration":
        monkeypatch.setattr(lab, "registration", lambda _: ("replacement-guid", install))
    elif fault == "path":
        document["install_root"] = str(tmp_path / "unrelated")
    elif fault == "volume":
        document["install_identity"][0] ^= 1 << 32
    elif fault == "format":
        document["identity_format"] = "unknown"
    elif fault == "field":
        document["unreviewed_field"] = True
    else:
        document["install_identity"][0] = True
    (state / "lease.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError):
        with lab.owned(state):
            pytest.fail("an unbound lab was yielded")


def test_legacy_low_volume_bits_never_become_full_identity_authority(tmp_path, monkeypatch):
    state, install, document = _lease(tmp_path, monkeypatch, legacy=True)
    full = (0xFEDCBA9812345678, 9)
    document["install_identity"] = [0x12345678, 9]
    monkeypatch.setattr(lab, "identity", lambda *_args, **_kwargs: full)
    with pytest.raises(ValueError, match="storage identity"):
        lab._lease_storage(document, state)


def test_new_preparation_can_reopen_storage_outside_state(tmp_path, monkeypatch):
    state = tmp_path / "state"
    store = tmp_path / "managed-storage"
    store.mkdir()
    install = store / ("wsl-distribution-" + "1" * 16)
    install.mkdir()
    lease = lab.DisposableWslDistribution(
        Path(sys.executable),
        state,
        "BlueFire-Gate11-Run-" + "1" * 16,
        install,
        lab.identity(install, directory=True),
        registration_id="original-guid",
    )
    monkeypatch.setattr(lab, "_distribution_storage_parent", lambda **_kwargs: store)
    monkeypatch.setattr(lab, "wheel_inputs", lambda *_args: [])
    monkeypatch.setattr(lab, "_trusted_wsl_executable", lambda: Path(sys.executable))
    monkeypatch.setattr(lab, "registration", lambda _: ("original-guid", install))
    monkeypatch.setattr(lab, "create_disposable_wsl_distribution", lambda *_args: lease)
    monkeypatch.setattr(lab.subprocess, "run", lambda *_args, **_kwargs: None)
    lab.prepare(state, tmp_path / "product.whl", tmp_path)
    with lab.owned(state) as (reopened, document):
        assert reopened.install_root == install
        assert document["schema_version"] == lab.SCHEMA
