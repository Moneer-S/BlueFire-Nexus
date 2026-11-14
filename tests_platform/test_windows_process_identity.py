from __future__ import annotations

import os

import pytest

from bluefire import cross_platform_recovery_witness as witness
from bluefire.windows_process_identity import (
    WindowsProcessIdentityError,
    capture_process_identity,
    process_identity_running,
)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows process handles")
def test_native_identity_checks_current_process_and_rejects_another_creation_time() -> None:
    identity = capture_process_identity(os.getpid())

    assert identity["process_id"] == os.getpid()
    assert identity["creation_time_100ns"] > 0
    assert process_identity_running(identity)
    assert witness.capture_process_identity(os.getpid()) == identity
    assert witness.process_identity_running(identity)
    assert not process_identity_running(
        {**identity, "creation_time_100ns": identity["creation_time_100ns"] + 1}
    )


def test_malformed_identity_preserves_native_and_witness_error_contracts() -> None:
    identity = {"process_id": True, "creation_time_100ns": 1}

    with pytest.raises(WindowsProcessIdentityError, match="process identity is invalid"):
        process_identity_running(identity)
    with pytest.raises(witness.RecoveryWitnessError, match="process identity is invalid"):
        witness.process_identity_running(identity)
