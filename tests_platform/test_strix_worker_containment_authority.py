from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from bluefire.strix_worker_containment_authority import (
    ControlledWorkerContainmentAuthorityV1,
    ControlledWorkerContainmentVerifierV1,
    LinuxWorkerContainmentFacts,
    LinuxWorkerLimits,
    StrixWorkerContainmentAuthorityError,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _facts() -> LinuxWorkerContainmentFacts:
    return LinuxWorkerContainmentFacts(
        schema_version="bluefire.strix-worker-containment-live-facts.v1",
        containment_ref=_digest("a"),
        startup_overlay_ref=_digest("1"),
        installed_projection_ref=_digest("2"),
        sealed_inputs_ref=_digest("3"),
        custody_identity=(42001, 20001, 20001, 880001, (42001, 1)),
        pidfd_ref=_digest("e"),
        policy_digest=_digest("b"),
        clone_filter_digest=_digest("f"),
        helper_digest=_digest("c"),
        limits=LinuxWorkerLimits(
            pids_max=16,
            memory_max=512 * 1024**2,
            cpu_quota=200_000,
            cpu_period=100_000,
        ),
        controller_rpc_identity=(1, 9),
        cgroup_identity=(1, 2),
        namespace_identities=(),
        root_identities=(),
        input_identities=(),
        relays=(),
    )


class _Verifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, authority: ControlledWorkerContainmentVerifierV1) -> None:
        assert authority.custody_identity == _facts().custody_identity
        self.calls += 1


def _authority(descriptor: int, verifier: _Verifier) -> ControlledWorkerContainmentAuthorityV1:
    # The native launcher is the only production constructor.  This deliberately
    # constructs the post-capture state to test the one-shot ownership transfer
    # without pretending the Windows test host has Linux namespaces or pidfds.
    authority = object.__new__(ControlledWorkerContainmentAuthorityV1)
    authority._facts = _facts()  # type: ignore[attr-defined]  # noqa: SLF001
    authority._descriptors = {"retained": descriptor}  # type: ignore[attr-defined]  # noqa: SLF001
    authority._verifier = verifier  # type: ignore[attr-defined]  # noqa: SLF001
    authority._taken = False  # type: ignore[attr-defined]  # noqa: SLF001
    return authority


def _binding(**changes: str) -> SimpleNamespace:
    values = {
        "worker_containment_ref": _facts().containment_ref,
        "startup_overlay_ref": _facts().startup_overlay_ref,
        "installed_projection_ref": _facts().installed_projection_ref,
        "sealed_inputs_ref": _facts().sealed_inputs_ref,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_rpc_verifier_transfer_is_one_shot_and_custody_bound() -> None:
    read_fd, write_fd = os.pipe()
    verifier = _Verifier()
    authority = _authority(read_fd, verifier)
    try:
        assert authority.containment_ref == _facts().containment_ref
        assert authority.startup_overlay_ref == _facts().startup_overlay_ref
        assert authority.installed_projection_ref == _facts().installed_projection_ref
        assert authority.sealed_inputs_ref == _facts().sealed_inputs_ref
        live = authority.take_verifier(
            worker=SimpleNamespace(custody_identity=_facts().custody_identity),
            binding=_binding(),
        )
        assert verifier.calls == 1
        assert live.startup_overlay_ref == _facts().startup_overlay_ref
        assert live.installed_projection_ref == _facts().installed_projection_ref
        assert live.sealed_inputs_ref == _facts().sealed_inputs_ref
        live.verify()
        assert verifier.calls == 2
        with pytest.raises(StrixWorkerContainmentAuthorityError, match="already transferred"):
            authority.take_verifier(
                worker=SimpleNamespace(custody_identity=_facts().custody_identity),
                binding=_binding(),
            )
        live.close()
        live.close()
        with pytest.raises(StrixWorkerContainmentAuthorityError, match="closed"):
            live.verify()
        with pytest.raises(OSError):
            os.fstat(read_fd)
    finally:
        try:
            os.close(read_fd)
        except OSError:
            pass
        os.close(write_fd)


@pytest.mark.parametrize(
    ("worker", "binding", "message"),
    [
        (
            SimpleNamespace(custody_identity=(42002, 20001, 20001, 880001, (42002, 1))),
            _binding(),
            "custody",
        ),
        (
            SimpleNamespace(custody_identity=_facts().custody_identity),
            _binding(worker_containment_ref=_digest("d")),
            "binding",
        ),
        (
            SimpleNamespace(custody_identity=_facts().custody_identity),
            _binding(startup_overlay_ref=_digest("d")),
            "binding",
        ),
        (
            SimpleNamespace(custody_identity=_facts().custody_identity),
            _binding(installed_projection_ref=_digest("d")),
            "binding",
        ),
        (
            SimpleNamespace(custody_identity=_facts().custody_identity),
            _binding(sealed_inputs_ref=_digest("d")),
            "binding",
        ),
    ],
)
def test_rpc_verifier_refuses_worker_or_receipt_substitution(
    worker: object, binding: object, message: str
) -> None:
    read_fd, write_fd = os.pipe()
    authority = _authority(read_fd, _Verifier())
    try:
        with pytest.raises(StrixWorkerContainmentAuthorityError, match=message):
            authority.take_verifier(worker=worker, binding=binding)  # type: ignore[arg-type]
        authority.close()
        with pytest.raises(OSError):
            os.fstat(read_fd)
    finally:
        try:
            os.close(read_fd)
        except OSError:
            pass
        os.close(write_fd)


def test_limits_reject_unbounded_thread_or_resource_profiles() -> None:
    valid = LinuxWorkerLimits(
        pids_max=16,
        memory_max=512 * 1024**2,
        cpu_quota=200_000,
        cpu_period=100_000,
    )
    valid.validate()
    for invalid in (
        LinuxWorkerLimits(1, valid.memory_max, valid.cpu_quota, valid.cpu_period),
        LinuxWorkerLimits(65, valid.memory_max, valid.cpu_quota, valid.cpu_period),
        LinuxWorkerLimits(valid.pids_max, 64 * 1024**2, valid.cpu_quota, valid.cpu_period),
        LinuxWorkerLimits(valid.pids_max, valid.memory_max, 10_000_000, 1_000),
    ):
        with pytest.raises(StrixWorkerContainmentAuthorityError):
            invalid.validate()
