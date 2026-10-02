"""Authored exception chains and inert lifecycle seams; no native effects."""

import inspect
import json
import ssl
from types import SimpleNamespace

import pytest

from bluefire.runner_lifecycle import RunnerLifecycleError
from bluefire.runner_transport_errors import RunnerAuthenticationError, RunnerConnectionError
from tests_platform import test_cross_platform_runtime as fixture
from tests_platform import transport_recovery_diagnostics as diagnostic

PRIVATE = "PRIVATE_PATH_MESSAGE_CREDENTIAL_MUST_NOT_APPEAR"


def read_report(capsys):
    output = capsys.readouterr().out
    assert PRIVATE not in output and len(output.encode()) < 2048
    return json.loads(output.removeprefix("Transport recovery diagnostic: "))


@pytest.mark.parametrize("underlying_type", [RunnerAuthenticationError, RunnerConnectionError])
def test_actual_finally_refusal_retains_suppressed_health_category(
    monkeypatch, tmp_path, capsys, underlying_type
):
    order = []
    underlying = underlying_type(PRIVATE)
    primary = RunnerLifecycleError(PRIVATE)
    cleanup = RunnerLifecycleError(PRIVATE)

    class Lifecycle:
        root = SimpleNamespace(exists=lambda: True)

        def bootstrap(self, **_kwargs):
            order.append("bootstrap")

        def client_for_profile(self, *_args, **_kwargs):
            try:
                raise underlying
            except underlying_type:
                raise primary from None

        def status(self, **_kwargs):
            order.append("status")
            return {"state": "stopped", "process": "absent", "enrollment": "active"}

        def revoke(self):
            order.append("revoke")
            raise cleanup

    lifecycle = Lifecycle()
    profile = SimpleNamespace(id=fixture.journey.PROFILE_ID, budgets=SimpleNamespace(max_seconds=5))
    service = SimpleNamespace(
        config=SimpleNamespace(runner_profiles=[profile]),
        start_runner=lambda **_kwargs: {"state": "ready"},
        close=lambda: order.append("service_close"),
    )
    monkeypatch.setattr(fixture, "ManagedRunnerLifecycle", lambda _root: lifecycle)
    monkeypatch.setattr(fixture, "BlueFireService", lambda **_kwargs: service)
    with pytest.raises(RunnerLifecycleError) as caught:
        fixture.test_authenticated_transport_recovery_is_full_and_independently_validated(tmp_path)
    assert caught.value is cleanup
    assert cleanup.__context__ is primary and primary.__context__ is underlying
    assert primary.__suppress_context__ is True
    assert order == ["bootstrap", "service_close", "status", "status", "revoke"]
    report = read_report(capsys)
    assert [row["category"] for row in report["exception_chain"]] == [
        "RunnerLifecycleError",
        "RunnerLifecycleError",
        underlying_type.__name__,
    ]
    assert [row["next"] for row in report["exception_chain"]] == ["context", "context", "none"]
    assert report["exception_chain"][1]["context_suppressed"] is True
    assert report["chain_truncated_or_cycle"] is False


@pytest.mark.parametrize(
    "error, label",
    [
        (TimeoutError(PRIVATE), "TimeoutError"),
        (ssl.SSLError(PRIVATE), "SSLError"),
        (OSError(PRIVATE), "OSError"),
    ],
)
def test_specific_os_categories_precede_general_os_error(error, label):
    assert diagnostic._summary(error)["exception_chain"] == [
        {"category": label, "next": "none", "context_suppressed": False}
    ]


def test_explicit_cause_takes_precedence_without_rendering_unknown_errors(monkeypatch, capsys):
    class UnknownError(Exception):
        def __str__(self):
            pytest.fail("Raw exception string accessed")

        def __repr__(self):
            pytest.fail("Raw exception repr accessed")

    error = UnknownError(PRIVATE)
    error.__cause__ = TimeoutError(PRIVATE)
    error.__context__ = OSError(PRIVATE)
    diagnostic._report(error)
    report = read_report(capsys)
    assert [row["category"] for row in report["exception_chain"]] == ["unknown", "TimeoutError"]
    assert report["exception_chain"][0]["next"] == "cause"


@pytest.mark.parametrize("cycle", [False, True])
def test_chain_is_bounded_and_cycles_are_explicit(cycle):
    errors = [RuntimeError(PRIVATE) for _ in range(10)]
    for first, second in zip(errors, errors[1:], strict=False):
        first.__context__ = second
    if cycle:
        errors[1].__context__ = errors[0]
    report = diagnostic._summary(errors[0])
    assert len(report["exception_chain"]) == (2 if cycle else 8)
    assert all(row["category"] == "unknown" for row in report["exception_chain"])
    assert report["chain_truncated_or_cycle"] is True


@pytest.mark.parametrize("failure_site", ["report", "print"])
def test_reporter_failure_preserves_final_exception_and_cleanup(monkeypatch, failure_site):
    order = []
    original = RunnerLifecycleError(PRIVATE)

    def unavailable(*_args, **_kwargs):
        raise KeyboardInterrupt(PRIVATE)

    monkeypatch.setattr(
        diagnostic, "_report" if failure_site == "report" else "print", unavailable, raising=False
    )

    @diagnostic.diagnose_transport_recovery
    def authored():
        try:
            raise original
        finally:
            order.append("cleanup")

    with pytest.raises(RunnerLifecycleError) as caught:
        authored()
    assert caught.value is original and order == ["cleanup"]


def test_success_does_not_report_and_pytest_fixture_signature_is_retained(monkeypatch):
    def unexpected(*_args):
        pytest.fail("Successful fixture produced diagnostics")

    monkeypatch.setattr(diagnostic, "_report", unexpected)

    @diagnostic.diagnose_transport_recovery
    def authored(tmp_path):
        return tmp_path

    value = object()
    assert authored(value) is value
    assert list(inspect.signature(authored).parameters) == ["tmp_path"]
    target = fixture.test_authenticated_transport_recovery_is_full_and_independently_validated
    assert list(inspect.signature(target).parameters) == ["tmp_path"]
    assert target.__wrapped__.__name__ == target.__name__
