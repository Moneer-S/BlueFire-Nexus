from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Event
from types import SimpleNamespace

import pytest

import bluefire.detection_backends as backends
from bluefire.application_errors import APIError
from bluefire.detection_lab import DetectionLabService
from bluefire.detections import DetectionCandidate, DetectionError, DetectionState
from bluefire.product_store import ProductStore, ProductStoreError, ResourceConflictError
from bluefire.registry import load_builtin_registry
from bluefire.run_store import RunStore
from bluefire.util import content_hash

SOURCE = 'rule BlueFire { strings: $a = "BLUEFIRE" condition: $a }'


@pytest.fixture
def fake_yara(monkeypatch):
    class Error(Exception):
        pass

    class TimeoutError(Error):
        pass

    state = SimpleNamespace(now=0.0, calls=[], elapsed=0.0, failure=None)

    def match(*, data, timeout):
        state.calls.append((data, timeout))
        state.now += state.elapsed
        if state.failure:
            raise state.failure
        return ["BlueFire"] if b"BLUEFIRE" in data else []

    module = SimpleNamespace(
        Error=Error,
        TimeoutError=TimeoutError,
        compile=lambda **kwargs: SimpleNamespace(match=match),
    )
    monkeypatch.setitem(sys.modules, "yara", module)
    monkeypatch.setattr(backends, "_package_version", lambda *args: backends._YARA_PIN)
    monkeypatch.setattr(backends, "monotonic", lambda: state.now)
    state.module = module
    return state


def candidate():
    return DetectionCandidate.hypothesis(
        behavior_id="sandbox.collection.stage.v1",
        title="Bounded YARA",
        target_language="yara",
        logsource={"category": "file_event"},
        selection={"marker": "BLUEFIRE"},
        predicted_fields=("data",),
        provenance={"source": "operator-authored", "license": "MIT"},
    )


def fixtures(count=1):
    return [{"fixture_id": f"fixture-{index}", "data": "BLUEFIRE"} for index in range(count)]


def lab(tmp_path):
    return DetectionLabService(
        product_store=ProductStore(tmp_path / "product.sqlite3"),
        run_store=RunStore(tmp_path / "runs"),
        registry=load_builtin_registry(),
    )


def parsed(service, *, second=False):
    hypothesis = candidate()
    if second:
        hypothesis = DetectionCandidate.hypothesis(
            behavior_id="sandbox.collection.stage.v1",
            title="Other YARA",
            target_language="yara",
            logsource={"category": "file_event"},
            selection={"marker": "OTHER"},
            predicted_fields=("data",),
            provenance={"source": "operator-authored", "license": "MIT"},
        )
    request = {
        key: hypothesis.to_dict()[key]
        for key in (
            "behavior_id",
            "title",
            "target_language",
            "logsource",
            "selection",
            "provenance",
            "predicted_fields",
        )
    }
    created = service.upsert_hypothesis(request)
    candidate_id = created["candidate"]["id"]
    service.parse(candidate_id, {"source": SOURCE})
    return candidate_id


@pytest.mark.parametrize("elapsed, expected_calls", [(0.6, 2), (1.1, 1), (2.0, 1)])
def test_yara_uses_one_deadline_and_never_scans_later_fixtures(fake_yara, elapsed, expected_calls):
    validator = backends.ExternalDetectionValidator()
    compiled = validator.compile_yara(candidate(), SOURCE)
    fake_yara.elapsed = elapsed
    with pytest.raises(DetectionError, match="timed out.*partial results were not accepted"):
        validator.exercise_yara_fixtures(compiled, fixtures(128))
    assert len(fake_yara.calls) == expected_calls
    assert fake_yara.calls[0][1] == 2
    if expected_calls == 2:
        assert fake_yara.calls[1][1] == 1
    assert compiled.state is DetectionState.PARSED


@pytest.mark.parametrize("benign", [False, True])
@pytest.mark.parametrize("failure", ["timeout", "error", "late_return"])
def test_incomplete_yara_never_changes_persisted_success(tmp_path, fake_yara, benign, failure):
    service = lab(tmp_path)
    candidate_id = parsed(service)
    if benign:
        service.exercise_fixtures(candidate_id, {"fixtures": fixtures()})
    before = service.candidate(candidate_id)
    fake_yara.calls.clear()
    if failure == "late_return":
        fake_yara.elapsed = 3.0
    else:
        error = fake_yara.module.TimeoutError if failure == "timeout" else fake_yara.module.Error
        fake_yara.failure = error("bounded backend failure")
    request = {"fixtures": fixtures(128), **({"notes": []} if benign else {})}
    operation = service.evaluate_benign if benign else service.exercise_fixtures
    with pytest.raises(APIError) as caught:
        operation(candidate_id, request)
    assert caught.value.code == "detection_validation_failed"
    assert len(fake_yara.calls) == 1
    assert service.candidate(candidate_id) == before


@pytest.mark.parametrize("benign", [False, True])
def test_unlocked_evaluation_preserves_snapshot_and_other_candidate_responsiveness(
    tmp_path,
    fake_yara,
    monkeypatch,
    benign,
):
    service = lab(tmp_path)
    candidate_id = parsed(service)
    other_id = parsed(service, second=True)
    if benign:
        service.exercise_fixtures(candidate_id, {"fixtures": fixtures()})
    before = service.candidate(candidate_id)["candidate"]["document"]
    entered, release = Event(), Event()
    method = "evaluate_yara_benign" if benign else "exercise_yara_fixtures"
    original = getattr(service.validator, method)

    def slow(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(service.validator, method, slow)
    request = {"fixtures": fixtures(), **({"notes": ["reviewed"]} if benign else {})}
    original_request_digest = content_hash(request)
    operation = service.evaluate_benign if benign else service.exercise_fixtures
    with ThreadPoolExecutor(max_workers=2) as pool:
        evaluation = pool.submit(operation, candidate_id, request)
        try:
            assert entered.wait(3)
            request["fixtures"][0]["data"] = "CHANGED"
            if benign:
                request["notes"].append("changed")
            other = pool.submit(service.reject, other_id, {"reason": "independent decision"})
            assert other.result(timeout=2)["candidate"]["status"] == "rejected"
        finally:
            release.set()
        result = evaluation.result(timeout=3)["candidate"]["document"]
    assert result["rule_source"] == before["rule_source"]
    assert result["definition_digest"] == before["definition_digest"]
    assert result["parser_backend"] == before["parser_backend"]
    assert result["validation"]["source_sha256"] == before["validation"]["source_sha256"]
    assert result["lifecycle_history"][-1]["input_digest"] == original_request_digest
    assert result["benign_fixtures" if benign else "malicious_fixtures"][0]["data"] == "BLUEFIRE"


@pytest.mark.parametrize("separate_service", [False, True])
@pytest.mark.parametrize("benign", [False, True])
def test_concurrent_decision_refuses_stale_evaluation(
    tmp_path,
    fake_yara,
    monkeypatch,
    separate_service,
    benign,
):
    service = lab(tmp_path)
    candidate_id = parsed(service)
    if benign:
        service.exercise_fixtures(candidate_id, {"fixtures": fixtures()})
    writer = lab(tmp_path) if separate_service else service
    entered, release = Event(), Event()
    method = "evaluate_yara_benign" if benign else "exercise_yara_fixtures"
    original = getattr(service.validator, method)

    def slow(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(service.validator, method, slow)
    operation = service.evaluate_benign if benign else service.exercise_fixtures
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(
            operation, candidate_id, {"fixtures": fixtures(), **({"notes": []} if benign else {})}
        )
        try:
            assert entered.wait(3)
            rejection = pool.submit(writer.reject, candidate_id, {"reason": "new decision"}).result(
                timeout=2
            )
        finally:
            release.set()
        with pytest.raises(APIError) as caught:
            future.result(timeout=3)
    assert caught.value.code == "detection_evaluation_conflict"
    assert service.candidate(candidate_id) == rejection


def test_two_evaluations_cannot_both_commit_same_snapshot(tmp_path, fake_yara, monkeypatch):
    service = lab(tmp_path)
    candidate_id = parsed(service)
    original = service.validator.exercise_yara_fixtures
    ready = Barrier(2)

    def together(*args, **kwargs):
        ready.wait(timeout=5)
        return original(*args, **kwargs)

    monkeypatch.setattr(service.validator, "exercise_yara_fixtures", together)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(service.exercise_fixtures, candidate_id, {"fixtures": fixtures()})
            for _ in range(2)
        ]
        results = []
        for future in futures:
            try:
                results.append(future.result(timeout=5))
            except APIError as exc:
                results.append(exc.code)
    assert sum(isinstance(result, dict) for result in results) == 1
    assert results.count("detection_evaluation_conflict") == 1


@pytest.mark.parametrize("changed", ["source", "parser"])
def test_yara_keeps_exact_source_authority(fake_yara, changed):
    validator = backends.ExternalDetectionValidator()
    compiled = validator.compile_yara(candidate(), SOURCE)
    altered = replace(
        compiled,
        **(
            {"rule_source": SOURCE + " "}
            if changed == "source"
            else {"parser_backend": {"name": "YARA-Python", "version": "other"}}
        ),
    )
    with pytest.raises(DetectionError, match="persisted YARA parser metadata"):
        validator.exercise_yara_fixtures(altered, fixtures())
    assert fake_yara.calls == []


def test_resource_cas_is_atomic_across_store_instances(tmp_path):
    first = ProductStore(tmp_path / "product.sqlite3")
    second = ProductStore(tmp_path / "product.sqlite3")
    initial = first.save_resource("collector", "reviewed", {"value": "initial"})
    latest = second.save_resource(
        "collector", "reviewed", {"value": "changed"}, expected_digest=initial["digest"]
    )
    with pytest.raises(ResourceConflictError):
        first.save_resource(
            "collector", "reviewed", {"value": "stale"}, expected_digest=initial["digest"]
        )
    with pytest.raises(ResourceConflictError):
        first.save_resource(
            "collector", "missing", {"value": "stale"}, expected_digest=initial["digest"]
        )
    with pytest.raises(ProductStoreError, match="expected resource digest"):
        first.save_resource("collector", "reviewed", {}, expected_digest="invalid")
    assert first.get_resource("collector", "reviewed") == latest
