from __future__ import annotations

import builtins
import importlib.util
from dataclasses import replace

import pytest

import bluefire.detection_backend_health as detection_backend_health
import bluefire.detection_backends as detection_backends
from bluefire.detection_backends import (
    DetectionBackendError,
    DetectionBackendUnavailable,
    ExternalDetectionValidator,
    execute_sqlite_query,
    inspect_sqlite_query,
)
from bluefire.detections import (
    DetectionCandidate,
    DetectionError,
    DetectionState,
)
from bluefire.detections import (
    ExternalDetectionValidator as LegacyExternalDetectionValidator,
)


def _query_candidate() -> DetectionCandidate:
    return DetectionCandidate.hypothesis(
        behavior_id="endpoint.process.discovery.v1",
        title="Bounded process query",
        target_language="sqlite",
        logsource={"category": "process_creation"},
        selection={"Image|endswith": "powershell.exe"},
        predicted_fields=("Image",),
        provenance={"source": "BlueFire Nexus", "license": "MIT"},
    )


def _sigma_candidate() -> DetectionCandidate:
    return DetectionCandidate.hypothesis(
        behavior_id="endpoint.process.discovery.v1",
        title="Converted process query",
        target_language="sigma",
        logsource={"category": "process_creation"},
        selection={"Image|endswith": "powershell.exe"},
        predicted_fields=("Image",),
        provenance={"source": "BlueFire Nexus", "license": "MIT"},
    )


def _yara_candidate() -> DetectionCandidate:
    return DetectionCandidate.hypothesis(
        behavior_id="endpoint.process.discovery.v1",
        title="Bounded YARA rule",
        target_language="yara",
        logsource={"category": "file_event"},
        selection={"marker": "BLUEFIRE"},
        predicted_fields=("data",),
        provenance={"source": "BlueFire Nexus", "license": "MIT"},
    )


def test_legacy_validator_import_is_compatible() -> None:
    assert LegacyExternalDetectionValidator is ExternalDetectionValidator


def test_sqlite_runtime_capabilities_degrade_safely_on_python_310() -> None:
    class Python310Connection:
        pass

    connection = Python310Connection()
    detection_backends._configure_limits(connection)  # type: ignore[arg-type]
    detection_backends._disable_load_extension(connection)  # type: ignore[arg-type]

    assert detection_backends._sqlite_constant("SQLITE_LIMIT_NOT_EXPOSED", 23) == 23
    assert [category for category, _limit in detection_backends._SQLITE_LIMITS] == list(range(10))


def test_authored_sqlite_query_executes_full_bounded_lifecycle() -> None:
    validator = ExternalDetectionValidator()
    parsed = validator.parse_sqlite(
        _query_candidate(),
        "SELECT fixture_id FROM logs WHERE Image LIKE '%powershell.exe'",
    )

    assert parsed.state is DetectionState.PARSED
    assert parsed.validation["query_compiled"] is True
    assert parsed.validation["source_rule_executed"] is False
    assert parsed.validation["mapped_fields"] == ["Image", "fixture_id"]
    assert parsed.validation["unsupported_fields"] == []
    assert parsed.validation["query_sha256"].startswith("sha256:")

    exercised = validator.exercise_query_fixtures(
        parsed,
        [
            {"fixture_id": "malicious-1", "Image": "C:/Windows/PowerShell.exe"},
            {"fixture_id": "malicious-2", "Image": "C:/Windows/notepad.exe"},
        ],
    )
    assert exercised.state is DetectionState.FIXTURE_EXERCISED
    assert exercised.match_count == 1
    assert exercised.validation["source_rule_executed"] is True
    assert exercised.validation["evaluated_fixture_ids"] == [
        "malicious-1",
        "malicious-2",
    ]
    assert exercised.validation["matched_fixture_ids"] == ["malicious-1"]
    assert exercised.validation["last_execution"]["query_only"] is True
    assert exercised.validation["last_execution"]["authorizer"] is True

    benign = validator.evaluate_query_benign(
        exercised,
        [{"fixture_id": "benign-1", "Image": "C:/Windows/explorer.exe"}],
        notes=("Known administrative shell use was reviewed.",),
    )
    assert benign.state is DetectionState.BENIGN_EVALUATED
    assert benign.benign_match_count == 0
    assert benign.validation["benign_evaluated_fixture_ids"] == ["benign-1"]
    assert benign.validation["benign_matched_fixture_ids"] == []


def test_unsupported_fields_are_reported_and_rejected() -> None:
    rejected = ExternalDetectionValidator().parse_sqlite(
        _query_candidate(),
        "SELECT fixture_id FROM logs WHERE SecretUnmappedField = 'x'",
    )

    assert rejected.state is DetectionState.REJECTED
    assert "unsupported fields" in str(rejected.rejection_reason)
    assert rejected.validation["unsupported_fields"] == ["SecretUnmappedField"]
    assert rejected.validation["source_rule_executed"] is False


@pytest.mark.parametrize(
    "query",
    [
        "PRAGMA query_only",
        "SELECT fixture_id FROM logs; SELECT fixture_id FROM logs",
        "SELECT fixture_id FROM logs UNION SELECT fixture_id FROM logs",
        "SELECT load_extension('plugin') FROM logs",
        "SELECT 'fixture-1' AS fixture_id FROM logs",
        "SELECT fixture_id FROM logs -- comment",
        "SELECT fixture_id FROM logs WHERE 1--\nOR 1",
        "SELECT fixture_id FROM logs JOIN logs AS second",
        "SELECT fixture_id FROM other",
    ],
)
def test_query_validation_denies_non_select_and_ambiguous_sql(query: str) -> None:
    with pytest.raises(DetectionBackendError):
        inspect_sqlite_query(query)


def test_query_requires_fixture_id_result_and_parameterized_ingestion_is_inert() -> None:
    with pytest.raises(DetectionBackendError, match="output fixture_id"):
        execute_sqlite_query(
            "SELECT Image FROM logs",
            [{"fixture_id": "fixture-1", "Image": "powershell.exe"}],
        )

    payload = "x'); DROP TABLE logs; --"
    result = execute_sqlite_query(
        "SELECT fixture_id FROM logs WHERE Image = 'x'",
        [{"fixture_id": "fixture-1", "Image": payload}],
    )
    assert result["matched_fixture_ids"] == []
    assert result["fixture_ids"] == ["fixture-1"]


def test_fixture_and_conversion_metadata_are_fail_closed() -> None:
    validator = ExternalDetectionValidator()
    parsed = validator.parse_sqlite(
        _query_candidate(),
        "SELECT fixture_id FROM logs WHERE Image = 'powershell.exe'",
    )
    forged = replace(
        parsed,
        validation={**dict(parsed.validation), "query_sha256": "sha256:" + "0" * 64},
    )
    with pytest.raises(DetectionError, match="digest"):
        validator.exercise_query_fixtures(
            forged,
            [{"fixture_id": "fixture-1", "Image": "powershell.exe"}],
        )
    with pytest.raises(DetectionError, match="fixture_id"):
        validator.exercise_query_fixtures(parsed, [{"Image": "powershell.exe"}])
    with pytest.raises(DetectionBackendError, match="count"):
        execute_sqlite_query(
            "SELECT fixture_id FROM logs",
            [{"fixture_id": f"fixture-{index}", "Image": "x"} for index in range(129)],
        )


def test_real_sigma_backend_conversion_and_execution_or_exact_dependency_error() -> None:
    validator = ExternalDetectionValidator()
    source = r"""
title: Fixed Process Discovery
id: 11111111-1111-4111-8111-111111111111
status: test
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
  condition: selection
falsepositives:
  - Approved inventory tooling
level: low
"""
    if importlib.util.find_spec("sigma.backends.sqlite") is None:
        with pytest.raises(
            DetectionError,
            match=r"pysigma-backend-sqlite==1\.2\.2.*remains a hypothesis",
        ):
            validator.parse_sigma(_sigma_candidate(), source)
        return

    parsed = validator.parse_sigma(_sigma_candidate(), source)
    assert parsed.state is DetectionState.PARSED
    assert parsed.parser_backend["name"] == "pySigma"
    assert parsed.parser_backend["conversion_backend"] == "pySigma SQLite"
    assert parsed.validation["source_rule_executed"] is False
    assert parsed.validation["query_sha256"].startswith("sha256:")
    exercised = validator.exercise_query_fixtures(
        parsed,
        [
            {"fixture_id": "malicious-1", "Image": r"C:\Windows\powershell.exe"},
            {"fixture_id": "benign-1", "Image": r"C:\Windows\notepad.exe"},
        ],
    )
    assert exercised.state is DetectionState.FIXTURE_EXERCISED
    assert exercised.validation["matched_fixture_ids"] == ["malicious-1"]


def test_yara_version_is_verified_before_untrusted_source_compilation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import_calls: list[str] = []
    original_import = builtins.__import__

    def wrong_version(_distribution: str, _expected: str) -> str:
        raise DetectionBackendUnavailable("reviewed YARA version mismatch")

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "yara":
            import_calls.append(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(detection_backends, "_package_version", wrong_version)
    monkeypatch.setattr(builtins, "__import__", guarded_import)

    with pytest.raises(DetectionError, match="version mismatch.*remains a hypothesis"):
        ExternalDetectionValidator().compile_yara(
            _yara_candidate(),
            "rule unsafe_on_wrong_version { condition: true }",
        )

    parsed = _yara_candidate().transition(
        DetectionState.PARSED,
        rule_source="rule unsafe_on_wrong_version { condition: true }",
    )
    with pytest.raises(DetectionError, match="version mismatch"):
        ExternalDetectionValidator().exercise_yara_fixtures(
            parsed,
            [{"fixture_id": "malicious-1", "data": "BLUEFIRE"}],
        )

    assert import_calls == []

    health_imports: list[str] = []

    def guarded_backend_import(name: str) -> object:
        health_imports.append(name)
        raise OSError("forced runtime loader failure")

    monkeypatch.setattr(detection_backend_health, "import_module", guarded_backend_import)
    monkeypatch.setattr(detection_backend_health.metadata, "version", lambda _name: "0")
    health = ExternalDetectionValidator.health()
    assert health["pySigma"]["ready"] is False
    assert health["YARA-Python"]["ready"] is False
    assert health_imports == []

    reviewed = {
        "pysigma": detection_backend_health.PYSIGMA_PIN,
        detection_backend_health.SQLITE_BACKEND_DISTRIBUTION: (
            detection_backend_health.SQLITE_BACKEND_PIN
        ),
        "yara-python": detection_backend_health.YARA_PIN,
    }
    monkeypatch.setattr(
        detection_backend_health.metadata,
        "version",
        lambda name: reviewed[name],
    )
    health = ExternalDetectionValidator.health()
    assert health["pySigma"]["ready"] is False
    assert health["YARA-Python"]["ready"] is False
    assert health_imports == ["sigma.collection", "yara"]


def test_yara_fixture_inventory_is_bounded_and_attributable() -> None:
    pytest.importorskip("yara")
    validator = ExternalDetectionValidator()
    parsed = validator.compile_yara(
        _yara_candidate(),
        'rule bluefire_marker { strings: $marker = "BLUEFIRE" condition: $marker }',
    )

    with pytest.raises(DetectionError, match="inventory.*exceeds"):
        validator.exercise_yara_fixtures(
            parsed,
            [{"fixture_id": f"fixture-{index}", "data": "BLUEFIRE"} for index in range(129)],
        )
    with pytest.raises(DetectionError, match="valid and unique"):
        validator.exercise_yara_fixtures(parsed, [{"data": "BLUEFIRE"}])
    with pytest.raises(DetectionError, match="valid and unique"):
        validator.exercise_yara_fixtures(
            parsed,
            [
                {"fixture_id": "duplicate", "data": "BLUEFIRE"},
                {"fixture_id": "duplicate", "data": "BLUEFIRE"},
            ],
        )
