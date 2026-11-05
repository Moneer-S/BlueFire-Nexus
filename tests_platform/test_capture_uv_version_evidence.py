from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import capture_uv_version_evidence as evidence


def _official_payload() -> str:
    return json.dumps(
        {
            "package_name": "uv",
            "version": "0.13.6",
            "commit_info": None,
            "target_triple": "x86_64-unknown-linux-gnu",
        }
    )


def test_capture_records_only_bounded_known_version_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = {
        ("-V",): "uv 0.13.6 (x86_64-unknown-linux-gnu)",
        ("self", "version", "--output-format", "json"): _official_payload(),
    }
    monkeypatch.setattr(evidence, "_run_uv", lambda arguments: outputs[tuple(arguments)])
    destination = tmp_path / evidence.OUTPUT_NAME
    receipt = evidence.capture_uv_version_evidence(destination)

    assert receipt["schema_version"] == evidence.SCHEMA_VERSION
    assert receipt["structured_output"]["root_keys"] == [
        "commit_info",
        "package_name",
        "target_triple",
        "version",
    ]
    assert receipt["structured_output"]["commit_info"] == {"type": "null", "value": None}
    assert json.loads(destination.read_text(encoding="utf-8")) == receipt
    assert destination.stat().st_size <= evidence.MAX_RECEIPT_BYTES


def test_unknown_or_unsafe_values_are_not_published(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = json.loads(_official_payload())
    payload["unexpected_field"] = "C:/private/operator/path"
    payload["version"] = "unsafe version with spaces and /path"
    outputs = {
        ("-V",): "uv 0.13.6 (x86_64-unknown-linux-gnu)",
        ("self", "version", "--output-format", "json"): json.dumps(payload),
    }
    monkeypatch.setattr(evidence, "_run_uv", lambda arguments: outputs[tuple(arguments)])
    destination = tmp_path / evidence.OUTPUT_NAME
    evidence.capture_uv_version_evidence(destination)
    published = destination.read_text(encoding="utf-8")

    assert "unexpected_field" in published
    assert "C:/private/operator/path" not in published
    assert "unsafe version" not in published
    assert '"value_omitted": true' in published


@pytest.mark.parametrize(
    ("raw", "status"),
    [
        ("not-json", "invalid-json"),
        ('{"package_name":"uv","package_name":"uv"}', "duplicate-key"),
        ("[]", "non-object"),
    ],
)
def test_invalid_structured_output_is_described_without_raw_content(raw: str, status: str) -> None:
    result = evidence._structured_evidence(raw)
    assert result["status"] == status
    assert raw not in json.dumps(result)


def test_capture_refuses_unbounded_output_or_destination_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / evidence.OUTPUT_NAME
    monkeypatch.setattr(evidence, "_run_uv", lambda _arguments: "x" * 5000)
    with pytest.raises(evidence.UvVersionEvidenceError, match="oversized"):
        evidence.capture_uv_version_evidence(destination)

    destination.write_text("existing", encoding="utf-8")
    with pytest.raises(evidence.UvVersionEvidenceError, match="destination"):
        evidence.capture_uv_version_evidence(destination)
