from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import capture_uv_version_evidence as evidence


def _official_payload(**commit_changes: object) -> str:
    commit = {
        "short_commit_hash": "329bf9448",
        "commit_hash": "329bf9448afd9f9088d14a4d57fbc61eb454f117",  # pragma: allowlist secret -- public uv release commit
        "commit_date": "2026-10-26",
        "last_tag": "0.13.6",
        "commits_since_last_tag": 0,
        **commit_changes,
    }
    return json.dumps(
        {
            "package_name": "uv",
            "version": "0.13.6",
            "commit_info": commit,
            "target_triple": "x86_64-unknown-linux-gnu",
        }
    )


def test_capture_records_only_bounded_known_version_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = {
        ("-V",): "uv 0.13.6 (329bf9448 2026-10-26 x86_64-unknown-linux-gnu)",
        ("self", "version", "--output-format", "json"): _official_payload(
            commits_since_last_tag=False
        ),
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
    distance = receipt["structured_output"]["commit_info"]["known_fields"]["commits_since_last_tag"]
    assert distance == {"type": "boolean", "value": False}
    assert json.loads(destination.read_text(encoding="utf-8")) == receipt
    assert destination.stat().st_size <= evidence.MAX_RECEIPT_BYTES


def test_unknown_or_unsafe_values_are_not_published(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = json.loads(_official_payload())
    payload["unexpected_field"] = "C:/private/operator/path"
    payload["commit_info"]["last_tag"] = "unsafe tag with spaces and /path"
    outputs = {
        ("-V",): "uv 0.13.6 (329bf9448 2026-10-26 x86_64-unknown-linux-gnu)",
        ("self", "version", "--output-format", "json"): json.dumps(payload),
    }
    monkeypatch.setattr(evidence, "_run_uv", lambda arguments: outputs[tuple(arguments)])
    destination = tmp_path / evidence.OUTPUT_NAME
    evidence.capture_uv_version_evidence(destination)
    published = destination.read_text(encoding="utf-8")

    assert "unexpected_field" in published
    assert "C:/private/operator/path" not in published
    assert "unsafe tag" not in published
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
