from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

import bluefire.service as service_module
import bluefire.source_intake as source_intake
from bluefire.source_intake import SourceIntakeError

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX no-replace publication regression")


def test_posix_retained_destination_is_quarantined_without_path_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    intake_root = tmp_path / "source-intakes"
    destination = intake_root / "retained-posix"
    intake_root.mkdir(mode=0o700)
    destination.mkdir(mode=0o700)
    retained = destination / ".bfi-retained"
    retained.write_bytes(b"retained-owned-state")
    token = "9" * 16
    quarantine_name = f".retained-{destination.name}-{token}"
    quarantine = intake_root / quarantine_name

    def refuse_path_cleanup(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("retained POSIX state must not be deleted by pathname")

    monkeypatch.setattr(service_module, "token_hex", lambda _size: token)
    monkeypatch.setattr(Path, "unlink", refuse_path_cleanup)
    outcome = service_module._release_failed_source_intake_destination(
        destination,
        destination_identity=service_module._filesystem_identity(destination.lstat()),
        intake_root_identity=service_module._filesystem_identity(intake_root.lstat()),
        destination_created=True,
        published_artifact=None,
        published_receipt=None,
    )

    assert outcome == ("quarantined", f"source-intakes/{quarantine_name}")
    assert not destination.exists()
    assert (quarantine / retained.name).read_bytes() == b"retained-owned-state"
    destination.mkdir(mode=0o700)
    assert destination.is_dir()


def test_posix_publication_preserves_a_rebound_temporary_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "destination"
    destination.mkdir()
    token = "c" * 12
    temporary = destination / (source_intake._TEMPORARY_OUTPUT_PREFIX + token)
    target = destination / "result.json"
    real_rename = source_intake._posix_rename_no_replace

    monkeypatch.setattr(source_intake.secrets, "token_hex", lambda _size: token)

    def rename_then_rebind(root_descriptor: int, source_name: str, target_name: str) -> None:
        real_rename(root_descriptor, source_name, target_name)
        temporary.write_bytes(b"operator-owned-temporary")

    def refuse_path_cleanup(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("POSIX publication must not delete by pathname")

    monkeypatch.setattr(source_intake, "_posix_rename_no_replace", rename_then_rebind)
    monkeypatch.setattr(source_intake.os, "unlink", refuse_path_cleanup)

    with pytest.raises(SourceIntakeError, match="temporary output changed"):
        source_intake._publish_new_file(destination, target.name, b'{"ok":true}')

    assert temporary.read_bytes() == b"operator-owned-temporary"
    assert target.read_bytes() == b'{"ok":true}'


def test_posix_publication_refuses_a_raced_target_without_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "destination"
    destination.mkdir()
    token = "d" * 12
    temporary = destination / (source_intake._TEMPORARY_OUTPUT_PREFIX + token)
    target = destination / "result.json"
    real_rename = source_intake._posix_rename_no_replace

    monkeypatch.setattr(source_intake.secrets, "token_hex", lambda _size: token)

    def collide_then_rename(root_descriptor: int, source_name: str, target_name: str) -> None:
        target.write_bytes(b"operator-owned-target")
        real_rename(root_descriptor, source_name, target_name)

    monkeypatch.setattr(source_intake, "_posix_rename_no_replace", collide_then_rename)

    with pytest.raises(SourceIntakeError, match="atomically published"):
        source_intake._publish_new_file(destination, target.name, b'{"ok":true}')

    assert target.read_bytes() == b"operator-owned-target"
    assert temporary.read_bytes() == b'{"ok":true}'
