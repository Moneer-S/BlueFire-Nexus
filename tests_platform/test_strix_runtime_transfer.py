from __future__ import annotations

import hashlib
import io
import os
import shutil
import tarfile
from pathlib import Path
from typing import Any

import pytest

from bluefire import strix_runtime_transfer as transfer
from bluefire.util import canonical_json_bytes

REVISION = "1" * 40
THREAT_REF = "sha256:" + "2" * 64


def _source_tree(root: Path) -> tuple[Path, Path, Path]:
    candidate = root / transfer.CANDIDATE_DIRECTORY
    preparation = root / transfer.PREPARATION_DIRECTORY
    work = root / transfer.WORK_DIRECTORY
    pip_tool = work / "pip-tool"
    pip_tool.mkdir(parents=True)
    candidate.mkdir()
    preparation.mkdir()
    (candidate / "candidate.json").write_text("candidate\n", encoding="utf-8")
    (preparation / "receipt.json").write_text("receipt\n", encoding="utf-8")
    (pip_tool / "pip.whl").write_text("pinned pip\n", encoding="utf-8")
    return candidate, preparation, work


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def test_transfer_bundle_is_deterministic_and_round_trips_without_path_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate, preparation, work = _source_tree(tmp_path)
    (work / "runtime/lib/python3.12/site-packages").mkdir(parents=True)
    (work / "runtime/lib/python3.12/site-packages/sitecustomize.py").write_text(
        "raise RuntimeError('must not transfer')\n", encoding="utf-8"
    )
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"
    first_ref = transfer.create_transfer_bundle(
        first,
        candidate_root=candidate,
        preparation_root=preparation,
        preparation_work_root=work,
        bluefire_source_revision=REVISION,
        threat_review_ref=THREAT_REF,
    )
    second_ref = transfer.create_transfer_bundle(
        second,
        candidate_root=candidate,
        preparation_root=preparation,
        preparation_work_root=work,
        bluefire_source_revision=REVISION,
        threat_review_ref=THREAT_REF,
    )
    assert first_ref == second_ref
    assert first.read_bytes() == second.read_bytes()
    for path in (candidate, preparation, work):
        shutil.rmtree(path)

    real_open = tarfile.open
    calls: list[dict[str, object]] = []

    def recording_open(*args: object, **kwargs: object) -> tarfile.TarFile:
        calls.append(dict(kwargs))
        return real_open(*args, **kwargs)

    monkeypatch.setattr(transfer.tarfile, "open", recording_open)
    extracted = transfer.extract_transfer_bundle(
        first,
        transfer_root=tmp_path,
        expected_ref=first_ref,
        bluefire_source_revision=REVISION,
        threat_review_ref=THREAT_REF,
    )
    assert (extracted[0] / "candidate.json").read_text(encoding="utf-8") == "candidate\n"
    assert (extracted[1] / "receipt.json").read_text(encoding="utf-8") == "receipt\n"
    assert (extracted[2] / "pip-tool/pip.whl").read_text(encoding="utf-8") == "pinned pip\n"
    assert not (extracted[2] / "runtime").exists()
    assert calls and calls[0].get("fileobj") is not None and "name" not in calls[0]
    transfer.remove_transfer_tree(tmp_path)
    assert all(not path.exists() for path in extracted)


def _metadata(root: Path) -> bytes:
    value = {
        "schema": transfer.SCHEMA,
        "bluefire_source_revision": REVISION,
        "threat_review_ref": THREAT_REF,
        "preparation_work_root": (root / transfer.WORK_DIRECTORY).as_posix(),
        "runtime_root": (root / transfer.WORK_DIRECTORY / "runtime").as_posix(),
        "pip_tool_root": (root / transfer.WORK_DIRECTORY / "pip-tool").as_posix(),
        "top_level": sorted(
            {
                transfer.CANDIDATE_DIRECTORY,
                transfer.PREPARATION_DIRECTORY,
                transfer.WORK_DIRECTORY,
            }
        ),
        "claims": {
            "strix_executed": False,
            "target": False,
            "model": False,
            "network_probe": False,
        },
    }
    return canonical_json_bytes(value) + b"\n"


def _member(name: str, *, kind: bytes, payload: bytes = b"", link: str = "") -> tarfile.TarInfo:
    item = tarfile.TarInfo(name)
    item.type = kind
    item.mode = 0o555 if kind == tarfile.DIRTYPE else 0o444
    item.uid = item.gid = item.mtime = 0
    item.size = len(payload)
    item.linkname = link
    return item


def _custom_bundle(root: Path, extras: list[tuple[tarfile.TarInfo, bytes]]) -> Path:
    path = root / "custom.tar"
    metadata = _metadata(root)
    with tarfile.open(path, "x", format=tarfile.PAX_FORMAT) as archive:
        archive.addfile(
            _member(transfer.METADATA_NAME, kind=tarfile.REGTYPE, payload=metadata),
            io.BytesIO(metadata),
        )
        for name in sorted(
            {
                transfer.CANDIDATE_DIRECTORY,
                transfer.PREPARATION_DIRECTORY,
                transfer.WORK_DIRECTORY,
                transfer.PIP_PREFIX,
            }
        ):
            archive.addfile(_member(name, kind=tarfile.DIRTYPE))
        for item, payload in extras:
            archive.addfile(item, io.BytesIO(payload) if item.isfile() else None)
    return path


@pytest.mark.parametrize(
    "extras",
    [
        [(_member("../escape", kind=tarfile.REGTYPE, payload=b"x"), b"x")],
        [(_member("/absolute", kind=tarfile.REGTYPE, payload=b"x"), b"x")],
        [(_member("bad\\path", kind=tarfile.REGTYPE, payload=b"x"), b"x")],
        [
            (_member(f"{transfer.CANDIDATE_DIRECTORY}/File", kind=tarfile.REGTYPE), b""),
            (_member(f"{transfer.CANDIDATE_DIRECTORY}/file", kind=tarfile.REGTYPE), b""),
        ],
        [(_member(f"{transfer.CANDIDATE_DIRECTORY}/hard", kind=tarfile.LNKTYPE), b"")],
        [(_member(f"{transfer.CANDIDATE_DIRECTORY}/fifo", kind=tarfile.FIFOTYPE), b"")],
        [(_member(f"{transfer.CANDIDATE_DIRECTORY}/contiguous", kind=tarfile.CONTTYPE), b"")],
        [
            (
                _member(
                    f"{transfer.WORK_DIRECTORY}/runtime/forbidden",
                    kind=tarfile.REGTYPE,
                    payload=b"x",
                ),
                b"x",
            )
        ],
        [
            (
                _member(
                    f"{transfer.CANDIDATE_DIRECTORY}/sparse",
                    kind=tarfile.GNUTYPE_SPARSE,
                ),
                b"",
            )
        ],
        [
            (
                _member(
                    f"{transfer.WORK_DIRECTORY}/outside",
                    kind=tarfile.REGTYPE,
                    payload=b"x",
                ),
                b"x",
            ),
            (
                _member(
                    f"{transfer.PIP_PREFIX}/escape",
                    kind=tarfile.SYMTYPE,
                    link="../outside",
                ),
                b"",
            ),
        ],
        [
            (
                _member(
                    f"{transfer.PIP_PREFIX}/missing-link",
                    kind=tarfile.SYMTYPE,
                    link="missing",
                ),
                b"",
            )
        ],
        [
            (
                _member(
                    f"{transfer.PIP_PREFIX}/bad-absolute",
                    kind=tarfile.SYMTYPE,
                    link="/etc/passwd",
                ),
                b"",
            )
        ],
    ],
)
def test_transfer_preflight_rejects_unsafe_members(
    tmp_path: Path, extras: list[tuple[tarfile.TarInfo, bytes]]
) -> None:
    bundle = _custom_bundle(tmp_path, extras)
    with pytest.raises(transfer.StrixRuntimeTransferError):
        transfer.extract_transfer_bundle(
            bundle,
            transfer_root=tmp_path,
            expected_ref=_digest(bundle),
            bluefire_source_revision=REVISION,
            threat_review_ref=THREAT_REF,
        )
    assert not (tmp_path / transfer.CANDIDATE_DIRECTORY).exists()
    assert not (tmp_path / transfer.PREPARATION_DIRECTORY).exists()
    assert not (tmp_path / transfer.WORK_DIRECTORY).exists()


def test_transfer_rejects_wrong_ref_and_cleans_partial_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate, preparation, work = _source_tree(tmp_path)
    bundle = tmp_path / "input.tar"
    reference = transfer.create_transfer_bundle(
        bundle,
        candidate_root=candidate,
        preparation_root=preparation,
        preparation_work_root=work,
        bluefire_source_revision=REVISION,
        threat_review_ref=THREAT_REF,
    )
    for path in (candidate, preparation, work):
        shutil.rmtree(path)
    with pytest.raises(transfer.StrixRuntimeTransferError, match="reference changed"):
        transfer.extract_transfer_bundle(
            bundle,
            transfer_root=tmp_path,
            expected_ref="sha256:" + "f" * 64,
            bluefire_source_revision=REVISION,
            threat_review_ref=THREAT_REF,
        )

    real_open = os.open

    def failing_open(
        path: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
        **kwargs: Any,
    ) -> int:
        if flags & os.O_WRONLY:
            raise OSError("injected extraction failure")
        return real_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(transfer.os, "open", failing_open)
    with pytest.raises(OSError, match="injected"):
        transfer.extract_transfer_bundle(
            bundle,
            transfer_root=tmp_path,
            expected_ref=reference,
            bluefire_source_revision=REVISION,
            threat_review_ref=THREAT_REF,
        )
    assert not (tmp_path / transfer.CANDIDATE_DIRECTORY).exists()
    assert not (tmp_path / transfer.PREPARATION_DIRECTORY).exists()
    assert not (tmp_path / transfer.WORK_DIRECTORY).exists()


def test_transfer_requires_the_same_absolute_cross_job_stage_layout(tmp_path: Path) -> None:
    stage = tmp_path / "bluefire-strix-preparation-stage"
    stage.mkdir()
    candidate, preparation, work = _source_tree(stage)
    bundle = tmp_path / "input.tar"
    reference = transfer.create_transfer_bundle(
        bundle,
        candidate_root=candidate,
        preparation_root=preparation,
        preparation_work_root=work,
        bluefire_source_revision=REVISION,
        threat_review_ref=THREAT_REF,
    )
    for path in (candidate, preparation, work):
        shutil.rmtree(path)

    drifted_stage = tmp_path / "different-stage"
    drifted_stage.mkdir()
    with pytest.raises(transfer.StrixRuntimeTransferError, match="metadata identity"):
        transfer.extract_transfer_bundle(
            bundle,
            transfer_root=drifted_stage,
            expected_ref=reference,
            bluefire_source_revision=REVISION,
            threat_review_ref=THREAT_REF,
        )
    extracted = transfer.extract_transfer_bundle(
        bundle,
        transfer_root=stage,
        expected_ref=reference,
        bluefire_source_revision=REVISION,
        threat_review_ref=THREAT_REF,
    )
    assert extracted[2] == stage / transfer.WORK_DIRECTORY
    transfer.remove_transfer_tree(stage)
