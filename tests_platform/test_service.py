from __future__ import annotations

from pathlib import Path

import pytest

from bluefire.service import BlueFireService

ROOT = Path(__file__).resolve().parents[1]


def test_default_run_store_uses_callers_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    service = BlueFireService(project_root=ROOT)

    assert service.store.root == (tmp_path / ".bluefire-runs").resolve()
