import sys
from pathlib import Path

import pytest

import bluefire.product_acceptance as acceptance
import bluefire.product_acceptance_process as acceptance_process


def test_gate_keeps_selected_venv_interpreter_and_redacts_both_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "base-python"
    base.write_bytes(b"interpreter identity fixture; never executed")
    selected = tmp_path / "venv" / "bin" / "python"
    selected.parent.mkdir(parents=True)
    try:
        selected.symlink_to(base)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")
    assert selected.resolve() == base.resolve()
    monkeypatch.setattr(sys, "executable", str(selected))
    repository = tmp_path / "repository"
    run_dir = tmp_path / "results"
    gate_dir = run_dir / "gate"
    receipt = gate_dir / "receipt.json"
    gate = acceptance.load_release_contract().gates[0]
    command = acceptance._render_command(
        gate, repository=repository, run_dir=run_dir, gate_dir=gate_dir, receipt=receipt
    )
    assert command[0] == str(selected.absolute())
    assert str(base) not in command
    assert (
        acceptance_process._redact_runtime_paths(
            f"selected={selected} resolved={base}", repository=repository, run_dir=run_dir
        )
        == "selected={python} resolved={python}"
    )
