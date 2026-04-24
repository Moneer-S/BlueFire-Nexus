"""Splunk SPL detection draft generator."""

from __future__ import annotations

from pathlib import Path

from ..models import ModuleResult


def render_spl(result: ModuleResult, run_id: str) -> str:
    technique = result.techniques[0] if result.techniques else "T0000"
    module = result.module
    return (
        f'| makeresults | eval run_id="{run_id}", module="{module}", technique="{technique}" '
        '| where module!="" | table run_id module technique'
    )


def write_spl(result: ModuleResult, output_dir: Path, run_id: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{result.module}.spl"
    target.write_text(render_spl(result, run_id), encoding="utf-8")
    return target
