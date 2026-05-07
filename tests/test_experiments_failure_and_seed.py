"""Failure-path and seed-determinism coverage for the experiments harness.

Companion to ``test_experiments.py`` (happy-path integration) and
``test_experiments_jitter.py`` (jitter applied as overrides). The
PR #42 audit flagged that ``src/core/experiments.py`` coverage was
essentially smoke. This file pins:

1. **Seed determinism** — the same `seed` produces the same jitter
   sequence (so reruns are reproducible and "experiment" really
   means a controlled experiment).
2. **Failure-mode counting** — `successes` / `failures` /
   `step_success_rate` / `detection_coverage_rate` are computed
   correctly from a mix of `success`, `partial_success`, `failure`,
   and `error` results.
3. **Edge cases** — `runs=0` returns a well-formed summary (no
   division by zero); empty/malformed step or detection structures
   do not crash.
4. **Helper invariants** —
   - ``_count_detection_artifacts`` handles list values, scalar
     truthy values, and missing keys.
   - ``_mutate_run_params`` is a no-op when `enable_jitter=False`.
   - ``_merge_step_mutation`` is a no-op when `mutation` is absent
     from the state, replaces a non-dict params with a fresh dict
     rather than erroring, and never mutates the input list in place.
5. **Output file** — `summary.json` is written under the runtime's
   `_output_root()` and contains exactly `runs` records.
6. **Compatibility wrapper** — ``run_experiment_series`` returns
   `results=[]` rather than raising when the summary file cannot
   be parsed.

All tests are unit-isolated: a `_FakeNexus` returns a deterministic
result so failures in real modules cannot bleed into the harness
contract.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any, Dict, List, Mapping

import pytest

from src.core.experiments import (
    _count_detection_artifacts,
    _merge_step_mutation,
    _mutate_run_params,
    run_experiment,
    run_experiment_series,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _FakeNexus:
    """Deterministic stand-in for BlueFireNexus with optional per-run results.

    ``results_for_run(index)`` returns the dict to publish on the
    ``index``-th call (zero-based). Defaults to a single
    success-step result. Mirrors ``BlueFireNexus._output_root`` so
    ``run_experiment`` writes its summary.json under the test's
    tmp directory.
    """

    def __init__(
        self,
        output_root: Path,
        per_run_results: List[Dict[str, Any]] | None = None,
    ) -> None:
        self.calls: list[tuple[str, str | None, dict | None]] = []
        self._output_root_path = output_root
        self._per_run = per_run_results or []

    def run_scenario_file(
        self,
        scenario_path: str,
        run_id: str | None = None,
        step_param_overrides: dict | None = None,
    ) -> Dict[str, Any]:
        index = len(self.calls)
        self.calls.append((scenario_path, run_id, step_param_overrides))
        if index < len(self._per_run):
            return self._per_run[index]
        return {
            "status": "success",
            "steps": [
                {"status": "success", "detections": {"sigma": ["rule-1"]}},
            ],
        }

    def _output_root(self) -> Path:
        return self._output_root_path


def _mini_scenario(tmp_path: Path) -> Path:
    """Write a one-step scenario YAML under tmp_path and return the path."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(
        "\n".join(
            [
                "id: mini",
                "name: Mini Scenario",
                "objective: test",
                "attack_coverage: ['T0001']",
                "steps:",
                "  - id: step-1",
                "    name: execute",
                "    module: execution",
                "    params:",
                "      command: echo hi",
            ]
        ),
        encoding="utf-8",
    )
    return scenario


# ---------------------------------------------------------------------------
# Seed determinism
# ---------------------------------------------------------------------------


def _capture_overrides(
    tmp_path: Path, *, seed: int, runs: int = 4
) -> List[Mapping[str, Any] | None]:
    scenario = _mini_scenario(tmp_path)
    nexus = _FakeNexus(output_root=tmp_path)
    run_experiment(nexus, str(scenario), runs=runs, seed=seed, jitter=True)
    return [overrides for _, _, overrides in nexus.calls]


def test_same_seed_produces_identical_jitter_sequence(tmp_path: Path) -> None:
    overrides_a = _capture_overrides(tmp_path / "a", seed=42)
    overrides_b = _capture_overrides(tmp_path / "b", seed=42)
    assert overrides_a == overrides_b


def test_different_seed_diverges_within_a_few_runs(tmp_path: Path) -> None:
    """Different seeds shouldn't produce identical sequences for non-trivial run counts."""
    overrides_a = _capture_overrides(tmp_path / "a", seed=1, runs=8)
    overrides_b = _capture_overrides(tmp_path / "b", seed=99, runs=8)
    assert overrides_a != overrides_b


def test_seed_isolation_per_call(tmp_path: Path) -> None:
    """``run_experiment(seed=...)`` must reseed the global RNG so a
    test that sets random.seed() before is not entangled with the
    harness's deterministic stream.
    """
    random.seed(12345)  # noisy ambient state
    captured = _capture_overrides(tmp_path, seed=7, runs=3)
    # Re-seed ambient again, then run with the same harness seed —
    # output must match the first call regardless of the ambient noise.
    random.seed(98765)
    second = _capture_overrides(tmp_path / "second", seed=7, runs=3)
    assert captured == second


# ---------------------------------------------------------------------------
# Failure-mode counting
# ---------------------------------------------------------------------------


def test_mix_of_success_failure_and_error_counts_correctly(tmp_path: Path) -> None:
    scenario = _mini_scenario(tmp_path)
    per_run = [
        {"status": "success", "steps": [{"status": "success"}]},
        {"status": "partial_success", "steps": [{"status": "success"}]},
        {"status": "failure", "steps": [{"status": "failure"}]},
        {"status": "error", "steps": [{"status": "error"}]},
    ]
    nexus = _FakeNexus(output_root=tmp_path, per_run_results=per_run)
    summary = run_experiment(nexus, str(scenario), runs=4)

    # successes counts both `success` and `partial_success`.
    assert summary.successes == 2
    assert summary.failures == 2
    assert summary.runs == 4


def test_step_success_rate_and_detection_coverage_rate(tmp_path: Path) -> None:
    """Two of four runs have a successful step + one detection each."""
    scenario = _mini_scenario(tmp_path)
    per_run = [
        {
            "status": "success",
            "steps": [
                {"status": "success", "detections": {"sigma": ["a"]}},
                {"status": "failure"},
            ],
        },
        {
            "status": "partial_success",
            "steps": [
                {"status": "success", "detections": {"sigma": ["b"]}},
                {"status": "failure"},
            ],
        },
        {"status": "failure", "steps": [{"status": "failure"}, {"status": "failure"}]},
        {"status": "failure", "steps": [{"status": "failure"}, {"status": "failure"}]},
    ]
    nexus = _FakeNexus(output_root=tmp_path, per_run_results=per_run)
    summary = run_experiment(nexus, str(scenario), runs=4)

    # 2 successful steps out of 8 total = 0.25.
    assert summary.step_success_rate == 0.25
    # 2 of 4 runs have a detection -> 0.5.
    assert summary.detection_coverage_rate == 0.5
    assert summary.detection_artifact_count == 2


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_zero_runs_does_not_divide_by_zero(tmp_path: Path) -> None:
    scenario = _mini_scenario(tmp_path)
    nexus = _FakeNexus(output_root=tmp_path)
    summary = run_experiment(nexus, str(scenario), runs=0)
    assert summary.runs == 0
    assert summary.successes == 0
    assert summary.failures == 0
    assert summary.step_success_rate == 0.0
    assert summary.detection_coverage_rate == 0.0
    assert summary.detection_artifact_count == 0


def test_run_with_no_steps_key_does_not_raise(tmp_path: Path) -> None:
    scenario = _mini_scenario(tmp_path)
    per_run = [{"status": "success"}]  # no `steps` key at all
    nexus = _FakeNexus(output_root=tmp_path, per_run_results=per_run)
    summary = run_experiment(nexus, str(scenario), runs=1)
    assert summary.successes == 1
    assert summary.step_success_rate == 0.0


def test_run_with_malformed_detections_does_not_raise(tmp_path: Path) -> None:
    """detections that aren't a dict (e.g. None / list) should be
    skipped, not raise."""
    scenario = _mini_scenario(tmp_path)
    per_run = [
        {"status": "success", "steps": [{"status": "success", "detections": None}]},
        {"status": "success", "steps": [{"status": "success", "detections": []}]},
    ]
    nexus = _FakeNexus(output_root=tmp_path, per_run_results=per_run)
    summary = run_experiment(nexus, str(scenario), runs=2)
    assert summary.detection_artifact_count == 0
    assert summary.detection_coverage_rate == 0.0


# ---------------------------------------------------------------------------
# Output file
# ---------------------------------------------------------------------------


def test_summary_file_written_under_output_root(tmp_path: Path) -> None:
    scenario = _mini_scenario(tmp_path)
    nexus = _FakeNexus(output_root=tmp_path / "isolated")
    summary = run_experiment(nexus, str(scenario), runs=3)
    output_file = Path(summary.output_file)
    assert output_file.exists()
    assert (tmp_path / "isolated").resolve() in output_file.resolve().parents
    records = json.loads(output_file.read_text(encoding="utf-8"))
    assert isinstance(records, list)
    assert len(records) == 3


# ---------------------------------------------------------------------------
# Helper invariants
# ---------------------------------------------------------------------------


def test_count_detection_artifacts_handles_list_and_scalar() -> None:
    result = {
        "steps": [
            {"detections": {"sigma": ["a", "b"], "yara": "c"}},
            {"detections": {"spl": [], "splunk": None}},
            {"detections": {}},  # empty dict
            {},  # no detections key
        ]
    }
    # 2 (sigma list) + 1 (yara scalar truthy) + 0 (empty list) + 0 (None)
    # + 0 (empty dict) + 0 (missing key) = 3.
    assert _count_detection_artifacts(result) == 3


def test_mutate_run_params_disabled_returns_empty_dict() -> None:
    assert _mutate_run_params({"status": "success"}, enable_jitter=False) == {}


def test_mutate_run_params_enabled_returns_populated_state() -> None:
    random.seed(0)
    state = _mutate_run_params({"status": "success"}, enable_jitter=True)
    assert state["mutation"]["intensity"] in {"low", "medium"}
    assert 0.05 <= state["mutation"]["noise_ratio"] <= 0.2
    assert state["mutation"]["variant"] in {"baseline", "alt-path"}
    assert state["previous_status"] == "success"


def test_merge_step_mutation_no_mutation_key_returns_steps_unchanged() -> None:
    steps = [{"step_id": "s1", "params": {"command": "echo"}}]
    assert _merge_step_mutation(steps, mutation_state={}) == steps


def test_merge_step_mutation_replaces_non_dict_params_with_fresh_dict() -> None:
    """A step whose `params` is not a dict (None, int, list) should be
    replaced with a dict rather than raising."""
    steps = [
        {"step_id": "s1", "params": None},
        {"step_id": "s2", "params": "not a dict"},
        {"step_id": "s3"},  # missing params entirely
    ]
    state = {"mutation": {"variant": "alt-path", "intensity": "medium"}}
    result = _merge_step_mutation(steps, mutation_state=state)
    for step in result:
        params = step["params"]
        assert isinstance(params, dict)
        assert params["mutation_applied"] is True
        assert params["mutation_variant"] == "alt-path"
        assert params["mutation_intensity"] == "medium"


def test_merge_step_mutation_does_not_mutate_input_list(tmp_path: Path) -> None:
    """Read-only input contract: original steps list must not be mutated."""
    original = [{"step_id": "s1", "params": {"command": "echo"}}]
    snapshot = json.dumps(original)
    state = {"mutation": {"variant": "baseline", "intensity": "low"}}
    _merge_step_mutation(original, mutation_state=state)
    assert json.dumps(original) == snapshot


# ---------------------------------------------------------------------------
# Compatibility wrapper
# ---------------------------------------------------------------------------


def test_run_experiment_series_falls_back_when_summary_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the summary.json cannot be read, the wrapper must return
    ``results=[]`` rather than propagating the IO/parse error."""
    scenario = _mini_scenario(tmp_path)

    # Patch BlueFireNexus to use our fake — keeps the integration
    # surface small while still exercising the wrapper's fallback.
    fake = _FakeNexus(output_root=tmp_path)

    def _fake_factory(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return fake

    monkeypatch.setattr("src.core.experiments.BlueFireNexus", _fake_factory)

    # Patch Path.read_text to raise on the summary file specifically.
    real_read_text = Path.read_text

    def flaky_read_text(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if self.name == "summary.json":
            raise OSError("simulated read failure")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", flaky_read_text)

    payload = run_experiment_series(str(scenario), iterations=2, jitter=False)
    assert payload["runs"] == 2
    # Fallback path: empty results list, harness keeps the rest of the summary.
    assert payload["results"] == []
    assert payload["successes"] + payload["failures"] == 2
