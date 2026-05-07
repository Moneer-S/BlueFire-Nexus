"""Edge-case hardening for the RAG index and the experiments harness.

Companion to ``test_ai_rag.py`` and
``test_experiments_failure_and_seed.py``. This file covers the
boundary cases those files do not pin: tie-breaking determinism in
RAG search, duplicate-id behaviour in the index, and invalid-input
handling in the experiments harness.

No production code change. All current behaviour holds; the tests
pin it so future refactors surface drift with a clear diagnostic.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.ai.rag import RAGIndex
from src.core.experiments import (
    _count_detection_artifacts,
    _merge_step_mutation,
    _mutate_run_params,
    run_experiment_series,
)


# ---------------------------------------------------------------------------
# 1. RAG tie-breaking determinism
# ---------------------------------------------------------------------------


def test_rag_search_tie_breaking_is_stable_across_invocations() -> None:
    """When multiple docs have identical TF-IDF scores, search order is stable.

    Two queries built from identical inputs should return the same
    snippet order — otherwise prompt content drifts run-to-run with
    no behaviour difference, which leaks non-determinism into
    every downstream copilot artifact.
    """
    index = RAGIndex()
    # Three docs with identical token distributions for the query
    # "alpha beta" → same TF, same DF, same score.
    index.add_text("doc-a", "alpha beta gamma")
    index.add_text("doc-b", "alpha beta gamma")
    index.add_text("doc-c", "alpha beta gamma")

    first = index.search("alpha beta", limit=10)
    second = index.search("alpha beta", limit=10)
    assert first == second, (
        f"identical queries returned different orders: {first} vs {second}"
    )


def test_rag_search_tie_breaking_preserves_insertion_order_on_identical_score() -> None:
    """Tied docs return in the order they were inserted.

    Pin the implicit contract so future refactors that change tie-
    breaking (e.g. switching to a hash-based ordering) surface
    here. The current implementation uses ``list.sort`` which is
    stable, so insertion order is preserved among ties.
    """
    index = RAGIndex()
    index.add_text("inserted-first", "alpha beta")
    index.add_text("inserted-second", "alpha beta")
    index.add_text("inserted-third", "alpha beta")

    results = index.search("alpha beta", limit=10)
    doc_ids = [snippet.split(": ", 1)[0] for snippet in results]
    assert doc_ids == ["inserted-first", "inserted-second", "inserted-third"]


# ---------------------------------------------------------------------------
# 2. RAG duplicate-id behaviour
# ---------------------------------------------------------------------------


def test_rag_duplicate_doc_id_appends_a_second_document() -> None:
    """``add_text`` does NOT dedupe by doc_id; both copies are searchable.

    Pin the documented behaviour: the index trusts callers to
    avoid duplicates. Adding the same doc twice produces two
    matching snippets in search results — a behaviour the copilot
    relies on (it indexes ``README.md`` + ``ARCHITECTURE.md`` +
    ``run_dir/report.md`` once each, and dedup is the caller's
    responsibility).

    This test exists so a future "improvement" that silently
    starts deduping by ``doc_id`` is caught here and either
    intentional (and documented) or reverted.
    """
    index = RAGIndex()
    index.add_text("dup", "alpha keyword content")
    index.add_text("dup", "alpha keyword content")

    results = index.search("alpha", limit=10)
    # Both copies are returned.
    assert len(results) == 2
    # Both share the same doc_id prefix.
    for snippet in results:
        assert snippet.startswith("dup: ")


# ---------------------------------------------------------------------------
# 3. RAG corpus with one doc and a query missing all tokens
# ---------------------------------------------------------------------------


def test_rag_search_returns_empty_when_no_tokens_match() -> None:
    """Pure non-match returns an empty list (no zero-score noise)."""
    index = RAGIndex()
    index.add_text("solo", "alpha beta gamma")
    results = index.search("zeta omega", limit=10)
    assert results == []


def test_rag_search_with_idf_zero_does_not_drop_doc() -> None:
    """Single-doc corpus where the query token matches still ranks > 0.

    Edge case: with one doc, IDF = log((1+1)/(1+1)) + 1 = 1, so
    score = TF * 1. The doc must survive the score>0 filter.
    """
    index = RAGIndex()
    index.add_text("solo", "alpha alpha alpha beta")
    results = index.search("alpha", limit=10)
    assert results
    assert results[0].startswith("solo:")


# ---------------------------------------------------------------------------
# 4. Experiments: invalid scenario file
# ---------------------------------------------------------------------------


def test_run_experiment_series_with_missing_scenario_raises_file_not_found(
    tmp_path: Path,
) -> None:
    """A non-existent scenario path raises a clear FileNotFoundError.

    The harness does not silently fall back to an empty summary;
    operators get a clean exception that points at the bad path.
    """
    missing = tmp_path / "nope.yaml"
    with pytest.raises(FileNotFoundError):
        run_experiment_series(str(missing), iterations=1)


def test_run_experiment_series_with_empty_scenario_steps_still_succeeds(
    tmp_path: Path,
) -> None:
    """A scenario with no steps still produces a valid summary dict.

    Edge case: someone writes a scenario stub with `steps: []`
    intentionally to test the harness wiring. The summary keys
    must all be present (zeros where appropriate), no
    ZeroDivisionError on rate calculations.
    """
    scenario = tmp_path / "empty.yaml"
    scenario.write_text(
        "id: empty\n"
        "name: Empty\n"
        "objective: edge case\n"
        "attack_coverage: []\n"
        "steps: []\n",
        encoding="utf-8",
    )
    payload = run_experiment_series(str(scenario), iterations=1)
    assert payload["runs"] == 1
    assert payload["successes"] + payload["failures"] == 1
    assert payload["step_success_rate"] == 0.0  # no steps -> rate is zero, not NaN
    assert payload["detection_artifact_count"] == 0


# ---------------------------------------------------------------------------
# 5. Experiments: jitter mutation determinism per seed
# ---------------------------------------------------------------------------


def test_mutate_run_params_disabled_returns_empty_dict_irrespective_of_input() -> None:
    """``enable_jitter=False`` yields an empty dict regardless of base_result.

    Reaffirms the documented invariant: jitter is fully opt-in;
    a non-empty mutation state can never appear unless the caller
    explicitly enabled it.
    """
    assert _mutate_run_params({}, enable_jitter=False) == {}
    assert _mutate_run_params({"status": "success"}, enable_jitter=False) == {}
    assert _mutate_run_params({"steps": [{"x": 1}]}, enable_jitter=False) == {}


def test_merge_step_mutation_creates_full_mutation_keys() -> None:
    """Every step in the merged list gets the documented mutation keys.

    Pin the merged-step shape so a refactor that drops a key
    (``experiment_mutation`` / ``mutation_applied`` /
    ``mutation_variant`` / ``mutation_intensity``) surfaces here.
    """
    steps = [{"id": "s1", "module": "x", "params": {}}]
    mutation_state = {
        "mutation": {"intensity": "low", "noise_ratio": 0.1, "variant": "alt-path"}
    }
    merged = _merge_step_mutation(steps, mutation_state)
    assert len(merged) == 1
    params = merged[0]["params"]
    assert params["mutation_applied"] is True
    assert params["mutation_variant"] == "alt-path"
    assert params["mutation_intensity"] == "low"
    assert params["experiment_mutation"]["noise_ratio"] == 0.1


# ---------------------------------------------------------------------------
# 6. Experiments: detection-count helper edge cases
# ---------------------------------------------------------------------------


def test_count_detection_artifacts_handles_step_without_detections_key() -> None:
    """Steps missing the ``detections`` key contribute zero, no exception."""
    result = {"steps": [{"id": "s1", "module": "x"}]}  # no "detections" key
    assert _count_detection_artifacts(result) == 0


def test_count_detection_artifacts_treats_none_value_as_zero() -> None:
    """A ``detections: None`` value contributes zero, not a TypeError."""
    result = {"steps": [{"id": "s1", "detections": None}]}
    assert _count_detection_artifacts(result) == 0


def test_count_detection_artifacts_aggregates_mixed_list_and_scalar_values() -> None:
    """Mixed list/scalar detection values aggregate into a single integer count.

    Defends the helper's documented behaviour: a list of N paths
    contributes N to the total; a non-empty scalar contributes 1;
    an empty / None value contributes 0.
    """
    result = {
        "steps": [
            {"detections": {"sigma": ["a", "b", "c"], "yara_l": "single", "spl": []}},
            {"detections": {"sigma": ["d"]}},
        ]
    }
    # 3 (sigma list-of-3) + 1 (yara_l scalar) + 0 (empty spl list) + 1 (sigma list-of-1) = 5
    assert _count_detection_artifacts(result) == 5


# ---------------------------------------------------------------------------
# 7. Experiments output file is valid JSON
# ---------------------------------------------------------------------------


def test_run_experiment_series_summary_file_is_valid_json(tmp_path: Path) -> None:
    """The on-disk ``summary.json`` parses as a JSON list of run records.

    The harness writes ``json.dumps(records, indent=2)`` so the
    file must round-trip through ``json.loads``. Pinning this so a
    refactor that introduces non-JSON data (e.g. raw repr() output)
    is caught at test time rather than at copilot read time.
    """
    scenario = tmp_path / "round-trip.yaml"
    scenario.write_text(
        "id: rt\n"
        "name: round-trip\n"
        "objective: edge case\n"
        "attack_coverage: ['T1059']\n"
        "steps:\n"
        "  - id: s1\n"
        "    name: exec\n"
        "    module: execution\n"
        "    params:\n"
        "      command: echo hi\n",
        encoding="utf-8",
    )
    payload = run_experiment_series(str(scenario), iterations=2)
    on_disk = Path(payload["output_file"]).read_text(encoding="utf-8")
    records = json.loads(on_disk)
    assert isinstance(records, list)
    assert len(records) == 2
