"""Deterministic property-fuzz checks used as dynamic GATE-10 evidence."""

from __future__ import annotations

import json
import random
import string
from typing import Any

import pytest

from bluefire.action_packages import ActionPackageError, parse_canonical_action_package
from bluefire.replay import ReplayError, ReplayRequest
from bluefire.runner_transport import RunnerAuthenticationError, _decode_json_object
from bluefire.util import canonical_json_bytes

_SAFE_TEXT = string.ascii_letters + string.digits + "-\u00e9\u03a9"


def _safe_text(randomizer: random.Random, *, maximum: int = 24) -> str:
    return "".join(randomizer.choice(_SAFE_TEXT) for _ in range(randomizer.randint(0, maximum)))


def _json_value(randomizer: random.Random, depth: int = 0) -> Any:
    terminal_kinds = ("null", "bool", "integer", "string")
    kinds = terminal_kinds if depth >= 3 else (*terminal_kinds, "array", "object")
    kind = randomizer.choice(kinds)
    if kind == "null":
        return None
    if kind == "bool":
        return bool(randomizer.getrandbits(1))
    if kind == "integer":
        return randomizer.randint(-(2**63), 2**63 - 1)
    if kind == "string":
        return _safe_text(randomizer)
    if kind == "array":
        return [_json_value(randomizer, depth + 1) for _ in range(randomizer.randint(0, 5))]
    return {
        f"field_{depth}_{index}_{randomizer.randrange(1_000_000)}": _json_value(
            randomizer, depth + 1
        )
        for index in range(randomizer.randint(0, 5))
    }


def _json_object(seed: int) -> dict[str, Any]:
    randomizer = random.Random(seed)
    return {
        f"field_0_{index}_{randomizer.randrange(1_000_000)}": _json_value(randomizer, 1)
        for index in range(randomizer.randint(1, 6))
    }


def test_action_package_parser_round_trips_seeded_json_and_rejects_noncanonical_forms() -> None:
    for seed in range(160):
        document = _json_object(seed)
        canonical = canonical_json_bytes(document)

        assert parse_canonical_action_package(canonical) == document, f"seed={seed}"
        assert canonical_json_bytes(parse_canonical_action_package(canonical)) == canonical

        noncanonical = json.dumps(document, ensure_ascii=False).encode("utf-8")
        assert noncanonical != canonical
        with pytest.raises(ActionPackageError, match="not canonical JSON"):
            parse_canonical_action_package(noncanonical)

    with pytest.raises(ActionPackageError, match="duplicate JSON object key"):
        parse_canonical_action_package(b'{"field":1,"field":2}')


def test_authenticated_decoder_preserves_seeded_canonical_objects_and_rejects_mutations() -> None:
    for seed in range(160, 320):
        document = _json_object(seed)
        canonical = canonical_json_bytes(document)

        assert _decode_json_object(canonical) == document, f"seed={seed}"
        with pytest.raises(RunnerAuthenticationError, match="not canonical JSON"):
            _decode_json_object(canonical + b"\n")

    with pytest.raises(RunnerAuthenticationError, match="valid canonical JSON"):
        _decode_json_object(b'{"field":1,"field":2}')


def test_replay_request_invariants_hold_across_seeded_variant_combinations() -> None:
    randomizer = random.Random(10_202_601)
    exact_variants: tuple[dict[str, Any], ...] = (
        {"swap_step_id": "step-a", "swap_behavior_id": "behavior-a"},
        {"parameter_overrides": {"step-a": {"count": 2}}},
        {"action_implementations": {"step-a": "action-a"}},
        {"ai_enabled": True},
        {"runner_profile_id": "profile-a"},
        {"defense_change": "enabled"},
    )
    assert (
        ReplayRequest(
            source_run_id="run-checkpoint",
            exact=True,
            from_step_id="step-a",
        ).from_step_id
        == "step-a"
    )
    for _iteration in range(200):
        source = f"run-{randomizer.randrange(1_000_000)}"
        variant = dict(randomizer.choice(exact_variants))
        with pytest.raises(ReplayError, match="exact replay cannot include variants"):
            ReplayRequest(source_run_id=source, exact=True, **variant)

        step = f"step-{randomizer.randrange(1_000_000)}"
        behavior = f"behavior-{randomizer.randrange(1_000_000)}"
        assert (
            ReplayRequest(
                source_run_id=source,
                swap_step_id=step,
                swap_behavior_id=behavior,
            ).swap_behavior_id
            == behavior
        )
        with pytest.raises(ReplayError, match="require both step and behavior IDs"):
            ReplayRequest(
                source_run_id=source,
                **randomizer.choice(({"swap_step_id": step}, {"swap_behavior_id": behavior})),
            )

    oversized = {f"step-{index}": {"value": index} for index in range(101)}
    with pytest.raises(ReplayError, match="bounded step mapping"):
        ReplayRequest(source_run_id="run-bounded", parameter_overrides=oversized)
