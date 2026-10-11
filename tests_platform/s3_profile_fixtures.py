"""Mutable test profiles retain the complete production profile contract."""

import json
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace

from bluefire.config import RunnerProfile


def managed_profile(profile_id, *, seconds=120):
    template = Path(__file__).resolve().parents[1] / "frontend/src/lib/s3-profile-template.json"
    document = json.loads(template.read_text(encoding="utf-8"))
    document["budgets"]["max_seconds"] = seconds
    parsed = RunnerProfile.from_mapping(document)
    profile = SimpleNamespace(
        **{field.name: getattr(parsed, field.name) for field in fields(parsed)}
    )
    # Legacy native-contract fixtures also exercise non-versioned identifiers.
    profile.id = profile_id
    profile.to_dict = lambda: RunnerProfile.to_dict(profile)
    return profile
