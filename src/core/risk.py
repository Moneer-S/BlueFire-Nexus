"""Risk scoring helpers for reporting and detection artifacts."""

from __future__ import annotations

from typing import Any, Dict, Mapping

from .models import ModuleResult

_PACK_BASE_SCORES = {
    "actor_pack": 55,
    "c2_pack": 62,
    "stealth_pack": 68,
}
_MODE_BONUS = {
    "simulate": 0,
    "emulate": 18,
}
_CAPABILITY_BONUS = {
    "apt29": 8,
    "apt28": 7,
    "apt32": 7,
    "apt38": 9,
    "apt41": 9,
    "dns_tunneling": 10,
    "tls_fast_flux": 11,
    "websocket_quic": 12,
    "solana_rpc": 11,
    "network_obfuscator_legacy": 12,
    "anti_forensic": 12,
    "anti_detection_legacy": 13,
    "anti_sandbox": 11,
    "dynamic_api": 12,
}
_STATUS_DELTA = {
    "success": 0,
    "partial_success": 3,
    "blocked": -12,
    "error": -15,
}


def _clamp(score: int) -> int:
    return max(0, min(100, score))


def severity_from_score(score: int) -> str:
    """Map a 0-100 score to a severity label."""
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def score_module_result(result: ModuleResult) -> Dict[str, Any]:
    """Return normalized risk score metadata for a module result."""
    hints = result.detection_hints if isinstance(result.detection_hints, Mapping) else {}
    artifacts = result.artifacts if isinstance(result.artifacts, Mapping) else {}
    legacy = artifacts.get("legacy")
    payload = legacy.get("payload", {}) if isinstance(legacy, Mapping) else {}

    pack = str(
        (legacy.get("pack") if isinstance(legacy, Mapping) else "")
        or hints.get("legacy_pack")
        or ""
    ).lower()
    capability = str(
        (legacy.get("capability") if isinstance(legacy, Mapping) else "")
        or hints.get("legacy_capability")
        or hints.get("capability")
        or ""
    ).lower()
    mode = str(
        (legacy.get("mode") if isinstance(legacy, Mapping) else "")
        or hints.get("legacy_mode")
        or hints.get("mode")
        or "simulate"
    ).lower()
    runtime_warning = bool(
        (payload.get("runtime_warning") if isinstance(payload, Mapping) else None)
        or hints.get("runtime_warning")
    )

    rationale: list[str] = []
    if pack:
        score = _PACK_BASE_SCORES.get(pack, 55)
        rationale.append(f"pack={pack}")
        score += _CAPABILITY_BONUS.get(capability, 6)
        if capability:
            rationale.append(f"capability={capability}")
        score += _MODE_BONUS.get(mode, 0)
        rationale.append(f"mode={mode}")
    else:
        score = 35 + min(20, len(result.techniques) * 5)
        rationale.append("standard-module")

    if runtime_warning:
        score += 10
        rationale.append("runtime_warning")

    score += _STATUS_DELTA.get(result.status, 0)
    score = _clamp(score)

    return {
        "score": score,
        "severity": severity_from_score(score),
        "pack": pack,
        "capability": capability,
        "mode": mode,
        "runtime_warning": runtime_warning,
        "rationale": rationale,
    }


__all__ = ["score_module_result", "severity_from_score"]
