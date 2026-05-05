"""Shared adapter utilities for legacy capability packs."""

from __future__ import annotations

import importlib
import logging
import platform
from typing import Any, Dict, Mapping

from ...legacy_controls import (
    LegacyCapabilityDecision,
    build_legacy_summary,
    evaluate_legacy_capability,
    is_domain_allowed,
)
from ...models import ModuleResult, TelemetryEvent
from ..base import BaseModule

LOGGER = logging.getLogger(__name__)


def _result(
    module: str,
    status: str,
    message: str,
    *,
    techniques: list[str] | None = None,
    artifacts: Dict[str, Any] | None = None,
    hints: Dict[str, Any] | None = None,
    telemetry: list[TelemetryEvent] | None = None,
    error: str | None = None,
) -> ModuleResult:
    return ModuleResult(
        status=status,
        module=module,
        message=message,
        techniques=techniques or [],
        artifacts=artifacts or {},
        detection_hints=hints or {},
        telemetry=telemetry or [],
        error=error,
    )


class LegacyAdapterBase(BaseModule):
    """Base adapter for safety-gated legacy capability modules."""

    pack_name: str = "legacy"
    capability_name: str = "legacy"
    legacy_import_path: str = ""
    supported_platforms: tuple[str, ...] = ("Linux", "Windows", "Darwin")
    default_mode: str = "simulate"
    attack_techniques: tuple[str, ...] = ()

    def __init__(self) -> None:
        super().__init__()
        self._legacy_module: Any = None
        self._decision: LegacyCapabilityDecision | None = None

    def update_config(self, config: Mapping[str, Any]) -> None:
        super().update_config(config)
        decision = evaluate_legacy_capability(
            self._config.get("config_root", {}),
            self.pack_name,
            self.capability_name,
        )
        self._decision = decision

    def validate(self, params: Mapping[str, Any]) -> str | None:
        del params
        if platform.system() not in self.supported_platforms:
            return (
                f"{self.name} is not supported on {platform.system()}; "
                f"supported platforms: {', '.join(self.supported_platforms)}"
            )
        return None

    @property
    def decision(self) -> LegacyCapabilityDecision:
        if self._decision is None:
            self._decision = evaluate_legacy_capability({}, self.pack_name, self.capability_name)
        return self._decision

    def _effective_mode(
        self,
        context: Mapping[str, Any],
        pack_name: str | None = None,
        capability_name: str | None = None,
    ) -> str:
        module_mode = self._config.get("mode")
        module_mode_str = str(module_mode) if module_mode is not None else None
        decision = evaluate_legacy_capability(
            context.get("config", {}),
            pack_name or self.pack_name,
            capability_name or self.capability_name,
            module_enabled=bool(self._config.get("enabled", False)),
            module_mode=module_mode_str,
            module_acknowledged=bool(
                self._config.get("lab_confirmation", False)
                or self._config.get("i_understand_this_is_a_lab", False)
            ),
        )
        return decision.mode

    def load_legacy_module(self) -> Any:
        if self._legacy_module is not None:
            return self._legacy_module
        if not self.legacy_import_path:
            raise RuntimeError(f"{self.name} missing legacy_import_path")
        try:
            self._legacy_module = importlib.import_module(self.legacy_import_path)
        except Exception as exc:
            LOGGER.warning("Failed to import legacy module %s: %s", self.legacy_import_path, exc)
            raise
        return self._legacy_module

    def legacy_summary(self) -> Dict[str, Any]:
        decision = self.decision
        return {
            "pack": self.pack_name,
            "capability": self.capability_name,
            "enabled": decision.enabled,
            "mode": decision.mode,
            "activation_source": decision.activation_source,
            "summary": decision.summary_message(),
        }

    def _resolved_decision(
        self,
        context: Mapping[str, Any],
        *,
        pack_name: str | None = None,
        capability_name: str | None = None,
        effective_enabled: bool | None = None,
        mode: str | None = None,
    ) -> LegacyCapabilityDecision:
        module_mode = self._config.get("mode")
        module_mode_str = str(module_mode) if module_mode is not None else None
        decision = evaluate_legacy_capability(
            context.get("config", {}),
            pack_name or self.pack_name,
            capability_name or self.capability_name,
            module_enabled=bool(self._config.get("enabled", False)),
            module_mode=mode or module_mode_str,
            module_acknowledged=bool(
                self._config.get("lab_confirmation", False)
                or self._config.get("i_understand_this_is_a_lab", False)
            ),
        )
        if effective_enabled is not None and effective_enabled != decision.enabled:
            decision = LegacyCapabilityDecision(
                enabled=effective_enabled,
                mode=decision.mode if not mode else mode,
                acknowledged=decision.acknowledged,
                activation_source=decision.activation_source,
                master_enabled=decision.master_enabled,
                pack_enabled=decision.pack_enabled,
                capability_enabled=decision.capability_enabled,
            )
        return decision

    def _ensure_allowed(
        self,
        context: Mapping[str, Any],
        *,
        pack_name: str | None = None,
        capability_name: str | None = None,
        effective_enabled: bool | None = None,
        mode: str | None = None,
    ) -> LegacyCapabilityDecision:
        decision = self._resolved_decision(
            context,
            pack_name=pack_name,
            capability_name=capability_name,
            effective_enabled=effective_enabled,
            mode=mode,
        )
        self._decision = decision
        if not decision.enabled:
            raise RuntimeError(
                f"{self.name} is disabled. Enable the relevant legacy pack/capability or "
                "the master lab toggle before running it."
            )
        if decision.mode == "emulate" and not decision.acknowledged:
            raise RuntimeError(
                f"{self.name} is in emulate mode but lab confirmation is missing. "
                "Enable lab_confirmation globally, at the pack level, or for the capability."
            )
        return decision

    def _domain_allowed(self, context: Mapping[str, Any], candidate: str) -> bool:
        return is_domain_allowed(candidate, context.get("config", {}))

    def _legacy_artifacts(
        self,
        context: Mapping[str, Any],
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        return {
            "legacy": {
                "decision": self.legacy_summary(),
                "controls": build_legacy_summary(context.get("config", {})),
                "payload": dict(payload or {}),
            }
        }

    def _build_event(
        self,
        event_type: str,
        details: Mapping[str, Any],
        *,
        severity: str = "info",
    ) -> TelemetryEvent:
        payload = dict(details)
        payload.setdefault("legacy_pack", self.pack_name)
        payload.setdefault("legacy_capability", self.capability_name)
        payload.setdefault("mode", self.decision.mode)
        payload.setdefault("activation_source", self.decision.activation_source)
        return TelemetryEvent(
            event_type=event_type,
            module=self.name,
            details=payload,
            severity=severity,
        )

    def blocked_result(self, reason: str) -> ModuleResult:
        return _result(
            self.name,
            "blocked",
            reason,
            techniques=list(self.attack_techniques),
            artifacts=self.legacy_summary(),
            hints={
                "mitre_technique": (
                    self.attack_techniques[0] if self.attack_techniques else "T0000"
                )
            },
            telemetry=[
                self._build_event(
                    "legacy_capability_blocked",
                    {"reason": reason},
                    severity="warning",
                )
            ],
            error="legacy_capability_blocked",
        )

    def simulated_result(
        self,
        message: str,
        *,
        artifacts: Dict[str, Any] | None = None,
        hints: Dict[str, Any] | None = None,
        extra_details: Dict[str, Any] | None = None,
    ) -> ModuleResult:
        details = {"message": message}
        if extra_details:
            details.update(extra_details)
        return _result(
            self.name,
            "success",
            message,
            techniques=list(self.attack_techniques),
            artifacts={**self.legacy_summary(), **(artifacts or {})},
            hints=hints or {},
            telemetry=[self._build_event("legacy_capability_simulated", details)],
        )
