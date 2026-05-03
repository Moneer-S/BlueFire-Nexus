import logging
from datetime import datetime
from typing import Any, Dict


class InitialAccess:
    """Initial access simulation handlers."""

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.config: Dict[str, Any] = {
            "default_vector": "phishing",
            "allow_simulated_remote_exploit": False,
        }

    def update_config(self, config: Dict[str, Any]) -> None:
        module_cfg = config.get("modules", {}).get("initial_access", {})
        if isinstance(module_cfg, dict):
            self.config.update(module_cfg)

    def run_operation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        request = data.get("initial_access", {}) if isinstance(data, dict) else {}
        vector = request.get("vector", self.config["default_vector"])
        details = request.get("details", {})

        if vector == "phishing":
            return self._handle_phishing(details)
        if vector == "remote_exploit":
            return self._handle_exploitation(details)
        return {"status": "error", "message": f"Unsupported initial access vector: {vector}"}

    def _handle_phishing(self, data: Dict[str, Any]) -> Dict[str, Any]:
        target = data.get("target", "test-user@example.lab")
        return {
            "status": "success",
            "technique": "phishing",
            "mitre_technique_id": "T1566",
            "mitre_technique_name": "Phishing",
            "timestamp": datetime.now().isoformat(),
            "details": {
                "target": target,
                "message": "Simulated phishing workflow completed in lab mode.",
            },
        }

    def _handle_exploitation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if not self.config.get("allow_simulated_remote_exploit", False):
            return {
                "status": "blocked",
                "technique": "remote_exploit",
                "mitre_technique_id": "T1210",
                "mitre_technique_name": "Exploitation of Remote Services",
                "timestamp": datetime.now().isoformat(),
                "details": {
                    "message": "Remote exploit simulation disabled by configuration.",
                },
            }
        return {
            "status": "success",
            "technique": "remote_exploit",
            "mitre_technique_id": "T1210",
            "mitre_technique_name": "Exploitation of Remote Services",
            "timestamp": datetime.now().isoformat(),
            "details": {"target": data.get("target", "127.0.0.1")},
        }
