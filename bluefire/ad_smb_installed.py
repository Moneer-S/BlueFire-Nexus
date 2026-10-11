"""Read exact owner-private AD configuration; never install or start a receiver.

The controller file is fixed beneath the existing managed runner root. Its
scope, role profiles and channels describe prior enrollment, not permission to
enroll or proof of a current remote Windows/SMB state.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .ad_smb_admitted_transport import AdmittedAdSmbClient, _profile
from .ad_smb_channel import AdSmbHostChannel
from .ad_smb_contract import AdSmbError, AdSmbScope, document, exact
from .ad_smb_private_storage import private_root
from .ad_smb_receiver_results import native_generation
from .ad_smb_results import environment
from .runner_trust import RunnerTrustError, _PinnedDirectory
from .util import canonical_json_bytes, content_hash

CONFIG_SCHEMA = "bluefire.ad-smb-controller-config.v1"
CONFIG_MAX = 512 * 1024


@dataclass(frozen=True)
class InstalledEnvironment:
    root: Path
    _canonical: bytes

    @classmethod
    def from_mapping(cls, root: Path, value: Mapping[str, Any]) -> InstalledEnvironment:
        row = document(value, limit=CONFIG_MAX)
        exact(row, {"environment", "profiles", "channels"}, "Installed AD environment")
        public = environment(row["environment"])
        if public["provenance"] != "runner_reported":
            raise AdSmbError("Installed AD configuration cannot declare synthetic admission.")
        scope = AdSmbScope.from_mapping(public["scope"])
        for key in ("profiles", "channels"):
            exact(row[key], {"member", "client"}, "Installed AD role bindings")
        for role in ("member", "client"):
            channel = AdSmbHostChannel.from_mapping(scope, row["channels"][role])
            bound = channel.to_dict()
            _profile(scope, channel, row["profiles"][role])
            expected = {
                "runner_profile_id": bound["profile_id"],
                "host_id": bound["host_id"],
                "native_generation": native_generation(channel),
                "profile_digest": bound["profile_digest"],
                "channel_digest": channel.digest,
            }
            if bound["role"] != role or public[role] != expected:
                raise AdSmbError("Installed AD role differs from its exact channel.")
        return cls(root, canonical_json_bytes(row))

    def to_dict(self) -> dict[str, Any]:
        return dict(json.loads(self._canonical))

    @property
    def public(self) -> dict[str, Any]:
        return dict(self.to_dict()["environment"])

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def channel(self, role: str) -> AdSmbHostChannel:
        if role not in {"member", "client"}:
            raise AdSmbError("AD installed role is invalid.")
        return AdSmbHostChannel.from_mapping(
            AdSmbScope.from_mapping(self.public["scope"]), self.to_dict()["channels"][role]
        )

    def client(self, role: str) -> AdmittedAdSmbClient:
        row = self.to_dict()
        channel = self.channel(role)
        # Each controller-side directory contains only its own TLS private key.
        # No host credential binding or reader secret is loaded on this side.
        return AdmittedAdSmbClient(
            self.root / row["environment"]["environment_id"] / role,
            scope=AdSmbScope.from_mapping(row["environment"]["scope"]),
            channel=channel,
            profile=row["profiles"][role],
            credential_binding_digest=(
                row["environment"]["principal_binding_digest"] if role == "client" else None
            ),
        )


def load_installed(root: Path) -> tuple[InstalledEnvironment, ...]:
    """Load one finite exact file through the existing private-directory guard."""
    try:
        path = private_root(root)
        with _PinnedDirectory(path, private=True, verify_permissions_only=True) as directory:
            row = document(directory.read("controller.json", maximum=CONFIG_MAX), limit=CONFIG_MAX)
            names = set(directory.names(maximum=9))
        exact(row, {"schema_version", "environments"}, "Installed AD controller")
        if (
            row["schema_version"] != CONFIG_SCHEMA
            or not isinstance(row["environments"], list)
            or not 1 <= len(row["environments"]) <= 8
        ):
            raise AdSmbError("Installed AD configuration is invalid.")
        entries = tuple(
            InstalledEnvironment.from_mapping(path, value) for value in row["environments"]
        )
        environment_ids = {entry.public["environment_id"] for entry in entries}
        if "controller.json" not in names or names - {"controller.json"} - environment_ids:
            raise AdSmbError("Installed AD controller contains unexpected files.")
        for name in names - {"controller.json"}:
            private_root(path / name)
        ids: set[str] = set()
        profiles: set[str] = set()
        resources: set[tuple[str, str, str]] = set()
        for item in entries:
            public = item.public
            identity = public["environment_id"]
            member = public["scope"]["hosts"]["member"]
            resource_keys = {
                (kind, member[kind], public["scope"]["share"]["name"])
                for kind in ("host_id", "fqdn", "ipv4")
            }
            role_profiles = {public[role]["runner_profile_id"] for role in ("member", "client")}
            if (
                identity in ids
                or resources.intersection(resource_keys)
                or profiles.intersection(role_profiles)
            ):
                raise AdSmbError(
                    "Installed AD configuration repeats a resource or profile authority."
                )
            ids.add(identity)
            resources.update(resource_keys)
            profiles.update(role_profiles)
        return entries
    except (OSError, ValueError, TypeError, KeyError, RunnerTrustError):
        raise AdSmbError("Installed AD configuration is unavailable or invalid.") from None
