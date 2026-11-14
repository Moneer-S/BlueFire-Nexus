"""Fail-closed bootstrap for the pinned Strix controlled runtime.

Only standard-library modules are imported at module import time.  ``main``
validates the complete non-secret attempt identity and package versions before
importing Strix.  It registers BlueFire's backend through Strix's public
registry and then delegates to the official CLI ``main`` unchanged.

The controller transport is deliberately injected.  Calling this module
without the protected controller composition cannot start a sandbox and fails
before Strix settings, model credentials, or the Docker client are imported.
"""

from __future__ import annotations

import importlib
import os
import re
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

_BACKEND = "bluefire-controlled"
_SOURCE_REVISION = "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"  # pragma: allowlist secret
_ATTEMPT = re.compile(r"^engine-attempt-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/:-]{0,255}@sha256:[0-9a-f]{64}$")
_PACKAGES = {
    "strix-agent": "1.7.0",
    "openai-agents": "0.19.0",
    "docker": "7.1.0",
}

_BOOTSTRAP_ENTERED = False


class ControlledBootstrapError(RuntimeError):
    """Raised before the official Strix main when bootstrap proof is missing."""


@dataclass(frozen=True, slots=True)
class ControlledBootstrapConfig:
    attempt_id: str
    docker_host: str = field(repr=False)
    source_revision: str = _SOURCE_REVISION
    build_digest: str = ""
    profile_digest: str = ""
    policy_digest: str = ""
    relay_digest: str = ""
    relay_upstream_digest: str = ""
    relay_channel_digest: str = ""
    relay_retry_digest: str = ""
    boundary_digest: str = ""
    admission_digest: str = ""
    image_reference: str = ""
    image_digest: str = ""
    manifest_digest: str = ""
    sdk_digest: str = ""
    bootstrap_digest: str = ""
    tmpfs_contract_digest: str = ""
    sandbox_uid: int = 0
    sandbox_gid: int = 0


@dataclass(frozen=True, slots=True)
class ControlledInstalledPackageIdentity:
    package: str
    version: str
    artifact_digest: str
    source_revision: str | None = None


def _required(environment: Mapping[str, str], name: str) -> str:
    try:
        value = environment.get(name)
    except Exception as exc:
        raise ControlledBootstrapError("controlled bootstrap environment is unavailable") from exc
    if not isinstance(value, str) or not value:
        raise ControlledBootstrapError("controlled bootstrap environment is incomplete")
    return value


def _digest(environment: Mapping[str, str], name: str) -> str:
    value = _required(environment, name)
    if _DIGEST.fullmatch(value) is None:
        raise ControlledBootstrapError("controlled bootstrap digest is invalid")
    return value


def _positive_identity(environment: Mapping[str, str], name: str) -> int:
    value = _required(environment, name)
    if not value.isascii() or not value.isdigit() or value.startswith("0"):
        raise ControlledBootstrapError("controlled sandbox identity is invalid")
    number = int(value)
    if not 1 <= number <= 2**31 - 1:
        raise ControlledBootstrapError("controlled sandbox identity is invalid")
    return number


def _docker_host(value: str, attempt_id: str) -> str:
    if (
        len(value) > 512
        or "\\" in value
        or "%" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ControlledBootstrapError("controlled Docker endpoint is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "unix"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or "//" in parsed.path
    ):
        raise ControlledBootstrapError("controlled Docker endpoint is invalid")
    parts = parsed.path.split("/")[1:]
    if (
        len(parts) < 3
        or any(not part or part in {".", "..", "~"} for part in parts)
        or parts[-2:] != [attempt_id, "docker.sock"]
    ):
        raise ControlledBootstrapError("controlled Docker endpoint is not attempt-private")
    return value


def _validate_environment(environment: Mapping[str, str]) -> ControlledBootstrapConfig:
    if _required(environment, "STRIX_RUNTIME_BACKEND") != _BACKEND:
        raise ControlledBootstrapError("controlled Strix backend selection is invalid")
    attempt_id = _required(environment, "BLUEFIRE_STRIX_ATTEMPT_ID")
    if _ATTEMPT.fullmatch(attempt_id) is None:
        raise ControlledBootstrapError("controlled attempt identity is invalid")
    source_revision = _required(environment, "BLUEFIRE_STRIX_SOURCE_REVISION")
    if source_revision != _SOURCE_REVISION:
        raise ControlledBootstrapError("controlled Strix source revision does not match")
    docker_host = _docker_host(_required(environment, "DOCKER_HOST"), attempt_id)
    image_reference = _required(environment, "STRIX_IMAGE")
    if _IMAGE.fullmatch(image_reference) is None:
        raise ControlledBootstrapError("controlled image reference is invalid")
    image_digest = _digest(environment, "BLUEFIRE_STRIX_IMAGE_DIGEST")
    if image_reference.rsplit("@", 1)[-1] != image_digest:
        raise ControlledBootstrapError("controlled image identity does not match")
    return ControlledBootstrapConfig(
        attempt_id=attempt_id,
        docker_host=docker_host,
        source_revision=source_revision,
        build_digest=_digest(environment, "BLUEFIRE_STRIX_BUILD_DIGEST"),
        profile_digest=_digest(environment, "BLUEFIRE_STRIX_PROFILE_DIGEST"),
        policy_digest=_digest(environment, "BLUEFIRE_STRIX_POLICY_DIGEST"),
        relay_digest=_digest(environment, "BLUEFIRE_STRIX_RELAY_DIGEST"),
        relay_upstream_digest=_digest(environment, "BLUEFIRE_STRIX_RELAY_UPSTREAM_DIGEST"),
        relay_channel_digest=_digest(environment, "BLUEFIRE_STRIX_RELAY_CHANNEL_DIGEST"),
        relay_retry_digest=_digest(environment, "BLUEFIRE_STRIX_RELAY_RETRY_DIGEST"),
        boundary_digest=_digest(environment, "BLUEFIRE_STRIX_BOUNDARY_DIGEST"),
        admission_digest=_digest(environment, "BLUEFIRE_STRIX_ADMISSION_DIGEST"),
        image_reference=image_reference,
        image_digest=image_digest,
        manifest_digest=_digest(environment, "BLUEFIRE_STRIX_MANIFEST_DIGEST"),
        sdk_digest=_digest(environment, "BLUEFIRE_STRIX_SDK_DIGEST"),
        bootstrap_digest=_digest(environment, "BLUEFIRE_STRIX_BOOTSTRAP_DIGEST"),
        tmpfs_contract_digest=_digest(environment, "BLUEFIRE_STRIX_TMPFS_DIGEST"),
        sandbox_uid=_positive_identity(environment, "BLUEFIRE_STRIX_SANDBOX_UID"),
        sandbox_gid=_positive_identity(environment, "BLUEFIRE_STRIX_SANDBOX_GID"),
    )


def _validate_packages(version_getter: Callable[[str], str]) -> None:
    for package, expected in _PACKAGES.items():
        try:
            observed = version_getter(package)
        except Exception as exc:
            raise ControlledBootstrapError("controlled runtime package is unavailable") from exc
        if observed != expected:
            raise ControlledBootstrapError("controlled runtime package version does not match")


def _validate_package_identities(
    config: ControlledBootstrapConfig,
    identity_getter: Callable[[str], ControlledInstalledPackageIdentity] | None,
) -> None:
    if identity_getter is None:
        raise ControlledBootstrapError("protected runtime package identity is unavailable")
    try:
        strix = identity_getter("strix-agent")
        agents = identity_getter("openai-agents")
    except Exception as exc:
        raise ControlledBootstrapError("protected runtime package identity is unavailable") from exc
    if (
        not isinstance(strix, ControlledInstalledPackageIdentity)
        or strix.package != "strix-agent"
        or strix.version != _PACKAGES["strix-agent"]
        or strix.artifact_digest != config.build_digest
        or strix.source_revision != _SOURCE_REVISION
    ):
        raise ControlledBootstrapError("installed Strix candidate identity does not match")
    if (
        not isinstance(agents, ControlledInstalledPackageIdentity)
        or agents.package != "openai-agents"
        or agents.version != _PACKAGES["openai-agents"]
        or agents.artifact_digest != config.sdk_digest
    ):
        raise ControlledBootstrapError("installed Agents SDK identity does not match")


def _load(module_loader: Callable[[str], Any], name: str) -> Any:
    try:
        return module_loader(name)
    except Exception as exc:
        raise ControlledBootstrapError("controlled runtime module is unavailable") from exc


def main(
    *,
    transport: Any = None,
    environment: Mapping[str, str] = os.environ,
    version_getter: Callable[[str], str] = metadata.version,
    identity_getter: Callable[[str], ControlledInstalledPackageIdentity] | None = None,
    module_loader: Callable[[str], Any] = importlib.import_module,
) -> Any:
    """Register the controlled backend, then invoke official Strix ``main``.

    Return values and ``SystemExit`` from upstream are intentionally preserved.
    """

    global _BOOTSTRAP_ENTERED

    config = _validate_environment(environment)
    _validate_packages(version_getter)
    _validate_package_identities(config, identity_getter)
    if transport is None:
        raise ControlledBootstrapError("controlled controller transport is unavailable")
    if _BOOTSTRAP_ENTERED:
        raise ControlledBootstrapError("controlled bootstrap is one-shot")

    backend_module = _load(module_loader, "bluefire.strix_controlled_backend")
    profile_type = getattr(backend_module, "ControlledRuntimeProfile", None)
    backend_builder = getattr(backend_module, "create_registered_backend", None)
    if profile_type is None or not callable(getattr(profile_type, "create", None)):
        raise ControlledBootstrapError("controlled runtime profile factory is unavailable")
    if not callable(backend_builder):
        raise ControlledBootstrapError("controlled backend factory is unavailable")
    try:
        profile = profile_type.create(
            attempt_id=config.attempt_id,
            build_digest=config.build_digest,
            policy_digest=config.policy_digest,
            relay_digest=config.relay_digest,
            relay_upstream_digest=config.relay_upstream_digest,
            relay_channel_digest=config.relay_channel_digest,
            relay_retry_digest=config.relay_retry_digest,
            boundary_digest=config.boundary_digest,
            admission_digest=config.admission_digest,
            image_reference=config.image_reference,
            image_digest=config.image_digest,
            manifest_digest=config.manifest_digest,
            sdk_digest=config.sdk_digest,
            bootstrap_digest=config.bootstrap_digest,
            tmpfs_contract_digest=config.tmpfs_contract_digest,
            sandbox_uid=config.sandbox_uid,
            sandbox_gid=config.sandbox_gid,
        )
    except Exception as exc:
        raise ControlledBootstrapError("controlled runtime profile is invalid") from exc
    if getattr(profile, "profile_digest", None) != config.profile_digest:
        raise ControlledBootstrapError("controlled runtime profile digest does not match")
    try:
        backend = backend_builder(
            profile,
            transport,
            version_getter=version_getter,
            module_loader=module_loader,
        )
    except Exception as exc:
        raise ControlledBootstrapError("controlled backend construction failed") from exc
    if not callable(backend):
        raise ControlledBootstrapError("controlled backend factory returned no callable")

    registry = _load(module_loader, "strix.runtime.backends")
    register_backend = getattr(registry, "register_backend", None)
    if not callable(register_backend):
        raise ControlledBootstrapError("Strix public backend registry is unavailable")
    _BOOTSTRAP_ENTERED = True
    register_backend(_BACKEND, backend, supports_bind_mounts=False)

    official_module = _load(module_loader, "strix.interface.main")
    official_main = getattr(official_module, "main", None)
    if not callable(official_main):
        raise ControlledBootstrapError("official Strix main is unavailable")
    return official_main()


__all__ = [
    "ControlledBootstrapConfig",
    "ControlledBootstrapError",
    "ControlledInstalledPackageIdentity",
    "main",
]
