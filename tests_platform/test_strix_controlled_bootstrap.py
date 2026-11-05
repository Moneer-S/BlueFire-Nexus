from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from bluefire import strix_controlled_backend as controlled
from bluefire import strix_controlled_bootstrap as bootstrap
from bluefire.util import content_hash

ATTEMPT = "engine-attempt-" + "a" * 32
DIGESTS = {
    name: "sha256:" + character * 64
    for name, character in (
        ("build", "1"),
        ("policy", "2"),
        ("relay", "3"),
        ("relay_upstream", "a"),
        ("relay_channel", "b"),
        ("relay_retry", "c"),
        ("boundary", "4"),
        ("admission", "5"),
        ("image", "6"),
        ("sdk", "7"),
        ("bootstrap", "8"),
        ("tmpfs", "9"),
    )
}
IMAGE = "ghcr.io/bluefire/strix-sandbox@" + DIGESTS["image"]


def _manifest_document() -> dict[str, Any]:
    proxy = "http://127.0.0.1:48080"
    return {
        "version": 1,
        "root": "/workspace",
        "entries": {},
        "environment": {
            "value": {
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
                "STRIX_HOST_UID": "1000",
                "STRIX_HOST_GID": "1000",
                "http_proxy": proxy,
                "https_proxy": proxy,
                "ALL_PROXY": proxy,
                "NO_PROXY": "localhost,127.0.0.1",
            }
        },
        "users": [],
        "groups": [],
        "extra_path_grants": [],
        "remote_mount_command_allowlist": list(controlled._DEFAULT_REMOTE_COMMAND_ALLOWLIST),
    }


def _profile() -> controlled.ControlledRuntimeProfile:
    return controlled.ControlledRuntimeProfile.create(
        attempt_id=ATTEMPT,
        build_digest=DIGESTS["build"],
        policy_digest=DIGESTS["policy"],
        relay_digest=DIGESTS["relay"],
        relay_upstream_digest=DIGESTS["relay_upstream"],
        relay_channel_digest=DIGESTS["relay_channel"],
        relay_retry_digest=DIGESTS["relay_retry"],
        boundary_digest=DIGESTS["boundary"],
        admission_digest=DIGESTS["admission"],
        image_reference=IMAGE,
        image_digest=DIGESTS["image"],
        manifest_digest=content_hash(_manifest_document()),
        sdk_digest=DIGESTS["sdk"],
        bootstrap_digest=DIGESTS["bootstrap"],
        tmpfs_contract_digest=DIGESTS["tmpfs"],
        sandbox_uid=1000,
        sandbox_gid=1000,
    )


def _environment() -> dict[str, str]:
    profile = _profile()
    return {
        "STRIX_RUNTIME_BACKEND": "bluefire-controlled",
        "BLUEFIRE_STRIX_ATTEMPT_ID": ATTEMPT,
        "BLUEFIRE_STRIX_SOURCE_REVISION": controlled.STRIX_SOURCE_REVISION,
        "DOCKER_HOST": f"unix:///run/bluefire/{ATTEMPT}/docker.sock",
        "STRIX_IMAGE": IMAGE,
        "BLUEFIRE_STRIX_BUILD_DIGEST": DIGESTS["build"],
        "BLUEFIRE_STRIX_PROFILE_DIGEST": profile.profile_digest,
        "BLUEFIRE_STRIX_POLICY_DIGEST": DIGESTS["policy"],
        "BLUEFIRE_STRIX_RELAY_DIGEST": DIGESTS["relay"],
        "BLUEFIRE_STRIX_RELAY_UPSTREAM_DIGEST": DIGESTS["relay_upstream"],
        "BLUEFIRE_STRIX_RELAY_CHANNEL_DIGEST": DIGESTS["relay_channel"],
        "BLUEFIRE_STRIX_RELAY_RETRY_DIGEST": DIGESTS["relay_retry"],
        "BLUEFIRE_STRIX_BOUNDARY_DIGEST": DIGESTS["boundary"],
        "BLUEFIRE_STRIX_ADMISSION_DIGEST": DIGESTS["admission"],
        "BLUEFIRE_STRIX_IMAGE_DIGEST": DIGESTS["image"],
        "BLUEFIRE_STRIX_MANIFEST_DIGEST": content_hash(_manifest_document()),
        "BLUEFIRE_STRIX_SDK_DIGEST": DIGESTS["sdk"],
        "BLUEFIRE_STRIX_BOOTSTRAP_DIGEST": DIGESTS["bootstrap"],
        "BLUEFIRE_STRIX_TMPFS_DIGEST": DIGESTS["tmpfs"],
        "BLUEFIRE_STRIX_SANDBOX_UID": "1000",
        "BLUEFIRE_STRIX_SANDBOX_GID": "1000",
    }


def _versions(package: str) -> str:
    return {
        "strix-agent": "1.7.0",
        "openai-agents": "0.19.0",
        "docker": "7.1.0",
    }[package]


def _identities(package: str) -> bootstrap.ControlledInstalledPackageIdentity:
    if package == "strix-agent":
        return bootstrap.ControlledInstalledPackageIdentity(
            package=package,
            version="1.7.0",
            artifact_digest=DIGESTS["build"],
            source_revision=controlled.STRIX_SOURCE_REVISION,
        )
    if package == "openai-agents":
        return bootstrap.ControlledInstalledPackageIdentity(
            package=package,
            version="0.19.0",
            artifact_digest=DIGESTS["sdk"],
        )
    raise KeyError(package)


class TrackingEnvironment(dict[str, str]):
    def __init__(self, values: dict[str, str]) -> None:
        super().__init__(values)
        self.reads: list[str] = []

    def get(self, key: str, default: Any = None) -> Any:
        self.reads.append(key)
        if key == "LLM_API_KEY":
            raise AssertionError("bootstrap read a model secret")
        return super().get(key, default)


class NullTransport:
    def __getattr__(self, name: str) -> Any:
        if name not in controlled._TRANSPORT_METHODS:
            raise AttributeError(name)

        async def unavailable(_request: Any) -> Any:
            raise AssertionError("registered backend must not run in bootstrap tests")

        return unavailable


@pytest.fixture(autouse=True)
def reset_bootstrap_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bootstrap, "_BOOTSTRAP_ENTERED", False)


def test_bootstrap_validates_registers_then_delegates_exactly() -> None:
    events: list[tuple[Any, ...]] = []
    registered: dict[str, Any] = {}
    official_result = object()

    def register_backend(name: str, backend: Any, *, supports_bind_mounts: bool) -> None:
        events.append(("register", name, supports_bind_mounts))
        registered["backend"] = backend

    def official_main() -> object:
        events.append(("main",))
        return official_result

    def loader(name: str) -> Any:
        events.append(("import", name))
        if name == "bluefire.strix_controlled_backend":
            return controlled
        if name == "strix.runtime.backends":
            return SimpleNamespace(register_backend=register_backend)
        if name == "strix.interface.main":
            return SimpleNamespace(main=official_main)
        raise ImportError(name)

    environment = TrackingEnvironment(_environment())
    result = bootstrap.main(
        transport=NullTransport(),
        environment=environment,
        version_getter=_versions,
        identity_getter=_identities,
        module_loader=loader,
    )

    assert result is official_result
    assert events == [
        ("import", "bluefire.strix_controlled_backend"),
        ("import", "strix.runtime.backends"),
        ("register", "bluefire-controlled", False),
        ("import", "strix.interface.main"),
        ("main",),
    ]
    assert callable(registered["backend"])
    assert "LLM_API_KEY" not in environment.reads
    assert environment == _environment()


def test_bootstrap_preserves_official_system_exit() -> None:
    def register_backend(name: str, backend: Any, *, supports_bind_mounts: bool) -> None:
        assert (name, supports_bind_mounts) == ("bluefire-controlled", False)
        assert callable(backend)

    def official_main() -> None:
        raise SystemExit(2)

    modules = {
        "bluefire.strix_controlled_backend": controlled,
        "strix.runtime.backends": SimpleNamespace(register_backend=register_backend),
        "strix.interface.main": SimpleNamespace(main=official_main),
    }
    with pytest.raises(SystemExit) as raised:
        bootstrap.main(
            transport=NullTransport(),
            environment=_environment(),
            version_getter=_versions,
            identity_getter=_identities,
            module_loader=modules.__getitem__,
        )
    assert raised.value.code == 2


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"STRIX_RUNTIME_BACKEND": "docker"}, "backend selection"),
        ({"DOCKER_HOST": "unix:///var/run/docker.sock"}, "attempt-private"),
        ({"DOCKER_HOST": f"tcp://127.0.0.1/{ATTEMPT}/docker.sock"}, "endpoint"),
        ({"STRIX_IMAGE": "ghcr.io/bluefire/strix-sandbox:latest"}, "image reference"),
    ],
)
def test_bootstrap_refuses_invalid_environment_before_strix_import(
    change: dict[str, str], message: str
) -> None:
    environment = _environment()
    environment.update(change)
    imports: list[str] = []

    def loader(name: str) -> Any:
        imports.append(name)
        raise AssertionError("module import should not occur")

    with pytest.raises(bootstrap.ControlledBootstrapError, match=message):
        bootstrap.main(
            transport=NullTransport(),
            environment=environment,
            version_getter=_versions,
            identity_getter=_identities,
            module_loader=loader,
        )
    assert imports == []


def test_package_drift_and_missing_transport_refuse_before_strix_import() -> None:
    imports: list[str] = []

    def loader(name: str) -> Any:
        imports.append(name)
        raise AssertionError("module import should not occur")

    with pytest.raises(bootstrap.ControlledBootstrapError, match="package version"):
        bootstrap.main(
            transport=NullTransport(),
            environment=_environment(),
            version_getter=lambda package: (
                "0.19.1" if package == "openai-agents" else _versions(package)
            ),
            identity_getter=_identities,
            module_loader=loader,
        )
    assert imports == []

    with pytest.raises(bootstrap.ControlledBootstrapError, match="transport"):
        bootstrap.main(
            transport=None,
            environment=_environment(),
            version_getter=_versions,
            identity_getter=_identities,
            module_loader=loader,
        )
    assert imports == []


def test_profile_digest_drift_refuses_before_any_strix_import() -> None:
    environment = _environment()
    environment["BLUEFIRE_STRIX_PROFILE_DIGEST"] = "sha256:" + "0" * 64
    imports: list[str] = []

    def loader(name: str) -> Any:
        imports.append(name)
        if name == "bluefire.strix_controlled_backend":
            return controlled
        raise AssertionError("Strix must not be imported")

    with pytest.raises(bootstrap.ControlledBootstrapError, match="profile digest"):
        bootstrap.main(
            transport=NullTransport(),
            environment=environment,
            version_getter=_versions,
            identity_getter=_identities,
            module_loader=loader,
        )
    assert imports == ["bluefire.strix_controlled_backend"]


def test_protected_installed_candidate_identity_is_required_before_import() -> None:
    imports: list[str] = []

    def loader(name: str) -> Any:
        imports.append(name)
        raise AssertionError("module import should not occur")

    def wrong_identity(package: str) -> bootstrap.ControlledInstalledPackageIdentity:
        identity = _identities(package)
        if package == "strix-agent":
            return bootstrap.ControlledInstalledPackageIdentity(
                package=identity.package,
                version=identity.version,
                artifact_digest="sha256:" + "f" * 64,
                source_revision=identity.source_revision,
            )
        return identity

    with pytest.raises(bootstrap.ControlledBootstrapError, match="candidate identity"):
        bootstrap.main(
            transport=NullTransport(),
            environment=_environment(),
            version_getter=_versions,
            identity_getter=wrong_identity,
            module_loader=loader,
        )
    assert imports == []


def test_registration_failure_prevents_official_main_import_and_retry() -> None:
    imports: list[str] = []

    def register_backend(name: str, backend: Any, *, supports_bind_mounts: bool) -> None:
        _ = (name, backend, supports_bind_mounts)
        raise RuntimeError("registry refused")

    def loader(name: str) -> Any:
        imports.append(name)
        if name == "bluefire.strix_controlled_backend":
            return controlled
        if name == "strix.runtime.backends":
            return SimpleNamespace(register_backend=register_backend)
        raise AssertionError("official main must not be imported")

    with pytest.raises(RuntimeError, match="registry refused"):
        bootstrap.main(
            transport=NullTransport(),
            environment=_environment(),
            version_getter=_versions,
            identity_getter=_identities,
            module_loader=loader,
        )
    assert "strix.interface.main" not in imports

    with pytest.raises(bootstrap.ControlledBootstrapError, match="one-shot"):
        bootstrap.main(
            transport=NullTransport(),
            environment=_environment(),
            version_getter=_versions,
            identity_getter=_identities,
            module_loader=loader,
        )


def test_bootstrap_errors_and_config_repr_do_not_expose_private_socket() -> None:
    environment = _environment()
    private_socket = environment["DOCKER_HOST"]
    config = bootstrap._validate_environment(environment)
    assert private_socket not in repr(config)

    environment["DOCKER_HOST"] = private_socket + "?token=top-secret"
    with pytest.raises(bootstrap.ControlledBootstrapError) as raised:
        bootstrap._validate_environment(environment)
    assert private_socket not in str(raised.value)
    assert "top-secret" not in str(raised.value)
