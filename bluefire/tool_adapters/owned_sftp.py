"""Preparatory metadata for one owned-loopback SFTP method, never execution authority.

This module is deliberately absent from the shipping adapter registry. It reuses
the existing native installation identity parser, not its single-tool dispatch.
No bundle is supplied or approved here. The future compiled consumer must resolve
authenticated references, inspect every protected executable and live resource,
and enforce its own reviewed operation and effect receipts before any execution.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, cast

from ..contracts import ContractError
from ..native_tool_installations import NativeToolInstallation
from ..util import canonical_json_bytes, content_hash

METHOD_ID = "endpoint.collection.openssh-sftp.v1"
VERSION = "0.1.0"
BUNDLE_SCHEMA = "bluefire.owned-loopback-sftp-bundle.v1"
REQUEST_SCHEMA = "bluefire.owned-loopback-sftp-client-preparation.v1"
MAX_BYTES = 16 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_BUILD = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}")
_ROLES = {
    "client": ("openssh", "sftp", "openssh.sftp.v1"),
    "transport": ("openssh", "ssh", "openssh.ssh.v1"),
    "server": ("openssh", "sshd", "openssh.sshd.v1"),
    "session_helper": ("openssh", "sshd-session", "openssh.sshd-session.v1"),
    "auth_helper": ("openssh", "sshd-auth", "openssh.sshd-auth.v1"),
    "observer": ("strace", "strace", "strace.observer.v1"),
}
REFERENCE_FIELDS = (
    "endpoint_binding_ref",
    "server_preparation_ref",
    "resource_ref",
    "resource_generation",
    "source_content_sha256",
    "host_key_ref",
    "reader_identity_ref",
    "access_observation_ref",
    "session_prerequisite_ref",
)


def preparation_contract() -> dict[str, Any]:
    """Return the closed design identity; contains no admitted binary/build hash."""
    return {
        "schema_version": "bluefire.owned-loopback-sftp-contract.v1",
        "method_id": METHOD_ID,
        "version": VERSION,
        "status": "preparatory_unregistered",
        "sources": {
            "openssh": {
                "version": "10.6p1",
                "revision": "a8c72b842423f0774f542d3c2197247c3dd28d74",  # pragma: allowlist secret -- public upstream commit
                "reference": "https://github.com/openssh/openssh-portable/tree/V_10_6_P1",
                "license_reference": "https://raw.githubusercontent.com/openssh/openssh-portable/V_10_6_P1/LICENCE",
                "license": "LicenseRef-OpenSSH-composite",
            },
            "strace": {
                "version": "7.2",
                "revision": "195ac8ddbf6fad16ff1ff125b0feb725b6c46dcf",  # pragma: allowlist secret -- public upstream commit
                "reference": "https://github.com/strace/strace/tree/v7.2",
                "license_reference": "https://raw.githubusercontent.com/strace/strace/v7.2/COPYING",
                "license": "LGPL-2.1-or-later",
            },
        },
        "member_roles": {role: list(spec) for role, spec in sorted(_ROLES.items())},
        "network": "owned-loopback-only",
        "client_privilege": "current-user",
        "server_preparation": "separate-privileged-receipt-required",
        "invocation": "compiled-single-get-no-shell-no-resume-no-proxy-no-multiplexing",
        "reference_fields": list(REFERENCE_FIELDS),
        "limits": {"max_transfer_bytes": 1_048_576, "timeout_ms": 30_000, "max_processes": 16},
    }


def _fail(message: str) -> ContractError:
    return ContractError("owned SFTP preparation: " + message)


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _fail(label + " must contain exactly its declared fields")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise _fail(label + " must be a SHA-256 reference")
    return value


def _bounded(data: Mapping[str, Any]) -> bytes:
    try:
        encoded = canonical_json_bytes(data)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise _fail("metadata must be finite JSON") from exc
    if len(encoded) > MAX_BYTES:
        raise _fail("metadata exceeds its byte bound")
    return encoded


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _fail("duplicate JSON field")
        result[key] = value
    return result


def _bundle(value: Any) -> bytes:
    data = _exact(
        value,
        {"schema_version", "contract_digest", "platform", "architecture", "sources", "members"},
        "bundle",
    )
    contract = preparation_contract()
    if data["schema_version"] != BUNDLE_SCHEMA or data["contract_digest"] != content_hash(contract):
        raise _fail("bundle differs from the closed preparation contract")
    if data["platform"] != "linux" or data["architecture"] not in ("x86_64", "aarch64"):
        raise _fail("unsupported native platform or architecture")
    if data["sources"] != contract["sources"]:
        raise _fail("source identities differ from the pinned projects")
    members = data["members"]
    if not isinstance(members, list) or len(members) != len(_ROLES):
        raise _fail("bundle requires exactly the six named executable roles")
    roles, paths, identities = set(), set(), set()
    builds: dict[str, tuple[str, str]] = {}
    normalized = []
    for value in members:
        row = _exact(
            value,
            {
                "role",
                "source_id",
                "build_id",
                "build_manifest_ref",
                "protected_installation_ref",
                "installation",
            },
            "bundle member",
        )
        role = row["role"]
        if not isinstance(role, str) or role not in _ROLES or role in roles:
            raise _fail("unknown or duplicate executable role")
        roles.add(role)
        source_id, program, tool_id = _ROLES[role]
        if row["source_id"] != source_id:
            raise _fail("executable role has the wrong pinned source")
        build_id = row["build_id"]
        if not isinstance(build_id, str) or _BUILD.fullmatch(build_id) is None:
            raise _fail("build identity must be a bounded package/build token")
        build_ref = _digest(row["build_manifest_ref"], "build manifest")
        protected_ref = _digest(row["protected_installation_ref"], "protected installation")
        build = (build_id, build_ref)
        if source_id in builds and builds[source_id] != build:
            raise _fail("members of one source must share an exact reviewed build identity")
        builds[source_id] = build
        installation = NativeToolInstallation.from_mapping(row["installation"])
        installation.check_binding(
            expected_adapter_id=METHOD_ID,
            expected_adapter_version=VERSION,
            expected_adapter_contract_digest=content_hash(contract),
            expected_tool_id=tool_id,
            expected_platform="linux",
            expected_architecture=data["architecture"],
        )
        native = installation.to_dict()
        if native["tool_version"] != contract["sources"][source_id]["version"]:
            raise _fail("member version differs from its pinned source")
        path = native["installation_location"]
        if path.rsplit("/", 1)[-1] != program:
            raise _fail("executable basename differs from its fixed role")
        if path in paths or protected_ref in identities:
            raise _fail("bundle members require distinct protected executable identities")
        paths.add(path)
        identities.add(protected_ref)
        normalized.append({**row, "installation": native})
    return _bounded({**data, "members": sorted(normalized, key=lambda row: row["role"])})


@dataclass(frozen=True, slots=True)
class OwnedSftpToolBundle:
    """Immutable review identity, not an installed/approved executable bundle.

    A protected-installation reference is an integrity binding to evidence that a
    future runner must independently authenticate and refresh. Its syntax cannot
    prove filesystem protection, same-image provenance, or current availability.
    """

    _canonical: bytes

    def __post_init__(self) -> None:
        if type(self._canonical) is not bytes or len(self._canonical) > MAX_BYTES:
            raise _fail("bundle must be bounded immutable bytes")
        try:
            normalized = _bundle(json.loads(self._canonical, object_pairs_hook=_unique))
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise _fail("invalid bundle JSON") from exc
        if normalized != self._canonical:
            raise _fail("bundle must use canonical encoding and member ordering")

    @classmethod
    def from_mapping(cls, value: Any) -> OwnedSftpToolBundle:
        return cls(_bundle(value))

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(self._canonical))

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())


def prepare_client_selection(
    bundle: OwnedSftpToolBundle,
    request: Any,
    *,
    expected_bundle_digest: str,
    current_references: Any,
) -> dict[str, Any]:
    """Compare metadata with separately supplied current bindings; never authorize.

    Callers must not obtain expected/current values from the request itself or
    historical findings. Even matching inputs return execution_available=False:
    this is a preparatory seam for a future compiled, independently checked method.
    Privileged server preparation is only a reference here, never dispatched.
    """
    # Reparse even a directly constructed object; immutable syntax is not trust.
    bundle = OwnedSftpToolBundle.from_mapping(bundle.to_dict())
    data = _exact(
        request,
        {"schema_version", "bundle_digest", "max_transfer_bytes", *REFERENCE_FIELDS},
        "client preparation",
    )
    if data["schema_version"] != REQUEST_SCHEMA:
        raise _fail("unsupported client preparation schema")
    _digest(expected_bundle_digest, "expected bundle")
    if (
        _digest(data["bundle_digest"], "bundle") != bundle.digest
        or bundle.digest != expected_bundle_digest
    ):
        raise _fail("bundle differs from the independently supplied review identity")
    current = _exact(current_references, set(REFERENCE_FIELDS), "current prerequisites")
    for field in REFERENCE_FIELDS:
        if _digest(data[field], field) != _digest(current[field], "current " + field):
            raise _fail("current prerequisite changed: " + field)
    limit = data["max_transfer_bytes"]
    if type(limit) is not int or not 1 <= limit <= 1_048_576:
        raise _fail("transfer byte limit exceeds the fixed preparation ceiling")
    encoded = _bounded(data)
    return {
        "schema_version": "bluefire.owned-loopback-sftp-selection.v1",
        "method_id": METHOD_ID,
        "bundle_digest": bundle.digest,
        "request_digest": content_hash(json.loads(encoded)),
        "current_references_digest": content_hash(current),
        "execution_available": False,
        "reason": "compiled_sftp_consumer_unimplemented",
    }
