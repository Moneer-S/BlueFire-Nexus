"""Canonical identity for BlueFire's runner-private Strix test sandbox image.

This contract is deliberately separate from :mod:`bluefire.strix_image_contract`.
The historical V2 declaration is bound to the upstream Strix sandbox image;
this test image is built from a pinned Docker Official Debian base and must
never satisfy that production-lineage contract.

Parsing a declaration proves only that its fields match the reviewed shape.
The hosted qualifier must still build, import, start, inspect, inventory, and
remove the exact image on one owned runner.  The image and its build context
are never publication artifacts.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence, cast

from .strix_image_contract import StrixImageContractError, validate_v2_image_reference
from .util import canonical_json_bytes, content_hash

SCHEMA_VERSION = "bluefire.strix-test-sandbox-image.v1"
CLEANUP_SCHEMA_VERSION = "bluefire.strix-test-sandbox-image-cleanup.v1"
STRIX_SOURCE_REVISION = "6b7ae2ebe4d47037a927aade23265ff4e4f27e84"  # pragma: allowlist secret
PLATFORM = {"os": "linux", "architecture": "x86_64", "oci_architecture": "amd64"}
SANDBOX_UID = 1000
SANDBOX_GID = 1000
WORKING_DIRECTORY = "/workspace"
CONTROLLED_ENTRYPOINT = "/opt/bluefire/bin/strix-test-sandbox-entrypoint"
CONTROLLED_SELF_TEST = "/opt/bluefire/bin/strix-test-sandbox-self-test"
TEST_PROVIDER_MODULE = "bluefire.test_caido_protocol_provider"
TEST_PROVIDER_HOST = "127.0.0.1"
TEST_PROVIDER_PORT = 48080
MANIFEST_FILENAME = "strix-test-sandbox-image-manifest.json"
CLEANUP_FILENAME = "strix-test-sandbox-image-cleanup.json"
CAIDO_SDK_CLIENT_WHEEL_DIGEST = (
    "sha256:bc573651681c093ee9663c7924d38d522a89cea60e2ce00d34ba9b02942b1da1"
)
CAIDO_SDK_WIRE_FIXTURE_DIGEST = (
    "sha256:0f83caa9253b07fec972b5aae877b8495cf5c81c8893df27b708fc515fe74966"
)
CAIDO_SDK_PROJECT_DOCUMENT_DIGEST = (
    "sha256:ea2c5935a9921295c029d2912589df5997f2b9eec185b1bf73556f1af7d986cf"
)
STRIX_CAIDO_BOOTSTRAP_DIGEST = (
    "sha256:f493e3a7c9219e52520d2fadfd8dde78782e17440056f98aa068b146a0e788af"
)

# Docker Official Image `debian:bookworm-20260918-slim`.  These identities
# were resolved from the Docker Hub tag record and registry V2 manifest on
# 2026-11-05.  The tag is documentation only; builds use the digest reference.
BASE_IMAGE = {
    "repository": "docker.io/library/debian",
    "version_label": "bookworm-20260918-slim",
    "index_reference": (
        "docker.io/library/debian@"
        "sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251"
    ),
    "index": {
        "media_type": "application/vnd.oci.image.index.v1+json",
        "digest": "sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251",
    },
    "platform_child": {
        "media_type": "application/vnd.oci.image.manifest.v1+json",
        "digest": "sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b",
        "platform": PLATFORM,
    },
    "config": {
        "media_type": "application/vnd.oci.image.config.v1+json",
        "digest": "sha256:db9f02c6bde9fa90cc8074c92754b2b046947392f1a857726e77f041febb7b82",
        "size": 453,
    },
    "layers": [
        {
            "media_type": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": "sha256:774043ccc8ccd0d0833a9ee0792142ab7ad93df971e59dd248fbf82db16d0150",
            "size": 28_238_443,
        }
    ],
    "source": {
        "project": "Docker Official Images / Debian",
        "registry_api": "https://registry-1.docker.io/v2/library/debian/",
        "tag_api": "https://hub.docker.com/v2/repositories/library/debian/tags/",
        "license_evidence": "image:/usr/share/doc/*/copyright",
    },
}

# The base already supplies bash, dash/sh, coreutils (mkdir/rm), and tar.  The
# only additional native tool required by the captured Strix SDK startup wire
# is curl.  Every added .deb is copied from the build context, SHA-256 checked,
# and installed while the Docker build network is disabled.
BASE_TOOL_CLOSURE = (
    {"name": "bash", "version": "5.2.15-2+b13", "source": "base-image"},
    {"name": "coreutils", "version": "9.1-1", "source": "base-image"},
    {"name": "dash", "version": "0.5.12-2", "source": "base-image"},
    {"name": "tar", "version": "1.34+dfsg-1.2+deb12u1", "source": "base-image"},
)


def _deb(
    name: str,
    version: str,
    filename: str,
    sha256: str,
) -> dict[str, str]:
    return {
        "name": name,
        "version": version,
        "architecture": "amd64",
        "url": f"https://deb.debian.org/debian/{filename}",
        "filename": filename.rsplit("/", 1)[-1],
        "sha256": sha256,
        "license_evidence": f"image:/usr/share/doc/{name}/copyright",
    }


OFFLINE_CURL_CLOSURE = (
    _deb(
        "curl",
        "7.88.1-10+deb12u15",
        "pool/main/c/curl/curl_7.88.1-10+deb12u15_amd64.deb",
        "0dd9b6bf7a0bd11af2d68a52ec44c2a223fa7c11f9104c36ce1047e1137d4a8f",
    ),
    _deb(
        "libcurl4",
        "7.88.1-10+deb12u15",
        "pool/main/c/curl/libcurl4_7.88.1-10+deb12u15_amd64.deb",
        "3042904de01f9c4fbdcf1452b8f81abedcf2b015f9b9deba109063322b5bd68b",
    ),
    _deb(
        "libbrotli1",
        "1.0.9-2+b6",
        "pool/main/b/brotli/libbrotli1_1.0.9-2+b6_amd64.deb",
        "563b4caec1aa5e876bd3355b36e7a38e1484baf5a293b48d1e8bd22db786e4d7",
    ),
    _deb(
        "libgssapi-krb5-2",
        "1.20.1-2+deb12u5",
        "pool/main/k/krb5/libgssapi-krb5-2_1.20.1-2+deb12u5_amd64.deb",
        "d8b87aea91b956b416c01a28c44ff6228315ae3b73de40acddac3dc5043607d2",
    ),
    _deb(
        "libk5crypto3",
        "1.20.1-2+deb12u5",
        "pool/main/k/krb5/libk5crypto3_1.20.1-2+deb12u5_amd64.deb",
        "7b6e47d15c5c9cdcd456137533d8308aeba608a54cec73b28bd59bfc4b54cf06",
    ),
    _deb(
        "libkrb5-3",
        "1.20.1-2+deb12u5",
        "pool/main/k/krb5/libkrb5-3_1.20.1-2+deb12u5_amd64.deb",
        "c90801be09701af221b54dd502a59cb378b7284ff31e480738baca317d2f7653",
    ),
    _deb(
        "libkrb5support0",
        "1.20.1-2+deb12u5",
        "pool/main/k/krb5/libkrb5support0_1.20.1-2+deb12u5_amd64.deb",
        "8b9c05f2d8d461a10d657b118f572af5bf8fd6c8f93dcef81e852c5ab0f428ab",
    ),
    _deb(
        "libkeyutils1",
        "1.6.3-2",
        "pool/main/k/keyutils/libkeyutils1_1.6.3-2_amd64.deb",
        "cfac89e6a7a54ff3c6a4f843310e25efeddaa771baeae470bd98bd588c373563",
    ),
    _deb(
        "libldap-2.5-0",
        "2.5.13+dfsg-5",
        "pool/main/o/openldap/libldap-2.5-0_2.5.13+dfsg-5_amd64.deb",
        "4b6c30f6554149c594628d945edc6003f0eea8d0cc1341638c0e71375db147ed",
    ),
    _deb(
        "libsasl2-2",
        "2.1.28+dfsg-10",
        "pool/main/c/cyrus-sasl2/libsasl2-2_2.1.28+dfsg-10_amd64.deb",
        "11ee190ad39f8d7af441d2c8347388b9449434c73acc67b4b372445ac4152efa",
    ),
    _deb(
        "libsasl2-modules-db",
        "2.1.28+dfsg-10",
        "pool/main/c/cyrus-sasl2/libsasl2-modules-db_2.1.28+dfsg-10_amd64.deb",
        "3ac4fd6cbe3b3b06e68d24b931bf3eb9385b42f15604a37ed25310e948ca0ee6",
    ),
    _deb(
        "libnghttp2-14",
        "1.52.0-1+deb12u3",
        "pool/main/n/nghttp2/libnghttp2-14_1.52.0-1+deb12u3_amd64.deb",
        "5a5736cee57e51c1baed869979e6ecdbc6495e939e33203d6cfe3b6e5a149e3f",
    ),
    _deb(
        "libpsl5",
        "0.21.2-1",
        "pool/main/libp/libpsl/libpsl5_0.21.2-1_amd64.deb",
        "4f0d35610204e4e754b057748719744114621f2f6f4202d846c314860a981afb",
    ),
    _deb(
        "librtmp1",
        "2.4+20151223.gitfa8646d.1-2+b2",
        "pool/main/r/rtmpdump/librtmp1_2.4+20151223.gitfa8646d.1-2+b2_amd64.deb",
        "e1f69020dc2c466e421ec6a58406b643be8b5c382abf0f8989011c1d3df91c87",
    ),
    _deb(
        "libssh2-1",
        "1.10.0-3+b1",
        "pool/main/libs/libssh2/libssh2-1_1.10.0-3+b1_amd64.deb",
        "d20a3ee34fa84ad8bd381e8be6e9c2c2ea32347cff5e1169c10e978d43f54f24",
    ),
    _deb(
        "libssl3",
        "3.0.20-1~deb12u2",
        "pool/main/o/openssl/libssl3_3.0.20-1~deb12u2_amd64.deb",
        "89be24b41bff568ee6e7caf5680a3d808e80315ed92e407056ce0fa7a5bda025",
    ),
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40,64}\Z")
_CLEANUP_LABEL = re.compile(r"bluefire\.strix-test-sandbox\.[0-9a-f]{32}\Z")
_OCI_MEDIA = {
    "index": frozenset({"application/vnd.oci.image.index.v1+json"}),
    "manifest": frozenset({"application/vnd.oci.image.manifest.v1+json"}),
    "config": frozenset({"application/vnd.oci.image.config.v1+json"}),
    "layer": frozenset(
        {
            "application/vnd.oci.image.layer.v1.tar",
            "application/vnd.oci.image.layer.v1.tar+gzip",
            "application/vnd.oci.image.layer.v1.tar+zstd",
        }
    ),
}


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise StrixImageContractError(f"{label} fields do not match the contract")
    return dict(value)


def _same(value: Any, expected: Any, label: str) -> None:
    try:
        matches = canonical_json_bytes(value) == canonical_json_bytes(expected)
    except (TypeError, ValueError, OverflowError) as exc:
        raise StrixImageContractError(f"{label} is not canonical JSON") from exc
    if not matches:
        raise StrixImageContractError(f"{label} does not match the reviewed profile")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise StrixImageContractError(f"{label} digest is invalid")
    return value


def _oci_descriptor(value: Any, role: str, *, platform: bool = False) -> dict[str, Any]:
    fields = {"media_type", "digest", "size"}
    if platform:
        fields.add("platform")
    row = _exact(value, fields, role)
    _digest(row["digest"], role)
    if row["media_type"] not in _OCI_MEDIA[role.rsplit(" ", 1)[-1]]:
        raise StrixImageContractError(f"{role} media type is invalid")
    if isinstance(row["size"], bool) or not isinstance(row["size"], int) or row["size"] <= 0:
        raise StrixImageContractError(f"{role} size is invalid")
    if platform:
        _same(row["platform"], PLATFORM, f"{role} platform")
    return row


def package_lock_document() -> dict[str, Any]:
    """Return the reviewed native-tool closure copied into the offline build."""

    return {
        "schema_version": "bluefire.strix-test-sandbox-packages.v1",
        "distribution": "debian-bookworm",
        "architecture": "amd64",
        "base_tools": [dict(item) for item in BASE_TOOL_CLOSURE],
        "offline_packages": [dict(item) for item in OFFLINE_CURL_CLOSURE],
        "build_network": "none",
        "runtime_package_manager_present": False,
        "runtime_installs": False,
    }


def package_lock_digest() -> str:
    return cast(str, content_hash(package_lock_document()))


def proposed_test_runtime_profile() -> dict[str, Any]:
    """Return the fixed profile expected by the controller for this test image."""

    return {
        "user": f"{SANDBOX_UID}:{SANDBOX_GID}",
        "read_only_root": True,
        "working_directory": WORKING_DIRECTORY,
        "entrypoint": [CONTROLLED_ENTRYPOINT],
        "environment": {
            "HOME": "/workspace/home",
            "TMPDIR": "/workspace/tmp",
            "XDG_CACHE_HOME": "/workspace/cache",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        },
        "tmpfs": {
            "/workspace": ("rw,nosuid,nodev,noexec,size=536870912,uid=1000,gid=1000,mode=0700")
        },
        "mounts": [],
        "volumes": [],
        "published_ports": [],
        "extra_hosts": [],
        "devices": [],
        "docker_socket": False,
        "host_gateway": False,
        "privileged": False,
        "cap_add": [],
        "cap_drop": ["ALL"],
        "security_options": ["no-new-privileges:true"],
        "seccomp": "runtime-default",
        "pid_mode": "private",
        "ipc_mode": "private",
        "uts_mode": "private",
        "network": {
            "mode": "attempt-internal",
            "public_egress": False,
            "dns": False,
            "attach_additional_networks": False,
            "allowed_destinations": [
                "test-provider-loopback:127.0.0.1:48080",
                "controller-enrolled-owned-target-relay",
            ],
        },
        "memory_bytes": 2 * 1024**3,
        "memory_swap_bytes": 2 * 1024**3,
        "nano_cpus": 2_000_000_000,
        "pids_limit": 256,
        "runtime_installs": False,
        "runtime_image_pulls": False,
        "preloaded_image_required": True,
        "restart_policy": "no",
    }


def installed_worker_invocation_document() -> dict[str, Any]:
    """Return the fixed fresh-exec worker vector used by the image entrypoint."""

    return {
        "schema_version": "bluefire.strix-installed-worker-invocation.v1",
        "argv": [
            "/runtime/bin/python",
            "-I",
            "-S",
            "-B",
            "-X",
            "utf8",
            "/bootstrap/worker.py",
        ],
        "caller_arguments_allowed": False,
    }


def installed_worker_invocation_digest() -> str:
    return cast(str, content_hash(installed_worker_invocation_document()))


def test_provider_invocation_document() -> dict[str, Any]:
    """Return the exact descriptor-adopting provider invocation contract."""

    return {
        "schema_version": "bluefire.test-caido-protocol-provider-invocation.v1",
        "execution_location": "controller",
        "argv": [
            "<controller-owned-python>",
            "-I",
            "-m",
            TEST_PROVIDER_MODULE,
            "--manifest-fd",
            "<controller-owned-fd>",
            "--listener-fd",
            "<prebound-127.0.0.1:48080-fd>",
            "--audit-fd",
            "<controller-owned-fd>",
            "--ready-fd",
            "<controller-owned-fd>",
        ],
        "conformance_argv": [
            "<controller-owned-python>",
            "-I",
            "-m",
            TEST_PROVIDER_MODULE,
            "--describe",
        ],
        "socket_creation": False,
        "socket_bind": False,
        "socket_listen": False,
        "socket_connect": False,
    }


def test_provider_invocation_digest() -> str:
    return cast(str, content_hash(test_provider_invocation_document()))


def _validate_runtime_closure(value: Any) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "schema_version",
            "composite_ref",
            "prelaunch_plan_ref",
            "fixed_exec_qualification_ref",
            "inventory_digest",
            "interpreter_digest",
            "entrypoint_digest",
            "worker_invocation_digest",
            "worker_distribution",
            "worker_artifact_digest",
            "worker_record_digest",
            "worker_source_revision",
            "installed_distributions_digest",
            "full_product_wheel_present",
            "strix_candidate_digest",
            "source_revision",
            "python_version",
        },
        "runtime closure",
    )
    _same(
        row["schema_version"],
        "bluefire.strix-linux-qualified-runtime-composite.v1",
        "runtime schema",
    )
    _same(row["source_revision"], STRIX_SOURCE_REVISION, "runtime Strix source revision")
    _same(row["python_version"], "3.12.14", "runtime Python version")
    for field in (
        "composite_ref",
        "prelaunch_plan_ref",
        "fixed_exec_qualification_ref",
        "inventory_digest",
        "interpreter_digest",
        "entrypoint_digest",
        "worker_invocation_digest",
        "worker_artifact_digest",
        "worker_record_digest",
        "installed_distributions_digest",
        "strix_candidate_digest",
    ):
        _digest(row[field], f"runtime {field}")
    _same(row["worker_distribution"], "bluefire-strix-worker", "runtime worker distribution")
    if (
        not isinstance(row["worker_source_revision"], str)
        or _REVISION.fullmatch(row["worker_source_revision"]) is None
    ):
        raise StrixImageContractError("runtime worker source revision is invalid")
    _same(row["full_product_wheel_present"], False, "full BlueFire product wheel presence")
    _same(
        row["worker_invocation_digest"],
        installed_worker_invocation_digest(),
        "runtime worker invocation",
    )
    expected_composite = content_hash(
        {
            "schema_version": "bluefire.strix-linux-qualified-runtime-composite.v1",
            "prelaunch_plan_ref": row["prelaunch_plan_ref"],
            "fixed_exec_qualification_ref": row["fixed_exec_qualification_ref"],
        }
    )
    _same(row["composite_ref"], expected_composite, "runtime qualified composite")
    return row


def _validate_test_provider(value: Any) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "schema_version",
            "module",
            "execution_location",
            "provider_source_digest",
            "artifact_digest",
            "invocation_digest",
            "sdk_client_wheel_digest",
            "sdk_wire_fixture_digest",
            "sdk_project_document_digest",
            "strix_bootstrap_digest",
            "host",
            "port",
            "test_provider",
            "live_caido_proof",
            "production_eligible",
            "caido_cli_or_server_present",
            "official_caido_image_present",
            "derived_caido_image_present",
        },
        "test provider",
    )
    _same(row["schema_version"], "bluefire.test-caido-protocol-provider.v1", "provider schema")
    _same(row["module"], TEST_PROVIDER_MODULE, "provider module")
    _same(row["execution_location"], "controller", "provider execution location")
    _same(row["host"], TEST_PROVIDER_HOST, "provider host")
    _same(row["port"], TEST_PROVIDER_PORT, "provider port")
    for field in ("provider_source_digest", "artifact_digest"):
        _digest(row[field], f"provider {field}")
    _same(row["artifact_digest"], row["provider_source_digest"], "provider source artifact")
    _same(row["invocation_digest"], test_provider_invocation_digest(), "provider invocation")
    _same(row["sdk_client_wheel_digest"], CAIDO_SDK_CLIENT_WHEEL_DIGEST, "provider SDK wheel")
    _same(row["sdk_wire_fixture_digest"], CAIDO_SDK_WIRE_FIXTURE_DIGEST, "provider wire fixture")
    _same(
        row["sdk_project_document_digest"],
        CAIDO_SDK_PROJECT_DOCUMENT_DIGEST,
        "provider project document",
    )
    _same(row["strix_bootstrap_digest"], STRIX_CAIDO_BOOTSTRAP_DIGEST, "Strix bootstrap")
    _same(
        {
            "test_provider": row["test_provider"],
            "live_caido_proof": row["live_caido_proof"],
            "production_eligible": row["production_eligible"],
            "caido_cli_or_server_present": row["caido_cli_or_server_present"],
            "official_caido_image_present": row["official_caido_image_present"],
            "derived_caido_image_present": row["derived_caido_image_present"],
        },
        {
            "test_provider": True,
            "live_caido_proof": False,
            "production_eligible": False,
            "caido_cli_or_server_present": False,
            "official_caido_image_present": False,
            "derived_caido_image_present": False,
        },
        "provider proof scope",
    )
    return row


def _validate_image(value: Any) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "index_reference",
            "index",
            "platform_child",
            "config",
            "layers",
            "image_id",
            "imported_reference",
        },
        "test image",
    )
    reference = validate_v2_image_reference(row["index_reference"], "test image reference")
    index = _oci_descriptor(row["index"], "test index")
    manifest = _oci_descriptor(row["platform_child"], "test manifest", platform=True)
    config = _oci_descriptor(row["config"], "test config")
    if reference.rsplit("@", 1)[-1] != index["digest"]:
        raise StrixImageContractError("test image reference and index digest differ")
    image_id = _digest(row["image_id"], "Docker image ID")
    if image_id != config["digest"]:
        raise StrixImageContractError("Docker image ID and OCI config differ")
    imported = validate_v2_image_reference(row["imported_reference"], "imported image reference")
    if imported.rsplit("@", 1)[-1] != manifest["digest"]:
        raise StrixImageContractError("imported image reference and platform manifest differ")
    layers = row["layers"]
    if not isinstance(layers, list) or not 1 <= len(layers) <= 64:
        raise StrixImageContractError("test image layer inventory is invalid")
    parsed_layers = [_oci_descriptor(item, "test layer") for item in layers]
    if len({item["digest"] for item in parsed_layers}) != len(parsed_layers):
        raise StrixImageContractError("test image layer inventory contains duplicates")
    if len({index["digest"], manifest["digest"], config["digest"]}) != 3:
        raise StrixImageContractError("test image OCI roles overlap")
    return row


def _validate_contract(value: Any) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "schema_version",
            "bluefire_source_revision",
            "strix_source_revision",
            "platform",
            "base_image",
            "package_lock",
            "runtime_closure",
            "test_provider",
            "build",
            "image",
            "runtime_profile",
            "qualification",
            "policy",
        },
        "test sandbox image",
    )
    _same(row["schema_version"], SCHEMA_VERSION, "test image schema")
    if (
        not isinstance(row["bluefire_source_revision"], str)
        or _REVISION.fullmatch(row["bluefire_source_revision"]) is None
    ):
        raise StrixImageContractError("BlueFire source revision is invalid")
    _same(row["strix_source_revision"], STRIX_SOURCE_REVISION, "Strix source revision")
    _same(row["platform"], PLATFORM, "test image platform")
    _same(row["base_image"], BASE_IMAGE, "test image base")
    package_lock = _exact(row["package_lock"], {"digest", "document"}, "package lock")
    _same(package_lock["document"], package_lock_document(), "package lock document")
    _same(package_lock["digest"], package_lock_digest(), "package lock digest")
    runtime_closure = _validate_runtime_closure(row["runtime_closure"])
    _same(
        runtime_closure["worker_source_revision"],
        row["bluefire_source_revision"],
        "runtime worker source revision",
    )
    _validate_test_provider(row["test_provider"])
    build = _exact(
        row["build"],
        {
            "dockerfile_digest",
            "context_digest",
            "runtime_closure_digest",
            "container_entrypoint_digest",
            "self_test_digest",
            "network_mode",
            "pull",
            "runtime_installs",
        },
        "test image build",
    )
    for field in (
        "dockerfile_digest",
        "context_digest",
        "runtime_closure_digest",
        "container_entrypoint_digest",
        "self_test_digest",
    ):
        _digest(build[field], f"build {field}")
    _same(build["runtime_closure_digest"], runtime_closure["composite_ref"], "runtime binding")
    _same(
        {
            "network_mode": build["network_mode"],
            "pull": build["pull"],
            "runtime_installs": build["runtime_installs"],
        },
        {"network_mode": "none", "pull": False, "runtime_installs": False},
        "offline build",
    )
    _validate_image(row["image"])
    _same(row["runtime_profile"], proposed_test_runtime_profile(), "test runtime profile")
    qualification = _exact(
        row["qualification"],
        {
            "qualification_ref",
            "qualifier_revision",
            "runner_os",
            "runner_image",
            "runner_architecture",
            "docker_server_digest",
            "sbom_digest",
            "provenance_digest",
            "notice_report_digest",
            "self_test_evidence_digest",
            "image_built",
            "image_imported",
            "image_started",
            "self_test_passed",
            "cleanup_label",
        },
        "test image qualification",
    )
    _digest(qualification["qualification_ref"], "test image qualification reference")
    if (
        not isinstance(qualification["qualifier_revision"], str)
        or _REVISION.fullmatch(qualification["qualifier_revision"]) is None
    ):
        raise StrixImageContractError("test image qualifier revision is invalid")
    _same(qualification["runner_os"], "Linux", "qualifier OS")
    _same(qualification["runner_image"], "ubuntu-24.04", "qualifier image")
    _same(qualification["runner_architecture"], "x86_64", "qualifier architecture")
    for field in (
        "docker_server_digest",
        "sbom_digest",
        "provenance_digest",
        "notice_report_digest",
        "self_test_evidence_digest",
    ):
        _digest(qualification[field], f"qualification {field}")
    _same(
        {
            "image_built": qualification["image_built"],
            "image_imported": qualification["image_imported"],
            "image_started": qualification["image_started"],
            "self_test_passed": qualification["self_test_passed"],
        },
        {
            "image_built": True,
            "image_imported": True,
            "image_started": True,
            "self_test_passed": True,
        },
        "image self-test result",
    )
    if (
        not isinstance(qualification["cleanup_label"], str)
        or _CLEANUP_LABEL.fullmatch(qualification["cleanup_label"]) is None
    ):
        raise StrixImageContractError("test image cleanup label is invalid")
    policy = _exact(
        row["policy"],
        {
            "test_only",
            "runner_private",
            "image_upload_allowed",
            "image_publish_allowed",
            "production_runtime_admitted",
            "live_engine_proof",
            "live_caido_proof",
            "redistribution_authorized",
        },
        "test image policy",
    )
    _same(
        policy,
        {
            "test_only": True,
            "runner_private": True,
            "image_upload_allowed": False,
            "image_publish_allowed": False,
            "production_runtime_admitted": False,
            "live_engine_proof": False,
            "live_caido_proof": False,
            "redistribution_authorized": False,
        },
        "test image policy",
    )
    return row


@dataclass(frozen=True, slots=True)
class StrixTestSandboxImageContractV1:
    """Canonical hosted qualification record for one runner-private image."""

    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.canonical_bytes) is not bytes or len(self.canonical_bytes) > 256 * 1024:
            raise StrixImageContractError("test sandbox image contract bytes are invalid")
        try:
            row = _validate_contract(json.loads(self.canonical_bytes))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StrixImageContractError("test sandbox image contract is not JSON") from exc
        if self.canonical_bytes != canonical_json_bytes(row):
            raise StrixImageContractError("test sandbox image contract is not canonical")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "StrixTestSandboxImageContractV1":
        try:
            return cls(canonical_json_bytes(_validate_contract(value)))
        except (TypeError, ValueError, OverflowError) as exc:
            if isinstance(exc, StrixImageContractError):
                raise
            raise StrixImageContractError("test sandbox image contract is invalid") from exc

    def to_dict(self) -> dict[str, Any]:
        return dict(json.loads(self.canonical_bytes))

    @property
    def contract_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def qualification_ref(self) -> str:
        return cast(str, self.to_dict()["qualification"]["qualification_ref"])

    @property
    def runtime_closure_ref(self) -> str:
        return cast(str, self.to_dict()["runtime_closure"]["composite_ref"])

    @property
    def worker_identity_ref(self) -> str:
        runtime = self.to_dict()["runtime_closure"]
        return cast(
            str,
            content_hash(
                {
                    "schema_version": "bluefire.strix-worker-identity.v1",
                    "distribution": runtime["worker_distribution"],
                    "artifact_digest": runtime["worker_artifact_digest"],
                    "record_digest": runtime["worker_record_digest"],
                    "source_revision": runtime["worker_source_revision"],
                    "installed_distributions_digest": runtime["installed_distributions_digest"],
                }
            ),
        )

    @property
    def image_reference(self) -> str:
        return cast(str, self.to_dict()["image"]["index_reference"])


def _validate_cleanup(value: Any) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "schema_version",
            "contract_digest",
            "qualification_ref",
            "cleanup_label",
            "container_absent",
            "network_absent",
            "image_absent",
            "build_context_absent",
            "oci_layout_absent",
            "docker_archive_absent",
            "runtime_stage_absent",
            "cleanup_evidence_digest",
        },
        "test image cleanup",
    )
    _same(row["schema_version"], CLEANUP_SCHEMA_VERSION, "cleanup schema")
    _digest(row["contract_digest"], "cleanup contract")
    _digest(row["qualification_ref"], "cleanup qualification reference")
    if (
        not isinstance(row["cleanup_label"], str)
        or _CLEANUP_LABEL.fullmatch(row["cleanup_label"]) is None
    ):
        raise StrixImageContractError("cleanup label is invalid")
    _same(
        {
            name: row[name]
            for name in (
                "container_absent",
                "network_absent",
                "image_absent",
                "build_context_absent",
                "oci_layout_absent",
                "docker_archive_absent",
                "runtime_stage_absent",
            )
        },
        {
            "container_absent": True,
            "network_absent": True,
            "image_absent": True,
            "build_context_absent": True,
            "oci_layout_absent": True,
            "docker_archive_absent": True,
            "runtime_stage_absent": True,
        },
        "cleanup result",
    )
    _digest(row["cleanup_evidence_digest"], "cleanup evidence")
    return row


@dataclass(frozen=True, slots=True)
class StrixTestSandboxImageCleanupReceiptV1:
    """Canonical proof that this run's private image material was removed."""

    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.canonical_bytes) is not bytes or len(self.canonical_bytes) > 16 * 1024:
            raise StrixImageContractError("test image cleanup receipt bytes are invalid")
        try:
            row = _validate_cleanup(json.loads(self.canonical_bytes))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StrixImageContractError("test image cleanup receipt is not JSON") from exc
        if self.canonical_bytes != canonical_json_bytes(row):
            raise StrixImageContractError("test image cleanup receipt is not canonical")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "StrixTestSandboxImageCleanupReceiptV1":
        return cls(canonical_json_bytes(_validate_cleanup(value)))

    def to_dict(self) -> dict[str, Any]:
        return dict(json.loads(self.canonical_bytes))

    @property
    def receipt_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes).hexdigest()


def validate_package_archive_digests(items: Sequence[Mapping[str, Any]]) -> None:
    """Reject a downloaded package set that differs from the reviewed lock."""

    observed: list[dict[str, str]] = []
    for item in items:
        row = _exact(item, {"filename", "sha256"}, "package archive")
        if not isinstance(row["filename"], str) or not row["filename"]:
            raise StrixImageContractError("package archive filename is invalid")
        if not isinstance(row["sha256"], str) or _SHA256.fullmatch(row["sha256"]) is None:
            raise StrixImageContractError("package archive SHA-256 is invalid")
        observed.append({"filename": row["filename"], "sha256": row["sha256"]})
    expected = [
        {"filename": item["filename"], "sha256": item["sha256"]} for item in OFFLINE_CURL_CLOSURE
    ]
    _same(observed, expected, "offline package archives")


__all__ = [
    "BASE_IMAGE",
    "BASE_TOOL_CLOSURE",
    "CAIDO_SDK_CLIENT_WHEEL_DIGEST",
    "CAIDO_SDK_PROJECT_DOCUMENT_DIGEST",
    "CAIDO_SDK_WIRE_FIXTURE_DIGEST",
    "CLEANUP_FILENAME",
    "CONTROLLED_ENTRYPOINT",
    "CONTROLLED_SELF_TEST",
    "MANIFEST_FILENAME",
    "OFFLINE_CURL_CLOSURE",
    "PLATFORM",
    "SANDBOX_GID",
    "SANDBOX_UID",
    "SCHEMA_VERSION",
    "STRIX_SOURCE_REVISION",
    "STRIX_CAIDO_BOOTSTRAP_DIGEST",
    "StrixTestSandboxImageCleanupReceiptV1",
    "StrixTestSandboxImageContractV1",
    "package_lock_digest",
    "package_lock_document",
    "proposed_test_runtime_profile",
    "installed_worker_invocation_digest",
    "installed_worker_invocation_document",
    "test_provider_invocation_digest",
    "test_provider_invocation_document",
    "validate_package_archive_digests",
]
