from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from bluefire import strix_adapter, strix_controlled_bootstrap
from bluefire.strix_adapter import (
    StrixBudgets,
    StrixBuildIdentity,
    StrixModelGateway,
    StrixRuntimeLimits,
    StrixScope,
    build_launch_plan,
    prepare_attempt_workspace,
)
from bluefire.strix_policy_overlay import (
    OVERLAY_SHA256,
    PATCHED_PROMPT_SHA256,
    REVIEWED_PROMPT_SHA256,
)
from bluefire.util import file_hash
from tools import build_strix_engine_candidate as candidate

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "strix_sdk_wire_v1.json"
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
ATTEMPT = "attempt-0123456789abcdef0123456789abcdef"
DIGEST = "sha256:" + "a" * 64


def _fixture() -> dict[str, Any]:
    value = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _walk_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for child in value for item in _walk_strings(child)]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _walk_strings(child)]
    return []


def _build(executable: Path) -> StrixBuildIdentity:
    return StrixBuildIdentity(
        source_revision=candidate.UPSTREAM_COMMIT,
        source_tree_sha256=DIGEST,
        package_sha256="sha256:" + "b" * 64,
        executable_sha256=file_hash(executable),
        image_reference="ghcr.io/usestrix/sandbox@sha256:" + "c" * 64,
        image_inventory_sha256="sha256:" + "d" * 64,
        prompt_upstream_sha256="sha256:" + REVIEWED_PROMPT_SHA256,
        prompt_overlay_sha256="sha256:" + OVERLAY_SHA256,
        prompt_patched_sha256="sha256:" + PATCHED_PROMPT_SHA256,
    )


def _launch(tmp_path: Path):
    executable = tmp_path / "strix"
    executable.write_bytes(b"reviewed exact candidate")
    root = tmp_path / "attempts"
    root.mkdir()
    workspace = prepare_attempt_workspace(
        root,
        attempt_id=ATTEMPT,
        objective="Assess only the admitted generated target.",
    )
    return build_launch_plan(
        build=_build(executable),
        scope=StrixScope(
            target="http://bluefire-lab:8080/",
            resolved_addresses=("172.18.0.7",),
            target_snapshot_digest=DIGEST,
            scope_digest="sha256:" + "2" * 64,
            network_policy_digest="sha256:" + "3" * 64,
            network_name="bf-strix-01234567",
        ),
        gateway=StrixModelGateway(
            model="controlled-test-provider",
            base_url="http://bluefire-model-gateway:8081/v1",
            authorization_digest="sha256:" + "4" * 64,
        ),
        budgets=StrixBudgets(900, 20, "5"),
        limits=StrixRuntimeLimits(),
        workspace=workspace,
        executable=executable.resolve(),
        path_environment="/reviewed/bin",
    )


def test_fixture_is_bound_to_the_reviewed_source_tree_and_exact_artifacts() -> None:
    fixture = _fixture()
    assert fixture["schema_version"] == "bluefire.strix-sdk-wire-fixture.v1"
    proof = fixture["proof"]
    assert proof == {
        "level": "mixed_exact_artifact_and_source_derived",
        "captured_on": "CPython 3.13 host",
        "target_runtime": "CPython 3.12.14",
        "candidate_runtime_qualified": False,
        "live_model_proof": False,
        "target_execution_proof": False,
        "notes": proof["notes"],
    }
    assert len(proof["notes"]) == 3

    sources = fixture["sources"]
    strix = sources["strix"]
    assert strix["commit"] == candidate.UPSTREAM_COMMIT
    assert strix["tree"] == candidate.UPSTREAM_TREE
    assert strix["commit"] == strix_adapter.REVIEWED_SOURCE_REVISION
    assert strix["uv_lock_sha256"] == strix["files"][-1]["sha256"]
    assert {item["path"]: (item["git_blob"], item["sha256"]) for item in strix["files"]} == {
        "strix/agents/factory.py": (
            "1b8742ba4ac9e0a9e841cd85313d7376671165cf",
            "7b77ddcf7b49e88f91d4129101bdb227a8e46520db0519819a5edb7ccfb43db1",
        ),
        "strix/runtime/caido_bootstrap.py": (
            "a9c7c82aef87e0109e87b2d8dc02af5fb37731af",
            "f493e3a7c9219e52520d2fadfd8dde78782e17440056f98aa068b146a0e788af",
        ),
        "strix/runtime/session_manager.py": (
            "d92b1fdbd47a569c5d24be1022133ff132cb158e",
            "739589d5d79f3d18b2ee86c27c7c3cf749889575e8d19e2ff6e89a6eb8c90fe4",
        ),
        "strix/interface/main.py": (
            "846a35da9878a299905a774247e6b537d07d81ce",
            "735ad8463f83256f049749a91c00f85cd6b58301c225244c7b6b798898cc7014",
        ),
        "uv.lock": (
            "aa7a27ef224c85aad82e9bb9a2e29a96a5a6a763",
            "e82b68f2d9ff70695843e43ce932b8c4ecb90551e1b0c2fff4b82d45248af36d",
        ),
    }
    assert strix["files"][-1]["git_blob"] == candidate.EXPECTED_BLOBS["uv.lock"]
    assert (
        next(item for item in strix["files"] if item["path"] == candidate.STARTUP_PATH)["git_blob"]
        == candidate.EXPECTED_BLOBS[candidate.STARTUP_PATH]
    )
    assert all(HEX_40.fullmatch(item["git_blob"]) for item in strix["files"])
    assert all(HEX_64.fullmatch(item["sha256"]) for item in strix["files"])

    agents = sources["openai_agents"]
    assert agents["version"] == candidate._REQUIRED_LOCKED_COMPONENTS["openai-agents"]
    assert agents["version"] == strix_controlled_bootstrap._PACKAGES["openai-agents"]
    assert agents["wheel_size"] == 928_463
    assert agents["wheel_sha256"] == (
        "25392cff993eca7c75b0679ec8d0111faef20c517222c0193111097d0f70db7a"
    )
    assert agents["members"] == {
        "agents/sandbox/capabilities/tools/shell_tool.py": (
            "6c82f099f18c7f46a0c4bbda0fbe8102b31c07c87f1ecb6a82560ef034d85479"
        ),
        "agents/sandbox/session/base_sandbox_session.py": (
            "805c7fe495c39c4b3efc59c28f998fdf4ffec12b814108be1ccb26796b43916c"
        ),
    }

    caido = sources["caido_sdk"]
    assert caido["version"] == candidate._REQUIRED_LOCKED_COMPONENTS["caido-sdk-client"]
    assert caido["locked_transport"] == {
        "aiohttp": "3.14.5",
        "gql": "4.0.0",
        "caido-server-auth": "0.1.2",
    }
    assert caido["capture_environment_transport"] == {
        "aiohttp": "3.14.5",
        "gql": "4.0.0",
        "caido-server-auth": "0.1.3",
        "matches_complete_locked_closure": False,
        "scope": "HTTP header and bearer shape capture only; no target-runtime qualification",
    }
    assert caido["wheel_sha256"] == (
        "bc573651681c093ee9663c7924d38d522a89cea60e2ce00d34ba9b02942b1da1"
    )
    assert caido["members"] == {
        "caido_sdk_client/client.py": (
            "100736e1ac42554d61ac914a051cb7d1925a787bc461fc6f0fd7239e2d90a700"
        ),
        "caido_sdk_client/graphql/client.py": (
            "a91f5fee583e3c74ebdbdfe2a105e4e6e1083d729708e7304be2150d3b8899e8"
        ),
        "caido_sdk_client/auth/manager.py": (
            "57f7b939ef62a7c9fdd125dc31094fc6bc09507b26572c8c46b2d34c3a890cdf"
        ),
        "caido_sdk_client/sdks/project.py": (
            "e04581f2be89848979bf04c3353db59d7cb10d026d83195a4cec34d8c1a9f5d6"
        ),
        "caido_sdk_client/graphql/documents/project.graphql": (
            "ea2c5935a9921295c029d2912589df5997f2b9eec185b1bf73556f1af7d986cf"
        ),
    }


def test_fixture_contains_no_secret_value_or_false_runtime_claim() -> None:
    fixture = _fixture()
    text = FIXTURE_PATH.read_text(encoding="utf-8")
    assert "sk-" not in text
    assert 'candidate_runtime_qualified": true' not in text
    assert 'live_model_proof": true' not in text
    assert 'target_execution_proof": true' not in text
    assert "Bearer <attempt-local-token>" in _walk_strings(fixture)
    assert (
        fixture["launch"]["provider_environment"]["controller_launch"][
            "secret_must_not_be_persisted"
        ]
        is True
    )


def test_exact_sdk_capture_preserves_default_and_non_login_shell_envelopes() -> None:
    shell = _fixture()["shell"]
    assert shell["strix_wrapper"] == {
        "omitted_shell_becomes": "bash",
        "source_proof": "source_derived",
    }
    captures = {item["case"]: item for item in shell["captures"]}
    assert captures["default"]["proof_level"] == "exact_artifact_import_capture"
    assert captures["default"]["session_exec"] == {
        "argv": ["bash", "-lc", "printf ready"],
        "timeout_seconds": 10.0,
        "user": None,
    }
    assert captures["login_false"]["proof_level"] == "exact_artifact_import_capture"
    assert captures["login_false"]["session_exec"] == {
        "argv": ["bash", "-c", "printf ready"],
        "timeout_seconds": 5.0,
        "user": None,
    }


def test_exact_sdk_start_capture_includes_the_workspace_prerequisite() -> None:
    start = _fixture()["sandbox_start"]
    assert start["proof_level"] == "exact_artifact_import_capture"
    assert start["case"] == "fresh_empty_manifest"
    assert start["capture"] == [
        {
            "operation": "mkdir_workspace",
            "argv": ["mkdir", "-p", "/workspace"],
            "timeout_seconds": 120.0,
            "working_directory": "/workspace",
        }
    ]
    assert start["manifest_entries"] == []
    assert start["caido_port"] == 48080
    staged = start["staged_files"]
    assert staged["proof_level"] == "exact_source_plus_artifact_transform_capture"
    assert staged["upstream_call"] == {
        "proof_level": "exact_source_derived",
        "boundary": "Strix source to BaseSandboxSession.exec inside the sandbox",
        "argv": [
            "sh",
            "-c",
            'tar --no-same-owner -xf "$1" -C "$2" && rm -f -- "$1"',
            "sh",
            "/workspace/.strix-extra-files.tar",
            "/workspace",
        ],
        "timeout_seconds": 120.0,
    }
    assert staged["session_exec"] == {
        "proof_level": "exact_artifact_import_capture",
        "boundary": "BaseSandboxSession to ControlledSandboxSession._exec_internal",
        "argv": [
            "sh",
            "-lc",
            'sh -c \'tar --no-same-owner -xf "$1" -C "$2" && rm -f -- "$1"\' sh /workspace/.strix-extra-files.tar /workspace',
        ],
        "timeout_seconds": 120.0,
    }


def test_strix_caido_bootstrap_records_source_call_and_final_shell_envelope() -> None:
    bootstrap = _fixture()["caido"]["bootstrap_exec"]
    assert bootstrap["proof_level"] == "exact_source_plus_artifact_transform_capture"
    assert bootstrap["upstream_call"] == {
        "proof_level": "exact_source_derived",
        "boundary": "Strix source to BaseSandboxSession.exec inside the sandbox",
        "argv": [
            "curl",
            "-fsS",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}',
            "http://127.0.0.1:48080/graphql",
        ],
        "timeout_seconds": 15.0,
    }
    assert bootstrap["session_exec"] == {
        "proof_level": "exact_artifact_import_capture",
        "boundary": "BaseSandboxSession to ControlledSandboxSession._exec_internal",
        "argv": [
            "sh",
            "-lc",
            "curl -fsS -X POST -H 'Content-Type: application/json' -d '{\"query\":\"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }\"}' http://127.0.0.1:48080/graphql",
        ],
        "timeout_seconds": 15.0,
    }
    assert {
        key: bootstrap[key]
        for key in (
            "maximum_attempts",
            "destination_is_fixed_sandbox_loopback",
            "destination_is_model_selectable",
            "container_port_profile_bound",
            "generic_curl_authority",
            "traverses_host_caido_relay",
        )
    } == {
        "maximum_attempts": 10,
        "destination_is_fixed_sandbox_loopback": True,
        "destination_is_model_selectable": False,
        "container_port_profile_bound": True,
        "generic_curl_authority": False,
        "traverses_host_caido_relay": False,
    }
    assert bootstrap["upstream_call"]["argv"].count("http://127.0.0.1:48080/graphql") == 1
    assert bootstrap["session_exec"]["argv"][:2] == ["sh", "-lc"]
    assert bootstrap["retry_backoff_seconds"] == [2.0, 4.0, 6.0] + [8.0] * 7


def test_caido_sdk_request_grammar_retains_required_defaults_and_auth_boundary() -> None:
    caido = _fixture()["caido"]
    health = caido["health"]
    assert (health["method"], health["target"], health["body"]) == ("GET", "/health", None)
    assert health["traffic_origin"] == (
        "host-side SDK through the resolved controller loopback relay"
    )
    assert health["required_headers"] == {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Host": "<controller-loopback-authority>",
        "User-Agent": "Python/3.12 aiohttp/3.14.5",
    }
    assert "Authorization" in health["forbidden_headers"]
    assert health["captured_user_agent"] == "Python/3.13 aiohttp/3.14.5"
    assert health["response_contract"] == {
        "name": "<string>",
        "version": "<string>",
        "ready": True,
    }
    assert health["readiness"] == {
        "request_timeout_ms": 5000,
        "maximum_attempts": 5,
        "retry_interval_ms": 5000,
        "authentication_occurs_after_ready": True,
    }

    graphql = caido["graphql"]
    assert (graphql["method"], graphql["target"]) == ("POST", "/graphql")
    assert graphql["traffic_origin"] == health["traffic_origin"]
    assert graphql["required_headers"]["Authorization"] == "Bearer <attempt-local-token>"
    assert graphql["required_headers"]["Accept"] == "*/*"
    assert graphql["required_headers"]["Accept-Encoding"] == "gzip, deflate"
    assert graphql["required_dynamic_headers"] == ["Content-Length"]
    assert graphql["captured_user_agent"] == "Python/3.13 aiohttp/3.14.5"
    assert {item["name"] for item in graphql["operations"]} == {
        "CreateProject",
        "SelectProject",
    }
    assert graphql["operations"][0]["variables"] == {
        "input": {"name": "sandbox", "temporary": True}
    }
    assert graphql["operations"][1]["variables"] == {"id": "<returned-project-id>"}
    assert set(graphql["forbidden_headers"]) >= {
        "Connection",
        "Proxy-Authorization",
        "Upgrade",
        "X-Forwarded-For",
        "X-Forwarded-Host",
    }
    assert graphql["header_order_significant"] is False
    assert graphql["json_member_order_significant"] is False


def test_launch_fixture_matches_the_current_controller_plan_and_backend_selection(
    tmp_path: Path,
) -> None:
    fixture = _fixture()["launch"]
    plan = _launch(tmp_path)
    argv = list(plan.argv)
    normalized_argv = list(argv)
    normalized_argv[0] = "<reviewed-executable>"
    normalized_argv[normalized_argv.index("--target") + 1] = "<admitted-target>"
    normalized_argv[normalized_argv.index("--instruction-file") + 1] = (
        "<attempt-private-objective-file>"
    )
    normalized_argv[normalized_argv.index("--config") + 1] = "<attempt-private-cli-config>"
    normalized_argv[normalized_argv.index("--mcp-config") + 1] = "<attempt-private-mcp-config>"
    normalized_argv[normalized_argv.index("--max-turns") + 1] = "<positive-turn-limit>"
    normalized_argv[normalized_argv.index("--max-budget") + 1] = "<finite-usd-limit>"
    assert normalized_argv == fixture["argv_template"]
    provider = fixture["provider_environment"]["controller_launch"]
    assert plan.required_secret_environment == (provider["one_use_secret"],)
    environment = plan.environment_dict()
    assert provider["model"] in environment
    assert provider["api_type"] in environment
    assert provider["api_base"] in environment
    assert provider["one_use_secret"] not in environment
    assert fixture["provider_environment"]["upstream_process_local_aliases"] == {
        "api_type": ["STRIX_API_TYPE", "STRIX_FORCE_API"],
        "api_key": ["LLM_API_KEY", "OPENAI_API_KEY"],
        "api_base": [
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
        ],
    }
    assert (
        environment["STRIX_RUNTIME_BACKEND"]
        == fixture["controlled_backend"]["current_adapter_value_at_capture"]
    )
    assert fixture["controlled_backend"] == {
        "required_value": strix_controlled_bootstrap._BACKEND,
        "current_adapter_value_at_capture": strix_controlled_bootstrap._BACKEND,
        "compatible": True,
        "reason": "The adapter selects the registered controlled backend; this source-derived fixture does not prove the controller transport or a qualified installed launch.",
    }
    assert json.loads(Path(argv[argv.index("--config") + 1]).read_text(encoding="utf-8")) == {
        "env": {}
    }
    assert json.loads(Path(argv[argv.index("--mcp-config") + 1]).read_text(encoding="utf-8")) == []
    objective = Path(argv[argv.index("--instruction-file") + 1]).read_bytes()
    assert objective == b"Assess only the admitted generated target.\n"
