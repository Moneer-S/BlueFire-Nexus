import os
import tempfile

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager, config
from src.core.rate_limiter import rate_limiter
from src.core.security import security


def test_security_key_generation() -> None:
    key = security.generate_key()
    assert key is not None
    assert len(key) > 0

    test_data = b"Hello, World!"
    nonce, ciphertext = security.encrypt(test_data)
    decrypted = security.decrypt(nonce, ciphertext)
    assert decrypted == test_data


def test_file_integrity() -> None:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"Test data")
        file_path = tmp.name

    try:
        initial_hash = security.hash_file(file_path)
        assert initial_hash is not None
        assert len(initial_hash) == 64
        assert security.verify_file_integrity(file_path, initial_hash)

        with open(file_path, "ab") as handle:
            handle.write(b"Modified")

        assert not security.verify_file_integrity(file_path, initial_hash)
    finally:
        os.unlink(file_path)


def test_rate_limiter() -> None:
    client_id = "test_client"
    for _ in range(5):
        assert rate_limiter.can_proceed(client_id)
        rate_limiter.release()

    for _ in range(rate_limiter.max_concurrent):
        assert rate_limiter.can_proceed(client_id)
    assert not rate_limiter.can_proceed(client_id)

    for _ in range(rate_limiter.max_concurrent):
        rate_limiter.release()

    rate_limiter.reset(client_id)
    assert rate_limiter.can_proceed(client_id)
    rate_limiter.release()


def test_config_management(tmp_path) -> None:
    test_config = tmp_path / "config.yaml"
    cfg = ConfigManager(str(test_config))

    assert cfg.get("general.safeties.allowed_subnets") is not None
    assert cfg.get("general.safeties.auto_wipe") is False

    cfg.set("test.key", "value")
    assert cfg.get("test.key") == "value"
    cfg.save()

    reloaded = ConfigManager(str(test_config))
    assert reloaded.get("test.key") == "value"
    assert config.get("general.mode") in {"simulation", "testing", "production"}


def test_bluefire_registers_legacy_modules() -> None:
    nexus = BlueFireNexus()
    for module_name in {
        "legacy_capability_summary",
        "legacy_actor_profile",
        "legacy_apt29_research",
        "legacy_protocol_research",
        "legacy_stealth_research",
    }:
        assert module_name in nexus.modules


def test_config_manager_legacy_summary_includes_acknowledged_field(tmp_path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.stealth_pack.enabled", True)
    cfg.set("modules.legacy.stealth_pack.lab_confirmation", True)
    summary = cfg.legacy_activation_summary()
    pack = summary["packs"]["stealth_pack"]
    assert pack["enabled"] is True
    assert pack["acknowledged"] is True


def test_config_manager_legacy_summary_surfaces_pack_mode_and_active_preset(tmp_path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.active_preset", "c2-simulate")
    cfg.set("modules.legacy.c2_pack.enabled", True)
    cfg.set("modules.legacy.c2_pack.mode", "simulate")
    summary = cfg.legacy_activation_summary()
    assert summary["active_preset"] == "c2-simulate"
    assert summary["packs"]["c2_pack"]["mode"] == "simulate"
