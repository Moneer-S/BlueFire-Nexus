import pytest
import os
import tempfile
from src.core.security import security
from src.core.rate_limiter import rate_limiter
from src.core.config import config

def test_security_key_generation():
    """Test key generation and encryption/decryption."""
    key = security.generate_key()
    assert key is not None
    assert len(key) > 0
    
    # Test encryption/decryption
    test_data = b"Hello, World!"
    nonce, ciphertext = security.encrypt(test_data)
    decrypted = security.decrypt(nonce, ciphertext)
    assert decrypted == test_data

def test_file_integrity():
    """Test file integrity checking."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"Test data")
        file_path = f.name
    
    try:
        # Get initial hash
        initial_hash = security.hash_file(file_path)
        assert initial_hash is not None
        assert len(initial_hash) == 64  # SHA-256 produces 64 hex characters
        
        # Verify integrity
        assert security.verify_file_integrity(file_path, initial_hash)
        
        # Modify file
        with open(file_path, "ab") as f:
            f.write(b"Modified")
        
        # Verify integrity fails
        assert not security.verify_file_integrity(file_path, initial_hash)
    finally:
        os.unlink(file_path)

def test_rate_limiter():
    """Test rate limiting functionality."""
    client_id = "test_client"
    
    # Test within limits
    for _ in range(5):
        assert rate_limiter.can_proceed(client_id)
        rate_limiter.release()
    
    # Test concurrent limit
    for _ in range(rate_limiter.max_concurrent):
        assert rate_limiter.can_proceed(client_id)
    
    assert not rate_limiter.can_proceed(client_id)
    
    # Release all slots
    for _ in range(rate_limiter.max_concurrent):
        rate_limiter.release()
    
    # Reset and verify
    rate_limiter.reset(client_id)
    assert rate_limiter.can_proceed(client_id)
    rate_limiter.release()

def test_config_management():
    """Test configuration management."""
    # Test default values
    assert config.get("lab_environment.network") == "10.100.0.0/24"
    assert config.get("safeties.auto_wipe") is True
    
    # Test setting values
    config.set("test.key", "value")
    assert config.get("test.key") == "value"
    
    # Test saving and reloading
    config.save()
    new_config = config.__class__()
    assert new_config.get("test.key") == "value" 