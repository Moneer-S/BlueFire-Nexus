import os
import hashlib
import secrets
from typing import Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..core.logger import get_logger

logger = get_logger(__name__)

class SecurityManager:
    """Manages security-related operations for BlueFire-Nexus."""
    
    def __init__(self):
        self.key = None
        self.fernet = None
        self.aesgcm = None
    
    def generate_key(self, password: Optional[str] = None) -> bytes:
        """
        Generate a secure encryption key.
        
        Args:
            password: Optional password to derive key from
            
        Returns:
            bytes: Generated key
        """
        if password:
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        else:
            key = Fernet.generate_key()
        
        self.key = key
        self.fernet = Fernet(key)
        self.aesgcm = AESGCM(key)
        
        return key
    
    def encrypt(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-GCM.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Tuple[bytes, bytes]: (nonce, ciphertext)
        """
        if not self.aesgcm:
            raise ValueError("Key not initialized")
        
        nonce = secrets.token_bytes(12)
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        
        return nonce, ciphertext
    
    def decrypt(self, nonce: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt data using AES-GCM.
        
        Args:
            nonce: Nonce used for encryption
            ciphertext: Encrypted data
            
        Returns:
            bytes: Decrypted data
        """
        if not self.aesgcm:
            raise ValueError("Key not initialized")
        
        return self.aesgcm.decrypt(nonce, ciphertext, None)
    
    def hash_file(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            str: File hash
        """
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def verify_file_integrity(self, file_path: str, expected_hash: str) -> bool:
        """
        Verify file integrity using SHA-256 hash.
        
        Args:
            file_path: Path to file
            expected_hash: Expected SHA-256 hash
            
        Returns:
            bool: True if hash matches, False otherwise
        """
        actual_hash = self.hash_file(file_path)
        return actual_hash == expected_hash
    
    def secure_delete(self, file_path: str, passes: int = 3) -> bool:
        """
        Securely delete a file by overwriting it multiple times.
        
        Args:
            file_path: Path to file
            passes: Number of overwrite passes
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            file_size = os.path.getsize(file_path)
            
            for _ in range(passes):
                with open(file_path, "wb") as f:
                    f.write(secrets.token_bytes(file_size))
            
            os.remove(file_path)
            return True
        except Exception as e:
            logger.error(f"Error during secure delete: {e}")
            return False

# Create global security instance
security = SecurityManager() 