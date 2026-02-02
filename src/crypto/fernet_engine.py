"""
Fernet Encryption Engine

Implements AES-128-CBC encryption using the cryptography library's Fernet.
Uses PBKDF2 for key derivation.
"""

import os
import base64
import hashlib
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from .encryption_base import EncryptionEngine


class FernetEngine(EncryptionEngine):
    """
    Fernet-based encryption engine.
    
    Security features:
    - AES-128-CBC encryption
    - HMAC for authentication
    - PBKDF2 with 100,000 iterations for key derivation
    - Random salt generation
    
    Why Fernet:
    - Built on cryptography library (industry standard)
    - Handles IV generation automatically
    - Provides authenticated encryption (prevents tampering)
    """
    
    # PBKDF2 iterations - higher = more secure but slower
    PBKDF2_ITERATIONS = 100_000
    
    # Salt length in bytes
    SALT_LENGTH = 32
    
    # Key length for Fernet (must be 32 bytes, base64-encoded to 44)
    KEY_LENGTH = 32
    
    def __init__(self):
        """Initialize the Fernet encryption engine."""
        self._backend = default_backend()
    
    def generate_salt(self) -> bytes:
        """
        Generate a cryptographically secure random salt.
        
        Returns:
            32 bytes of random data
        """
        return os.urandom(self.SALT_LENGTH)
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a Fernet-compatible key from password using PBKDF2.
        
        Args:
            password: The master password
            salt: Random salt (should be stored with encrypted data)
            
        Returns:
            Base64-encoded 32-byte key suitable for Fernet
            
        Security notes:
        - Uses SHA-256 as the hash function
        - 100,000 iterations slows brute-force attacks
        - Salt prevents rainbow table attacks
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=self._backend
        )
        
        # Derive key and encode for Fernet
        key = kdf.derive(password.encode('utf-8'))
        return base64.urlsafe_b64encode(key)
    
    def encrypt(self, plaintext: str, key: bytes) -> bytes:
        """
        Encrypt plaintext using Fernet (AES-128-CBC + HMAC).
        
        Args:
            plaintext: The string to encrypt
            key: Fernet-compatible key (from derive_key)
            
        Returns:
            Encrypted ciphertext bytes
            
        Security notes:
        - Fernet automatically generates random IV
        - Ciphertext includes HMAC for authentication
        - Timestamp included for token expiration (optional)
        """
        fernet = Fernet(key)
        plaintext_bytes = plaintext.encode('utf-8')
        return fernet.encrypt(plaintext_bytes)
    
    def decrypt(self, ciphertext: bytes, key: bytes) -> Optional[str]:
        """
        Decrypt ciphertext using Fernet.
        
        Args:
            ciphertext: The encrypted data
            key: Fernet-compatible key (same as used for encryption)
            
        Returns:
            Decrypted plaintext string, or None if decryption fails
            
        Security notes:
        - Verifies HMAC before decryption
        - Returns None on any error (no information leakage)
        """
        try:
            fernet = Fernet(key)
            plaintext_bytes = fernet.decrypt(ciphertext)
            return plaintext_bytes.decode('utf-8')
        except (InvalidToken, ValueError, TypeError):
            # Don't reveal why decryption failed
            return None
    
    def hash_password(self, password: str, salt: bytes) -> str:
        """
        Create a secure hash of the master password for storage.
        
        Args:
            password: The master password
            salt: Random salt
            
        Returns:
            Hex-encoded password hash
            
        Note: This is different from derive_key - this hash is stored
        in the database for password verification.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=self._backend
        )
        
        hash_bytes = kdf.derive(password.encode('utf-8'))
        return hash_bytes.hex()
    
    def verify_password(self, password: str, salt: bytes, 
                        stored_hash: str) -> bool:
        """
        Verify a password against a stored hash.
        
        Args:
            password: The password to verify
            salt: The salt used during initial hashing
            stored_hash: The stored password hash (hex string)
            
        Returns:
            True if password matches, False otherwise
            
        Security notes:
        - Uses constant-time comparison to prevent timing attacks
        """
        try:
            # Compute hash of provided password
            computed_hash = self.hash_password(password, salt)
            
            # Constant-time comparison
            return self._constant_time_compare(computed_hash, stored_hash)
        except Exception:
            return False
    
    def _constant_time_compare(self, a: str, b: str) -> bool:
        """
        Compare two strings in constant time.
        
        Prevents timing attacks by always comparing all characters.
        
        Args:
            a: First string
            b: Second string
            
        Returns:
            True if strings are equal
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0
    
    def encrypt_to_string(self, plaintext: str, key: bytes) -> str:
        """
        Encrypt and return as a base64 string (for database storage).
        
        Args:
            plaintext: The string to encrypt
            key: Encryption key
            
        Returns:
            Base64-encoded ciphertext string
        """
        ciphertext = self.encrypt(plaintext, key)
        return base64.urlsafe_b64encode(ciphertext).decode('utf-8')
    
    def decrypt_from_string(self, ciphertext_str: str, key: bytes) -> Optional[str]:
        """
        Decrypt a base64-encoded ciphertext string.
        
        Args:
            ciphertext_str: Base64-encoded ciphertext
            key: Decryption key
            
        Returns:
            Decrypted plaintext, or None if failed
        """
        try:
            ciphertext = base64.urlsafe_b64decode(ciphertext_str.encode('utf-8'))
            return self.decrypt(ciphertext, key)
        except Exception:
            return None
    
    def generate_secure_password(self, length: int = 20) -> str:
        """
        Generate a cryptographically secure VERY STRONG random password.
        
        Generates passwords that meet VERY_STRONG criteria:
        - 20+ characters (default)
        - All 4 character types (upper, lower, digits, special)
        - High uniqueness ratio
        
        Args:
            length: Desired password length (minimum 20 enforced)
            
        Returns:
            Random password string rated VERY_STRONG
        """
        import secrets
        import string
        
        # Enforce minimum length for strong passwords
        actual_length = max(length, 20)
        
        # Character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        # Use safe special characters (avoiding ambiguous ones)
        special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        
        alphabet = lowercase + uppercase + digits + special
        
        # Ensure at least 2 of each type for better distribution
        password = [
            secrets.choice(lowercase),
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(digits),
            secrets.choice(special),
            secrets.choice(special)
        ]
        
        # Fill remaining length with random characters
        password += [secrets.choice(alphabet) for _ in range(actual_length - 8)]
        
        # Shuffle to randomize positions
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)


# Singleton instance for application-wide use
_engine_instance: Optional[FernetEngine] = None


def set_encryption_engine(instance: FernetEngine) -> None:
    """
    Set the singleton encryption engine instance.
    
    Args:
        instance: The FernetEngine instance to use globally
    """
    global _engine_instance
    _engine_instance = instance


def get_encryption_engine() -> FernetEngine:
    """
    Get the singleton encryption engine instance.
    
    Returns:
        The FernetEngine instance
    """
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = FernetEngine()
    return _engine_instance
