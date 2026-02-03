"""
Abstract Encryption Interface

Defines the contract for encryption engines.
Demonstrates abstraction - allows swapping encryption algorithms.
"""

from abc import ABC, abstractmethod
from typing import Optional


class EncryptionEngine(ABC):
    """
    Abstract base class for encryption implementations.
    
    Why this exists:
    - Abstraction: Hides implementation details
    - Polymorphism: Allows different encryption backends
    - Security: Centralized crypto interface
    
    Subclasses must implement:
    - encrypt(): Encrypt plaintext data
    - decrypt(): Decrypt ciphertext data
    - derive_key(): Generate key from password
    """
    
    @abstractmethod
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from a password.
        
        Uses a Key Derivation Function (KDF) like PBKDF2.
        
        Args:
            password: The master password
            salt: Random salt for key derivation
            
        Returns:
            Derived key bytes
        """
        pass
    
    @abstractmethod
    def encrypt(self, plaintext: str, key: bytes) -> bytes:
        """
        Encrypt plaintext data.
        
        Args:
            plaintext: The data to encrypt
            key: The encryption key
            
        Returns:
            Encrypted ciphertext
        """
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes) -> Optional[str]:
        """
        Decrypt ciphertext data.
        
        Args:
            ciphertext: The encrypted data
            key: The encryption key
            
        Returns:
            Decrypted plaintext, or None if decryption fails
        """
        pass
    
    @abstractmethod
    def generate_salt(self) -> bytes:
        """
        Generate a random salt for key derivation.
        
        Returns:
            Random salt bytes
        """
        pass
    
    @abstractmethod
    def hash_password(self, password: str, salt: bytes) -> str:
        """
        Create a secure hash of the password for storage.
        
        This is different from derive_key - this is for
        verifying the master password.
        
        Args:
            password: The password to hash
            salt: Salt for hashing
            
        Returns:
            Hashed password string
        """
        pass
    
    @abstractmethod
    def verify_password(self, password: str, salt: bytes, 
                        stored_hash: str) -> bool:
        """
        Verify a password against a stored hash.
        
        Args:
            password: The password to verify
            salt: The salt used during hashing
            stored_hash: The stored password hash
            
        Returns:
            True if password matches, False otherwise
        """
        pass
    
    def quick_hash(self, data: str) -> str:
        """
        Create a quick hash for comparison (e.g., password reuse detection).
        
        Not for security - just for fast comparison.
        
        Args:
            data: The data to hash
            
        Returns:
            Hash string
        """
        import hashlib
        return hashlib.sha256(data.encode()).hexdigest()
