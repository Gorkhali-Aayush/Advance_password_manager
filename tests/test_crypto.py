"""
Unittest: Cryptography Module
=============================

Tests for FernetEngine encryption/decryption functionality.
Uses unittest with setUp() method pattern.

Run with: python -m unittest tests.unitTestCrypto
or: python tests/unitTestCrypto.py
"""

import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from crypto.fernetEngine import FernetEngine
from crypto.encryptionBase import EncryptionEngine


class TestFernetEngine(unittest.TestCase):
    """Test Fernet encryption engine."""
    
    def setUp(self):
        """Initialize test fixtures before each test method."""
        self.engine = FernetEngine()
        self.test_password = "test_password_123"
        self.test_data = "sensitive_data"
    
    def tearDown(self):
        """Clean up after each test method."""
        self.engine = None
    
    # ===== Salt Generation Tests =====
    def test_generate_salt_returns_bytes(self):
        """Test that generate_salt returns bytes."""
        salt = self.engine.generate_salt()
        self.assertIsInstance(salt, bytes)
    
    def test_generate_salt_correct_length(self):
        """Test that salt has correct length (32 bytes)."""
        salt = self.engine.generate_salt()
        self.assertEqual(len(salt), 32)
    
    def test_generate_salt_uniqueness(self):
        """Test that each salt generated is unique."""
        salt1 = self.engine.generate_salt()
        salt2 = self.engine.generate_salt()
        self.assertNotEqual(salt1, salt2)
    
    # ===== Key Derivation Tests =====
    def test_derive_key_returns_bytes(self):
        """Test that derive_key returns bytes."""
        salt = self.engine.generate_salt()
        key = self.engine.derive_key(self.test_password, salt)
        self.assertIsInstance(key, bytes)
    
    def test_derive_key_deterministic(self):
        """Test that same password + salt produces same key."""
        salt = self.engine.generate_salt()
        key1 = self.engine.derive_key(self.test_password, salt)
        key2 = self.engine.derive_key(self.test_password, salt)
        self.assertEqual(key1, key2)
    
    def test_derive_key_different_passwords(self):
        """Test that different passwords produce different keys."""
        salt = self.engine.generate_salt()
        key1 = self.engine.derive_key("password1", salt)
        key2 = self.engine.derive_key("password2", salt)
        self.assertNotEqual(key1, key2)
    
    def test_derive_key_different_salts(self):
        """Test that different salts produce different keys."""
        salt1 = self.engine.generate_salt()
        salt2 = self.engine.generate_salt()
        key1 = self.engine.derive_key(self.test_password, salt1)
        key2 = self.engine.derive_key(self.test_password, salt2)
        self.assertNotEqual(key1, key2)
    
    # ===== Encryption Tests =====
    def test_encrypt_returns_bytes(self):
        """Test that encrypt returns bytes."""
        salt = self.engine.generate_salt()
        key = self.engine.derive_key(self.test_password, salt)
        ciphertext = self.engine.encrypt(self.test_data, key)
        self.assertIsInstance(ciphertext, bytes)
    
    def test_encrypt_produces_different_ciphertexts(self):
        """Test that encryption produces different ciphertexts (due to IV)."""
        salt = self.engine.generate_salt()
        key = self.engine.derive_key(self.test_password, salt)
        ciphertext1 = self.engine.encrypt(self.test_data, key)
        ciphertext2 = self.engine.encrypt(self.test_data, key)
        self.assertNotEqual(ciphertext1, ciphertext2)
    
    def test_encrypt_empty_string(self):
        """Test encrypting empty string."""
        salt = self.engine.generate_salt()
        key = self.engine.derive_key(self.test_password, salt)
        ciphertext = self.engine.encrypt("", key)
        self.assertIsNotNone(ciphertext)
    
    def test_encrypt_unicode_data(self):
        """Test encrypting unicode data."""
        salt = self.engine.generate_salt()
        key = self.engine.derive_key(self.test_password, salt)
        unicode_data = "Hello 世界 🌍"
        ciphertext = self.engine.encrypt(unicode_data, key)
        self.assertIsNotNone(ciphertext)
    
    # ===== Decryption Tests =====
    def test_decrypt_returns_plaintext(self):
        """Test that decrypt returns original plaintext."""
        salt = self.engine.generate_salt()
        key = self.engine.derive_key(self.test_password, salt)
        ciphertext = self.engine.encrypt(self.test_data, key)
        decrypted = self.engine.decrypt(ciphertext, key)
        self.assertEqual(decrypted, self.test_data)
    
    def test_decrypt_empty_string(self):
        """Test decrypting empty string."""
        salt = self.engine.generate_salt()
        key = self.engine.derive_key(self.test_password, salt)
        ciphertext = self.engine.encrypt("", key)
        decrypted = self.engine.decrypt(ciphertext, key)
        self.assertEqual(decrypted, "")
    
    def test_decrypt_unicode_data(self):
        """Test decrypting unicode data."""
        salt = self.engine.generate_salt()
        key = self.engine.derive_key(self.test_password, salt)
        unicode_data = "密码🔐пароль"
        ciphertext = self.engine.encrypt(unicode_data, key)
        decrypted = self.engine.decrypt(ciphertext, key)
        self.assertEqual(decrypted, unicode_data)
    
    def test_decrypt_wrong_key_returns_none(self):
        """Test that wrong key returns None."""
        salt = self.engine.generate_salt()
        key1 = self.engine.derive_key("password1", salt)
        key2 = self.engine.derive_key("password2", salt)
        ciphertext = self.engine.encrypt(self.test_data, key1)
        decrypted = self.engine.decrypt(ciphertext, key2)
        self.assertIsNone(decrypted)
    
    def test_decrypt_tampered_ciphertext_returns_none(self):
        """Test that tampered ciphertext returns None."""
        salt = self.engine.generate_salt()
        key = self.engine.derive_key(self.test_password, salt)
        ciphertext = self.engine.encrypt(self.test_data, key)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[10] = (tampered[10] + 1) % 256
        tampered = bytes(tampered)
        
        decrypted = self.engine.decrypt(tampered, key)
        self.assertIsNone(decrypted)
    
    def test_decrypt_invalid_ciphertext_returns_none(self):
        """Test that invalid ciphertext returns None."""
        salt = self.engine.generate_salt()
        key = self.engine.derive_key(self.test_password, salt)
        invalid_ciphertext = b"not_valid_ciphertext"
        decrypted = self.engine.decrypt(invalid_ciphertext, key)
        self.assertIsNone(decrypted)
    
    # ===== Password Hashing Tests =====
    def test_hash_password_returns_string(self):
        """Test that hash_password returns string."""
        salt = self.engine.generate_salt()
        hash_result = self.engine.hash_password(self.test_password, salt)
        self.assertIsInstance(hash_result, str)
    
    def test_hash_password_deterministic(self):
        """Test that same password + salt produces same hash."""
        salt = self.engine.generate_salt()
        hash1 = self.engine.hash_password(self.test_password, salt)
        hash2 = self.engine.hash_password(self.test_password, salt)
        self.assertEqual(hash1, hash2)
    
    def test_hash_password_different_passwords(self):
        """Test that different passwords produce different hashes."""
        salt = self.engine.generate_salt()
        hash1 = self.engine.hash_password("password1", salt)
        hash2 = self.engine.hash_password("password2", salt)
        self.assertNotEqual(hash1, hash2)
    
    # ===== Password Verification Tests =====
    def test_verify_password_correct(self):
        """Test verification with correct password."""
        salt = self.engine.generate_salt()
        password_hash = self.engine.hash_password(self.test_password, salt)
        is_valid = self.engine.verify_password(self.test_password, salt, password_hash)
        self.assertTrue(is_valid)
    
    def test_verify_password_incorrect(self):
        """Test verification with incorrect password."""
        salt = self.engine.generate_salt()
        password_hash = self.engine.hash_password(self.test_password, salt)
        is_valid = self.engine.verify_password("wrong_password", salt, password_hash)
        self.assertFalse(is_valid)
    
    # ===== Integration Tests =====
    def test_full_encryption_workflow(self):
        """Test complete encryption/decryption workflow."""
        # Generate salt
        salt = self.engine.generate_salt()
        self.assertIsNotNone(salt)
        
        # Derive key
        key = self.engine.derive_key(self.test_password, salt)
        self.assertIsNotNone(key)
        
        # Encrypt
        ciphertext = self.engine.encrypt(self.test_data, key)
        self.assertIsNotNone(ciphertext)
        
        # Decrypt
        decrypted = self.engine.decrypt(ciphertext, key)
        self.assertEqual(decrypted, self.test_data)
    
    def test_multiple_credentials_encryption(self):
        """Test encrypting multiple pieces of data with same key."""
        salt = self.engine.generate_salt()
        key = self.engine.derive_key(self.test_password, salt)
        
        data_list = ["credential1", "credential2", "credential3"]
        encrypted_list = []
        
        for data in data_list:
            encrypted = self.engine.encrypt(data, key)
            encrypted_list.append(encrypted)
        
        # Verify all were encrypted
        self.assertEqual(len(encrypted_list), 3)
        
        # Verify decryption works for all
        for i, encrypted in enumerate(encrypted_list):
            decrypted = self.engine.decrypt(encrypted, key)
            self.assertEqual(decrypted, data_list[i])


class TestEncryptionEngineInterface(unittest.TestCase):
    """Test that FernetEngine implements EncryptionEngine correctly."""
    
    def setUp(self):
        """Initialize test objects."""
        self.engine = FernetEngine()
    
    def test_is_instance_of_encryption_engine(self):
        """Test that FernetEngine is instance of EncryptionEngine."""
        self.assertIsInstance(self.engine, EncryptionEngine)
    
    def test_has_all_required_methods(self):
        """Test that all required methods are present."""
        required_methods = [
            'derive_key',
            'encrypt',
            'decrypt',
            'hash_password',
            'verify_password',
            'generate_salt'
        ]
        
        for method in required_methods:
            self.assertTrue(hasattr(self.engine, method))
            self.assertTrue(callable(getattr(self.engine, method)))


if __name__ == '__main__':
    # Run with: python -m unittest tests.unitTestCrypto
    # or: python tests/unitTestCrypto.py
    unittest.main(verbosity=2)
