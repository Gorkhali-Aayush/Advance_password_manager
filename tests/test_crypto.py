"""
Test Suite: Cryptography Module
===============================

Tests for FernetEngine encryption/decryption functionality.
Uses Fernet (AES-128-CBC + HMAC) with PBKDF2 key derivation.

Author: Advanced Password Manager Team
"""

import pytest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from crypto.fernet_engine import FernetEngine
from crypto.encryption_base import EncryptionEngine


class TestKeyDerivation:
    """Test cases for key derivation."""
    
    def test_derive_key_deterministic(self):
        """Test that same password + salt produces same key."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key1 = engine.derive_key("password", salt)
        key2 = engine.derive_key("password", salt)
        
        assert key1 == key2
    
    def test_derive_key_different_passwords(self):
        """Test that different passwords produce different keys."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key1 = engine.derive_key("password1", salt)
        key2 = engine.derive_key("password2", salt)
        
        assert key1 != key2
    
    def test_derive_key_different_salts(self):
        """Test that different salts produce different keys."""
        engine = FernetEngine()
        
        salt1 = engine.generate_salt()
        salt2 = engine.generate_salt()
        
        key1 = engine.derive_key("password", salt1)
        key2 = engine.derive_key("password", salt2)
        
        assert key1 != key2
    
    def test_derive_key_output_format(self):
        """Test that derived key is base64-encoded bytes."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        assert isinstance(key, bytes)
        # Fernet keys are 44 bytes when base64 encoded
        assert len(key) == 44
    
    def test_derive_key_empty_password(self):
        """Test deriving key from empty password."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("", salt)
        
        assert key is not None
        assert isinstance(key, bytes)
    
    def test_derive_key_unicode_password(self):
        """Test deriving key from unicode password."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("密码🔐пароль", salt)
        
        assert key is not None
        assert isinstance(key, bytes)


class TestSaltGeneration:
    """Test cases for salt generation."""
    
    def test_generate_salt_uniqueness(self):
        """Test that generated salts are unique."""
        engine = FernetEngine()
        
        salts = set()
        for _ in range(100):
            salt = engine.generate_salt()
            assert salt not in salts
            salts.add(salt)
    
    def test_generate_salt_length(self):
        """Test that salt has correct length (32 bytes for this impl)."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        
        # Salt should be 32 bytes per SALT_LENGTH constant
        assert len(salt) == 32
    
    def test_generate_salt_type(self):
        """Test that salt is bytes type."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        
        assert isinstance(salt, bytes)


class TestEncryption:
    """Test cases for encryption operations."""
    
    def test_encrypt_returns_bytes(self):
        """Test that encryption returns bytes."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        plaintext = "secret message"
        ciphertext = engine.encrypt(plaintext, key)
        
        assert isinstance(ciphertext, bytes)
    
    def test_encrypt_different_each_time(self):
        """Test that encryption produces different ciphertext each time (IV)."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        plaintext = "secret message"
        ciphertext1 = engine.encrypt(plaintext, key)
        ciphertext2 = engine.encrypt(plaintext, key)
        
        # Due to random IV, ciphertext should differ
        assert ciphertext1 != ciphertext2
    
    def test_encrypt_empty_string(self):
        """Test encrypting empty string."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        ciphertext = engine.encrypt("", key)
        decrypted = engine.decrypt(ciphertext, key)
        
        assert decrypted == ""
    
    def test_encrypt_long_message(self):
        """Test encrypting long message."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        long_message = "A" * 100000
        ciphertext = engine.encrypt(long_message, key)
        decrypted = engine.decrypt(ciphertext, key)
        
        assert decrypted == long_message
    
    def test_encrypt_unicode(self):
        """Test encrypting unicode text."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        unicode_text = "Hello 世界 🌍 مرحبا"
        ciphertext = engine.encrypt(unicode_text, key)
        decrypted = engine.decrypt(ciphertext, key)
        
        assert decrypted == unicode_text


class TestDecryption:
    """Test cases for decryption operations."""
    
    def test_decrypt_basic(self):
        """Test basic decryption."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        plaintext = "secret message"
        ciphertext = engine.encrypt(plaintext, key)
        decrypted = engine.decrypt(ciphertext, key)
        
        assert decrypted == plaintext
    
    def test_decrypt_empty_string(self):
        """Test decrypting empty string."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        ciphertext = engine.encrypt("", key)
        decrypted = engine.decrypt(ciphertext, key)
        
        assert decrypted == ""
    
    def test_decrypt_unicode(self):
        """Test decrypting unicode text."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        original = "密码🔐пароль"
        ciphertext = engine.encrypt(original, key)
        decrypted = engine.decrypt(ciphertext, key)
        
        assert decrypted == original
    
    def test_decrypt_wrong_key_returns_none(self):
        """Test that wrong key returns None (doesn't raise exception)."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key1 = engine.derive_key("password1", salt)
        key2 = engine.derive_key("password2", salt)
        
        ciphertext = engine.encrypt("secret", key1)
        
        # Should return None with wrong key (secure failure)
        result = engine.decrypt(ciphertext, key2)
        assert result is None
    
    def test_decrypt_tampered_ciphertext_returns_none(self):
        """Test that tampered ciphertext returns None."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        ciphertext = engine.encrypt("secret", key)
        
        # Tamper with the ciphertext
        tampered = bytearray(ciphertext)
        tampered[10] = (tampered[10] + 1) % 256
        tampered = bytes(tampered)
        
        # Should return None (HMAC verification fails)
        result = engine.decrypt(tampered, key)
        assert result is None
    
    def test_decrypt_invalid_ciphertext_returns_none(self):
        """Test that invalid ciphertext returns None."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        invalid_ciphertext = b"this is not valid ciphertext"
        
        result = engine.decrypt(invalid_ciphertext, key)
        assert result is None


class TestPasswordHashing:
    """Test cases for password hashing (for master password storage)."""
    
    def test_hash_password_basic(self):
        """Test basic password hashing with salt."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        password = "my_secure_password"
        hash_result = engine.hash_password(password, salt)
        
        assert hash_result is not None
        assert isinstance(hash_result, str)
    
    def test_hash_password_deterministic(self):
        """Test that same password + salt produces same hash."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        password = "password123"
        
        hash1 = engine.hash_password(password, salt)
        hash2 = engine.hash_password(password, salt)
        
        assert hash1 == hash2
    
    def test_hash_password_different_passwords(self):
        """Test that different passwords produce different hashes."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        hash1 = engine.hash_password("password1", salt)
        hash2 = engine.hash_password("password2", salt)
        
        assert hash1 != hash2
    
    def test_hash_password_different_salts(self):
        """Test that different salts produce different hashes."""
        engine = FernetEngine()
        
        salt1 = engine.generate_salt()
        salt2 = engine.generate_salt()
        
        hash1 = engine.hash_password("password", salt1)
        hash2 = engine.hash_password("password", salt2)
        
        assert hash1 != hash2
    
    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        password = "correct_password"
        hash_result = engine.hash_password(password, salt)
        
        assert engine.verify_password(password, salt, hash_result) is True
    
    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        password = "correct_password"
        hash_result = engine.hash_password(password, salt)
        
        assert engine.verify_password("wrong_password", salt, hash_result) is False
    
    def test_hash_empty_password(self):
        """Test hashing empty password."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        hash_result = engine.hash_password("", salt)
        
        assert hash_result is not None
        assert engine.verify_password("", salt, hash_result) is True
        assert engine.verify_password("not_empty", salt, hash_result) is False
    
    def test_hash_unicode_password(self):
        """Test hashing unicode password."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        password = "密码🔐пароль"
        hash_result = engine.hash_password(password, salt)
        
        assert engine.verify_password(password, salt, hash_result) is True


class TestEncryptionEngineInterface:
    """Test that FernetEngine correctly implements EncryptionEngine interface."""
    
    def test_implements_interface(self):
        """Test that FernetEngine is instance of EncryptionEngine."""
        engine = FernetEngine()
        
        assert isinstance(engine, EncryptionEngine)
    
    def test_has_required_methods(self):
        """Test that all required methods are present."""
        engine = FernetEngine()
        
        assert hasattr(engine, 'derive_key')
        assert hasattr(engine, 'encrypt')
        assert hasattr(engine, 'decrypt')
        assert hasattr(engine, 'hash_password')
        assert hasattr(engine, 'verify_password')
        assert hasattr(engine, 'generate_salt')
        
        # All should be callable
        assert callable(engine.derive_key)
        assert callable(engine.encrypt)
        assert callable(engine.decrypt)
        assert callable(engine.hash_password)
        assert callable(engine.verify_password)
        assert callable(engine.generate_salt)


class TestCryptoIntegration:
    """Integration tests for complete encryption workflow."""
    
    def test_full_credential_encryption_workflow(self):
        """Test complete workflow of encrypting and decrypting credentials."""
        engine = FernetEngine()
        
        # Step 1: Generate salt for user
        user_salt = engine.generate_salt()
        
        # Step 2: Derive key from master password
        master_password = "MySecureMasterPassword123!"
        master_key = engine.derive_key(master_password, user_salt)
        
        # Step 3: Encrypt credential passwords
        credentials = [
            {"website": "gmail.com", "password": "gmail_pass_123"},
            {"website": "amazon.com", "password": "amazon_secure!"},
            {"website": "bank.com", "password": "b@nk1ng_p@ss"},
        ]
        
        encrypted_creds = []
        for cred in credentials:
            encrypted_pass = engine.encrypt(cred["password"], master_key)
            encrypted_creds.append({
                "website": cred["website"],
                "encrypted_password": encrypted_pass
            })
        
        # Step 4: Later, decrypt with same master password
        decrypted_key = engine.derive_key(master_password, user_salt)
        
        for i, enc_cred in enumerate(encrypted_creds):
            decrypted_pass = engine.decrypt(enc_cred["encrypted_password"], decrypted_key)
            assert decrypted_pass == credentials[i]["password"]
    
    def test_user_registration_and_login_flow(self):
        """Test user registration and login with password hashing."""
        engine = FernetEngine()
        
        # Registration
        master_password = "UserMasterPassword!"
        salt = engine.generate_salt()
        password_hash = engine.hash_password(master_password, salt)
        
        # Simulate storing in database...
        stored_hash = password_hash
        stored_salt = salt
        
        # Login - correct password
        login_attempt = "UserMasterPassword!"
        assert engine.verify_password(login_attempt, stored_salt, stored_hash) is True
        
        # Login - wrong password
        wrong_attempt = "WrongPassword!"
        assert engine.verify_password(wrong_attempt, stored_salt, stored_hash) is False
    
    def test_key_change_scenario(self):
        """Test re-encrypting data when master password changes."""
        engine = FernetEngine()
        
        # Original encryption
        old_salt = engine.generate_salt()
        old_key = engine.derive_key("old_password", old_salt)
        
        plaintext = "sensitive_data"
        ciphertext = engine.encrypt(plaintext, old_key)
        
        # User changes password
        new_salt = engine.generate_salt()
        new_key = engine.derive_key("new_password", new_salt)
        
        # Re-encrypt with new key
        decrypted = engine.decrypt(ciphertext, old_key)
        new_ciphertext = engine.encrypt(decrypted, new_key)
        
        # Verify new encryption works
        final_decrypted = engine.decrypt(new_ciphertext, new_key)
        assert final_decrypted == plaintext
        
        # Old key should not work on new ciphertext (returns None)
        result = engine.decrypt(new_ciphertext, old_key)
        assert result is None


class TestCryptoEdgeCases:
    """Test edge cases and error handling."""
    
    def test_very_long_password(self):
        """Test with very long password."""
        engine = FernetEngine()
        
        long_password = "A" * 10000
        salt = engine.generate_salt()
        
        key = engine.derive_key(long_password, salt)
        assert key is not None
    
    def test_special_characters_password(self):
        """Test password with special characters."""
        engine = FernetEngine()
        
        special_password = "!@#$%^&*()_+-=[]{}|;':\",./<>?\\"
        salt = engine.generate_salt()
        
        key = engine.derive_key(special_password, salt)
        ciphertext = engine.encrypt("test", key)
        decrypted = engine.decrypt(ciphertext, key)
        
        assert decrypted == "test"
    
    def test_binary_data_encryption(self):
        """Test encrypting binary data."""
        engine = FernetEngine()
        
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        # Binary data (as string representation)
        binary_data = bytes(range(256)).hex()
        
        ciphertext = engine.encrypt(binary_data, key)
        decrypted = engine.decrypt(ciphertext, key)
        
        assert decrypted == binary_data
    
    def test_concurrent_operations(self):
        """Test that engine is thread-safe for concurrent operations."""
        import threading
        
        engine = FernetEngine()
        salt = engine.generate_salt()
        key = engine.derive_key("password", salt)
        
        results = []
        errors = []
        
        def encrypt_decrypt():
            try:
                for i in range(10):
                    plaintext = f"message_{threading.current_thread().name}_{i}"
                    ciphertext = engine.encrypt(plaintext, key)
                    decrypted = engine.decrypt(ciphertext, key)
                    if decrypted != plaintext:
                        errors.append(f"Mismatch: {plaintext} != {decrypted}")
                results.append(True)
            except Exception as e:
                errors.append(str(e))
        
        threads = [threading.Thread(target=encrypt_decrypt) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
