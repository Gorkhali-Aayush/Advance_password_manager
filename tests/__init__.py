"""
Advanced Password Manager - Test Suite
=======================================

This package contains the test suite for the Advanced Password Manager application.
Tests are organized by module and cover:

    - Data structures (BST, HashTable, Graph, LinkedList)
    - Cryptography (Fernet encryption, PBKDF2 key derivation)
    - Database operations (MySQL engine)
    - OS layer (threads, clipboard, file locking)
    - Core functionality (vault, credentials, sessions)
    - UI components (windows, dialogs)

Running Tests:
    pytest tests/ -v                    # Run all tests
    pytest tests/test_bst.py -v         # Run specific test file
    pytest tests/ -v --cov=src          # Run with coverage
    pytest tests/ -v -k "encryption"    # Run tests matching keyword

Test Markers:
    @pytest.mark.unit        - Unit tests (fast, isolated)
    @pytest.mark.integration - Integration tests (require MySQL)
    @pytest.mark.slow        - Slow tests

Author: Advanced Password Manager Team
Date: 2024
"""

# Test modules are imported dynamically by pytest
# No need to import them here as it can cause circular import issues

__all__ = [
    'test_bst',
    'test_graph', 
    'test_crypto',
    'test_mysql',
    'test_threads'
]
