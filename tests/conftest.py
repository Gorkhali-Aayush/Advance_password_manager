"""
Pytest Configuration and Fixtures

This module provides common fixtures for all tests.
Fixtures help avoid code duplication across test files.

Author: Advanced Password Manager Team
"""

import sys
import os
from pathlib import Path
import pytest
from unittest.mock import MagicMock

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


# ============ Crypto Fixtures ============

@pytest.fixture
def crypto_engine():
    """Provide a FernetEngine instance for testing."""
    from crypto.fernetEngine import FernetEngine
    return FernetEngine()


@pytest.fixture
def master_key(crypto_engine):
    """Provide a derived master key for testing."""
    salt = crypto_engine.generate_salt()
    return crypto_engine.derive_key("test_master_password", salt)


@pytest.fixture
def test_password():
    """Provide a test password."""
    return "TestPassword123!@#"


@pytest.fixture
def encrypted_password(crypto_engine, master_key, test_password):
    """Provide an encrypted password."""
    return crypto_engine.encrypt(test_password, master_key)


# ============ Data Structure Fixtures ============

@pytest.fixture
def empty_bst():
    """Provide an empty Binary Search Tree."""
    from datastructures.bst import BinarySearchTree
    return BinarySearchTree()


@pytest.fixture
def populated_bst(empty_bst):
    """Provide a BST with sample data."""
    bst = empty_bst
    bst.insert("amazon.com", {"username": "user@amazon.com"})
    bst.insert("github.com", {"username": "developer"})
    bst.insert("gmail.com", {"username": "user@gmail.com"})
    return bst


@pytest.fixture
def empty_hash_table():
    """Provide an empty HashTable."""
    from datastructures.hashtable import HashTable
    return HashTable()


@pytest.fixture
def security_graph():
    """Provide a SecurityGraph with sample data."""
    from datastructures.graph import SecurityGraph
    sg = SecurityGraph()
    
    # Create some password reuse edges
    sg.add_password_edge("gmail.com", "yahoo.com", "shared_hash_1")
    sg.add_password_edge("gmail.com", "outlook.com", "shared_hash_1")
    sg.add_vertex("bank.com")  # No reuse
    
    return sg


@pytest.fixture
def password_history_list():
    """Provide a PasswordHistory linked list."""
    from datastructures.linkedList import PasswordHistory
    return PasswordHistory()


# ============ Sample Data Fixtures ============

@pytest.fixture
def sample_credentials():
    """Provide sample credential data for testing."""
    return [
        {
            "id": 1,
            "website": "gmail.com",
            "username": "user@gmail.com",
            "password": "password123",
            "notes": "Personal email"
        },
        {
            "id": 2,
            "website": "amazon.com",
            "username": "shopper@email.com",
            "password": "shop_securely!",
            "notes": "Shopping account"
        },
        {
            "id": 3,
            "website": "github.com",
            "username": "developer",
            "password": "c0de_m@ster",
            "notes": "Work repository"
        },
    ]


@pytest.fixture
def sample_users():
    """Provide sample user data for testing."""
    return [
        {
            "id": 1,
            "username": "admin",
            "role": "admin",
            "created_at": "2024-01-01"
        },
        {
            "id": 2,
            "username": "user1",
            "role": "user",
            "created_at": "2024-01-02"
        },
    ]


# ============ Database Fixtures ============

@pytest.fixture
def mock_database():
    """Provide a mock database engine."""
    mock_db = MagicMock()
    mock_db.connect.return_value = True
    mock_db.is_connected.return_value = True
    mock_db.create_user.return_value = 1
    mock_db.get_user.return_value = {
        "id": 1,
        "username": "testuser",
        "master_password_hash": "hash123",
        "salt": "salt456"
    }
    return mock_db


# ============ Test Markers ============

def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "unit: Unit tests (fast, isolated)"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests (require MySQL)"
    )
    config.addinivalue_line(
        "markers", "slow: Slow tests"
    )
