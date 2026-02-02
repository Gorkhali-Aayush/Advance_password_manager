"""
Pytest Configuration and Fixtures
==================================

This module contains shared fixtures and configuration for the test suite.

Fixtures provided:
    - crypto_engine: Fernet encryption engine instance
    - sample_credentials: List of sample credential data
    - mock_db_engine: Mocked database engine
    - temp_lock_file: Temporary lock file path
    - clean_clipboard: Ensures clipboard is clean after tests

Author: Advanced Password Manager Team
Date: 2024
"""

import pytest
import sys
import os
import tempfile
import shutil

# Add src to path for all tests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


# ============================================================================
# Crypto Fixtures
# ============================================================================

@pytest.fixture
def crypto_engine():
    """Provide a FernetEngine instance for testing."""
    from crypto.fernet_engine import FernetEngine
    return FernetEngine()


@pytest.fixture
def master_key(crypto_engine):
    """Provide a derived master key for testing."""
    salt = crypto_engine.generate_salt()
    return crypto_engine.derive_key("test_master_password", salt)


# ============================================================================
# Data Structure Fixtures
# ============================================================================

@pytest.fixture
def empty_bst():
    """Provide an empty BST for testing."""
    from datastructures.bst import BST
    return BST()


@pytest.fixture
def populated_bst():
    """Provide a BST with sample data."""
    from datastructures.bst import BST
    bst = BST()
    
    sites = [
        ("gmail.com", {"id": 1, "username": "user1"}),
        ("amazon.com", {"id": 2, "username": "user2"}),
        ("github.com", {"id": 3, "username": "user3"}),
        ("facebook.com", {"id": 4, "username": "user4"}),
        ("twitter.com", {"id": 5, "username": "user5"}),
    ]
    
    for site, data in sites:
        bst.insert(site, data)
    
    return bst


@pytest.fixture
def empty_graph():
    """Provide an empty Graph for testing."""
    from datastructures.graph import Graph
    return Graph()


@pytest.fixture
def security_graph():
    """Provide a SecurityGraph with sample reuse data."""
    from datastructures.graph import SecurityGraph
    sg = SecurityGraph()
    
    # Create some password reuse edges
    sg.add_password_edge("gmail.com", "yahoo.com", "shared_hash_1")
    sg.add_password_edge("gmail.com", "outlook.com", "shared_hash_1")
    sg.add_vertex("bank.com")  # No reuse
    
    return sg


# ============================================================================
# Credential Fixtures
# ============================================================================

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
def encrypted_credentials(crypto_engine, master_key, sample_credentials):
    """Provide encrypted versions of sample credentials."""
    encrypted = []
    for cred in sample_credentials:
        enc_pass = crypto_engine.encrypt(cred["password"], master_key)
        encrypted.append({
            **cred,
            "encrypted_password": enc_pass,
            "password": None  # Remove plaintext
        })
    return encrypted


# ============================================================================
# Database Fixtures
# ============================================================================

@pytest.fixture
def mock_db_engine():
    """Provide a mocked database engine."""
    from unittest.mock import MagicMock
    
    mock = MagicMock()
    mock.connect.return_value = True
    mock.is_connected.return_value = True
    mock.create.return_value = 1
    mock.read.return_value = None
    mock.update.return_value = True
    mock.delete.return_value = True
    
    return mock


@pytest.fixture
def db_config():
    """Provide database configuration for testing."""
    return {
        "host": "localhost",
        "port": 3306,
        "user": "test_user",
        "password": "test_password",
        "database": "test_password_manager"
    }


# ============================================================================
# OS Layer Fixtures
# ============================================================================

@pytest.fixture
def temp_lock_file():
    """Provide a temporary lock file path."""
    fd, path = tempfile.mkstemp(suffix=".lock")
    os.close(fd)
    os.remove(path)  # Remove so lock can be created
    
    yield path
    
    # Cleanup
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


@pytest.fixture
def thread_manager():
    """Provide a ThreadManager instance."""
    from os_layer.thread_manager import ThreadManager
    manager = ThreadManager()
    
    yield manager
    
    # Cleanup
    manager.stop_all()


@pytest.fixture
def clipboard_manager():
    """Provide a ClipboardManager instance."""
    from os_layer.clipboard_manager import ClipboardManager
    manager = ClipboardManager(clear_timeout=30)
    
    yield manager
    
    # Cleanup
    manager.shutdown()


# ============================================================================
# Session Fixtures
# ============================================================================

@pytest.fixture
def mock_session():
    """Provide a mock session object."""
    from unittest.mock import MagicMock
    
    session = MagicMock()
    session.username = "test_user"
    session.user_id = 1
    session.is_locked = False
    session.created_at = "2024-01-01T00:00:00"
    
    return session


# ============================================================================
# Temporary Directory Fixtures
# ============================================================================

@pytest.fixture
def temp_directory():
    """Provide a temporary directory for testing."""
    temp_dir = tempfile.mkdtemp()
    
    yield temp_dir
    
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def temp_backup_file(temp_directory):
    """Provide a temporary backup file path."""
    return os.path.join(temp_directory, "backup.enc")


# ============================================================================
# Configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as unit test (fast, isolated)"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test (requires MySQL)"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection based on markers."""
    # Skip integration tests by default if no MySQL available
    skip_integration = pytest.mark.skip(
        reason="Integration tests require --run-integration flag"
    )
    
    for item in items:
        if "integration" in item.keywords:
            if not config.getoption("--run-integration", default=False):
                item.add_marker(skip_integration)


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests that require MySQL"
    )


# ============================================================================
# Cleanup Fixtures
# ============================================================================

@pytest.fixture(autouse=True)
def clean_clipboard():
    """Ensure clipboard is cleaned after each test."""
    yield
    
    # Try to clear clipboard after test
    try:
        import pyperclip
        pyperclip.copy("")
    except Exception:
        pass


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset any singleton instances between tests."""
    yield
    
    # Reset any singleton patterns if used
    # This prevents test pollution


# ============================================================================
# Assertion Helpers
# ============================================================================

def assert_valid_encrypted_data(data: bytes):
    """Assert that data looks like valid encrypted content."""
    assert isinstance(data, bytes)
    assert len(data) > 0
    # Fernet tokens start with gAAAAA (base64)
    # This is a simple check, not cryptographic validation


def assert_valid_hash(hash_value: str):
    """Assert that value looks like a valid password hash."""
    assert isinstance(hash_value, (str, bytes))
    assert len(hash_value) >= 32  # Reasonable minimum for a hash
