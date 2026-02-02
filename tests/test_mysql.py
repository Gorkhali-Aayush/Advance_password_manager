"""
Test Suite: MySQL Database Engine
=================================

Tests for MySQLEngine database operations.
Tests use mocking to avoid needing a real MySQL server.

Author: Advanced Password Manager Team
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from storage.mysql_engine import MySQLEngine
from storage.db_base import DatabaseEngine


class TestMySQLEngineInterface:
    """Test that MySQLEngine correctly implements DatabaseEngine interface."""
    
    def test_implements_interface(self):
        """Test that MySQLEngine is instance of DatabaseEngine."""
        config = {
            'host': 'localhost',
            'port': 3306,
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        
        assert isinstance(engine, DatabaseEngine)
    
    def test_has_required_methods(self):
        """Test that key methods are present."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        
        required_methods = [
            'connect', 'disconnect', 'is_connected',
            'create_user', 'get_user', 'user_exists',
            'create_credential', 'get_credential', 'update_credential',
            'delete_credential', 'get_credentials_by_user',
            'initialize_database'
        ]
        
        for method in required_methods:
            assert hasattr(engine, method), f"Missing method: {method}"
            assert callable(getattr(engine, method))


class TestMySQLEngineConfiguration:
    """Test configuration and initialization."""
    
    def test_initialization_with_config(self):
        """Test engine initialization with config dictionary."""
        config = {
            'host': '192.168.1.100',
            'port': 3307,
            'user': 'custom_user',
            'password': 'custom_pass',
            'database': 'custom_db'
        }
        engine = MySQLEngine(config)
        
        assert engine._config['host'] == '192.168.1.100'
        assert engine._config['port'] == 3307
        assert engine._config['user'] == 'custom_user'
        assert engine._config['database'] == 'custom_db'
    
    def test_default_config(self):
        """Test engine with default config."""
        engine = MySQLEngine()
        
        assert engine._config['host'] == 'localhost'
        assert engine._config['port'] == 3306
    
    def test_partial_config_uses_defaults(self):
        """Test that partial config uses defaults for missing values."""
        config = {
            'host': 'myhost',
            'user': 'myuser',
            'password': 'mypass',
            'database': 'mydb'
        }
        engine = MySQLEngine(config)
        
        assert engine._config['host'] == 'myhost'
        # Port should be provided or use DEFAULT_CONFIG


class TestMySQLEngineMocked:
    """Tests using mocked database connections."""
    
    @patch('storage.mysql_engine.pooling.MySQLConnectionPool')
    def test_connect_success(self, mock_pool_class):
        """Test successful database connection."""
        mock_pool = MagicMock()
        mock_conn = MagicMock()
        mock_pool.get_connection.return_value = mock_conn
        mock_conn.is_connected.return_value = True
        mock_pool_class.return_value = mock_pool
        
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        
        result = engine.connect()
        
        assert result is True
        mock_pool_class.assert_called_once()
    
    @patch('storage.mysql_engine.pooling.MySQLConnectionPool')
    def test_connect_failure(self, mock_pool_class):
        """Test database connection failure."""
        from mysql.connector import Error
        mock_pool_class.side_effect = Error("Connection refused")
        
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        
        result = engine.connect()
        
        assert result is False
    
    def test_disconnect(self):
        """Test database disconnection."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._pool = MagicMock()
        engine._connection = MagicMock()
        
        engine.disconnect()
        
        assert engine._pool is None
        assert engine._connection is None
    
    def test_is_connected_no_pool(self):
        """Test is_connected when no pool exists."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        
        assert engine.is_connected() is False


class TestUserOperations:
    """Test user-related database operations."""
    
    def test_create_user_builds_correct_query(self):
        """Test that create_user uses correct SQL."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock(return_value=1)
        
        result = engine.create_user("testuser", "hash123", "salt456")
        
        engine._execute_query.assert_called_once()
        call_args = engine._execute_query.call_args
        assert "INSERT INTO users" in call_args[0][0]
        assert call_args[0][1] == ("testuser", "hash123", "salt456")
    
    def test_get_user_returns_dict(self):
        """Test that get_user returns user dictionary."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock(return_value=[{
            'id': 1,
            'username': 'testuser',
            'master_password_hash': 'hash123',
            'salt': 'salt456',
            'created_at': '2024-01-01'
        }])
        
        result = engine.get_user("testuser")
        
        assert result is not None
        assert result['username'] == 'testuser'
    
    def test_get_user_returns_none_when_not_found(self):
        """Test that get_user returns None when user not found."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock(return_value=[])
        
        result = engine.get_user("nonexistent")
        
        assert result is None
    
    def test_user_exists_true(self):
        """Test user_exists returns True when user exists."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock(return_value=[{'count': 1}])
        
        result = engine.user_exists("testuser")
        
        assert result is True
    
    def test_user_exists_false(self):
        """Test user_exists returns False when user doesn't exist."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock(return_value=[{'count': 0}])
        
        result = engine.user_exists("nonexistent")
        
        assert result is False


class TestCredentialOperations:
    """Test credential CRUD operations."""
    
    def test_create_credential(self):
        """Test creating a credential."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock(return_value=42)
        
        result = engine.create_credential(
            user_id=1,
            site_name="example.com",
            username="user@example.com",
            encrypted_password="encrypted_data",
            url="https://example.com",
            notes="Test notes"
        )
        
        assert result == 42
        engine._execute_query.assert_called_once()
    
    def test_get_credential(self):
        """Test getting a credential by ID."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock(return_value=[{
            'id': 1,
            'user_id': 1,
            'site_name': 'example.com',
            'username': 'user@example.com',
            'encrypted_password': 'encrypted_data'
        }])
        
        result = engine.get_credential(1)
        
        assert result is not None
        assert result['site_name'] == 'example.com'
    
    def test_get_credentials_by_user(self):
        """Test getting all credentials for a user."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock(return_value=[
            {'id': 1, 'site_name': 'site1.com'},
            {'id': 2, 'site_name': 'site2.com'}
        ])
        
        result = engine.get_credentials_by_user(1)
        
        assert len(result) == 2
    
    def test_update_credential(self):
        """Test updating a credential."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock()
        
        result = engine.update_credential(1, {
            'site_name': 'newsite.com',
            'notes': 'Updated notes'
        })
        
        assert result is True
        engine._execute_query.assert_called_once()
    
    def test_update_credential_empty_updates(self):
        """Test that empty updates returns False."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        
        result = engine.update_credential(1, {})
        
        assert result is False
    
    def test_update_credential_filters_invalid_fields(self):
        """Test that invalid fields are filtered out."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock()
        
        result = engine.update_credential(1, {
            'invalid_field': 'value',
            'another_invalid': 'value'
        })
        
        # Should return False since no valid fields
        assert result is False
    
    def test_delete_credential(self):
        """Test deleting a credential."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock()
        
        result = engine.delete_credential(1)
        
        assert result is True
    
    def test_search_credentials(self):
        """Test searching credentials."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock(return_value=[
            {'id': 1, 'site_name': 'gmail.com'}
        ])
        
        result = engine.search_credentials(1, "gmail")
        
        assert len(result) == 1
        assert result[0]['site_name'] == 'gmail.com'


class TestPasswordHistory:
    """Test password history operations."""
    
    def test_add_password_history(self):
        """Test adding to password history."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock()
        
        result = engine.add_password_history(1, "old_encrypted_password")
        
        assert result is True
    
    def test_get_password_history(self):
        """Test getting password history."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock(return_value=[
            {'id': 1, 'encrypted_password': 'pass1'},
            {'id': 2, 'encrypted_password': 'pass2'}
        ])
        
        result = engine.get_password_history(1)
        
        assert len(result) == 2


class TestTransactionSupport:
    """Test transaction management."""
    
    @patch('storage.mysql_engine.pooling.MySQLConnectionPool')
    def test_begin_transaction(self, mock_pool_class):
        """Test beginning a transaction."""
        mock_pool = MagicMock()
        mock_conn = MagicMock()
        mock_pool.get_connection.return_value = mock_conn
        
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._pool = mock_pool
        
        engine.begin_transaction()
        
        assert engine._in_transaction is True
        mock_conn.start_transaction.assert_called_once()
    
    def test_commit_transaction(self):
        """Test committing a transaction."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._connection = MagicMock()
        engine._in_transaction = True
        
        engine.commit_transaction()
        
        assert engine._in_transaction is False
        assert engine._connection is None
    
    def test_rollback_transaction(self):
        """Test rolling back a transaction."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._connection = MagicMock()
        engine._in_transaction = True
        
        engine.rollback_transaction()
        
        assert engine._in_transaction is False
        assert engine._connection is None


class TestDatabaseInitialization:
    """Test database schema initialization."""
    
    def test_initialize_database(self):
        """Test database initialization creates tables."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock()
        
        result = engine.initialize_database()
        
        assert result is True
        # Should be called 3 times for users, credentials, password_history
        assert engine._execute_query.call_count == 3
    
    def test_initialize_database_creates_users_table(self):
        """Test that users table is created."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        
        queries_executed = []
        def capture_query(query, *args, **kwargs):
            queries_executed.append(query)
        
        engine._execute_query = capture_query
        
        engine.initialize_database()
        
        # Check that at least one query creates the users table specifically
        users_query = [q for q in queries_executed if 'CREATE TABLE IF NOT EXISTS users' in q]
        assert len(users_query) >= 1
    
    def test_initialize_database_creates_credentials_table(self):
        """Test that credentials table is created."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        
        queries_executed = []
        def capture_query(query, *args, **kwargs):
            queries_executed.append(query)
        
        engine._execute_query = capture_query
        
        engine.initialize_database()
        
        # Check that at least one query creates the credentials table specifically
        creds_query = [q for q in queries_executed if 'CREATE TABLE IF NOT EXISTS credentials' in q]
        assert len(creds_query) >= 1


class TestSQLInjectionPrevention:
    """Test SQL injection prevention."""
    
    def test_parameterized_queries_used(self):
        """Test that parameterized queries are used."""
        config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        engine = MySQLEngine(config)
        engine._execute_query = MagicMock(return_value=[])
        
        # Try to inject SQL
        malicious_input = "'; DROP TABLE users; --"
        engine.get_user(malicious_input)
        
        # Should use parameterized query, not string concatenation
        call_args = engine._execute_query.call_args
        query = call_args[0][0]
        params = call_args[0][1]
        
        # Query should use placeholders
        assert "%s" in query
        # Malicious input should be in params, not in query
        assert malicious_input in params


class TestSingletonPattern:
    """Test singleton database instance."""
    
    def test_get_database_returns_instance(self):
        """Test that get_database returns an instance."""
        from storage.mysql_engine import get_database
        
        db = get_database()
        
        assert isinstance(db, MySQLEngine)
    
    def test_get_database_returns_same_instance(self):
        """Test that get_database returns the same instance."""
        from storage.mysql_engine import get_database
        
        db1 = get_database()
        db2 = get_database()
        
        assert db1 is db2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
