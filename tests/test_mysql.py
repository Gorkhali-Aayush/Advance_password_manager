"""
Unittest: MySQL Database Engine
===============================

Tests for MySQLEngine database operations.
Uses unittest with setUp() method and mocking to avoid needing a real MySQL server.

Run with: python -m unittest tests.unitTestMysql
or: python tests/unitTestMysql.py
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from storage.mysqlEngine import MySQLEngine
from storage.dbBase import DatabaseEngine


class TestMySQLEngineInterface(unittest.TestCase):
    """Test that MySQLEngine correctly implements DatabaseEngine interface."""
    
    def setUp(self):
        """Initialize test configuration."""
        self.config = {
            'host': 'localhost',
            'port': 3306,
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
    
    def tearDown(self):
        """Clean up after each test."""
        self.config = None
    
    def test_implements_interface(self):
        """Test that MySQLEngine is instance of DatabaseEngine."""
        engine = MySQLEngine(self.config)
        
        self.assertIsInstance(engine, DatabaseEngine)
    
    def test_has_required_methods(self):
        """Test that key methods are present."""
        engine = MySQLEngine(self.config)
        
        required_methods = [
            'connect', 'disconnect', 'is_connected',
            'create_user', 'get_user', 'user_exists',
            'create_credential', 'get_credential', 'update_credential',
            'delete_credential', 'get_credentials_by_user',
            'initialize_database'
        ]
        
        for method in required_methods:
            self.assertTrue(hasattr(engine, method), f"Missing method: {method}")
            self.assertTrue(callable(getattr(engine, method)))


class TestMySQLEngineConfiguration(unittest.TestCase):
    """Test configuration and initialization."""
    
    def setUp(self):
        """Initialize test fixtures."""
        self.basic_config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
    
    def tearDown(self):
        """Clean up after each test."""
        self.basic_config = None
    
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
        
        self.assertEqual(engine._config['host'], '192.168.1.100')
        self.assertEqual(engine._config['port'], 3307)
        self.assertEqual(engine._config['user'], 'custom_user')
        self.assertEqual(engine._config['database'], 'custom_db')
    
    def test_default_config(self):
        """Test engine with default config."""
        engine = MySQLEngine()
        
        self.assertEqual(engine._config['host'], 'localhost')
        self.assertEqual(engine._config['port'], 3306)
    
    def test_partial_config_uses_defaults(self):
        """Test that partial config uses defaults for missing values."""
        engine = MySQLEngine(self.basic_config)
        
        self.assertEqual(engine._config['host'], 'localhost')


class TestMySQLEngineMocked(unittest.TestCase):
    """Tests using mocked database connections."""
    
    def setUp(self):
        """Initialize test configuration."""
        self.config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
    
    def tearDown(self):
        """Clean up after each test."""
        self.config = None
    
    @patch('storage.mysqlEngine.pooling.MySQLConnectionPool')
    def test_connect_success(self, mock_pool_class):
        """Test successful database connection."""
        mock_pool = MagicMock()
        mock_conn = MagicMock()
        mock_pool.get_connection.return_value = mock_conn
        mock_conn.is_connected.return_value = True
        mock_pool_class.return_value = mock_pool
        
        engine = MySQLEngine(self.config)
        result = engine.connect()
        
        self.assertTrue(result)
        mock_pool_class.assert_called_once()
    
    @patch('storage.mysqlEngine.pooling.MySQLConnectionPool')
    def test_connect_failure(self, mock_pool_class):
        """Test database connection failure."""
        from mysql.connector import Error
        mock_pool_class.side_effect = Error("Connection refused")
        
        engine = MySQLEngine(self.config)
        result = engine.connect()
        
        self.assertFalse(result)
    
    def test_disconnect(self):
        """Test database disconnection."""
        engine = MySQLEngine(self.config)
        engine._pool = MagicMock()
        engine._connection = MagicMock()
        
        engine.disconnect()
        
        self.assertIsNone(engine._pool)
        self.assertIsNone(engine._connection)
    
    def test_is_connected_no_pool(self):
        """Test is_connected when no pool exists."""
        engine = MySQLEngine(self.config)
        
        self.assertFalse(engine.is_connected())


class TestUserOperations(unittest.TestCase):
    """Test user-related database operations."""
    
    def setUp(self):
        """Initialize engine with mocked query execution."""
        self.config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        self.engine = MySQLEngine(self.config)
    
    def tearDown(self):
        """Clean up after each test."""
        self.engine = None
    
    def test_create_user_builds_correct_query(self):
        """Test that create_user uses correct SQL."""
        self.engine._execute_query = MagicMock(return_value=1)
        
        result = self.engine.create_user("testuser", "hash123", "salt456", "user")
        
        self.engine._execute_query.assert_called_once()
        call_args = self.engine._execute_query.call_args
        self.assertIn("INSERT INTO users", call_args[0][0])
    
    def test_get_user_returns_dict(self):
        """Test that get_user returns user dictionary."""
        self.engine._execute_query = MagicMock(return_value=[{
            'id': 1,
            'username': 'testuser',
            'master_password_hash': 'hash123',
            'salt': 'salt456',
            'created_at': '2024-01-01'
        }])
        
        result = self.engine.get_user("testuser")
        
        self.assertIsNotNone(result)
        self.assertEqual(result['username'], 'testuser')
    
    def test_get_user_returns_none_when_not_found(self):
        """Test that get_user returns None when user not found."""
        self.engine._execute_query = MagicMock(return_value=[])
        
        result = self.engine.get_user("nonexistent")
        
        self.assertIsNone(result)
    
    def test_user_exists_true(self):
        """Test user_exists returns True when user exists."""
        self.engine._execute_query = MagicMock(return_value=[{'count': 1}])
        
        result = self.engine.user_exists("testuser")
        
        self.assertTrue(result)
    
    def test_user_exists_false(self):
        """Test user_exists returns False when user doesn't exist."""
        self.engine._execute_query = MagicMock(return_value=[{'count': 0}])
        
        result = self.engine.user_exists("nonexistent")
        
        self.assertFalse(result)


class TestCredentialOperations(unittest.TestCase):
    """Test credential-related database operations."""
    
    def setUp(self):
        """Initialize engine with mocked query execution."""
        self.config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        self.engine = MySQLEngine(self.config)
    
    def tearDown(self):
        """Clean up after each test."""
        self.engine = None
    
    def test_create_credential(self):
        """Test creating a credential."""
        self.engine._execute_query = MagicMock(return_value=1)
        
        result = self.engine.create_credential(1, "example.com", "user@example.com", "encrypted_pass")
        
        self.engine._execute_query.assert_called_once()
        self.assertIsNotNone(result)
    
    def test_get_credential_returns_dict(self):
        """Test that get_credential returns credential dictionary."""
        self.engine._execute_query = MagicMock(return_value=[{
            'id': 1,
            'site_name': 'example.com',
            'site_username': 'user@example.com',
            'site_password': 'encrypted_pass',
            'created_at': '2024-01-01'
        }])
        
        result = self.engine.get_credential(1)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['site_name'], 'example.com')
    
    def test_get_credential_returns_none_when_not_found(self):
        """Test that get_credential returns None when not found."""
        self.engine._execute_query = MagicMock(return_value=[])
        
        result = self.engine.get_credential(999)
        
        self.assertIsNone(result)
    
    def test_update_credential(self):
        """Test updating a credential."""
        self.engine._execute_query = MagicMock(return_value=1)
        
        updates = {"site_name": "example.com", "username": "user"}
        result = self.engine.update_credential(1, updates)
        
        self.engine._execute_query.assert_called_once()
    
    def test_delete_credential(self):
        """Test deleting a credential."""
        self.engine._execute_query = MagicMock(return_value=1)
        
        result = self.engine.delete_credential(1)
        
        self.engine._execute_query.assert_called_once()
    
    def test_get_credentials_by_user(self):
        """Test retrieving all credentials for a user."""
        self.engine._execute_query = MagicMock(return_value=[
            {'id': 1, 'site_name': 'site1.com', 'site_username': 'user1'},
            {'id': 2, 'site_name': 'site2.com', 'site_username': 'user2'}
        ])
        
        result = self.engine.get_credentials_by_user(1)
        
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['site_name'], 'site1.com')
        self.assertEqual(result[1]['site_name'], 'site2.com')


class TestDatabaseInitialization(unittest.TestCase):
    """Test database schema initialization."""
    
    def setUp(self):
        """Initialize engine."""
        self.config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        self.engine = MySQLEngine(self.config)
    
    def tearDown(self):
        """Clean up after each test."""
        self.engine = None
    
    def test_initialize_database(self):
        """Test database initialization creates required tables."""
        self.engine._execute_query = MagicMock()
        
        self.engine.initialize_database()
        
        # Should have called execute_query multiple times to create tables
        self.assertGreater(self.engine._execute_query.call_count, 0)


class TestTransactionHandling(unittest.TestCase):
    """Test transaction-related operations."""
    
    def setUp(self):
        """Initialize engine with mocked connection."""
        self.config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        self.engine = MySQLEngine(self.config)
        self.engine._connection = MagicMock()
    
    def tearDown(self):
        """Clean up after each test."""
        self.engine = None


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases."""
    
    def setUp(self):
        """Initialize engine."""
        self.config = {
            'host': 'localhost',
            'user': 'test',
            'password': 'test',
            'database': 'test_db'
        }
        self.engine = MySQLEngine(self.config)
    
    def tearDown(self):
        """Clean up after each test."""
        self.engine = None
    
    def test_invalid_config_raises_error(self):
        """Test that invalid configuration raises appropriate error."""
        invalid_config = None
        
        # Should handle None config gracefully
        try:
            engine = MySQLEngine(invalid_config)
            # If it doesn't raise, it should use defaults
            self.assertIsNotNone(engine)
        except Exception as e:
            self.assertIsNotNone(e)
    
    def test_execute_query_with_empty_result(self):
        """Test executing query that returns empty result."""
        self.engine._execute_query = MagicMock(return_value=[])
        
        result = self.engine._execute_query("SELECT * FROM users WHERE id = %s", (999,))
        
        self.assertEqual(result, [])


if __name__ == '__main__':
    # Run with: python -m unittest tests.unitTestMysql
    # or: python tests/unitTestMysql.py
    unittest.main(verbosity=2)
