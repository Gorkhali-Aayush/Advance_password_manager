"""
MySQL Database Engine

Implements the DatabaseEngine interface for MySQL.
Uses mysql-connector-python for database operations.
"""

import mysql.connector
from mysql.connector import Error, pooling
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from .db_base import DatabaseEngine


class MySQLEngine(DatabaseEngine):
    """
    MySQL implementation of the database engine.
    
    Features:
    - Connection pooling for performance
    - Parameterized queries (SQL injection prevention)
    - Transaction support
    - Automatic reconnection
    
    Configuration:
    - Update the DEFAULT_CONFIG for your MySQL setup
    """
    
    # Default database configuration
    # Update these values for your MySQL Workbench setup
    DEFAULT_CONFIG = {
        'host': 'localhost',
        'port': 3306,
        'user': 'root',
        'password': 'root',  # Change this!
        'database': 'password_manager',
        'pool_name': 'password_manager_pool',
        'pool_size': 5,
        'autocommit': False
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize MySQL engine.
        
        Args:
            config: Database configuration dictionary.
                    Uses DEFAULT_CONFIG if not provided.
        """
        self._config = config or self.DEFAULT_CONFIG.copy()
        self._pool: Optional[pooling.MySQLConnectionPool] = None
        self._connection = None
        self._in_transaction = False
    
    def connect(self) -> bool:
        """
        Establish connection pool to MySQL database.
        
        Returns:
            True if connection successful
        """
        try:
            # Create connection pool
            pool_config = {
                'pool_name': self._config.get('pool_name', 'default_pool'),
                'pool_size': self._config.get('pool_size', 5),
                'host': self._config['host'],
                'port': self._config.get('port', 3306),
                'user': self._config['user'],
                'password': self._config['password'],
                'database': self._config['database'],
                'autocommit': self._config.get('autocommit', False)
            }
            
            self._pool = pooling.MySQLConnectionPool(**pool_config)
            
            # Test connection
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                cursor.close()
            
            return True
            
        except Error as e:
            print(f"MySQL Connection Error: {e}")
            return False
    
    def disconnect(self) -> None:
        """Close all connections in the pool."""
        if self._connection:
            try:
                self._connection.close()
            except Error:
                pass
            self._connection = None
        self._pool = None
    
    def is_connected(self) -> bool:
        """Check if database is connected."""
        if self._pool is None:
            return False
        
        try:
            with self._get_connection() as conn:
                return conn.is_connected()
        except Error:
            return False
    
    @contextmanager
    def _get_connection(self):
        """
        Get a connection from the pool.
        
        Yields:
            MySQL connection object
        """
        connection = None
        try:
            if self._in_transaction and self._connection:
                yield self._connection
            else:
                connection = self._pool.get_connection()
                yield connection
        finally:
            if connection and not self._in_transaction:
                connection.close()
    
    def _execute_query(self, query: str, params: tuple = None,
                       fetch: bool = False) -> Any:
        """
        Execute a parameterized query.
        
        Args:
            query: SQL query with %s placeholders
            params: Query parameters
            fetch: Whether to fetch results
            
        Returns:
            Query results if fetch=True, else last row ID or row count
            
        Security: Uses parameterized queries to prevent SQL injection
        """
        with self._get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute(query, params or ())
                
                if fetch:
                    result = cursor.fetchall()
                else:
                    if not self._in_transaction:
                        conn.commit()
                    result = cursor.lastrowid or cursor.rowcount
                
                return result
            except Error as e:
                if not self._in_transaction:
                    conn.rollback()
                raise e
            finally:
                cursor.close()
    
    # ============ User Operations ============
    
    def create_user(self, username: str, password_hash: str,
                    salt: str, role: str = 'user') -> Optional[int]:
        """Create a new user account."""
        query = """
            INSERT INTO users (username, master_password_hash, salt, role)
            VALUES (%s, %s, %s, %s)
        """
        try:
            return self._execute_query(query, (username, password_hash, salt, role))
        except Error:
            return None
    
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        query = """
            SELECT id, username, master_password_hash, salt, role, created_at
            FROM users WHERE username = %s
        """
        results = self._execute_query(query, (username,), fetch=True)
        return results[0] if results else None
    
    def user_exists(self, username: str) -> bool:
        """Check if username exists."""
        query = "SELECT COUNT(*) as count FROM users WHERE username = %s"
        results = self._execute_query(query, (username,), fetch=True)
        return results[0]['count'] > 0 if results else False
    
    def update_master_password(self, user_id: int, password_hash: str,
                                salt: str) -> bool:
        """Update user's master password."""
        query = """
            UPDATE users 
            SET master_password_hash = %s, salt = %s
            WHERE id = %s
        """
        try:
            self._execute_query(query, (password_hash, salt, user_id))
            return True
        except Error:
            return False
    
    # ============ Credential Operations ============
    
    def create_credential(self, user_id: int, site_name: str,
                          username: str, encrypted_password: str,
                          url: Optional[str] = None,
                          notes: Optional[str] = None) -> Optional[int]:
        """Create a new credential entry."""
        query = """
            INSERT INTO credentials 
            (user_id, site_name, username, encrypted_password, url, notes)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        try:
            return self._execute_query(
                query, 
                (user_id, site_name, username, encrypted_password, url, notes)
            )
        except Error:
            return None
    
    def get_credential(self, credential_id: int) -> Optional[Dict[str, Any]]:
        """Get a credential by ID."""
        query = """
            SELECT id, user_id, site_name, username, encrypted_password,
                   url, notes, created_at, updated_at
            FROM credentials WHERE id = %s
        """
        results = self._execute_query(query, (credential_id,), fetch=True)
        return results[0] if results else None
    
    def get_credentials_by_user(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all credentials for a user."""
        query = """
            SELECT id, user_id, site_name, username, encrypted_password,
                   url, notes, created_at, updated_at
            FROM credentials 
            WHERE user_id = %s
            ORDER BY site_name ASC
        """
        return self._execute_query(query, (user_id,), fetch=True) or []
    
    def update_credential(self, credential_id: int,
                          updates: Dict[str, Any]) -> bool:
        """Update a credential with given fields."""
        if not updates:
            return False
        
        # Build dynamic update query
        set_clauses = []
        values = []
        
        allowed_fields = ['site_name', 'username', 'encrypted_password', 
                          'url', 'notes']
        
        for field, value in updates.items():
            if field in allowed_fields:
                set_clauses.append(f"{field} = %s")
                values.append(value)
        
        if not set_clauses:
            return False
        
        values.append(credential_id)
        query = f"""
            UPDATE credentials 
            SET {', '.join(set_clauses)}
            WHERE id = %s
        """
        
        try:
            self._execute_query(query, tuple(values))
            return True
        except Error:
            return False
    
    def delete_credential(self, credential_id: int) -> bool:
        """Delete a credential."""
        query = "DELETE FROM credentials WHERE id = %s"
        try:
            self._execute_query(query, (credential_id,))
            return True
        except Error:
            return False
    
    def search_credentials(self, user_id: int,
                           search_term: str) -> List[Dict[str, Any]]:
        """Search credentials by site name (case-insensitive)."""
        query = """
            SELECT id, user_id, site_name, username, encrypted_password,
                   url, notes, created_at, updated_at
            FROM credentials 
            WHERE user_id = %s AND site_name LIKE %s
            ORDER BY site_name ASC
        """
        search_pattern = f"%{search_term}%"
        return self._execute_query(
            query, (user_id, search_pattern), fetch=True
        ) or []
    
    # ============ Password History ============
    
    def add_password_history(self, credential_id: int,
                             encrypted_password: str) -> bool:
        """Add a password to history."""
        query = """
            INSERT INTO password_history (credential_id, encrypted_password)
            VALUES (%s, %s)
        """
        try:
            self._execute_query(query, (credential_id, encrypted_password))
            return True
        except Error:
            return False
    
    def get_password_history(self, credential_id: int) -> List[Dict[str, Any]]:
        """Get password history for a credential."""
        query = """
            SELECT id, credential_id, encrypted_password, changed_at
            FROM password_history
            WHERE credential_id = %s
            ORDER BY changed_at DESC
        """
        return self._execute_query(query, (credential_id,), fetch=True) or []
    
    # ============ Transaction Support ============
    
    def begin_transaction(self) -> None:
        """Begin a database transaction."""
        self._connection = self._pool.get_connection()
        self._connection.start_transaction()
        self._in_transaction = True
    
    def commit_transaction(self) -> None:
        """Commit the current transaction."""
        if self._connection and self._in_transaction:
            self._connection.commit()
            self._connection.close()
            self._connection = None
            self._in_transaction = False
    
    def rollback_transaction(self) -> None:
        """Rollback the current transaction."""
        if self._connection and self._in_transaction:
            self._connection.rollback()
            self._connection.close()
            self._connection = None
            self._in_transaction = False
    
    # ============ Admin Operations ============
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """Get all registered users with their credential count."""
        query = """
            SELECT 
                u.id,
                u.username,
                u.role,
                u.created_at,
                COUNT(c.id) as credential_count
            FROM users u
            LEFT JOIN credentials c ON u.id = c.user_id
            GROUP BY u.id, u.username, u.role, u.created_at
            ORDER BY u.created_at DESC
        """
        results = self._execute_query(query, fetch=True)
        return results if results else []
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        query = """
            SELECT id, username, role, created_at
            FROM users WHERE id = %s
        """
        results = self._execute_query(query, (user_id,), fetch=True)
        return results[0] if results else None
    
    def get_user_credentials_count(self, user_id: int) -> int:
        """Get count of credentials for a user."""
        query = """
            SELECT COUNT(*) as count FROM credentials WHERE user_id = %s
        """
        results = self._execute_query(query, (user_id,), fetch=True)
        return results[0]['count'] if results else 0
    
    def update_user_role(self, user_id: int, role: str) -> bool:
        """Update user role (admin or user)."""
        query = """
            UPDATE users SET role = %s WHERE id = %s
        """
        try:
            self._execute_query(query, (role, user_id))
            return True
        except Error:
            return False
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics for admin dashboard."""
        stats = {}
        
        # Total users
        result = self._execute_query("SELECT COUNT(*) as count FROM users", fetch=True)
        stats['total_users'] = result[0]['count'] if result else 0
        
        # Total credentials
        result = self._execute_query("SELECT COUNT(*) as count FROM credentials", fetch=True)
        stats['total_credentials'] = result[0]['count'] if result else 0
        
        # Admin count
        result = self._execute_query(
            "SELECT COUNT(*) as count FROM users WHERE role = 'admin'", 
            fetch=True
        )
        stats['admin_count'] = result[0]['count'] if result else 0
        
        # User count
        result = self._execute_query(
            "SELECT COUNT(*) as count FROM users WHERE role = 'user'", 
            fetch=True
        )
        stats['user_count'] = result[0]['count'] if result else 0
        
        # Password history count
        result = self._execute_query("SELECT COUNT(*) as count FROM password_history", fetch=True)
        stats['password_changes'] = result[0]['count'] if result else 0
        
        return stats
    
    # ============ Database Setup ============
    
    def initialize_database(self) -> bool:
        """
        Create database tables if they don't exist.
        
        Returns:
            True if successful
        """
        queries = [
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                master_password_hash VARCHAR(512) NOT NULL,
                salt VARCHAR(128) NOT NULL,
                role ENUM('admin', 'user') DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                site_name VARCHAR(255) NOT NULL,
                username VARCHAR(255) NOT NULL,
                encrypted_password TEXT NOT NULL,
                url VARCHAR(512),
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
                           ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS password_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                credential_id INT NOT NULL,
                encrypted_password TEXT NOT NULL,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (credential_id) REFERENCES credentials(id) 
                           ON DELETE CASCADE
            )
            """
        ]
        
        try:
            for query in queries:
                self._execute_query(query)
            return True
        except Error as e:
            print(f"Database initialization error: {e}")
            return False


# Singleton instance
_db_instance: Optional[MySQLEngine] = None


def set_database(instance: MySQLEngine) -> None:
    """
    Set the singleton database instance.
    
    Args:
        instance: The MySQLEngine instance to use globally
    """
    global _db_instance
    _db_instance = instance


def get_database() -> MySQLEngine:
    """
    Get the singleton database instance.
    
    Returns:
        The MySQLEngine instance
    """
    global _db_instance
    if _db_instance is None:
        _db_instance = MySQLEngine()
        _db_instance.connect()
    return _db_instance
