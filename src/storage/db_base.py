"""
Abstract Database Interface

Defines the contract for database implementations.
Demonstrates abstraction - allows swapping storage backends.
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any


class DatabaseEngine(ABC):
    """
    Abstract base class for database implementations.
    
    Why this exists:
    - Abstraction: Hides database-specific code
    - Polymorphism: Could swap MySQL for SQLite, PostgreSQL, etc.
    - Testability: Easy to mock for unit tests
    
    Subclasses must implement all abstract methods.
    """
    
    @abstractmethod
    def connect(self) -> bool:
        """
        Establish database connection.
        
        Returns:
            True if connection successful, False otherwise
        """
        pass
    
    @abstractmethod
    def disconnect(self) -> None:
        """Close database connection."""
        pass
    
    @abstractmethod
    def is_connected(self) -> bool:
        """
        Check if database is connected.
        
        Returns:
            True if connected, False otherwise
        """
        pass
    
    # ============ User Operations ============
    
    @abstractmethod
    def create_user(self, username: str, password_hash: str, 
                    salt: str) -> Optional[int]:
        """
        Create a new user account.
        
        Args:
            username: Unique username
            password_hash: Hashed master password
            salt: Salt used for hashing
            
        Returns:
            User ID if created, None if failed
        """
        pass
    
    @abstractmethod
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get user by username.
        
        Args:
            username: The username to look up
            
        Returns:
            User data dictionary or None if not found
        """
        pass
    
    @abstractmethod
    def user_exists(self, username: str) -> bool:
        """
        Check if a username already exists.
        
        Args:
            username: The username to check
            
        Returns:
            True if exists, False otherwise
        """
        pass
    
    @abstractmethod
    def update_master_password(self, user_id: int, password_hash: str,
                                salt: str) -> bool:
        """
        Update user's master password.
        
        Args:
            user_id: The user's ID
            password_hash: New password hash
            salt: New salt
            
        Returns:
            True if updated, False otherwise
        """
        pass
    
    # ============ Credential Operations ============
    
    @abstractmethod
    def create_credential(self, user_id: int, site_name: str, 
                          username: str, encrypted_password: str,
                          url: Optional[str] = None,
                          notes: Optional[str] = None) -> Optional[int]:
        """
        Create a new credential entry.
        
        Args:
            user_id: Owner's user ID
            site_name: Website/service name
            username: Account username
            encrypted_password: Encrypted password
            url: Optional URL
            notes: Optional notes
            
        Returns:
            Credential ID if created, None if failed
        """
        pass
    
    @abstractmethod
    def get_credential(self, credential_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a credential by ID.
        
        Args:
            credential_id: The credential ID
            
        Returns:
            Credential data or None if not found
        """
        pass
    
    @abstractmethod
    def get_credentials_by_user(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get all credentials for a user.
        
        Args:
            user_id: The user's ID
            
        Returns:
            List of credential dictionaries
        """
        pass
    
    @abstractmethod
    def update_credential(self, credential_id: int, 
                          updates: Dict[str, Any]) -> bool:
        """
        Update a credential.
        
        Args:
            credential_id: The credential to update
            updates: Dictionary of fields to update
            
        Returns:
            True if updated, False otherwise
        """
        pass
    
    @abstractmethod
    def delete_credential(self, credential_id: int) -> bool:
        """
        Delete a credential.
        
        Args:
            credential_id: The credential to delete
            
        Returns:
            True if deleted, False otherwise
        """
        pass
    
    @abstractmethod
    def search_credentials(self, user_id: int, 
                           search_term: str) -> List[Dict[str, Any]]:
        """
        Search credentials by site name.
        
        Args:
            user_id: The user's ID
            search_term: Search query
            
        Returns:
            List of matching credentials
        """
        pass
    
    # ============ Password History ============
    
    @abstractmethod
    def add_password_history(self, credential_id: int, 
                             encrypted_password: str) -> bool:
        """
        Add a password to history.
        
        Args:
            credential_id: The credential ID
            encrypted_password: The old encrypted password
            
        Returns:
            True if added, False otherwise
        """
        pass
    
    @abstractmethod
    def get_password_history(self, credential_id: int) -> List[Dict[str, Any]]:
        """
        Get password history for a credential.
        
        Args:
            credential_id: The credential ID
            
        Returns:
            List of historical password entries
        """
        pass
    
    # ============ Transaction Support ============
    
    @abstractmethod
    def begin_transaction(self) -> None:
        """Begin a database transaction."""
        pass
    
    @abstractmethod
    def commit_transaction(self) -> None:
        """Commit the current transaction."""
        pass
    
    @abstractmethod
    def rollback_transaction(self) -> None:
        """Rollback the current transaction."""
        pass
