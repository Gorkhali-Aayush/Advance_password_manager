"""
Credential Class

Represents a single credential entry in the password vault.
Demonstrates encapsulation and data validation.
"""

from datetime import datetime
from typing import Optional, Dict, Any
import re


class Credential:
    """
    Represents a stored credential (site + username + password).
    
    OOP Concepts demonstrated:
    - Encapsulation: Password is private, accessed via methods
    - Validation: Data is validated before storage
    - Immutability: ID cannot be changed after creation
    
    Security features:
    - Password never returned directly (use dedicated methods)
    - String representation hides sensitive data
    """
    
    def __init__(self, credential_id: Optional[int], site_name: str,
                 username: str, encrypted_password: str,
                 url: Optional[str] = None, notes: Optional[str] = None,
                 created_at: Optional[datetime] = None,
                 updated_at: Optional[datetime] = None):
        """
        Initialize a credential.
        
        Args:
            credential_id: Database ID (None for new credentials)
            site_name: Name of the website/service
            username: Account username
            encrypted_password: Encrypted password (never plaintext!)
            url: Optional URL for the site
            notes: Optional notes about the credential
            created_at: Creation timestamp
            updated_at: Last update timestamp
        """
        # Validate inputs
        self._validate_site_name(site_name)
        self._validate_username(username)
        
        # Private attributes (encapsulation)
        self._id: Optional[int] = credential_id
        self._site_name: str = site_name.strip()
        self._username: str = username.strip()
        self._encrypted_password: str = encrypted_password
        self._url: Optional[str] = self._normalize_url(url)
        self._notes: Optional[str] = notes.strip() if notes else None
        self._created_at: datetime = created_at or datetime.now()
        self._updated_at: datetime = updated_at or datetime.now()
    
    # ============ Properties (Encapsulation) ============
    
    @property
    def id(self) -> Optional[int]:
        """Get credential ID (read-only after creation)."""
        return self._id
    
    @property
    def site_name(self) -> str:
        """Get site name."""
        return self._site_name
    
    @site_name.setter
    def site_name(self, value: str) -> None:
        """Set site name with validation."""
        self._validate_site_name(value)
        self._site_name = value.strip()
        self._updated_at = datetime.now()
    
    @property
    def username(self) -> str:
        """Get username."""
        return self._username
    
    @username.setter
    def username(self, value: str) -> None:
        """Set username with validation."""
        self._validate_username(value)
        self._username = value.strip()
        self._updated_at = datetime.now()
    
    @property
    def url(self) -> Optional[str]:
        """Get URL."""
        return self._url
    
    @url.setter
    def url(self, value: Optional[str]) -> None:
        """Set URL with normalization."""
        self._url = self._normalize_url(value)
        self._updated_at = datetime.now()
    
    @property
    def notes(self) -> Optional[str]:
        """Get notes."""
        return self._notes
    
    @notes.setter
    def notes(self, value: Optional[str]) -> None:
        """Set notes."""
        self._notes = value.strip() if value else None
        self._updated_at = datetime.now()
    
    @property
    def created_at(self) -> datetime:
        """Get creation timestamp."""
        return self._created_at
    
    @property
    def updated_at(self) -> datetime:
        """Get last update timestamp."""
        return self._updated_at
    
    @property
    def display_name(self) -> str:
        """Get display name (site + username)."""
        return f"{self._site_name} ({self._username})"
    
    # ============ Password Methods (Secure Access) ============
    
    def get_encrypted_password(self) -> str:
        """
        Get the encrypted password.
        
        Returns:
            The encrypted password string
            
        Note: This returns the encrypted form, not plaintext.
        Decryption must happen in the vault with proper key.
        """
        return self._encrypted_password
    
    def set_encrypted_password(self, encrypted_password: str) -> None:
        """
        Set a new encrypted password.
        
        Args:
            encrypted_password: The encrypted password
        """
        if not encrypted_password:
            raise ValueError("Encrypted password cannot be empty")
        self._encrypted_password = encrypted_password
        self._updated_at = datetime.now()
    
    def has_password(self) -> bool:
        """Check if credential has a password set."""
        return bool(self._encrypted_password)
    
    # ============ Validation Methods ============
    
    def _validate_site_name(self, site_name: str) -> None:
        """
        Validate site name.
        
        Args:
            site_name: The site name to validate
            
        Raises:
            ValueError: If validation fails
        """
        if not site_name or not site_name.strip():
            raise ValueError("Site name cannot be empty")
        if len(site_name) > 255:
            raise ValueError("Site name too long (max 255 characters)")
    
    def _validate_username(self, username: str) -> None:
        """
        Validate username.
        
        Args:
            username: The username to validate
            
        Raises:
            ValueError: If validation fails
        """
        if not username or not username.strip():
            raise ValueError("Username cannot be empty")
        if len(username) > 255:
            raise ValueError("Username too long (max 255 characters)")
    
    def _normalize_url(self, url: Optional[str]) -> Optional[str]:
        """
        Normalize URL format.
        
        Args:
            url: The URL to normalize
            
        Returns:
            Normalized URL or None
        """
        if not url or not url.strip():
            return None
        
        url = url.strip()
        
        # Add https:// if no protocol specified
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        return url
    
    # ============ Serialization ============
    
    def to_dict(self, include_password: bool = True) -> Dict[str, Any]:
        """
        Convert to dictionary for storage/transmission.
        
        Args:
            include_password: Whether to include encrypted password
            
        Returns:
            Dictionary representation
        """
        result = {
            'id': self._id,
            'site_name': self._site_name,
            'username': self._username,
            'url': self._url,
            'notes': self._notes,
            'created_at': self._created_at.isoformat(),
            'updated_at': self._updated_at.isoformat()
        }
        
        if include_password:
            result['encrypted_password'] = self._encrypted_password
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Credential':
        """
        Create a Credential from a dictionary.
        
        Args:
            data: Dictionary with credential data
            
        Returns:
            New Credential instance
        """
        created_at = data.get('created_at')
        updated_at = data.get('updated_at')
        
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)
        
        return cls(
            credential_id=data.get('id'),
            site_name=data.get('site_name', ''),
            username=data.get('username', ''),
            encrypted_password=data.get('encrypted_password', ''),
            url=data.get('url'),
            notes=data.get('notes'),
            created_at=created_at,
            updated_at=updated_at
        )
    
    @classmethod
    def from_db_row(cls, row: Dict[str, Any]) -> 'Credential':
        """
        Create a Credential from a database row.
        
        Args:
            row: Database row dictionary
            
        Returns:
            New Credential instance
        """
        return cls(
            credential_id=row.get('id'),
            site_name=row.get('site_name', ''),
            username=row.get('username', ''),
            encrypted_password=row.get('encrypted_password', ''),
            url=row.get('url'),
            notes=row.get('notes'),
            created_at=row.get('created_at'),
            updated_at=row.get('updated_at')
        )
    
    # ============ Comparison Methods ============
    
    def matches_search(self, query: str) -> bool:
        """
        Check if credential matches a search query.
        
        Args:
            query: Search query string
            
        Returns:
            True if credential matches
        """
        query_lower = query.lower()
        
        return (
            query_lower in self._site_name.lower() or
            query_lower in self._username.lower() or
            (self._url and query_lower in self._url.lower()) or
            (self._notes and query_lower in self._notes.lower())
        )
    
    def __eq__(self, other: object) -> bool:
        """Check equality based on ID."""
        if not isinstance(other, Credential):
            return False
        if self._id is None or other._id is None:
            return False
        return self._id == other._id
    
    def __hash__(self) -> int:
        """Hash based on site name and username (for collections)."""
        return hash((self._site_name.lower(), self._username.lower()))
    
    def __repr__(self) -> str:
        """Developer-friendly representation."""
        return (f"Credential(id={self._id}, site='{self._site_name}', "
                f"user='{self._username}')")
    
    def __str__(self) -> str:
        """User-friendly representation (hides sensitive data)."""
        return f"{self._site_name} - {self._username}"

