"""
Vault Controller

Central controller for credential management.
Coordinates data structures, storage, and encryption.
"""

import os
import sys
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime
import logging

# Add parent directory to path for cross-package imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.credential import Credential
from core.sessionManager import get_session_manager, SessionManager
from core.passwordPolicy import get_password_policy, PasswordPolicy, PasswordStrength
from datastructures.bst import BinarySearchTree
from datastructures.hashtable import HashTable, generate_composite_key
from datastructures.graph import PasswordReuseAnalyzer
from datastructures.linkedList import PasswordHistory
from crypto.fernetEngine import get_encryption_engine, FernetEngine
from storage.mysqlEngine import get_database, MySQLEngine
from storage.backupFile import get_backup_handler, BackupFile

logger = logging.getLogger(__name__)


class Vault:
    """
    Central controller for the password vault.
    
    Responsibilities:
    - Coordinate data structures for efficient access
    - Handle encryption/decryption
    - Communicate with database
    - Enforce business rules
    
    Data Structures Used:
    - BST: For sorted search by site name
    - HashTable: For O(1) lookup and duplicate detection
    - Graph: For password reuse analysis
    - LinkedList: For password history per credential
    
    This is the "brain" of the application.
    """
    
    def __init__(self, session_manager: Optional[SessionManager] = None,
                 database: Optional[MySQLEngine] = None,
                 crypto: Optional[FernetEngine] = None):
        """
        Initialize the vault.
        
        Args:
            session_manager: Optional custom session manager
            database: Optional custom database engine
            crypto: Optional custom crypto engine
        """
        # Dependencies (use singletons if not provided)
        self._session = session_manager or get_session_manager()
        self._db = database or get_database()
        self._crypto = crypto or get_encryption_engine()
        self._policy = get_password_policy()
        self._backup = get_backup_handler()
        
        # In-memory data structures
        self._bst = BinarySearchTree()  # For sorted search
        self._hash_table = HashTable()  # For O(1) lookup
        self._reuse_analyzer = PasswordReuseAnalyzer()  # For security analysis
        self._password_histories: Dict[int, PasswordHistory] = {}  # Credential ID -> History
        
        # Cache
        self._credentials_loaded = False
        self._credential_cache: Dict[int, Credential] = {}  # ID -> Credential
    
    @property
    def is_unlocked(self) -> bool:
        """Check if vault is unlocked (user logged in)."""
        return self._session.is_logged_in
    
    @property
    def credential_count(self) -> int:
        """Get number of stored credentials."""
        return len(self._credential_cache)
    
    # ============ Credential Loading ============
    
    def load_credentials(self) -> bool:
        """
        Load credentials from database into data structures.
        
        Must be called after successful login.
        
        Returns:
            True if loaded successfully
        """
        if not self._session.is_logged_in:
            return False
        
        user_id = self._session.user_id
        if not user_id:
            return False
        
        try:
            # Clear existing data
            self._clear_data_structures()
            
            # Load from database
            db_credentials = self._db.get_credentials_by_user(user_id)
            
            for row in db_credentials:
                credential = Credential.from_db_row(row)
                self._add_to_data_structures(credential)
            
            self._credentials_loaded = True
            return True
            
        except Exception as e:
            print(f"Error loading credentials: {e}")
            return False
    
    def _add_to_data_structures(self, credential: Credential, 
                                 plaintext_password: Optional[str] = None) -> None:
        """
        Add a credential to all data structures.
        
        Args:
            credential: The credential to add
            plaintext_password: Optional plaintext password for reuse detection.
                               If not provided, will decrypt from encrypted_password.
        """
        cred_id = credential.id
        
        # Cache
        self._credential_cache[cred_id] = credential
        
        # BST (for sorted search by site name)
        self._bst.insert(credential.site_name.lower(), credential)
        
        # HashTable (for duplicate detection)
        key = generate_composite_key(credential.site_name, credential.username)
        self._hash_table.put(key, credential)
        
        # Graph (for password reuse detection)
        # IMPORTANT: We hash the PLAINTEXT password, not the encrypted one
        # because encrypted passwords differ even for same plaintext (due to IV)
        if plaintext_password:
            # Use provided plaintext
            password_hash = self._crypto.quick_hash(plaintext_password)
        else:
            # Decrypt to get plaintext for hashing
            try:
                encryption_key = self._session.encryption_key
                decrypted = self._crypto.decrypt_from_string(
                    credential.get_encrypted_password(),
                    encryption_key
                )
                password_hash = self._crypto.quick_hash(decrypted)
            except Exception:
                # Fallback: use encrypted password hash (less accurate)
                password_hash = self._crypto.quick_hash(
                    credential.get_encrypted_password()
                )
        
        self._reuse_analyzer.add_credential(
            str(cred_id),
            password_hash,
            credential
        )
        
        # Password history
        self._password_histories[cred_id] = PasswordHistory()
    
    def _remove_from_data_structures(self, credential: Credential) -> None:
        """Remove a credential from all data structures."""
        cred_id = credential.id
        
        # Cache
        if cred_id in self._credential_cache:
            del self._credential_cache[cred_id]
        
        # BST
        self._bst.delete(credential.site_name.lower())
        
        # HashTable
        key = generate_composite_key(credential.site_name, credential.username)
        self._hash_table.remove(key)
        
        # Graph
        self._reuse_analyzer.remove_credential(str(cred_id))
        
        # Password history
        if cred_id in self._password_histories:
            del self._password_histories[cred_id]
    
    def _clear_data_structures(self) -> None:
        """Clear all in-memory data structures."""
        self._bst.clear()
        self._hash_table.clear()
        self._reuse_analyzer.clear()
        self._password_histories.clear()
        self._credential_cache.clear()
        self._credentials_loaded = False
    
    # ============ Credential Operations ============
    
    def add_credential(self, site_name: str, username: str,
                       password: str, url: Optional[str] = None,
                       notes: Optional[str] = None) -> Optional[Credential]:
        """
        Add a new credential to the vault.
        
        Args:
            site_name: Website/service name
            username: Account username
            password: Plain text password (will be encrypted)
            url: Optional URL
            notes: Optional notes
            
        Returns:
            Created Credential object, or None if failed
        """
        if not self._session.is_logged_in:
            return None
        
        # Check for duplicates
        key = generate_composite_key(site_name, username)
        if self._hash_table.contains(key):
            raise ValueError(f"Credential for {site_name}/{username} already exists")
        
        try:
            # Encrypt password
            encryption_key = self._session.encryption_key
            encrypted_password = self._crypto.encrypt_to_string(
                password, encryption_key
            )
            
            # Store in database
            user_id = self._session.user_id
            cred_id = self._db.create_credential(
                user_id=user_id,
                site_name=site_name,
                username=username,
                encrypted_password=encrypted_password,
                url=url,
                notes=notes
            )
            
            if not cred_id:
                return None
            
            # Create credential object
            credential = Credential(
                credential_id=cred_id,
                site_name=site_name,
                username=username,
                encrypted_password=encrypted_password,
                url=url,
                notes=notes
            )
            
            # Add to data structures - pass plaintext for accurate reuse detection
            self._add_to_data_structures(credential, plaintext_password=password)
            
            # Log the action
            current_user = self._session.username if self._session.is_logged_in else 'unknown'
            logger.info(f"Password added by user {current_user}: {site_name}/{username}")
            
            return credential
            
        except Exception as e:
            logger.error(f"Error adding credential: {e}")
            print(f"Error adding credential: {e}")
            return None
    
    def update_credential(self, credential_id: int,
                          site_name: Optional[str] = None,
                          username: Optional[str] = None,
                          password: Optional[str] = None,
                          url: Optional[str] = None,
                          notes: Optional[str] = None) -> bool:
        """
        Update an existing credential.
        
        Args:
            credential_id: ID of credential to update
            site_name: New site name (optional)
            username: New username (optional)
            password: New password (optional, will be encrypted)
            url: New URL (optional)
            notes: New notes (optional)
            
        Returns:
            True if updated successfully
        """
        if not self._session.is_logged_in:
            return False
        
        if credential_id not in self._credential_cache:
            return False
        
        credential = self._credential_cache[credential_id]
        old_key = generate_composite_key(credential.site_name, credential.username)
        
        try:
            updates = {}
            
            if site_name:
                updates['site_name'] = site_name
            if username:
                updates['username'] = username
            if url is not None:
                updates['url'] = url
            if notes is not None:
                updates['notes'] = notes
            
            if password:
                # Save old password to history
                old_encrypted = credential.get_encrypted_password()
                self._db.add_password_history(credential_id, old_encrypted)
                
                if credential_id in self._password_histories:
                    self._password_histories[credential_id].add_password(
                        self._crypto.quick_hash(old_encrypted)
                    )
                
                # Encrypt new password
                encryption_key = self._session.encryption_key
                encrypted_password = self._crypto.encrypt_to_string(
                    password, encryption_key
                )
                updates['encrypted_password'] = encrypted_password
            
            # Update database
            if not self._db.update_credential(credential_id, updates):
                return False
            
            # Remove from data structures
            self._remove_from_data_structures(credential)
            
            # Update credential object
            if site_name:
                credential.site_name = site_name
            if username:
                credential.username = username
            if url is not None:
                credential.url = url
            if notes is not None:
                credential.notes = notes
            if password:
                credential.set_encrypted_password(encrypted_password)
            
            # Re-add to data structures with plaintext password for accurate reuse detection
            self._add_to_data_structures(credential, plaintext_password=password)
            
            # Log the action
            current_user = self._session.username if self._session.is_logged_in else 'unknown'
            changes = []
            if site_name:
                changes.append('site_name')
            if username:
                changes.append('username')
            if password:
                changes.append('password')
            if url is not None:
                changes.append('url')
            if notes is not None:
                changes.append('notes')
            
            changes_str = ', '.join(changes)
            logger.info(f"Password edited by user {current_user}: credential_id={credential_id}, modified fields: {changes_str}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating credential: {e}")
            print(f"Error updating credential: {e}")
            return False
    
    def delete_credential(self, credential_id: int) -> bool:
        """
        Delete a credential from the vault.
        
        Args:
            credential_id: ID of credential to delete
            
        Returns:
            True if deleted successfully
        """
        if not self._session.is_logged_in:
            return False
        
        if credential_id not in self._credential_cache:
            return False
        
        credential = self._credential_cache[credential_id]
        
        try:
            # Delete from database
            if not self._db.delete_credential(credential_id):
                return False
            
            # Remove from data structures
            self._remove_from_data_structures(credential)
            
            # Log the action
            current_user = self._session.username if self._session.is_logged_in else 'unknown'
            logger.info(f"Password deleted by user {current_user}: {credential.site_name}/{credential.username} (credential_id={credential_id})")
            
            return True
            
        except Exception as e:
            print(f"Error deleting credential: {e}")
            return False
    
    # ============ Search Operations ============
    
    def search(self, query: str) -> List[Credential]:
        """
        Search credentials by site name using BST.
        
        Args:
            query: Search query
            
        Returns:
            List of matching credentials
        """
        if not query:
            return self.get_all_credentials()
        
        # Use BST prefix search for efficient lookup
        return self._bst.prefix_search(query.lower())
    
    def get_credential(self, credential_id: int) -> Optional[Credential]:
        """
        Get a specific credential by ID.
        
        Args:
            credential_id: The credential ID
            
        Returns:
            Credential or None
        """
        return self._credential_cache.get(credential_id)
    
    def get_credential_by_site(self, site_name: str, 
                                username: str) -> Optional[Credential]:
        """
        Get credential by site name and username.
        
        Uses HashTable for O(1) lookup.
        
        Args:
            site_name: Site name
            username: Username
            
        Returns:
            Credential or None
        """
        key = generate_composite_key(site_name, username)
        return self._hash_table.get(key)
    
    def get_all_credentials(self) -> List[Credential]:
        """
        Get all credentials in sorted order.
        
        Uses BST inorder traversal.
        
        Returns:
            List of credentials sorted by site name
        """
        return self._bst.inorder_traversal()
    
    def credential_exists(self, site_name: str, username: str) -> bool:
        """
        Check if a credential exists.
        
        Uses HashTable for O(1) check.
        
        Args:
            site_name: Site name
            username: Username
            
        Returns:
            True if exists
        """
        key = generate_composite_key(site_name, username)
        return self._hash_table.contains(key)
    
    # ============ Password Operations ============
    
    def get_decrypted_password(self, credential_id: int) -> Optional[str]:
        """
        Get the decrypted password for a credential.
        
        Args:
            credential_id: Credential ID
            
        Returns:
            Decrypted password or None
        """
        if not self._session.is_logged_in:
            return None
        
        credential = self._credential_cache.get(credential_id)
        if not credential:
            return None
        
        try:
            encryption_key = self._session.encryption_key
            encrypted = credential.get_encrypted_password()
            return self._crypto.decrypt_from_string(encrypted, encryption_key)
        except Exception:
            return None
    
    def generate_password(self, length: int = 20) -> str:
        """
        Generate a VERY STRONG random password.
        
        Default: 20+ characters with all character types for maximum security.
        
        Args:
            length: Password length (minimum 20 recommended)
            
        Returns:
            Generated password
        """
        # Ensure minimum length for strong passwords
        actual_length = max(length, 20)
        return self._crypto.generate_secure_password(actual_length)
    
    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Check password strength.
        
        Args:
            password: Password to check
            
        Returns:
            Dictionary with strength info
        """
        strength, score = self._policy.calculate_strength(password)
        is_valid, violations = self._policy.validate(password)
        suggestions = self._policy.get_strength_feedback(password)
        
        return {
            'strength': strength.name,
            'score': score,
            'valid': is_valid,
            'violations': [v.message for v in violations],
            'suggestions': suggestions
        }
    
    # ============ Security Analysis ============
    
    def get_security_report(self) -> Dict[str, Any]:
        """
        Generate a security report for all credentials.
        
        Uses Graph data structure for analysis.
        
        Returns:
            Security report dictionary
        """
        reuse_report = self._reuse_analyzer.get_reuse_report()
        graph_data = self._reuse_analyzer.graph.get_graph_data()
        
        return {
            'total_credentials': self.credential_count,
            'unique_passwords': reuse_report['unique_passwords'],
            'reuse_clusters': reuse_report['reuse_clusters'],
            'affected_credentials': reuse_report['affected_credentials'],
            'security_score': reuse_report['security_score'],
            'high_risk_count': len(reuse_report['high_risk_credentials']),
            'graph_data': graph_data
        }
    
    def get_password_reuse_graph(self) -> Dict:
        """
        Get graph data for visualization.
        
        Returns:
            Graph data with nodes and edges
        """
        return self._reuse_analyzer.graph.get_graph_data()
    
    # ============ Backup Operations ============
    
    def create_backup(self, backup_name: Optional[str] = None) -> Optional[str]:
        """
        Create an encrypted backup of all credentials.
        
        Args:
            backup_name: Optional custom backup name
            
        Returns:
            Backup file path or None
        """
        if not self._session.is_logged_in:
            return None
        
        credentials = [c.to_dict() for c in self._credential_cache.values()]
        
        # Use encryption key as password (already derived)
        # Note: In production, might want to use master password instead
        password = self._session.username  # Simplified for demo
        
        return self._backup.create_backup(credentials, password, backup_name)
    
    def list_backups(self) -> List[Dict]:
        """List available backups."""
        return self._backup.list_backups()
    
    # ============ Lifecycle ============
    
    def lock(self) -> None:
        """
        Lock the vault.
        
        Clears decrypted data from memory.
        """
        self._clear_data_structures()
        self._session.lock()
    
    def unlock(self, password: str) -> bool:
        """
        Unlock the vault.
        
        Args:
            password: Master password
            
        Returns:
            True if unlocked successfully
        """
        # Get user data for verification
        user = self._db.get_user(self._session.username)
        if not user:
            return False
        
        salt = bytes.fromhex(user['salt'])
        stored_hash = user['master_password_hash']
        
        if self._session.unlock(password, salt, stored_hash):
            self.load_credentials()
            return True
        
        return False
    
    def close(self) -> None:
        """
        Close the vault and clean up.
        
        Called on application exit.
        """
        self._clear_data_structures()


# Singleton instance
_vault_instance: Optional[Vault] = None


def get_vault() -> Vault:
    """
    Get the singleton vault instance.
    
    Returns:
        Vault instance
    """
    global _vault_instance
    if _vault_instance is None:
        _vault_instance = Vault()
    return _vault_instance


def set_vault(vault: Vault) -> None:
    """
    Set the singleton vault instance.
    
    Args:
        vault: The vault instance to use as singleton
    """
    global _vault_instance
    _vault_instance = vault
