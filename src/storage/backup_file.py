"""
Encrypted Backup File Handler

Provides encrypted file-based backup of credentials.
Ensures data redundancy and offline access.
"""

import os
import sys
import json
from datetime import datetime
from typing import Optional, Dict, List, Any
from pathlib import Path

# Add parent directory to path for cross-package imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.fernet_engine import get_encryption_engine


class BackupFile:
    """
    Handles encrypted backup of credentials to local files.
    
    Features:
    - AES-256 encrypted backup files
    - Automatic backup naming with timestamps
    - Backup restoration
    - Backup verification
    
    Why this exists:
    - Redundancy: Database could fail
    - Portability: Export/import credentials
    - Recovery: Restore from backup
    """
    
    # Default backup directory (relative to project)
    DEFAULT_BACKUP_DIR = "backups"
    
    # Backup file extension
    BACKUP_EXTENSION = ".vault"
    
    # Maximum backups to keep
    MAX_BACKUPS = 10
    
    def __init__(self, backup_dir: Optional[str] = None):
        """
        Initialize backup handler.
        
        Args:
            backup_dir: Custom backup directory path
        """
        self._backup_dir = Path(backup_dir or self.DEFAULT_BACKUP_DIR)
        self._crypto = get_encryption_engine()
        
        # Create backup directory if it doesn't exist
        self._backup_dir.mkdir(parents=True, exist_ok=True)
    
    @property
    def backup_directory(self) -> Path:
        """Get the backup directory path."""
        return self._backup_dir
    
    def create_backup(self, credentials: List[Dict[str, Any]], 
                      master_password: str,
                      backup_name: Optional[str] = None) -> Optional[str]:
        """
        Create an encrypted backup of credentials.
        
        Args:
            credentials: List of credential dictionaries
            master_password: Password for encryption
            backup_name: Optional custom backup name
            
        Returns:
            Backup file path if successful, None if failed
        """
        try:
            # Generate backup filename
            if backup_name:
                filename = f"{backup_name}{self.BACKUP_EXTENSION}"
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"backup_{timestamp}{self.BACKUP_EXTENSION}"
            
            filepath = self._backup_dir / filename
            
            # Prepare backup data
            backup_data = {
                'version': '1.0',
                'created_at': datetime.now().isoformat(),
                'credential_count': len(credentials),
                'credentials': credentials
            }
            
            # Convert to JSON
            json_data = json.dumps(backup_data, default=str)
            
            # Generate salt and derive key
            salt = self._crypto.generate_salt()
            key = self._crypto.derive_key(master_password, salt)
            
            # Encrypt the data
            encrypted_data = self._crypto.encrypt(json_data, key)
            
            # Write to file: salt + encrypted data
            with open(filepath, 'wb') as f:
                f.write(salt)
                f.write(encrypted_data)
            
            # Cleanup old backups
            self._cleanup_old_backups()
            
            return str(filepath)
            
        except Exception as e:
            print(f"Backup creation failed: {e}")
            return None
    
    def restore_backup(self, filepath: str, 
                       master_password: str) -> Optional[List[Dict[str, Any]]]:
        """
        Restore credentials from an encrypted backup.
        
        Args:
            filepath: Path to the backup file
            master_password: Password for decryption
            
        Returns:
            List of credentials if successful, None if failed
        """
        try:
            with open(filepath, 'rb') as f:
                # Read salt (first 32 bytes)
                salt = f.read(32)
                # Read encrypted data
                encrypted_data = f.read()
            
            # Derive key
            key = self._crypto.derive_key(master_password, salt)
            
            # Decrypt
            decrypted_json = self._crypto.decrypt(encrypted_data, key)
            
            if decrypted_json is None:
                print("Decryption failed - wrong password?")
                return None
            
            # Parse JSON
            backup_data = json.loads(decrypted_json)
            
            return backup_data.get('credentials', [])
            
        except Exception as e:
            print(f"Backup restoration failed: {e}")
            return None
    
    def verify_backup(self, filepath: str, master_password: str) -> bool:
        """
        Verify a backup file can be decrypted.
        
        Args:
            filepath: Path to the backup file
            master_password: Password for decryption
            
        Returns:
            True if backup is valid and readable
        """
        try:
            result = self.restore_backup(filepath, master_password)
            return result is not None
        except Exception:
            return False
    
    def get_backup_info(self, filepath: str, 
                        master_password: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata about a backup file.
        
        Args:
            filepath: Path to the backup file
            master_password: Password for decryption
            
        Returns:
            Backup metadata dictionary
        """
        try:
            with open(filepath, 'rb') as f:
                salt = f.read(32)
                encrypted_data = f.read()
            
            key = self._crypto.derive_key(master_password, salt)
            decrypted_json = self._crypto.decrypt(encrypted_data, key)
            
            if decrypted_json is None:
                return None
            
            backup_data = json.loads(decrypted_json)
            
            # Return metadata only (not credentials)
            return {
                'version': backup_data.get('version'),
                'created_at': backup_data.get('created_at'),
                'credential_count': backup_data.get('credential_count'),
                'file_size': os.path.getsize(filepath)
            }
            
        except Exception:
            return None
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """
        List all backup files in the backup directory.
        
        Returns:
            List of backup file information
        """
        backups = []
        
        for filepath in self._backup_dir.glob(f"*{self.BACKUP_EXTENSION}"):
            stat = filepath.stat()
            backups.append({
                'filename': filepath.name,
                'path': str(filepath),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        
        # Sort by modification time (newest first)
        backups.sort(key=lambda x: x['modified'], reverse=True)
        
        return backups
    
    def delete_backup(self, filepath: str) -> bool:
        """
        Delete a backup file.
        
        Args:
            filepath: Path to the backup file
            
        Returns:
            True if deleted, False if failed
        """
        try:
            path = Path(filepath)
            if path.exists() and path.suffix == self.BACKUP_EXTENSION:
                path.unlink()
                return True
            return False
        except Exception:
            return False
    
    def _cleanup_old_backups(self) -> None:
        """
        Remove old backups if exceeding MAX_BACKUPS.
        
        Keeps the most recent backups.
        """
        backups = self.list_backups()
        
        if len(backups) > self.MAX_BACKUPS:
            # Remove oldest backups
            for backup in backups[self.MAX_BACKUPS:]:
                self.delete_backup(backup['path'])
    
    def export_to_csv(self, credentials: List[Dict[str, Any]], 
                      filepath: str, 
                      include_passwords: bool = False) -> bool:
        """
        Export credentials to CSV (optionally with passwords).
        
        WARNING: CSV is NOT encrypted! Use with caution.
        
        Args:
            credentials: List of credentials
            filepath: Output CSV path
            include_passwords: Whether to include passwords
            
        Returns:
            True if successful
        """
        import csv
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                fields = ['site_name', 'username', 'url', 'notes']
                if include_passwords:
                    fields.insert(2, 'password')
                
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                
                for cred in credentials:
                    row = {
                        'site_name': cred.get('site_name', ''),
                        'username': cred.get('username', ''),
                        'url': cred.get('url', ''),
                        'notes': cred.get('notes', '')
                    }
                    if include_passwords:
                        row['password'] = cred.get('password', '')
                    writer.writerow(row)
            
            return True
            
        except Exception as e:
            print(f"CSV export failed: {e}")
            return False
    
    def import_from_csv(self, filepath: str) -> Optional[List[Dict[str, Any]]]:
        """
        Import credentials from a CSV file.
        
        Expected columns: site_name, username, password, url, notes
        
        Args:
            filepath: Path to CSV file
            
        Returns:
            List of credential dictionaries
        """
        import csv
        
        try:
            credentials = []
            
            with open(filepath, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    credentials.append({
                        'site_name': row.get('site_name', ''),
                        'username': row.get('username', ''),
                        'password': row.get('password', ''),
                        'url': row.get('url', ''),
                        'notes': row.get('notes', '')
                    })
            
            return credentials
            
        except Exception as e:
            print(f"CSV import failed: {e}")
            return None


# Singleton instance
_backup_instance: Optional[BackupFile] = None


def get_backup_handler(backup_dir: Optional[str] = None) -> BackupFile:
    """
    Get the singleton backup handler instance.
    
    Args:
        backup_dir: Optional custom backup directory
        
    Returns:
        BackupFile instance
    """
    global _backup_instance
    if _backup_instance is None:
        _backup_instance = BackupFile(backup_dir)
    return _backup_instance
