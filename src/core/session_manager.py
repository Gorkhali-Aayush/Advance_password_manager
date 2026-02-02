"""
Session Manager

Manages user login sessions with security features.
Handles authentication, auto-lock, and memory wiping.
"""

import os
import sys
import threading
import time
from typing import Optional, Callable, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

# Add parent directory to path for cross-package imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from os_layer.thread_manager import AutoLockTimer, get_thread_manager
from os_layer.clipboard_manager import get_clipboard_manager
from crypto.fernet_engine import get_encryption_engine


class SessionState(Enum):
    """User session states."""
    LOGGED_OUT = "logged_out"
    LOGGED_IN = "logged_in"
    LOCKED = "locked"


class Session:
    """
    Represents a user session.
    
    Contains:
    - User information
    - Encryption key (in memory only!)
    - Session timing
    """
    
    def __init__(self, user_id: int, username: str, 
                 encryption_key: bytes, role: str = 'user'):
        """
        Initialize a session.
        
        Args:
            user_id: Database user ID
            username: Username
            encryption_key: Derived encryption key
            role: User role (admin or user)
        """
        self._user_id = user_id
        self._username = username
        self._encryption_key = encryption_key
        self._role = role
        self._created_at = datetime.now()
        self._last_activity = datetime.now()
    
    @property
    def user_id(self) -> int:
        return self._user_id
    
    @property
    def username(self) -> str:
        return self._username
    
    @property
    def role(self) -> str:
        return self._role
    
    @property
    def encryption_key(self) -> bytes:
        return self._encryption_key
    
    @property
    def created_at(self) -> datetime:
        return self._created_at
    
    @property
    def last_activity(self) -> datetime:
        return self._last_activity
    
    @property
    def session_duration(self) -> timedelta:
        return datetime.now() - self._created_at
    
    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self._last_activity = datetime.now()
    
    def wipe(self) -> None:
        """
        Securely wipe sensitive session data.
        
        Overwrites the encryption key in memory.
        """
        # Overwrite key with zeros
        if self._encryption_key:
            key_len = len(self._encryption_key)
            # Note: In Python, we can't truly overwrite immutable bytes
            # This is a best-effort approach
            self._encryption_key = b'\x00' * key_len
            self._encryption_key = None


class SessionManager:
    """
    Central manager for user sessions.
    
    Features:
    - Login/logout handling
    - Session state management
    - Auto-lock on inactivity
    - Memory wiping on logout
    - Activity tracking
    
    Security:
    - Encryption keys only in memory
    - Automatic session termination
    - Secure logout process
    """
    
    # Default auto-lock timeout (5 minutes)
    DEFAULT_LOCK_TIMEOUT = 300
    
    # Maximum session duration (8 hours)
    MAX_SESSION_DURATION = 28800
    
    def __init__(self, lock_timeout: int = DEFAULT_LOCK_TIMEOUT):
        """
        Initialize session manager.
        
        Args:
            lock_timeout: Seconds before auto-lock
        """
        self._lock_timeout = lock_timeout
        self._session: Optional[Session] = None
        self._state = SessionState.LOGGED_OUT
        self._lock = threading.Lock()
        
        # Callbacks
        self._on_lock: Optional[Callable] = None
        self._on_logout: Optional[Callable] = None
        self._on_session_expired: Optional[Callable] = None
        
        # Auto-lock timer
        self._auto_lock_timer: Optional[AutoLockTimer] = None
    
    @property
    def state(self) -> SessionState:
        """Get current session state."""
        with self._lock:
            return self._state
    
    @property
    def is_logged_in(self) -> bool:
        """Check if user is logged in (not locked)."""
        return self._state == SessionState.LOGGED_IN
    
    @property
    def is_locked(self) -> bool:
        """Check if session is locked."""
        return self._state == SessionState.LOCKED
    
    @property
    def current_session(self) -> Optional[Session]:
        """Get current session (if logged in)."""
        with self._lock:
            if self._state == SessionState.LOGGED_IN:
                return self._session
            return None
    
    @property
    def user_id(self) -> Optional[int]:
        """Get current user ID."""
        return self._session.user_id if self._session else None
    
    @property
    def username(self) -> Optional[str]:
        """Get current username."""
        return self._session.username if self._session else None
    
    @property
    def encryption_key(self) -> Optional[bytes]:
        """Get encryption key (only if logged in)."""
        with self._lock:
            if self._state == SessionState.LOGGED_IN and self._session:
                return self._session.encryption_key
            return None
    
    def set_callbacks(self, on_lock: Optional[Callable] = None,
                      on_logout: Optional[Callable] = None,
                      on_session_expired: Optional[Callable] = None) -> None:
        """
        Set session event callbacks.
        
        Args:
            on_lock: Called when session is locked
            on_logout: Called on logout
            on_session_expired: Called when max session duration reached
        """
        self._on_lock = on_lock
        self._on_logout = on_logout
        self._on_session_expired = on_session_expired
    
    def login(self, user_id: int, username: str, 
              master_password: str, salt: bytes, role: str = 'user') -> bool:
        """
        Start a new session.
        
        Args:
            user_id: User's database ID
            username: Username
            master_password: Master password (for key derivation)
            salt: Salt for key derivation
            role: User role (admin or user)
            
        Returns:
            True if login successful
        """
        with self._lock:
            # End any existing session
            if self._session:
                self._cleanup_session()
            
            try:
                # Derive encryption key
                crypto = get_encryption_engine()
                key = crypto.derive_key(master_password, salt)
                
                # Create session
                self._session = Session(user_id, username, key, role)
                self._state = SessionState.LOGGED_IN
                
                # Start auto-lock timer
                self._start_auto_lock()
                
                return True
                
            except Exception as e:
                print(f"Login error: {e}")
                return False
    
    def logout(self) -> None:
        """
        End the current session.
        
        Performs secure cleanup:
        - Wipes encryption key
        - Clears clipboard
        - Stops timers
        """
        with self._lock:
            self._cleanup_session()
            self._state = SessionState.LOGGED_OUT
        
        if self._on_logout:
            try:
                self._on_logout()
            except Exception:
                pass
    
    def lock(self) -> None:
        """
        Lock the current session.
        
        User must re-enter password to unlock.
        Encryption key is preserved for unlock.
        """
        with self._lock:
            if self._state == SessionState.LOGGED_IN:
                self._state = SessionState.LOCKED
                
                # Stop auto-lock (already locked)
                if self._auto_lock_timer:
                    self._auto_lock_timer.stop()
        
        if self._on_lock:
            try:
                self._on_lock()
            except Exception:
                pass
    
    def unlock(self, master_password: str, salt: bytes,
               stored_hash: str) -> bool:
        """
        Unlock a locked session.
        
        Args:
            master_password: Master password
            salt: Salt for verification
            stored_hash: Stored password hash
            
        Returns:
            True if unlock successful
        """
        with self._lock:
            if self._state != SessionState.LOCKED:
                return False
            
            # Verify password
            crypto = get_encryption_engine()
            if crypto.verify_password(master_password, salt, stored_hash):
                self._state = SessionState.LOGGED_IN
                
                # Restart auto-lock timer
                self._start_auto_lock()
                
                return True
            
            return False
    
    def update_activity(self) -> None:
        """
        Update session activity timestamp.
        
        Call this on user actions to reset auto-lock timer.
        """
        with self._lock:
            if self._session:
                self._session.update_activity()
            
            if self._auto_lock_timer:
                self._auto_lock_timer.reset_activity()
    
    def get_time_until_lock(self) -> int:
        """
        Get seconds until auto-lock.
        
        Returns:
            Seconds remaining, or 0 if not active
        """
        if self._auto_lock_timer:
            return self._auto_lock_timer.time_remaining
        return 0
    
    def set_lock_timeout(self, seconds: int) -> None:
        """
        Set auto-lock timeout.
        
        Args:
            seconds: New timeout value
        """
        self._lock_timeout = max(30, seconds)
        if self._auto_lock_timer:
            self._auto_lock_timer.timeout = self._lock_timeout
    
    def _start_auto_lock(self) -> None:
        """Start the auto-lock timer."""
        # Stop existing timer
        if self._auto_lock_timer:
            self._auto_lock_timer.stop()
        
        # Create new timer
        self._auto_lock_timer = AutoLockTimer(
            timeout_seconds=self._lock_timeout,
            on_lock=self._on_auto_lock
        )
        self._auto_lock_timer.start()
    
    def _on_auto_lock(self) -> None:
        """Callback when auto-lock triggers."""
        self.lock()
    
    def _cleanup_session(self) -> None:
        """Clean up session resources."""
        # Stop timer
        if self._auto_lock_timer:
            self._auto_lock_timer.stop()
            self._auto_lock_timer = None
        
        # Wipe session data
        if self._session:
            self._session.wipe()
            self._session = None
        
        # Clear clipboard
        try:
            clipboard = get_clipboard_manager()
            clipboard.clear_clipboard()
        except Exception:
            pass
    
    def check_session_expiry(self) -> bool:
        """
        Check if session has exceeded maximum duration.
        
        Returns:
            True if session is expired
        """
        if not self._session:
            return False
        
        duration = self._session.session_duration.total_seconds()
        
        if duration >= self.MAX_SESSION_DURATION:
            self.logout()
            
            if self._on_session_expired:
                try:
                    self._on_session_expired()
                except Exception:
                    pass
            
            return True
        
        return False
    
    def get_session_info(self) -> Dict[str, Any]:
        """
        Get information about the current session.
        
        Returns:
            Session information dictionary
        """
        with self._lock:
            if not self._session:
                return {
                    'state': self._state.value,
                    'logged_in': False
                }
            
            return {
                'state': self._state.value,
                'logged_in': self._state == SessionState.LOGGED_IN,
                'locked': self._state == SessionState.LOCKED,
                'user_id': self._session.user_id,
                'username': self._session.username,
                'session_start': self._session.created_at.isoformat(),
                'last_activity': self._session.last_activity.isoformat(),
                'duration_seconds': self._session.session_duration.total_seconds(),
                'time_until_lock': self.get_time_until_lock()
            }


# Singleton instance
_session_manager: Optional[SessionManager] = None


def set_session_manager(instance: SessionManager) -> None:
    """
    Set the singleton session manager instance.
    
    Args:
        instance: The SessionManager instance to use globally
    """
    global _session_manager
    _session_manager = instance


def get_session_manager() -> SessionManager:
    """
    Get the singleton session manager instance.
    
    Returns:
        SessionManager instance
    """
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
