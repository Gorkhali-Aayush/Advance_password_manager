"""
File Lock Manager

Prevents multiple instances of the application from running.
Demonstrates OS-level file locking.
"""

import os
import sys
import time
import atexit
from typing import Optional
from pathlib import Path

# Try Windows-specific modules
try:
    import msvcrt
    HAS_MSVCRT = True
except ImportError:
    HAS_MSVCRT = False

# Try fcntl for Unix-like systems
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False


class FileLock:
    """
    File-based lock to prevent multiple application instances.
    
    Features:
    - Cross-platform file locking
    - Automatic cleanup on exit
    - Stale lock detection
    
    Why this exists:
    - Security: Multiple instances could cause data corruption
    - OS Interaction: Demonstrates file locking
    - Race condition prevention: Only one vault access at a time
    """
    
    # Default lock file location
    DEFAULT_LOCK_FILE = ".password_manager.lock"
    
    # Stale lock timeout in seconds
    STALE_TIMEOUT = 60
    
    def __init__(self, lock_file: Optional[str] = None):
        """
        Initialize file lock.
        
        Args:
            lock_file: Path to lock file
        """
        if lock_file:
            self._lock_path = Path(lock_file)
        else:
            # Use temp directory for lock file
            temp_dir = Path(os.environ.get('TEMP', '/tmp'))
            self._lock_path = temp_dir / self.DEFAULT_LOCK_FILE
        
        self._lock_file = None
        self._is_locked = False
    
    @property
    def lock_path(self) -> Path:
        """Get the lock file path."""
        return self._lock_path
    
    @property
    def is_locked(self) -> bool:
        """Check if we hold the lock."""
        return self._is_locked
    
    def acquire(self) -> bool:
        """
        Attempt to acquire the lock.
        
        Returns:
            True if lock acquired, False if another instance running
        """
        # Check for stale lock first
        self._check_stale_lock()
        
        try:
            # Open lock file
            self._lock_file = open(self._lock_path, 'w')
            
            # Attempt platform-specific lock
            if HAS_MSVCRT:
                # Windows locking
                try:
                    msvcrt.locking(
                        self._lock_file.fileno(),
                        msvcrt.LK_NBLCK,
                        1
                    )
                except IOError:
                    self._lock_file.close()
                    self._lock_file = None
                    return False
                    
            elif HAS_FCNTL:
                # Unix locking
                try:
                    fcntl.flock(self._lock_file.fileno(), 
                               fcntl.LOCK_EX | fcntl.LOCK_NB)
                except IOError:
                    self._lock_file.close()
                    self._lock_file = None
                    return False
            else:
                # Fallback: simple file existence check
                if self._lock_path.exists():
                    self._lock_file.close()
                    self._lock_file = None
                    return False
            
            # Write PID to lock file
            self._lock_file.write(str(os.getpid()))
            self._lock_file.flush()
            
            self._is_locked = True
            
            # Register cleanup
            atexit.register(self.release)
            
            return True
            
        except Exception as e:
            print(f"Lock acquisition error: {e}")
            if self._lock_file:
                self._lock_file.close()
                self._lock_file = None
            return False
    
    def release(self) -> None:
        """Release the lock."""
        if not self._is_locked:
            return
        
        try:
            if self._lock_file:
                if HAS_MSVCRT:
                    try:
                        msvcrt.locking(
                            self._lock_file.fileno(),
                            msvcrt.LK_UNLCK,
                            1
                        )
                    except IOError:
                        pass
                        
                elif HAS_FCNTL:
                    try:
                        fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
                    except IOError:
                        pass
                
                self._lock_file.close()
                self._lock_file = None
            
            # Remove lock file
            if self._lock_path.exists():
                self._lock_path.unlink()
            
        except Exception as e:
            print(f"Lock release error: {e}")
        finally:
            self._is_locked = False
    
    def _check_stale_lock(self) -> None:
        """
        Check for and remove stale lock files.
        
        A lock is considered stale if:
        - The PID in the lock file doesn't exist
        - The lock file is older than STALE_TIMEOUT
        """
        if not self._lock_path.exists():
            return
        
        try:
            # Check file age
            stat = self._lock_path.stat()
            age = time.time() - stat.st_mtime
            
            if age > self.STALE_TIMEOUT:
                # Lock is old, check if process exists
                try:
                    with open(self._lock_path, 'r') as f:
                        pid = int(f.read().strip())
                    
                    if not self._is_process_running(pid):
                        # Process is dead, remove stale lock
                        self._lock_path.unlink()
                        
                except (ValueError, IOError):
                    # Can't read PID, assume stale
                    self._lock_path.unlink()
                    
        except Exception:
            pass
    
    def _is_process_running(self, pid: int) -> bool:
        """
        Check if a process is running.
        
        Args:
            pid: Process ID to check
            
        Returns:
            True if process is running
        """
        if sys.platform == 'win32':
            # Windows: use kernel32
            try:
                import ctypes
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                
                handle = ctypes.windll.kernel32.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    False,
                    pid
                )
                
                if handle:
                    ctypes.windll.kernel32.CloseHandle(handle)
                    return True
                return False
                
            except Exception:
                return True  # Assume running on error
        else:
            # Unix: use signal 0
            try:
                os.kill(pid, 0)
                return True
            except OSError:
                return False
    
    def get_existing_instance_pid(self) -> Optional[int]:
        """
        Get the PID of an existing instance.
        
        Returns:
            PID if another instance is running, None otherwise
        """
        if not self._lock_path.exists():
            return None
        
        try:
            with open(self._lock_path, 'r') as f:
                pid = int(f.read().strip())
            
            if self._is_process_running(pid):
                return pid
            return None
            
        except (ValueError, IOError):
            return None
    
    def __enter__(self):
        """Context manager entry."""
        if not self.acquire():
            raise RuntimeError("Could not acquire file lock - another instance running?")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.release()
        return False


class SingleInstanceGuard:
    """
    Guard to ensure only one application instance runs.
    
    Usage:
        guard = SingleInstanceGuard()
        if not guard.check():
            print("Another instance is already running!")
            sys.exit(1)
    """
    
    def __init__(self, app_name: str = "PasswordManager"):
        """
        Initialize the guard.
        
        Args:
            app_name: Application name for lock file
        """
        self._app_name = app_name
        temp_dir = Path(os.environ.get('TEMP', '/tmp'))
        lock_file = temp_dir / f".{app_name.lower()}.lock"
        self._lock = FileLock(str(lock_file))
    
    def check(self) -> bool:
        """
        Check if this is the only instance.
        
        Returns:
            True if this is the only instance
        """
        return self._lock.acquire()
    
    def release(self) -> None:
        """Release the instance lock."""
        self._lock.release()
    
    def get_other_instance_pid(self) -> Optional[int]:
        """Get PID of other running instance."""
        return self._lock.get_existing_instance_pid()


# Singleton instance
_instance_guard: Optional[SingleInstanceGuard] = None


def get_instance_guard() -> SingleInstanceGuard:
    """
    Get the singleton instance guard.
    
    Returns:
        SingleInstanceGuard instance
    """
    global _instance_guard
    if _instance_guard is None:
        _instance_guard = SingleInstanceGuard()
    return _instance_guard
