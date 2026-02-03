"""
Thread Manager

Manages background threads for security features.
Demonstrates OS-level interaction and multi-threading.
"""

import threading
import time
from typing import Optional, Callable, Dict, Any
from datetime import datetime, timedelta
from enum import Enum


class ThreadState(Enum):
    """Thread states for monitoring."""
    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED = "paused"


class ManagedThread:
    """
    Wrapper for managed background threads.
    
    Provides:
    - Start/stop control
    - State monitoring
    - Graceful shutdown
    """
    
    def __init__(self, name: str, target: Callable, 
                 interval: float = 1.0, daemon: bool = True):
        """
        Initialize a managed thread.
        
        Args:
            name: Thread name for identification
            target: Function to run periodically
            interval: Seconds between executions
            daemon: Whether thread is daemon (exits with main program)
        """
        self._name = name
        self._target = target
        self._interval = interval
        self._daemon = daemon
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._state = ThreadState.STOPPED
        self._lock = threading.Lock()
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def state(self) -> ThreadState:
        with self._lock:
            return self._state
    
    @property
    def is_running(self) -> bool:
        return self._state == ThreadState.RUNNING
    
    def start(self) -> bool:
        """
        Start the thread.
        
        Returns:
            True if started, False if already running
        """
        with self._lock:
            if self._state == ThreadState.RUNNING:
                return False
            
            self._stop_event.clear()
            self._pause_event.set()  # Not paused
            
            self._thread = threading.Thread(
                target=self._run_loop,
                name=self._name,
                daemon=self._daemon
            )
            self._thread.start()
            self._state = ThreadState.RUNNING
            return True
    
    def stop(self) -> None:
        """Stop the thread gracefully."""
        with self._lock:
            if self._state == ThreadState.STOPPED:
                return
            
            self._stop_event.set()
            self._pause_event.set()  # Unblock if paused
            
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        
        with self._lock:
            self._state = ThreadState.STOPPED
    
    def pause(self) -> None:
        """Pause the thread execution."""
        with self._lock:
            if self._state == ThreadState.RUNNING:
                self._pause_event.clear()
                self._state = ThreadState.PAUSED
    
    def resume(self) -> None:
        """Resume a paused thread."""
        with self._lock:
            if self._state == ThreadState.PAUSED:
                self._pause_event.set()
                self._state = ThreadState.RUNNING
    
    def _run_loop(self) -> None:
        """Internal thread loop."""
        while not self._stop_event.is_set():
            # Check for pause
            self._pause_event.wait()
            
            if self._stop_event.is_set():
                break
            
            try:
                self._target()
            except Exception as e:
                print(f"Thread {self._name} error: {e}")
            
            # Wait for interval or stop signal
            self._stop_event.wait(timeout=self._interval)


class ThreadManager:
    """
    Centralized manager for all application threads.
    
    Manages:
    - Auto-lock timer thread
    - Clipboard clear thread
    - Session timeout thread
    
    Why this exists:
    - Security: Automatic protection mechanisms
    - OS Interaction: Demonstrates threading
    - Clean shutdown: Proper resource cleanup
    """
    
    def __init__(self):
        """Initialize the thread manager."""
        self._threads: Dict[str, ManagedThread] = {}
        self._lock = threading.Lock()
        self._callbacks: Dict[str, Callable] = {}
    
    def register_thread(self, name: str, target: Callable,
                        interval: float = 1.0) -> bool:
        """
        Register a new managed thread.
        
        Args:
            name: Unique thread name
            target: Function to execute
            interval: Execution interval in seconds
            
        Returns:
            True if registered, False if name exists
        """
        with self._lock:
            if name in self._threads:
                return False
            
            self._threads[name] = ManagedThread(
                name=name,
                target=target,
                interval=interval
            )
            return True
    
    def start_thread(self, name: str) -> bool:
        """Start a registered thread."""
        with self._lock:
            if name not in self._threads:
                return False
            return self._threads[name].start()
    
    def stop_thread(self, name: str) -> bool:
        """Stop a running thread."""
        with self._lock:
            if name not in self._threads:
                return False
            self._threads[name].stop()
            return True
    
    def start_all(self) -> None:
        """Start all registered threads."""
        with self._lock:
            for thread in self._threads.values():
                thread.start()
    
    def stop_all(self) -> None:
        """Stop all running threads."""
        with self._lock:
            for thread in self._threads.values():
                thread.stop()
    
    def get_thread_state(self, name: str) -> Optional[ThreadState]:
        """Get the state of a thread."""
        with self._lock:
            if name in self._threads:
                return self._threads[name].state
            return None
    
    def get_all_states(self) -> Dict[str, ThreadState]:
        """Get states of all threads."""
        with self._lock:
            return {name: thread.state 
                    for name, thread in self._threads.items()}
    
    def remove_thread(self, name: str) -> bool:
        """Remove a thread (must be stopped first)."""
        with self._lock:
            if name not in self._threads:
                return False
            
            thread = self._threads[name]
            if thread.is_running:
                thread.stop()
            
            del self._threads[name]
            return True


class AutoLockTimer:
    """
    Timer for automatic session locking.
    
    Features:
    - Configurable timeout
    - Activity tracking
    - Lock callback
    """
    
    # Default timeout in seconds (5 minutes)
    DEFAULT_TIMEOUT = 300
    
    def __init__(self, timeout_seconds: int = DEFAULT_TIMEOUT,
                 on_lock: Optional[Callable] = None):
        """
        Initialize auto-lock timer.
        
        Args:
            timeout_seconds: Inactivity timeout
            on_lock: Callback when lock triggers
        """
        self._timeout = timeout_seconds
        self._on_lock = on_lock
        self._last_activity = datetime.now()
        self._lock = threading.Lock()
        self._is_locked = False
        self._thread: Optional[ManagedThread] = None
    
    @property
    def timeout(self) -> int:
        return self._timeout
    
    @timeout.setter
    def timeout(self, seconds: int) -> None:
        with self._lock:
            self._timeout = max(30, seconds)  # Minimum 30 seconds
    
    @property
    def is_locked(self) -> bool:
        with self._lock:
            return self._is_locked
    
    @property
    def time_remaining(self) -> int:
        """Seconds until auto-lock."""
        with self._lock:
            elapsed = (datetime.now() - self._last_activity).total_seconds()
            remaining = self._timeout - elapsed
            return max(0, int(remaining))
    
    def reset_activity(self) -> None:
        """Reset the activity timer (user did something)."""
        with self._lock:
            self._last_activity = datetime.now()
            self._is_locked = False
    
    def _check_timeout(self) -> None:
        """Check if timeout has been reached."""
        callback = None  # Initialize callback before the lock
        
        with self._lock:
            if self._is_locked:
                return
            
            elapsed = (datetime.now() - self._last_activity).total_seconds()
            
            if elapsed >= self._timeout:
                self._is_locked = True
                if self._on_lock:
                    # Run callback outside lock to prevent deadlock
                    callback = self._on_lock
        
        if callback:
            try:
                callback()
            except Exception as e:
                print(f"Auto-lock callback error: {e}")
    
    def start(self) -> None:
        """Start the auto-lock timer."""
        self._thread = ManagedThread(
            name="auto_lock_timer",
            target=self._check_timeout,
            interval=1.0
        )
        self._thread.start()
    
    def stop(self) -> None:
        """Stop the auto-lock timer."""
        if self._thread:
            self._thread.stop()
            self._thread = None
    
    def unlock(self) -> None:
        """Manually unlock."""
        with self._lock:
            self._is_locked = False
            self._last_activity = datetime.now()


# Singleton instance
_thread_manager: Optional[ThreadManager] = None


def get_thread_manager() -> ThreadManager:
    """
    Get the singleton thread manager instance.
    
    Returns:
        ThreadManager instance
    """
    global _thread_manager
    if _thread_manager is None:
        _thread_manager = ThreadManager()
    return _thread_manager
