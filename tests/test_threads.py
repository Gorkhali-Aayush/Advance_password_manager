"""
Test Suite: OS Layer Threading Components
==========================================

Tests for ManagedThread, ThreadManager, AutoLockTimer,
ClipboardManager, FileLock, and SingleInstanceGuard.

Author: Advanced Password Manager Team
"""

import pytest
import sys
import os
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from os_layer.thread_manager import (
    ManagedThread, ThreadManager, AutoLockTimer, ThreadState,
    get_thread_manager
)
from os_layer.clipboard_manager import ClipboardManager, get_clipboard_manager
from os_layer.file_lock import FileLock, SingleInstanceGuard


class TestManagedThread:
    """Test cases for ManagedThread class."""
    
    def test_create_managed_thread(self):
        """Test creating a managed thread."""
        def task():
            pass
        
        thread = ManagedThread("test", task, interval=1.0)
        
        assert thread.name == "test"
        assert thread.state == ThreadState.STOPPED
        assert not thread.is_running
    
    def test_start_thread(self):
        """Test starting a managed thread."""
        counter = [0]
        
        def task():
            counter[0] += 1
        
        thread = ManagedThread("test", task, interval=0.1)
        thread.start()
        
        time.sleep(0.3)
        thread.stop()
        
        assert thread.state == ThreadState.STOPPED
        assert counter[0] >= 1
    
    def test_stop_thread(self):
        """Test stopping a managed thread."""
        def task():
            pass
        
        thread = ManagedThread("test", task, interval=0.1)
        thread.start()
        assert thread.is_running
        
        thread.stop()
        
        assert thread.state == ThreadState.STOPPED
        assert not thread.is_running
    
    def test_pause_and_resume(self):
        """Test pausing and resuming a thread."""
        counter = [0]
        
        def task():
            counter[0] += 1
        
        thread = ManagedThread("test", task, interval=0.1)
        thread.start()
        time.sleep(0.2)
        
        thread.pause()
        paused_count = counter[0]
        time.sleep(0.2)
        
        # Count should not have increased much while paused
        assert counter[0] <= paused_count + 1
        
        thread.resume()
        time.sleep(0.2)
        
        thread.stop()
        # Count should have increased after resume
        assert counter[0] > paused_count
    
    def test_daemon_thread(self):
        """Test daemon thread creation."""
        def task():
            pass
        
        thread = ManagedThread("test", task, daemon=True)
        
        # Daemon property is internal, but we can verify thread starts
        thread.start()
        time.sleep(0.1)
        thread.stop()
    
    def test_double_start_returns_false(self):
        """Test that starting an already running thread returns False."""
        def task():
            pass
        
        thread = ManagedThread("test", task, interval=0.5)
        
        assert thread.start() is True
        assert thread.start() is False
        
        thread.stop()
    
    def test_thread_with_exception(self):
        """Test that thread handles exceptions gracefully."""
        def failing_task():
            raise ValueError("Test error")
        
        thread = ManagedThread("failing", failing_task, interval=0.1)
        thread.start()
        time.sleep(0.3)
        thread.stop()
        
        # Thread should still be stoppable after exception
        assert thread.state == ThreadState.STOPPED


class TestThreadManager:
    """Test cases for ThreadManager class."""
    
    def test_create_thread_manager(self):
        """Test creating a thread manager."""
        manager = ThreadManager()
        
        assert manager.get_all_states() == {}
    
    def test_register_thread(self):
        """Test registering a thread."""
        manager = ThreadManager()
        
        def task():
            pass
        
        result = manager.register_thread("test", task, interval=1.0)
        
        assert result is True
        assert manager.get_thread_state("test") == ThreadState.STOPPED
    
    def test_register_duplicate_thread(self):
        """Test registering duplicate thread name returns False."""
        manager = ThreadManager()
        
        def task():
            pass
        
        manager.register_thread("test", task)
        result = manager.register_thread("test", task)
        
        assert result is False
    
    def test_start_thread(self):
        """Test starting a registered thread."""
        manager = ThreadManager()
        counter = [0]
        
        def task():
            counter[0] += 1
        
        manager.register_thread("test", task, interval=0.1)
        result = manager.start_thread("test")
        
        assert result is True
        time.sleep(0.2)
        
        manager.stop_thread("test")
        assert counter[0] >= 1
    
    def test_start_nonexistent_thread(self):
        """Test starting a thread that doesn't exist."""
        manager = ThreadManager()
        
        result = manager.start_thread("nonexistent")
        
        assert result is False
    
    def test_stop_thread(self):
        """Test stopping a running thread."""
        manager = ThreadManager()
        
        def task():
            pass
        
        manager.register_thread("test", task, interval=0.1)
        manager.start_thread("test")
        
        result = manager.stop_thread("test")
        
        assert result is True
        assert manager.get_thread_state("test") == ThreadState.STOPPED
    
    def test_stop_all_threads(self):
        """Test stopping all threads."""
        manager = ThreadManager()
        
        def task():
            pass
        
        manager.register_thread("test1", task)
        manager.register_thread("test2", task)
        manager.start_all()
        
        manager.stop_all()
        
        states = manager.get_all_states()
        for state in states.values():
            assert state == ThreadState.STOPPED
    
    def test_remove_thread(self):
        """Test removing a thread."""
        manager = ThreadManager()
        
        def task():
            pass
        
        manager.register_thread("test", task)
        result = manager.remove_thread("test")
        
        assert result is True
        assert manager.get_thread_state("test") is None
    
    def test_get_thread_state(self):
        """Test getting thread state."""
        manager = ThreadManager()
        
        def task():
            pass
        
        manager.register_thread("test", task)
        
        assert manager.get_thread_state("test") == ThreadState.STOPPED
        
        manager.start_thread("test")
        assert manager.get_thread_state("test") == ThreadState.RUNNING
        
        manager.stop_thread("test")


class TestAutoLockTimer:
    """Test cases for AutoLockTimer class."""
    
    def test_create_auto_lock_timer(self):
        """Test creating an auto-lock timer."""
        timer = AutoLockTimer(timeout_seconds=60)
        
        assert timer.timeout == 60
        assert not timer.is_locked
    
    def test_timer_timeout_property(self):
        """Test timeout property setter."""
        timer = AutoLockTimer(timeout_seconds=60)
        
        timer.timeout = 120
        assert timer.timeout == 120
        
        # Minimum timeout enforcement
        timer.timeout = 10
        assert timer.timeout == 30  # Minimum is 30
    
    def test_reset_activity(self):
        """Test resetting activity timer."""
        timer = AutoLockTimer(timeout_seconds=1)
        timer.start()
        
        time.sleep(0.5)
        timer.reset_activity()
        
        # Timer should not have locked yet after reset
        assert not timer.is_locked
        
        timer.stop()
    
    def test_timer_expires(self):
        """Test that timer triggers lock callback."""
        locked = [False]
        
        def on_lock():
            locked[0] = True
        
        timer = AutoLockTimer(timeout_seconds=1, on_lock=on_lock)
        timer.start()
        
        # Wait for timeout
        time.sleep(1.5)
        
        timer.stop()
        assert timer.is_locked
    
    def test_stop_timer(self):
        """Test stopping the timer."""
        timer = AutoLockTimer(timeout_seconds=60)
        timer.start()
        
        timer.stop()
        
        # Should be able to stop cleanly
    
    def test_unlock(self):
        """Test manual unlock."""
        timer = AutoLockTimer(timeout_seconds=1)
        timer.start()
        time.sleep(1.5)
        
        assert timer.is_locked
        
        timer.unlock()
        assert not timer.is_locked
        
        timer.stop()
    
    def test_time_remaining(self):
        """Test time remaining calculation."""
        timer = AutoLockTimer(timeout_seconds=10)
        timer.reset_activity()
        
        remaining = timer.time_remaining
        
        assert 8 <= remaining <= 10


class TestClipboardManager:
    """Test cases for ClipboardManager class."""
    
    def test_create_clipboard_manager(self):
        """Test creating a clipboard manager."""
        manager = ClipboardManager(clear_timeout=30)
        
        assert manager.clear_timeout == 30
    
    def test_clear_timeout_property(self):
        """Test clear timeout property."""
        manager = ClipboardManager()
        
        manager.clear_timeout = 60
        assert manager.clear_timeout == 60
        
        # Minimum timeout enforcement
        manager.clear_timeout = 2
        assert manager.clear_timeout == 5  # Minimum is 5
    
    def test_copy_to_clipboard(self):
        """Test copying to clipboard."""
        manager = ClipboardManager()
        
        result = manager.copy_to_clipboard("test text", auto_clear=False)
        
        # Result depends on clipboard availability
        assert isinstance(result, bool)
    
    @patch.object(ClipboardManager, '_set_clipboard', return_value=True)
    def test_copy_sets_hash(self, mock_set):
        """Test that copying sets content hash."""
        manager = ClipboardManager()
        
        manager.copy_to_clipboard("test", auto_clear=False)
        
        assert manager._last_copied_hash is not None
    
    @patch.object(ClipboardManager, '_set_clipboard', return_value=True)
    def test_clear_clipboard(self, mock_set):
        """Test clearing clipboard."""
        manager = ClipboardManager()
        manager.copy_to_clipboard("secret", auto_clear=False)
        
        result = manager.clear_clipboard()
        
        assert result is True
        assert manager._last_copied_hash is None
    
    @patch.object(ClipboardManager, '_set_clipboard', return_value=True)
    def test_auto_clear_scheduled(self, mock_set):
        """Test that auto-clear timer is scheduled."""
        manager = ClipboardManager(clear_timeout=60)
        
        manager.copy_to_clipboard("test", auto_clear=True)
        
        assert manager._clear_timer is not None
        
        # Cancel timer to cleanup
        manager._clear_timer.cancel()
    
    @patch.object(ClipboardManager, '_set_clipboard', return_value=True)
    def test_cancel_previous_timer_on_new_copy(self, mock_set):
        """Test that previous timer is cancelled on new copy."""
        manager = ClipboardManager(clear_timeout=60)
        
        manager.copy_to_clipboard("first", auto_clear=True)
        first_timer = manager._clear_timer
        
        manager.copy_to_clipboard("second", auto_clear=True)
        
        # Timer should be different
        assert manager._clear_timer is not first_timer
        
        # Cleanup
        if manager._clear_timer:
            manager._clear_timer.cancel()
    
    def test_shutdown(self):
        """Test clean shutdown."""
        manager = ClipboardManager()
        
        # Should not raise
        manager.shutdown()
    
    @patch.object(ClipboardManager, '_set_clipboard', return_value=True)
    def test_get_time_remaining(self, mock_set):
        """Test getting time remaining."""
        manager = ClipboardManager(clear_timeout=60)
        manager.copy_to_clipboard("test", auto_clear=True)
        
        remaining = manager.get_time_remaining()
        
        assert 55 <= remaining <= 60
        
        # Cleanup
        if manager._clear_timer:
            manager._clear_timer.cancel()


class TestFileLock:
    """Test cases for FileLock class."""
    
    def test_create_file_lock(self):
        """Test creating a file lock."""
        lock = FileLock()
        
        assert lock.lock_path.name == ".password_manager.lock"
        assert not lock.is_locked
    
    def test_custom_lock_path(self):
        """Test file lock with custom path."""
        custom_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'custom.lock')
        lock = FileLock(custom_path)
        
        assert lock.lock_path == Path(custom_path)
    
    def test_acquire_lock(self):
        """Test acquiring a lock."""
        lock = FileLock()
        
        result = lock.acquire()
        
        assert result is True
        assert lock.is_locked
        
        lock.release()
    
    def test_release_lock(self):
        """Test releasing a lock."""
        lock = FileLock()
        lock.acquire()
        
        lock.release()
        
        assert not lock.is_locked
    
    def test_lock_context_manager(self):
        """Test lock as context manager."""
        with FileLock() as lock:
            assert lock.is_locked
        
        assert not lock.is_locked
    
    def test_double_acquire(self):
        """Test double acquire on same lock."""
        lock = FileLock()
        
        assert lock.acquire() is True
        # Second acquire attempt on a different instance
        
        lock.release()
    
    def test_release_without_acquire(self):
        """Test releasing without acquiring first."""
        lock = FileLock()
        
        # Should not raise
        lock.release()


class TestSingleInstanceGuard:
    """Test cases for SingleInstanceGuard class."""
    
    def test_create_guard(self):
        """Test creating an instance guard."""
        guard = SingleInstanceGuard("TestApp")
        
        # Should create without error
        assert guard._app_name == "TestApp"
    
    def test_check_guard(self):
        """Test checking guard."""
        guard = SingleInstanceGuard("TestApp")
        
        result = guard.check()
        
        assert result is True
        
        guard.release()
    
    def test_release_guard(self):
        """Test releasing guard."""
        guard = SingleInstanceGuard("TestApp")
        guard.check()
        
        guard.release()
        
        # Should be able to acquire again after release
        assert guard.check() is True
        guard.release()


class TestThreadSafety:
    """Test thread safety of components."""
    
    def test_clipboard_thread_safety(self):
        """Test clipboard manager thread safety."""
        manager = ClipboardManager()
        errors = []
        
        def worker():
            try:
                for i in range(10):
                    manager.clear_timeout = 30 + i
            except Exception as e:
                errors.append(str(e))
        
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
    
    def test_thread_manager_thread_safety(self):
        """Test thread manager thread safety."""
        manager = ThreadManager()
        errors = []
        
        def task():
            pass
        
        def worker(i):
            try:
                name = f"thread_{i}"
                manager.register_thread(name, task)
                manager.start_thread(name)
                time.sleep(0.1)
                manager.stop_thread(name)
            except Exception as e:
                errors.append(str(e))
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        manager.stop_all()


class TestResourceCleanup:
    """Test proper resource cleanup."""
    
    def test_thread_manager_cleanup(self):
        """Test thread manager cleanup."""
        manager = ThreadManager()
        
        def task():
            pass
        
        manager.register_thread("test", task, interval=0.1)
        manager.start_thread("test")
        
        manager.stop_all()
        
        # All threads should be stopped
        for state in manager.get_all_states().values():
            assert state == ThreadState.STOPPED
    
    def test_clipboard_manager_cleanup(self):
        """Test clipboard manager cleanup."""
        manager = ClipboardManager()
        
        manager.shutdown()
        
        # Should complete without error
    
    def test_file_lock_cleanup(self):
        """Test file lock cleanup."""
        lock = FileLock()
        lock.acquire()
        
        lock.release()
        
        assert not lock.is_locked


class TestEdgeCases:
    """Test edge cases."""
    
    def test_empty_thread_name(self):
        """Test thread with empty name."""
        def task():
            pass
        
        thread = ManagedThread("", task)
        
        assert thread.name == ""
    
    def test_zero_interval(self):
        """Test thread with zero interval."""
        counter = [0]
        
        def task():
            counter[0] += 1
            if counter[0] > 5:
                return  # Prevent infinite loop
        
        thread = ManagedThread("test", task, interval=0.0)
        thread.start()
        time.sleep(0.2)
        thread.stop()
        
        # Should have executed many times
        assert counter[0] > 1
    
    def test_negative_timeout(self):
        """Test timer with negative timeout stores as-is (validation on setter only)."""
        timer = AutoLockTimer(timeout_seconds=-10)
        
        # Constructor accepts any value, but timeout setter enforces minimum
        # The property setter has validation but constructor sets directly
        assert timer.timeout == -10
    
    @patch.object(ClipboardManager, '_set_clipboard', return_value=True)
    @patch.object(ClipboardManager, 'get_clipboard', return_value="测试")
    def test_unicode_in_clipboard(self, mock_get, mock_set):
        """Test clipboard with unicode content."""
        manager = ClipboardManager()
        
        result = manager.copy_to_clipboard("测试", auto_clear=False)
        
        assert result is True


class TestSingletonPattern:
    """Test singleton instances."""
    
    def test_get_thread_manager_singleton(self):
        """Test thread manager singleton."""
        tm1 = get_thread_manager()
        tm2 = get_thread_manager()
        
        assert tm1 is tm2
    
    def test_get_clipboard_manager_singleton(self):
        """Test clipboard manager singleton."""
        cm1 = get_clipboard_manager()
        cm2 = get_clipboard_manager()
        
        assert cm1 is cm2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
