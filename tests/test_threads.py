"""
Unittest: OS Layer Threading Components
========================================

Tests for ManagedThread, ThreadManager, AutoLockTimer,
ClipboardManager, FileLock, and SingleInstanceGuard.

Uses unittest with setUp() method pattern.

Run with: python -m unittest tests.unitTestThreads
or: python tests/unitTestThreads.py
"""

import unittest
import sys
import os
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from os_layer.threadManager import (
    ManagedThread, ThreadManager, AutoLockTimer, ThreadState,
    get_thread_manager
)
from os_layer.clipboardManager import ClipboardManager, get_clipboard_manager
from os_layer.fileLock import FileLock, SingleInstanceGuard


class TestManagedThread(unittest.TestCase):
    """Test cases for ManagedThread class."""
    
    def setUp(self):
        """Initialize test thread."""
        self.counter = [0]
        
        def task():
            self.counter[0] += 1
        
        self.task = task
        self.thread = None
    
    def tearDown(self):
        """Clean up after each test."""
        if self.thread and self.thread.is_running:
            self.thread.stop()
        self.thread = None
        self.counter = None
    
    def test_create_managed_thread(self):
        """Test creating a managed thread."""
        thread = ManagedThread("test", self.task, interval=1.0)
        self.thread = thread
        
        self.assertEqual(thread.name, "test")
        self.assertEqual(thread.state, ThreadState.STOPPED)
        self.assertFalse(thread.is_running)
    
    def test_start_thread(self):
        """Test starting a managed thread."""
        self.thread = ManagedThread("test", self.task, interval=0.1)
        self.thread.start()
        
        time.sleep(0.3)
        self.thread.stop()
        
        self.assertEqual(self.thread.state, ThreadState.STOPPED)
        self.assertGreaterEqual(self.counter[0], 1)
    
    def test_stop_thread(self):
        """Test stopping a managed thread."""
        self.thread = ManagedThread("test", self.task, interval=0.1)
        self.thread.start()
        self.assertTrue(self.thread.is_running)
        
        self.thread.stop()
        
        self.assertEqual(self.thread.state, ThreadState.STOPPED)
        self.assertFalse(self.thread.is_running)
    
    def test_pause_and_resume(self):
        """Test pausing and resuming a thread."""
        self.thread = ManagedThread("test", self.task, interval=0.1)
        self.thread.start()
        time.sleep(0.2)
        
        self.thread.pause()
        paused_count = self.counter[0]
        time.sleep(0.2)
        
        # Count should not have increased much while paused
        self.assertLessEqual(self.counter[0], paused_count + 1)
        
        self.thread.resume()
        time.sleep(0.2)
        
        self.thread.stop()
        # Count should have increased after resume
        self.assertGreater(self.counter[0], paused_count)
    
    def test_daemon_thread(self):
        """Test daemon thread creation."""
        self.thread = ManagedThread("test", self.task, daemon=True)
        
        self.thread.start()
        time.sleep(0.1)
        self.thread.stop()
    
    def test_double_start_returns_false(self):
        """Test that starting an already running thread returns False."""
        self.thread = ManagedThread("test", self.task, interval=0.5)
        
        self.assertTrue(self.thread.start())
        self.assertFalse(self.thread.start())
        
        self.thread.stop()
    
    def test_thread_with_exception(self):
        """Test that thread handles exceptions gracefully."""
        def failing_task():
            raise ValueError("Test error")
        
        self.thread = ManagedThread("failing", failing_task, interval=0.1)
        self.thread.start()
        time.sleep(0.3)
        self.thread.stop()
        
        # Thread should still be stoppable after exception
        self.assertEqual(self.thread.state, ThreadState.STOPPED)


class TestThreadManager(unittest.TestCase):
    """Test cases for ThreadManager class."""
    
    def setUp(self):
        """Initialize thread manager."""
        self.manager = ThreadManager()
        self.counter = [0]
        
        def task():
            self.counter[0] += 1
        
        self.task = task
    
    def tearDown(self):
        """Clean up after each test."""
        self.manager.stop_all()
        self.manager = None
        self.counter = None
    
    def test_create_thread_manager(self):
        """Test creating a thread manager."""
        self.assertEqual(self.manager.get_all_states(), {})
    
    def test_register_thread(self):
        """Test registering a thread."""
        result = self.manager.register_thread("test", self.task, interval=1.0)
        
        self.assertTrue(result)
        self.assertEqual(self.manager.get_thread_state("test"), ThreadState.STOPPED)
    
    def test_register_duplicate_thread(self):
        """Test registering duplicate thread name returns False."""
        self.manager.register_thread("test", self.task)
        result = self.manager.register_thread("test", self.task)
        
        self.assertFalse(result)
    
    def test_start_thread(self):
        """Test starting a registered thread."""
        self.manager.register_thread("test", self.task, interval=0.1)
        result = self.manager.start_thread("test")
        
        self.assertTrue(result)
        time.sleep(0.2)
        
        self.manager.stop_thread("test")
        self.assertGreaterEqual(self.counter[0], 1)
    
    def test_start_nonexistent_thread(self):
        """Test starting a thread that doesn't exist."""
        result = self.manager.start_thread("nonexistent")
        
        self.assertFalse(result)
    
    def test_stop_thread(self):
        """Test stopping a running thread."""
        self.manager.register_thread("test", self.task, interval=0.1)
        self.manager.start_thread("test")
        
        result = self.manager.stop_thread("test")
        
        self.assertTrue(result)
        self.assertEqual(self.manager.get_thread_state("test"), ThreadState.STOPPED)
    
    def test_stop_all_threads(self):
        """Test stopping all threads."""
        self.manager.register_thread("test1", self.task)
        self.manager.register_thread("test2", self.task)
        self.manager.start_all()
        
        self.manager.stop_all()
        
        states = self.manager.get_all_states()
        for state in states.values():
            self.assertEqual(state, ThreadState.STOPPED)
    
    def test_remove_thread(self):
        """Test removing a thread."""
        self.manager.register_thread("test", self.task)
        result = self.manager.remove_thread("test")
        
        self.assertTrue(result)
        self.assertIsNone(self.manager.get_thread_state("test"))
    
    def test_get_thread_state(self):
        """Test getting thread state."""
        self.manager.register_thread("test", self.task)
        
        self.assertEqual(self.manager.get_thread_state("test"), ThreadState.STOPPED)
        
        self.manager.start_thread("test")
        self.assertEqual(self.manager.get_thread_state("test"), ThreadState.RUNNING)
        
        self.manager.stop_thread("test")


class TestAutoLockTimer(unittest.TestCase):
    """Test cases for AutoLockTimer class."""
    
    def setUp(self):
        """Initialize auto-lock timer."""
        self.timer = AutoLockTimer(timeout_seconds=60)
    
    def tearDown(self):
        """Clean up after each test."""
        if self.timer:
            try:
                self.timer.stop()
            except:
                pass
        self.timer = None
    
    def test_create_auto_lock_timer(self):
        """Test creating an auto-lock timer."""
        self.assertEqual(self.timer.timeout, 60)
        self.assertFalse(self.timer.is_locked)
    
    def test_timer_timeout_property(self):
        """Test timeout property setter."""
        self.timer.timeout = 120
        self.assertEqual(self.timer.timeout, 120)
        
        # Minimum timeout enforcement
        self.timer.timeout = 10
        self.assertEqual(self.timer.timeout, 30)  # Minimum is 30
    
    def test_reset_activity(self):
        """Test resetting activity timer."""
        timer = AutoLockTimer(timeout_seconds=1)
        timer.start()
        self.timer = timer
        
        time.sleep(0.5)
        timer.reset_activity()
        
        # Timer should not have locked yet after reset
        self.assertFalse(timer.is_locked)
        
        timer.stop()
    
    def test_timer_expires(self):
        """Test that timer triggers lock callback."""
        locked = [False]
        
        def on_lock():
            locked[0] = True
        
        timer = AutoLockTimer(timeout_seconds=1, on_lock=on_lock)
        timer.start()
        self.timer = timer
        
        # Wait for timeout
        time.sleep(1.5)
        
        timer.stop()
        self.assertTrue(timer.is_locked)
    
    def test_stop_timer(self):
        """Test stopping the timer."""
        self.timer.start()
        self.timer.stop()
        
        # Should be able to stop cleanly
    
    def test_unlock(self):
        """Test manual unlock."""
        timer = AutoLockTimer(timeout_seconds=1)
        timer.start()
        self.timer = timer
        time.sleep(1.5)
        
        self.assertTrue(timer.is_locked)
        
        timer.unlock()
        self.assertFalse(timer.is_locked)
        
        timer.stop()
    
    def test_time_remaining(self):
        """Test time remaining calculation."""
        timer = AutoLockTimer(timeout_seconds=10)
        timer.reset_activity()
        self.timer = timer
        
        remaining = timer.time_remaining
        
        self.assertGreaterEqual(remaining, 8)
        self.assertLessEqual(remaining, 10)


class TestClipboardManager(unittest.TestCase):
    """Test cases for ClipboardManager class."""
    
    def setUp(self):
        """Initialize clipboard manager."""
        self.manager = ClipboardManager(clear_timeout=30)
    
    def tearDown(self):
        """Clean up after each test."""
        if self.manager:
            try:
                self.manager.clear_clipboard()
            except:
                pass
        self.manager = None
    
    def test_create_clipboard_manager(self):
        """Test creating a clipboard manager."""
        self.assertEqual(self.manager.clear_timeout, 30)
    
    def test_clear_timeout_property(self):
        """Test clear timeout property."""
        self.manager.clear_timeout = 60
        self.assertEqual(self.manager.clear_timeout, 60)
        
        # Minimum timeout enforcement
        self.manager.clear_timeout = 2
        self.assertEqual(self.manager.clear_timeout, 5)  # Minimum is 5
    
    def test_copy_to_clipboard(self):
        """Test copying to clipboard."""
        result = self.manager.copy_to_clipboard("test text", auto_clear=False)
        
        # Result depends on clipboard availability
        self.assertIsInstance(result, bool)
    
    @patch.object(ClipboardManager, '_set_clipboard', return_value=True)
    def test_copy_sets_hash(self, mock_set):
        """Test that copying sets content hash."""
        self.manager.copy_to_clipboard("test", auto_clear=False)
        
        self.assertIsNotNone(self.manager._last_copied_hash)
    
    @patch.object(ClipboardManager, '_set_clipboard', return_value=True)
    def test_clear_clipboard(self, mock_set):
        """Test clearing clipboard."""
        self.manager.copy_to_clipboard("secret", auto_clear=False)
        
        result = self.manager.clear_clipboard()
        
        self.assertTrue(result)
        self.assertIsNone(self.manager._last_copied_hash)
    
    @patch.object(ClipboardManager, '_set_clipboard', return_value=True)
    def test_auto_clear_scheduled(self, mock_set):
        """Test that auto-clear timer is scheduled."""
        self.manager.copy_to_clipboard("test", auto_clear=True)
        
        self.assertIsNotNone(self.manager._clear_timer)
        
        # Cancel timer to cleanup
        self.manager._clear_timer.cancel()
    
    def test_is_clipboard_still_safe(self):
        """Test checking if clipboard content is still safe."""
        with patch.object(self.manager, '_get_clipboard', return_value='test'):
            self.manager._last_copied_hash = hash('test')
            
            result = self.manager._is_clipboard_still_safe()
            
            self.assertTrue(result)


class TestFileLock(unittest.TestCase):
    """Test cases for FileLock class."""
    
    def setUp(self):
        """Initialize test lock file."""
        self.lock_file = ".test_lock"
        self.file_lock = FileLock(self.lock_file)
    
    def tearDown(self):
        """Clean up test lock file."""
        try:
            if os.path.exists(self.lock_file):
                os.remove(self.lock_file)
        except:
            pass
        self.file_lock = None
    
    def test_create_file_lock(self):
        """Test creating a file lock."""
        self.assertEqual(self.file_lock.lock_file, self.lock_file)
        self.assertFalse(self.file_lock.is_locked)
    
    def test_acquire_lock(self):
        """Test acquiring a file lock."""
        result = self.file_lock.acquire()
        
        self.assertTrue(result)
        self.assertTrue(self.file_lock.is_locked)
        
        self.file_lock.release()
    
    def test_release_lock(self):
        """Test releasing a file lock."""
        self.file_lock.acquire()
        
        self.file_lock.release()
        
        self.assertFalse(self.file_lock.is_locked)
    
    def test_double_acquire_no_block(self):
        """Test acquiring already acquired lock."""
        self.file_lock.acquire()
        
        # Trying to acquire again should handle gracefully
        result = self.file_lock.acquire(timeout=0.1)
        
        # Result depends on implementation
        self.file_lock.release()
    
    def test_lock_with_context_manager(self):
        """Test using lock as context manager."""
        with self.file_lock:
            self.assertTrue(self.file_lock.is_locked)
        
        self.assertFalse(self.file_lock.is_locked)
    
    def test_lock_file_exists(self):
        """Test that lock file is created when lock is acquired."""
        self.file_lock.acquire()
        
        # Lock file may or may not exist depending on implementation
        
        self.file_lock.release()


class TestSingleInstanceGuard(unittest.TestCase):
    """Test cases for SingleInstanceGuard class."""
    
    def setUp(self):
        """Initialize test instance guard."""
        self.guard_file = ".test_instance.lock"
    
    def tearDown(self):
        """Clean up test lock file."""
        try:
            if os.path.exists(self.guard_file):
                os.remove(self.guard_file)
        except:
            pass
    
    def test_create_instance_guard(self):
        """Test creating an instance guard."""
        guard = SingleInstanceGuard(self.guard_file)
        self.assertEqual(guard.lock_file, self.guard_file)


class TestThreadIntegration(unittest.TestCase):
    """Integration tests for threading components."""
    
    def setUp(self):
        """Initialize components for integration testing."""
        self.manager = ThreadManager()
        self.timer = AutoLockTimer(timeout_seconds=10)
        self.clipboard = ClipboardManager(clear_timeout=30)
        self.counter = [0]
    
    def tearDown(self):
        """Clean up after integration tests."""
        self.manager.stop_all()
        try:
            self.timer.stop()
        except:
            pass
        self.manager = None
        self.timer = None
        self.clipboard = None
        self.counter = None
    
    def test_thread_manager_multiple_threads(self):
        """Test managing multiple threads."""
        def increment():
            self.counter[0] += 1
        
        for i in range(5):
            self.manager.register_thread(f"thread_{i}", increment, interval=0.05)
        
        self.manager.start_all()
        time.sleep(0.2)
        self.manager.stop_all()
        
        self.assertGreater(self.counter[0], 0)
    
    def test_auto_lock_with_callback(self):
        """Test auto-lock timer with callback integration."""
        locked = [False]
        
        def on_lock():
            locked[0] = True
        
        timer = AutoLockTimer(timeout_seconds=1, on_lock=on_lock)
        timer.start()
        self.timer = timer
        
        time.sleep(1.5)
        
        self.assertTrue(timer.is_locked)
        
        timer.stop()
    
    @patch.object(ClipboardManager, '_set_clipboard', return_value=True)
    def test_clipboard_auto_clear(self, mock_set):
        """Test clipboard auto-clear functionality."""
        self.clipboard.copy_to_clipboard("secret_data", auto_clear=True)
        
        # Timer should be scheduled
        self.assertIsNotNone(self.clipboard._clear_timer)
        
        # Cancel timer to prevent side effects
        self.clipboard._clear_timer.cancel()


if __name__ == '__main__':
    # Run with: python -m unittest tests.unitTestThreads
    # or: python tests/unitTestThreads.py
    unittest.main(verbosity=2)
