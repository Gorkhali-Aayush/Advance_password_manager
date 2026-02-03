"""
OS Layer Package

Provides OS-level functionality including threading,
clipboard management, and file locking.
"""

from .threadManager import (
    ThreadManager,
    ManagedThread,
    ThreadState,
    AutoLockTimer,
    get_thread_manager
)
from .clipboardManager import ClipboardManager, get_clipboard_manager
from .fileLock import FileLock, SingleInstanceGuard, get_instance_guard

__all__ = [
    'ThreadManager',
    'ManagedThread',
    'ThreadState',
    'AutoLockTimer',
    'get_thread_manager',
    'ClipboardManager',
    'get_clipboard_manager',
    'FileLock',
    'SingleInstanceGuard',
    'get_instance_guard'
]
