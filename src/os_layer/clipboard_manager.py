"""
Clipboard Manager

Handles Windows clipboard operations with security features.
Demonstrates OS-level interaction.
"""

import threading
import time
from typing import Optional, Callable
from datetime import datetime

# Try to import Windows-specific modules
try:
    import ctypes
    from ctypes import wintypes
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

# Alternative: try pyperclip for cross-platform
try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False


class ClipboardManager:
    """
    Manages clipboard operations with security focus.
    
    Features:
    - Copy sensitive data to clipboard
    - Auto-clear after timeout
    - Track clipboard ownership
    - Secure overwrite on clear
    
    Why this exists:
    - Security: Passwords shouldn't stay in clipboard
    - OS Interaction: Direct Windows API usage
    - User convenience: Easy copy with protection
    """
    
    # Default clear timeout in seconds
    DEFAULT_CLEAR_TIMEOUT = 30
    
    def __init__(self, clear_timeout: int = DEFAULT_CLEAR_TIMEOUT,
                 on_clear: Optional[Callable] = None):
        """
        Initialize clipboard manager.
        
        Args:
            clear_timeout: Seconds before auto-clear
            on_clear: Callback when clipboard is cleared
        """
        self._clear_timeout = clear_timeout
        self._on_clear = on_clear
        self._lock = threading.Lock()
        self._clear_timer: Optional[threading.Timer] = None
        self._copy_timestamp: Optional[datetime] = None
    
    @property
    def clear_timeout(self) -> int:
        return self._clear_timeout
    
    @clear_timeout.setter
    def clear_timeout(self, seconds: int) -> None:
        with self._lock:
            self._clear_timeout = max(5, seconds)  # Minimum 5 seconds
    
    def copy_to_clipboard(self, text: str, auto_clear: bool = True) -> bool:
        """
        Copy text to clipboard.
        
        Args:
            text: Text to copy
            auto_clear: Whether to auto-clear after timeout
            
        Returns:
            True if successful
        """
        with self._lock:
            # Cancel any existing timer
            if self._clear_timer:
                self._clear_timer.cancel()
                self._clear_timer = None
            
            success = self._set_clipboard(text)
            
            if success:
                self._copy_timestamp = datetime.now()
                
                # Schedule auto-clear
                if auto_clear:
                    self._clear_timer = threading.Timer(
                        self._clear_timeout,
                        self._auto_clear
                    )
                    self._clear_timer.daemon = True
                    self._clear_timer.start()
            
            return success
    
    def _set_clipboard(self, text: str) -> bool:
        """
        Set clipboard content using available method.
        
        Args:
            text: Text to set
            
        Returns:
            True if successful
        """
        # Try pyperclip first (most reliable cross-platform)
        if HAS_PYPERCLIP:
            try:
                pyperclip.copy(text)
                return True
            except Exception:
                pass
        
        # Try Windows API directly
        if HAS_WIN32:
            try:
                return self._set_clipboard_win32(text)
            except Exception:
                pass
        
        # Fallback: try tkinter
        try:
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()
            root.clipboard_clear()
            root.clipboard_append(text)
            root.update()  # Required for clipboard to work
            root.destroy()
            return True
        except Exception:
            pass
        
        return False
    
    def _set_clipboard_win32(self, text: str) -> bool:
        """
        Set clipboard using Windows API.
        
        Args:
            text: Text to set
            
        Returns:
            True if successful
        """
        CF_UNICODETEXT = 13
        GMEM_MOVEABLE = 0x0002
        
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        
        # Open clipboard
        if not user32.OpenClipboard(None):
            return False
        
        try:
            user32.EmptyClipboard()
            
            # Encode text
            data = text.encode('utf-16-le') + b'\x00\x00'
            
            # Allocate global memory
            h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
            if not h_mem:
                return False
            
            # Lock and copy
            ptr = kernel32.GlobalLock(h_mem)
            if not ptr:
                kernel32.GlobalFree(h_mem)
                return False
            
            ctypes.memmove(ptr, data, len(data))
            kernel32.GlobalUnlock(h_mem)
            
            # Set clipboard data
            if not user32.SetClipboardData(CF_UNICODETEXT, h_mem):
                kernel32.GlobalFree(h_mem)
                return False
            
            return True
            
        finally:
            user32.CloseClipboard()
    
    def get_clipboard(self) -> Optional[str]:
        """
        Get current clipboard content.
        
        Returns:
            Clipboard text or None
        """
        if HAS_PYPERCLIP:
            try:
                return pyperclip.paste()
            except Exception:
                pass
        
        if HAS_WIN32:
            try:
                return self._get_clipboard_win32()
            except Exception:
                pass
        
        try:
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()
            try:
                text = root.clipboard_get()
            except tk.TclError:
                text = None
            root.destroy()
            return text
        except Exception:
            pass
        
        return None
    
    def _get_clipboard_win32(self) -> Optional[str]:
        """Get clipboard using Windows API."""
        CF_UNICODETEXT = 13
        
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        
        if not user32.OpenClipboard(None):
            return None
        
        try:
            h_data = user32.GetClipboardData(CF_UNICODETEXT)
            if not h_data:
                return None
            
            ptr = kernel32.GlobalLock(h_data)
            if not ptr:
                return None
            
            try:
                text = ctypes.wstring_at(ptr)
                return text
            finally:
                kernel32.GlobalUnlock(h_data)
                
        finally:
            user32.CloseClipboard()
    
    def clear_clipboard(self) -> bool:
        """
        Clear the clipboard.
        
        Uses secure overwrite before clearing.
        
        Returns:
            True if successful
        """
        with self._lock:
            # Cancel timer if active
            if self._clear_timer:
                self._clear_timer.cancel()
                self._clear_timer = None
            
            # Overwrite with garbage first (security)
            self._set_clipboard("*" * 64)
            
            # Then clear
            success = self._set_clipboard("")
            
            if success:
                self._last_copied_hash = None
                self._copy_timestamp = None
                
                if self._on_clear:
                    try:
                        self._on_clear()
                    except Exception:
                        pass
            
            return success
    
    def _auto_clear(self) -> None:
        """
        Auto-clear callback.
        
        Only clears if we still own the clipboard content.
        """
        with self._lock:
            # Check if clipboard still has our content
            current = self.get_clipboard()
            if current:
                import hashlib
                current_hash = hashlib.sha256(current.encode()).hexdigest()
                
                if current_hash == self._last_copied_hash:
                    # Still our content, clear it
                    self._set_clipboard("")
                    self._last_copied_hash = None
                    self._copy_timestamp = None
                    
                    if self._on_clear:
                        try:
                            self._on_clear()
                        except Exception:
                            pass
    
    def is_our_content(self) -> bool:
        """
        Check if clipboard still contains our copied content.
        
        Returns:
            True if we own the clipboard content
        """
        if not self._last_copied_hash:
            return False
        
        current = self.get_clipboard()
        if not current:
            return False
        
        import hashlib
        current_hash = hashlib.sha256(current.encode()).hexdigest()
        return current_hash == self._last_copied_hash
    
    def get_time_remaining(self) -> int:
        """
        Get seconds until auto-clear.
        
        Returns:
            Seconds remaining, or 0 if not active
        """
        with self._lock:
            if not self._copy_timestamp or not self._clear_timer:
                return 0
            
            elapsed = (datetime.now() - self._copy_timestamp).total_seconds()
            remaining = self._clear_timeout - elapsed
            return max(0, int(remaining))
    
    def shutdown(self) -> None:
        """Clean shutdown - clear any sensitive data."""
        self.clear_clipboard()


# Singleton instance
_clipboard_manager: Optional[ClipboardManager] = None


def get_clipboard_manager() -> ClipboardManager:
    """
    Get the singleton clipboard manager instance.
    
    Returns:
        ClipboardManager instance
    """
    global _clipboard_manager
    if _clipboard_manager is None:
        _clipboard_manager = ClipboardManager()
    return _clipboard_manager
