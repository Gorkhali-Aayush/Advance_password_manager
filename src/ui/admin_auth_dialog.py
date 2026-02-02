"""
Admin Authentication Dialog

Dialog for authenticating admin operations with password verification.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Callable

# Add parent directory to path for cross-package imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.base_window import BaseWindow
from core.session_manager import get_session_manager
from crypto.fernet_engine import get_encryption_engine
from storage.mysql_engine import get_database


class AdminAuthDialog(BaseWindow):
    """
    Dialog for admin password authentication.
    
    Used to verify admin identity before performing sensitive operations
    like changing user roles.
    """
    
    def __init__(self, parent: Optional[tk.Tk] = None, 
                 operation: str = "sensitive operation"):
        """
        Initialize the admin auth dialog.
        
        Args:
            parent: Parent window
            operation: Description of the operation requiring authentication
        """
        super().__init__(
            parent=parent,
            title="🔐 Admin Authentication Required",
            width=450,
            height=280
        )
        
        self._operation = operation
        self._authenticated = False
        self._result = None
        
        # Make dialog modal
        if parent:
            self._root.transient(parent)
        
        # Get dependencies
        self._session = get_session_manager()
        self._crypto = get_encryption_engine()
        self._db = get_database()
        
        # Build UI
        self._build_ui()
        
        # Center dialog on parent
        self._root.update_idletasks()
        if parent:
            x = parent.winfo_x() + (parent.winfo_width() // 2) - (self._root.winfo_width() // 2)
            y = parent.winfo_y() + (parent.winfo_height() // 2) - (self._root.winfo_height() // 2)
            self._root.geometry(f"+{x}+{y}")
        
        # Make dialog modal AFTER building UI and centering
        if parent:
            self._root.grab_set()
        
    def _build_ui(self) -> None:
        """Build the authentication dialog UI."""
        # Configure root window
        self._root.resizable(False, False)
        
        main_frame = ttk.Frame(self._root, padding=20)
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title = ttk.Label(
            main_frame,
            text="🔐 Admin Authentication Required",
            font=('Segoe UI', 12, 'bold')
        )
        title.pack(pady=(0, 15))
        
        # Operation description
        desc = ttk.Label(
            main_frame,
            text=f"Authenticating for:\n{self._operation}\n\nPlease enter your admin password",
            wraplength=350,
            justify='center'
        )
        desc.pack(pady=(0, 20))
        
        # Password field
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(fill='both', expand=True, pady=10)
        
        ttk.Label(password_frame, text="Admin Password:").pack(anchor='w', pady=(0, 5))
        self._password_entry = ttk.Entry(password_frame, show='•', width=40)
        self._password_entry.pack(fill='both', expand=True, pady=5, ipady=8)
        self._password_entry.bind('<Return>', lambda e: self._authenticate())
        
        # Status
        self._status_var = tk.StringVar(value="")
        status_label = ttk.Label(
            main_frame,
            textvariable=self._status_var,
            foreground='red'
        )
        status_label.pack(pady=10, fill='x')
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(15, 0))
        
        ttk.Button(
            button_frame,
            text="✓ Authenticate",
            command=self._authenticate,
            width=20
        ).pack(side='left', padx=5, ipady=5)
        
        ttk.Button(
            button_frame,
            text="✗ Cancel",
            command=self._cancel,
            width=20
        ).pack(side='left', padx=5, ipady=5)
        
        # Set focus to password entry
        self._root.after(100, self._password_entry.focus)
    
    def _authenticate(self) -> None:
        """Authenticate the admin password."""
        password = self._password_entry.get()
        
        if not password:
            self._status_var.set("Please enter your password")
            return
        
        try:
            # Get current admin user from session
            current_user_id = self._session.current_session.user_id
            current_username = self._session.current_session.username
            
            # Get user from database
            user = self._db.get_user(current_username)
            if not user:
                self._status_var.set("User not found in database")
                return
            
            # Verify password
            salt = bytes.fromhex(user['salt'])
            stored_hash = user['master_password_hash']
            
            if self._crypto.verify_password(password, salt, stored_hash):
                # Authentication successful
                self._authenticated = True
                self._result = True
                self._root.destroy()
            else:
                self._status_var.set("❌ Incorrect password")
                self._password_entry.delete(0, tk.END)
                self._password_entry.focus()
        
        except Exception as e:
            self._status_var.set(f"Error: {str(e)}")
    
    def _cancel(self) -> None:
        """Cancel the authentication."""
        self._result = False
        self._root.destroy()
    
    def is_authenticated(self) -> bool:
        """
        Check if authentication was successful.
        
        Returns:
            True if admin password was correctly verified
        """
        return self._authenticated
    
    @staticmethod
    def authenticate(parent: Optional[tk.Tk] = None, 
                    operation: str = "sensitive operation") -> bool:
        """
        Show the authentication dialog and return result.
        
        Args:
            parent: Parent window
            operation: Description of operation requiring auth
            
        Returns:
            True if authentication successful, False otherwise
        """
        dialog = AdminAuthDialog(parent=parent, operation=operation)
        dialog._root.wait_window()
        return dialog.is_authenticated()
