"""
Login Window

Handles user authentication with master password.
First window shown when application starts.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable
import logging

# Add parent directory to path for cross-package imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.base_window import BaseWindow
from core.session_manager import get_session_manager
from crypto.fernet_engine import get_encryption_engine
from storage.mysql_engine import get_database

logger = logging.getLogger(__name__)


class LoginWindow(BaseWindow):
    """
    Login window for master password authentication.
    
    Features:
    - Master password entry
    - Login/Register modes
    - Failed attempt tracking
    - UI lockout after failures
    
    Security:
    - Password never stored in plain text
    - Lockout prevents brute force
    """
    
    # Maximum failed login attempts before lockout
    MAX_ATTEMPTS = 5
    
    # Lockout duration in seconds
    LOCKOUT_DURATION = 60
    
    def __init__(self, on_login_success: Optional[Callable] = None):
        """
        Initialize login window.
        
        Args:
            on_login_success: Callback when login succeeds
        """
        super().__init__(
            title="Password Manager - Login",
            width=550,
            height=550,
            resizable=False
        )
        
        self._on_login_success = on_login_success
        self._failed_attempts = 0
        self._lockout_until: Optional[float] = None
        self._is_register_mode = False
        
        # Get dependencies
        self._session = get_session_manager()
        self._crypto = get_encryption_engine()
        self._db = get_database()
        
        # Build UI
        self._build_ui()
    
    def _build_ui(self) -> None:
        """Build the login interface."""
        # Main container
        main_frame = ttk.Frame(self._root, padding=30)
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="🔐 Password Manager",
            style='Title.TLabel'
        )
        title_label.pack(pady=(0, 5))
        
        subtitle_label = ttk.Label(
            main_frame,
            text="Secure your digital life",
            style='Subtitle.TLabel'
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Register mode title (hidden initially)
        self._register_title = ttk.Label(
            main_frame,
            text="📝 Register New User",
            font=('Segoe UI', 12),
            foreground='#1976D2'
        )
        # Don't pack it yet - will be shown in register mode
        
        # Username field
        username_frame, _, self._username_entry, self._username_var = \
            self.create_label_entry(main_frame, "Username:", width=35)
        username_frame.pack(fill='x', pady=(0, 15))
        
        # Password field with show/hide button
        self._password_frame = ttk.Frame(main_frame)
        self._password_frame.pack(fill='x', pady=(0, 10))
        
        password_label = ttk.Label(self._password_frame, text="Master Password:")
        password_label.pack(anchor='w')
        
        password_input_frame = ttk.Frame(self._password_frame)
        password_input_frame.pack(fill='x', pady=(2, 0))
        
        self._password_var = tk.StringVar()
        self._password_entry = ttk.Entry(password_input_frame, width=32, show='•')
        self._password_entry.pack(side='left', fill='x', expand=True)
        
        self._password_visible = False
        self._password_eye_btn = ttk.Button(
            password_input_frame, text="👁", width=3,
            command=self._toggle_password_visibility
        )
        self._password_eye_btn.pack(side='left', padx=(5, 0))
        
        # Confirm password field with show/hide button (for registration)
        self._confirm_frame = ttk.Frame(main_frame)
        
        confirm_label = ttk.Label(self._confirm_frame, text="Confirm Password:")
        confirm_label.pack(anchor='w')
        
        confirm_input_frame = ttk.Frame(self._confirm_frame)
        confirm_input_frame.pack(fill='x', pady=(2, 0))
        
        self._confirm_var = tk.StringVar()
        self._confirm_entry = ttk.Entry(confirm_input_frame, width=32, show='•')
        self._confirm_entry.pack(side='left', fill='x', expand=True)
        
        self._confirm_visible = False
        self._confirm_eye_btn = ttk.Button(
            confirm_input_frame, text="👁", width=3,
            command=self._toggle_confirm_visibility
        )
        self._confirm_eye_btn.pack(side='left', padx=(5, 0))
        # Initially hidden
        
        # Status label
        self._status_var = tk.StringVar()
        self._status_label = ttk.Label(
            main_frame,
            textvariable=self._status_var,
            foreground=self.COLORS['error']
        )
        self._status_label.pack(pady=(10, 10))
        
        # Login button
        self._login_button = ttk.Button(
            main_frame,
            text="Login",
            command=self._on_login_click,
            width=20
        )
        self._login_button.pack(pady=(10, 5))
        
        # Register toggle
        self._toggle_button = ttk.Button(
            main_frame,
            text="Create Account",
            command=self._toggle_mode,
            width=20
        )
        self._toggle_button.pack(pady=(5, 0))
        
        # Bind Enter key
        self.bind_enter_key(self._password_entry, self._on_login_click)
        self.bind_enter_key(self._username_entry, 
                           lambda: self._password_entry.focus())
        
        # Focus username
        self._username_entry.focus()
    
    def _toggle_password_visibility(self) -> None:
        """Toggle password field visibility."""
        self._password_visible = not self._password_visible
        if self._password_visible:
            self._password_entry.configure(show='')
            self._password_eye_btn.configure(text='🔒')
        else:
            self._password_entry.configure(show='•')
            self._password_eye_btn.configure(text='👁')
    
    def _toggle_confirm_visibility(self) -> None:
        """Toggle confirm password field visibility."""
        self._confirm_visible = not self._confirm_visible
        if self._confirm_visible:
            self._confirm_entry.configure(show='')
            self._confirm_eye_btn.configure(text='🔒')
        else:
            self._confirm_entry.configure(show='•')
            self._confirm_eye_btn.configure(text='👁')
    
    def _toggle_mode(self) -> None:
        """Toggle between login and register modes."""
        self._is_register_mode = not self._is_register_mode
        
        if self._is_register_mode:
            # Show register title
            self._register_title.pack(before=self._username_entry.master, pady=(0, 15))
            # Update button text
            self._login_button.configure(text="Register")
            self._toggle_button.configure(text="Back to Login")
            # Unpack and repack widgets in correct order
            self._status_label.pack_forget()
            self._login_button.pack_forget()
            self._toggle_button.pack_forget()
            # Pack confirm password field
            self._confirm_frame.pack(fill='x', pady=(0, 10))
            # Repack status and buttons
            self._status_label.pack(pady=(5, 5))
            self._login_button.pack(pady=(5, 5))
            self._toggle_button.pack(pady=(5, 0))
            # Bind Enter key on confirm field
            self.bind_enter_key(self._confirm_entry, self._on_login_click)
            self._confirm_entry.focus()
            self._status_var.set("")
            # Resize window to fit new content
            self._root.update_idletasks()
        else:
            # Hide register title
            self._register_title.pack_forget()
            # Update button text
            self._login_button.configure(text="Login")
            self._toggle_button.configure(text="Create Account")
            self._confirm_frame.pack_forget()
            self._confirm_var.set("")
            self._status_var.set("")
            self._username_entry.focus()
    
    def _on_login_click(self) -> None:
        """Handle login/register button click."""
        # Check lockout
        if self._is_locked_out():
            return
        
        # Get values directly from entry widgets (StringVar binding unreliable)
        username = self._username_entry.get().strip()
        password = self._password_entry.get()
        
        # Validate inputs
        if not username:
            self._status_var.set("Please enter a username")
            return
        
        if not password:
            self._status_var.set("Please enter a password")
            return
        
        if self._is_register_mode:
            self._handle_register(username, password)
        else:
            self._handle_login(username, password)
    
    def _handle_login(self, username: str, password: str) -> None:
        """
        Handle login attempt.
        
        Args:
            username: Username
            password: Password
        """
        # Get user from database
        user = self._db.get_user(username)
        
        if not user:
            self._on_failed_attempt()
            self._status_var.set("Invalid username or password")
            return
        
        # Verify password
        salt = bytes.fromhex(user['salt'])
        stored_hash = user['master_password_hash']
        role = user.get('role', 'user')
        
        if not self._crypto.verify_password(password, salt, stored_hash):
            self._on_failed_attempt()
            self._status_var.set("Invalid username or password")
            return
        
        # Login successful
        self._failed_attempts = 0
        
        if not self._session.login(user['id'], username, password, salt, user.get('role', 'user')):
            self._status_var.set("Login failed. Please try again.")
            logger.error(f"Login failed for user {username}")
            return
        
        # Login successful
        self._failed_attempts = 0
        logger.info(f"User {username} logged in successfully with role: {user.get('role', 'user')}")
        self._status_var.set("")
        
        if self._on_login_success:
            # Derive master key from password for vault encryption
            master_key = self._crypto.derive_key(password, salt)
            # Hide window before callback (callback may destroy the root)
            # Note: Don't call hide() as the callback will handle window transition
            self._on_login_success(username, master_key)
    
    def _handle_register(self, username: str, password: str) -> None:
        """
        Handle registration attempt.
        
        Args:
            username: Username
            password: Password
        """
        from tkinter import messagebox
        
        try:
            # Get confirm password directly from entry widget
            confirm = self._confirm_entry.get()
            
            # Check password match
            if password != confirm:
                self._status_var.set("Passwords do not match")
                messagebox.showerror("Error", "Passwords do not match")
                return
            
            # Check if username exists
            try:
                exists = self._db.user_exists(username)
            except Exception as db_err:
                self._status_var.set(f"Database error: {db_err}")
                messagebox.showerror("Database Error", str(db_err))
                return
                
            if exists:
                self._status_var.set("Username already exists")
                messagebox.showerror("Error", "Username already exists")
                return
            
            # Validate password strength
            try:
                from core.password_policy import get_password_policy
                policy = get_password_policy()
                is_valid, violations = policy.validate(password)
                
                if not is_valid:
                    msg = violations[0].message
                    self._status_var.set(msg)
                    messagebox.showerror("Password Policy", msg)
                    return
            except Exception as policy_err:
                self._status_var.set(f"Policy error: {policy_err}")
                messagebox.showerror("Policy Error", str(policy_err))
                return
            
            # Create user
            try:
                salt = self._crypto.generate_salt()
                password_hash = self._crypto.hash_password(password, salt)
                
                user_id = self._db.create_user(
                    username=username,
                    password_hash=password_hash,
                    salt=salt.hex()
                )
            except Exception as create_err:
                self._status_var.set(f"Create error: {create_err}")
                messagebox.showerror("Create Error", str(create_err))
                return
            
            if user_id:
                self._status_var.set("Account created successfully!")
                logger.info(f"New user registered: {username} (user_id={user_id})")
                messagebox.showinfo("Success", "Account created! You can now login.")
                self._toggle_mode()  # Switch back to login
                self._username_var.set(username)  # Keep username for convenience
                self._password_var.set("")
                self._confirm_var.set("")
            else:
                self._status_var.set("Registration failed. Please try again.")
                logger.error(f"Registration failed for user {username}: user_id is None")
                messagebox.showerror("Error", "Registration failed. Please try again.")
        except Exception as e:
            self._status_var.set(f"Error: {str(e)}")
            logger.error(f"Unexpected error during registration for user {username}: {str(e)}")
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")
    
    def _on_failed_attempt(self) -> None:
        """Handle a failed login attempt."""
        self._failed_attempts += 1
        
        remaining = self.MAX_ATTEMPTS - self._failed_attempts
        
        if remaining <= 0:
            self._start_lockout()
        elif remaining <= 2:
            self._status_var.set(
                f"Invalid credentials. {remaining} attempts remaining."
            )
    
    def _start_lockout(self) -> None:
        """Start the lockout timer."""
        import time
        self._lockout_until = time.time() + self.LOCKOUT_DURATION
        
        self._login_button.configure(state='disabled')
        self._update_lockout_display()
    
    def _is_locked_out(self) -> bool:
        """Check if currently locked out."""
        if self._lockout_until is None:
            return False
        
        import time
        if time.time() >= self._lockout_until:
            self._lockout_until = None
            self._failed_attempts = 0
            self._login_button.configure(state='normal')
            self._status_var.set("")
            return False
        
        return True
    
    def _update_lockout_display(self) -> None:
        """Update the lockout countdown display."""
        if not self._is_locked_out():
            return
        
        import time
        remaining = int(self._lockout_until - time.time())
        
        if remaining > 0:
            self._status_var.set(
                f"Too many failed attempts. Locked for {remaining}s"
            )
            self.after(1000, self._update_lockout_display)
        else:
            self._status_var.set("")
            self._login_button.configure(state='normal')
    
    def show_unlock_mode(self, username: str) -> None:
        """
        Show in unlock mode (for locked session).
        
        Args:
            username: Username to display
        """
        self._username_var.set(username)
        self._username_entry.configure(state='disabled')
        self._toggle_button.pack_forget()
        self._login_button.configure(text="Unlock")
        
        self.show()
        self._password_entry.focus()
    
    def reset(self) -> None:
        """Reset the login form."""
        self._username_var.set("")
        self._password_var.set("")
        self._confirm_var.set("")
        self._status_var.set("")
        self._failed_attempts = 0
        self._lockout_until = None
        self._login_button.configure(state='normal')
        self._username_entry.configure(state='normal')
