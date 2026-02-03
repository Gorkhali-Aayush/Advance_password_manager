"""
Vault Window

Main application window displaying credentials.
Provides search, add, edit, delete, and copy functionality.
"""

import os
import sys
import logging
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Callable, List
from pathlib import Path
import psutil

# Configure logging
logger = logging.getLogger(__name__)

# Add parent directory to path for cross-package imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.baseWindow import BaseWindow
from core.vault import get_vault, Vault
from core.credential import Credential
from core.sessionManager import get_session_manager
from os_layer.clipboardManager import get_clipboard_manager
from storage.mysqlEngine import get_database


class VaultWindow(BaseWindow):
    """
    Main vault window for credential management.
    
    Features:
    - Credential list with Treeview
    - Search functionality
    - Add/Edit/Delete credentials
    - Copy password to clipboard
    - Security score display
    - Auto-lock timer display
    """
    
    def __init__(self, on_logout: Optional[Callable] = None,
                 on_lock: Optional[Callable] = None):
        """
        Initialize vault window.
        
        Args:
            on_logout: Callback when user logs out
            on_lock: Callback when vault is locked
        """
        logger.info("Initializing VaultWindow...")
        super().__init__(
            title="Password Manager - Vault",
            width=900,
            height=600
        )
        
        self._on_logout = on_logout
        self._on_lock = on_lock
        
        # Get dependencies
        logger.info("Getting vault singleton...")
        self._vault = get_vault()
        logger.info(f"Vault obtained: {self._vault}")
        
        logger.info("Getting session manager singleton...")
        self._session = get_session_manager()
        logger.info(f"Session manager obtained: {self._session}")
        
        logger.info("Getting clipboard manager singleton...")
        self._clipboard = get_clipboard_manager()
        logger.info(f"Clipboard manager obtained: {self._clipboard}")
        
        # Get user role
        self._user_role = self._session.current_session.role if self._session.current_session else 'user'
        logger.info(f"User role: {self._user_role}")
        
        # UI state
        self._selected_credential_id: Optional[int] = None
        self._update_timer: Optional[str] = None
        
        # Build UI
        logger.info("Building vault UI...")
        self._build_ui()
        logger.info("Vault UI built successfully")
        
        # Load data
        logger.info("Refreshing credentials...")
        self._refresh_credentials()
        
        # Start periodic updates
        logger.info("Starting periodic updates...")
        self._start_updates()
        logger.info("VaultWindow initialization complete")
    
    def _build_ui(self) -> None:
        """Build the main vault interface."""
        # If admin, use notebook with tabs
        if self._user_role == 'admin':
            self._build_ui_with_admin_tabs()
        else:
            # Regular user - simple layout
            self._build_ui_simple()
    
    def _build_ui_simple(self) -> None:
        """Build simple vault interface for regular users."""
        # Main container
        main_frame = ttk.Frame(self._root, padding=10)
        main_frame.pack(fill='both', expand=True)
        
        # Top toolbar
        self._build_toolbar(main_frame)
        
        # Content area with credentials list
        self._build_content(main_frame)
        
        # Bottom status bar
        self._build_statusbar(main_frame)
    
    def _build_ui_with_admin_tabs(self) -> None:
        """Build vault interface with admin dashboard for admin users."""
        # Main container
        main_frame = ttk.Frame(self._root, padding=10)
        main_frame.pack(fill='both', expand=True)
        
        # Top toolbar with admin label
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill='x', pady=(0, 10))
        
        admin_label = ttk.Label(
            header_frame,
            text="🛡️ Admin Panel (Password Manager)",
            font=('Segoe UI', 10, 'bold'),
            foreground='darkblue'
        )
        admin_label.pack(side='left', padx=5)
        
        # Create notebook for tabs
        self._notebook = ttk.Notebook(main_frame)
        self._notebook.pack(fill='both', expand=True)
        
        # Tab 1: User Vault (credentials)
        vault_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(vault_frame, text="🔐 My Vault")
        
        # Build vault UI inside the tab
        self._build_toolbar(vault_frame)
        self._build_content(vault_frame)
        self._build_statusbar(vault_frame)
        
        # Tab 2: Admin Dashboard
        admin_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(admin_frame, text="⚙️ Admin Dashboard")
        self._build_admin_dashboard_in_tab(admin_frame)
    
    def _build_admin_dashboard_in_tab(self, parent: ttk.Frame) -> None:
        """Build the admin dashboard inside a tab frame."""
        from ui.adminDashboard import AdminDashboard
        
        # We'll create a lightweight admin view in this frame
        # Header
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill='x', pady=(0, 10))
        
        title = ttk.Label(header_frame, text="⚙️ Admin Dashboard", font=('Segoe UI', 12, 'bold'))
        title.pack(side='left')
        
        refresh_btn = ttk.Button(header_frame, text="🔄 Refresh", command=self._refresh_admin_dashboard)
        refresh_btn.pack(side='right')
        
        # Create notebook for admin tabs
        admin_notebook = ttk.Notebook(parent)
        admin_notebook.pack(fill='both', expand=True)
        self._admin_notebook = admin_notebook
        
        # Import here to avoid circular imports
        from storage.mysqlEngine import get_database
        
        db = get_database()
        
        # Tab 1: System Overview
        overview_frame = ttk.Frame(admin_notebook, padding=10)
        admin_notebook.add(overview_frame, text="📊 Overview")
        self._build_admin_overview(overview_frame, db)
        
        # Tab 2: User Management
        users_frame = ttk.Frame(admin_notebook, padding=10)
        admin_notebook.add(users_frame, text="👥 Users")
        self._build_admin_users(users_frame, db)
        
        # Tab 3: System Resources
        resources_frame = ttk.Frame(admin_notebook, padding=10)
        admin_notebook.add(resources_frame, text="⚙️ Resources")
        self._build_admin_resources(resources_frame)
        
        # Tab 4: Activity Logs
        logs_frame = ttk.Frame(admin_notebook, padding=10)
        admin_notebook.add(logs_frame, text="📝 Activity Logs")
        self._build_admin_logs(logs_frame)
    
    def _build_admin_overview(self, parent: ttk.Frame, db) -> None:
        """Build admin overview statistics."""
        stats = db.get_database_stats()
        
        # Create statistics cards
        stats_frame = ttk.Frame(parent)
        stats_frame.pack(fill='x', pady=10)
        
        cards = [
            ('Total Users', str(stats.get('total_users', 0)), '👥'),
            ('Admins', str(stats.get('admin_count', 0)), '👮'),
            ('Regular Users', str(stats.get('user_count', 0)), '👤'),
            ('Total Credentials', str(stats.get('total_credentials', 0)), '🔐'),
        ]
        
        for label, value, icon in cards:
            card = ttk.LabelFrame(stats_frame, text=f"{icon} {label}", padding=10)
            card.pack(side='left', fill='both', expand=True, padx=5)
            
            value_label = ttk.Label(card, text=value, font=('Segoe UI', 14, 'bold'))
            value_label.pack()
    
    def _build_admin_users(self, parent: ttk.Frame, db) -> None:
        """Build admin user management panel."""
        # Treeview for users
        columns = ('ID', 'Username', 'Role', 'Credentials', 'Created')
        self._admin_users_tree = ttk.Treeview(parent, columns=columns, height=15)
        self._admin_users_tree.column('#0', width=0, stretch='no')
        self._admin_users_tree.column('ID', anchor='center', width=40)
        self._admin_users_tree.column('Username', anchor='w', width=120)
        self._admin_users_tree.column('Role', anchor='center', width=80)
        self._admin_users_tree.column('Credentials', anchor='center', width=80)
        self._admin_users_tree.column('Created', anchor='center', width=120)
        
        self._admin_users_tree.heading('#0', text='', anchor='w')
        for col in columns:
            self._admin_users_tree.heading(col, text=col, anchor='w')
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient='vertical', command=self._admin_users_tree.yview)
        self._admin_users_tree.configure(yscroll=scrollbar.set)
        
        # Pack
        self._admin_users_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', pady=(10, 0))
        
        ttk.Button(button_frame, text="👤 View Details", command=self._admin_view_user_details).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🔐 Make Admin", command=self._admin_make_admin).pack(side='left', padx=5)
        ttk.Button(button_frame, text="👥 Make User", command=self._admin_make_user).pack(side='left', padx=5)
        
        # Load data
        self._refresh_admin_users(db)
    
    def _build_admin_resources(self, parent: ttk.Frame) -> None:
        """Build admin system resources panel."""
        try:
            # CPU Usage
            cpu_frame = ttk.LabelFrame(parent, text="CPU Usage", padding=10)
            cpu_frame.pack(fill='x', pady=5)
            
            self._admin_cpu_label = ttk.Label(cpu_frame, text="--", font=('Segoe UI', 14, 'bold'))
            self._admin_cpu_label.pack()
            
            # Memory Usage
            mem_frame = ttk.LabelFrame(parent, text="Memory Usage", padding=10)
            mem_frame.pack(fill='x', pady=5)
            
            self._admin_mem_label = ttk.Label(mem_frame, text="--", font=('Segoe UI', 14, 'bold'))
            self._admin_mem_label.pack()
            
            # Process Count
            proc_frame = ttk.LabelFrame(parent, text="Processes", padding=10)
            proc_frame.pack(fill='x', pady=5)
            
            self._admin_proc_label = ttk.Label(proc_frame, text="--", font=('Segoe UI', 12))
            self._admin_proc_label.pack()
        except Exception as e:
            logger.error(f"Error building resources panel: {e}")
    
    def _build_admin_logs(self, parent: ttk.Frame) -> None:
        """Build admin activity logs panel."""
        # Text widget for logs
        self._admin_logs_text = tk.Text(parent, height=20, width=100, state='disabled')
        self._admin_logs_text.pack(fill='both', expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient='vertical', command=self._admin_logs_text.yview)
        self._admin_logs_text.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        
        # Load logs
        self._refresh_admin_logs()
    
    def _refresh_admin_dashboard(self) -> None:
        """Refresh admin dashboard data."""
        try:
            from storage.mysqlEngine import get_database
            db = get_database()
            
            # Refresh all admin panels
            self._refresh_admin_users(db)
            self._refresh_admin_resources()
            self._refresh_admin_logs()
        except Exception as e:
            logger.error(f"Error refreshing admin dashboard: {e}")
    
    def _refresh_admin_users(self, db) -> None:
        """Refresh admin users list."""
        # Clear existing items
        for item in self._admin_users_tree.get_children():
            self._admin_users_tree.delete(item)
        
        # Get all users
        users = db.get_all_users()
        
        for user in users:
            values = (
                user['id'],
                user['username'],
                user['role'].upper(),
                user['credential_count'],
                user['created_at'].strftime('%Y-%m-%d %H:%M') if user['created_at'] else 'N/A'
            )
            self._admin_users_tree.insert('', 'end', values=values)
    
    def _refresh_admin_resources(self) -> None:
        """Refresh admin system resources display."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self._admin_cpu_label.config(text=f"{cpu_percent:.1f}%")
            
            # Memory usage
            memory = psutil.virtual_memory()
            self._admin_mem_label.config(
                text=f"Used: {memory.percent:.1f}% ({memory.used / (1024**3):.1f}GB / {memory.total / (1024**3):.1f}GB)"
            )
            
            # Process info
            proc_count = len(psutil.pids())
            self._admin_proc_label.config(text=f"Total Processes: {proc_count}")
        except Exception as e:
            logger.error(f"Error refreshing resources: {e}")
    
    def _refresh_admin_logs(self) -> None:
        """Refresh admin activity logs."""
        try:
            self._admin_logs_text.config(state='normal')
            self._admin_logs_text.delete('1.0', tk.END)
            
            # Read log file from backups directory
            log_file = Path('backups') / 'password_manager.log'
            
            if not log_file.exists():
                self._admin_logs_text.insert(tk.END, '📝 No logs available yet.\n')
                self._admin_logs_text.config(state='disabled')
                return
            
            # Read logs
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Display last 50 entries
            recent_lines = lines[-50:] if len(lines) > 50 else lines
            
            for line in recent_lines:
                if line.strip():
                    self._admin_logs_text.insert(tk.END, line)
            
            self._admin_logs_text.config(state='disabled')
        except Exception as e:
            logger.error(f"Error loading logs: {e}")
    
    def _admin_view_user_details(self) -> None:
        """View details of selected admin user."""
        selected = self._admin_users_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user")
            return
        
        values = self._admin_users_tree.item(selected[0])['values']
        user_id, username, role, credentials = values[0], values[1], values[2], values[3]
        
        info = f"User: {username}\nRole: {role}\nCredentials: {credentials}\nID: {user_id}"
        messagebox.showinfo("User Details", info)
    
    def _admin_make_admin(self) -> None:
        """Promote selected user to admin."""
        selected = self._admin_users_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user")
            return
        
        values = self._admin_users_tree.item(selected[0])['values']
        user_id, username = values[0], values[1]
        
        # Require admin authentication
        from ui.adminAuthDialog import AdminAuthDialog
        if not AdminAuthDialog.authenticate(
            parent=self._root,
            operation=f"Promote user '{username}' to admin role"
        ):
            messagebox.showwarning("Authentication Failed", "Admin authentication required")
            return
        
        db = get_database()
        if db.update_user_role(user_id, 'admin'):
            messagebox.showinfo("Success", f"✅ {username} is now an admin")
            self._refresh_admin_users(db)
        else:
            messagebox.showerror("Error", "Failed to update user role")
    
    def _admin_make_user(self) -> None:
        """Demote selected admin to regular user."""
        selected = self._admin_users_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user")
            return
        
        values = self._admin_users_tree.item(selected[0])['values']
        user_id, username = values[0], values[1]
        
        # Require admin authentication
        from ui.adminAuthDialog import AdminAuthDialog
        if not AdminAuthDialog.authenticate(
            parent=self._root,
            operation=f"Demote user '{username}' to regular user role"
        ):
            messagebox.showwarning("Authentication Failed", "Admin authentication required")
            return
        
        db = get_database()
        if db.update_user_role(user_id, 'user'):
            messagebox.showinfo("Success", f"✅ {username} is now a regular user")
            self._refresh_admin_users(db)
        else:
            messagebox.showerror("Error", "Failed to update user role")
    
    
    def _build_toolbar(self, parent: ttk.Frame) -> None:
        """Build the top toolbar."""
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill='x', pady=(0, 10))
        
        # Left side - Search
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side='left', fill='x', expand=True)
        
        ttk.Label(search_frame, text="🔍").pack(side='left', padx=(0, 5))
        
        self._search_var = tk.StringVar()
        self._search_debounce_id = None  # For debouncing search
        self._search_var.trace('w', lambda *args: self._on_search_changed())
        
        self._search_entry = ttk.Entry(
            search_frame, 
            textvariable=self._search_var,
            width=40
        )
        self._search_entry.pack(side='left', fill='x', expand=True)
        
        # Clear search button
        self._clear_search_btn = ttk.Button(
            search_frame,
            text="✕",
            width=3,
            command=self._clear_search
        )
        self._clear_search_btn.pack(side='left', padx=(5, 0))
        
        # Search results count label
        self._search_count_label = ttk.Label(
            search_frame,
            text="",
            foreground='gray'
        )
        self._search_count_label.pack(side='left', padx=(10, 0))
        
        # Right side - Buttons
        button_frame = ttk.Frame(toolbar)
        button_frame.pack(side='right')
        
        ttk.Button(
            button_frame, 
            text="➕ Add", 
            command=self._on_add_click
        ).pack(side='left', padx=2)
        
        ttk.Button(
            button_frame, 
            text="📊 Security", 
            command=self._on_security_click
        ).pack(side='left', padx=2)
        
        ttk.Button(
            button_frame, 
            text="🔒 Lock", 
            command=self._on_lock_click
        ).pack(side='left', padx=2)
        
        ttk.Button(
            button_frame, 
            text="🚪 Logout", 
            command=self._on_logout_click
        ).pack(side='left', padx=2)
    
    def _build_content(self, parent: ttk.Frame) -> None:
        """Build the main content area."""
        # Create paned window for list and details
        paned = ttk.PanedWindow(parent, orient='horizontal')
        paned.pack(fill='both', expand=True)
        
        # Left - Credentials list
        list_frame = ttk.Frame(paned)
        paned.add(list_frame, weight=2)
        
        self._build_credentials_list(list_frame)
        
        # Right - Details panel
        self._details_frame = ttk.Frame(paned, padding=10)
        paned.add(self._details_frame, weight=1)
        
        self._build_details_panel(self._details_frame)
    
    def _build_credentials_list(self, parent: ttk.Frame) -> None:
        """Build the credentials treeview."""
        # Treeview with scrollbar
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill='both', expand=True)
        
        columns = ('site', 'username', 'updated')
        self._tree = ttk.Treeview(
            tree_frame, 
            columns=columns, 
            show='headings',
            selectmode='browse'
        )
        
        # Define columns
        self._tree.heading('site', text='Site', anchor='w')
        self._tree.heading('username', text='Username', anchor='w')
        self._tree.heading('updated', text='Last Updated', anchor='w')
        
        self._tree.column('site', width=200)
        self._tree.column('username', width=150)
        self._tree.column('updated', width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(
            tree_frame, 
            orient='vertical',
            command=self._tree.yview
        )
        self._tree.configure(yscrollcommand=scrollbar.set)
        
        self._tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Bind selection event
        self._tree.bind('<<TreeviewSelect>>', self._on_select)
        self._tree.bind('<Double-1>', lambda e: self._on_copy_password())
    
    def _build_details_panel(self, parent: ttk.Frame) -> None:
        """Build the credential details panel."""
        # Title
        ttk.Label(
            parent, 
            text="Credential Details",
            style='Title.TLabel'
        ).pack(anchor='w', pady=(0, 15))
        
        # Details labels
        self._detail_site = self._create_detail_row(parent, "Site:")
        self._detail_username = self._create_detail_row(parent, "Username:")
        
        # Password row with eye toggle button
        self._detail_password, self._password_toggle_btn = self._create_password_detail_row(parent, "Password:")
        self._password_visible = False  # Track password visibility state
        
        self._detail_url = self._create_detail_row(parent, "URL:")
        self._detail_notes = self._create_detail_row(parent, "Notes:")
        self._detail_updated = self._create_detail_row(parent, "Updated:")
        
        # Action buttons
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', pady=(20, 0))
        
        self._copy_btn = ttk.Button(
            button_frame, 
            text="📋 Copy Password",
            command=self._on_copy_password,
            state='disabled'
        )
        self._copy_btn.pack(fill='x', pady=2)
        
        self._edit_btn = ttk.Button(
            button_frame, 
            text="✏️ Edit",
            command=self._on_edit_click,
            state='disabled'
        )
        self._edit_btn.pack(fill='x', pady=2)
        
        self._delete_btn = ttk.Button(
            button_frame, 
            text="🗑️ Delete",
            command=self._on_delete_click,
            state='disabled'
        )
        self._delete_btn.pack(fill='x', pady=2)
    
    def _create_detail_row(self, parent: ttk.Frame, 
                           label: str) -> ttk.Label:
        """Create a detail row with label and value."""
        frame = ttk.Frame(parent)
        frame.pack(fill='x', pady=3)
        
        ttk.Label(
            frame, 
            text=label, 
            width=10,
            foreground=self.COLORS['text_secondary']
        ).pack(side='left')
        
        value_label = ttk.Label(frame, text="-")
        value_label.pack(side='left', fill='x', expand=True)
        
        return value_label
    
    def _create_password_detail_row(self, parent: ttk.Frame, 
                                     label: str) -> tuple:
        """Create a password detail row with label, value, and eye toggle button."""
        frame = ttk.Frame(parent)
        frame.pack(fill='x', pady=3)
        
        ttk.Label(
            frame, 
            text=label, 
            width=10,
            foreground=self.COLORS['text_secondary']
        ).pack(side='left')
        
        value_label = ttk.Label(frame, text="-")
        value_label.pack(side='left', fill='x', expand=True)
        
        # Eye toggle button
        toggle_btn = ttk.Button(
            frame,
            text="👁",
            width=3,
            command=self._toggle_password_visibility
        )
        toggle_btn.pack(side='right', padx=(5, 0))
        
        return value_label, toggle_btn
    
    def _toggle_password_visibility(self) -> None:
        """Toggle password visibility in the details panel."""
        if not self._selected_credential_id:
            return
        
        self._password_visible = not self._password_visible
        
        if self._password_visible:
            # Show the actual password
            password = self._vault.get_decrypted_password(self._selected_credential_id)
            if password:
                self._detail_password.configure(text=password)
                self._password_toggle_btn.configure(text="🙈")
        else:
            # Hide the password
            self._detail_password.configure(text="••••••••••••")
            self._password_toggle_btn.configure(text="👁")
    
    def _build_statusbar(self, parent: ttk.Frame) -> None:
        """Build the bottom status bar."""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill='x', pady=(10, 0))
        
        # Left - Credential count
        self._count_label = ttk.Label(
            status_frame, 
            text="0 credentials",
            foreground=self.COLORS['text_secondary']
        )
        self._count_label.pack(side='left')
        
        # Center - Clipboard status
        self._clipboard_label = ttk.Label(
            status_frame,
            text="",
            foreground=self.COLORS['secondary']
        )
        self._clipboard_label.pack(side='left', padx=20)
        
        # Right - Lock timer
        self._timer_label = ttk.Label(
            status_frame,
            text="",
            foreground=self.COLORS['text_secondary']
        )
        self._timer_label.pack(side='right')
    
    # ============ Data Operations ============
    
    def _refresh_credentials(self) -> None:
        """Refresh the credentials list from vault."""
        # Use the search function to refresh (respects current search query)
        self._perform_search()
        
        # Update total count in status bar
        total = len(self._vault.get_all_credentials())
        self._count_label.configure(
            text=f"{total} credentials"
        )
    
    def _on_search_changed(self) -> None:
        """Handle search input with debouncing."""
        # Cancel previous debounce timer
        if self._search_debounce_id:
            self._root.after_cancel(self._search_debounce_id)
        
        # Set new debounce timer (150ms delay for smooth typing)
        self._search_debounce_id = self._root.after(150, self._perform_search)
    
    def _perform_search(self) -> None:
        """Perform the actual search after debounce."""
        query = self._search_var.get().strip().lower()
        
        # Clear tree
        for item in self._tree.get_children():
            self._tree.delete(item)
        
        # Get all credentials and filter
        all_credentials = self._vault.get_all_credentials()
        
        if not query:
            # Show all if no query
            results = all_credentials
        else:
            # Search in site name, username, url, and notes
            results = []
            for cred in all_credentials:
                if (query in cred.site_name.lower() or 
                    query in cred.username.lower() or
                    (cred.url and query in cred.url.lower()) or
                    (cred.notes and query in cred.notes.lower())):
                    results.append(cred)
        
        # Populate tree with results
        for cred in results:
            updated_str = cred.updated_at.strftime("%Y-%m-%d")
            self._tree.insert('', 'end', iid=str(cred.id), values=(
                cred.site_name,
                cred.username,
                updated_str
            ))
        
        # Update search count
        total = len(all_credentials)
        found = len(results)
        if query:
            self._search_count_label.configure(text=f"{found} of {total} found")
        else:
            self._search_count_label.configure(text="")
        
        # Clear selection
        self._clear_selection()
    
    def _clear_search(self) -> None:
        """Clear the search field and show all credentials."""
        self._search_var.set("")
        self._search_entry.focus_set()
    
    def _on_select(self, event) -> None:
        """Handle credential selection."""
        selection = self._tree.selection()
        
        if not selection:
            self._clear_selection()
            return
        
        cred_id = int(selection[0])
        credential = self._vault.get_credential(cred_id)
        
        if credential:
            self._selected_credential_id = cred_id
            self._show_credential_details(credential)
            
            # Enable buttons
            self._copy_btn.configure(state='normal')
            self._edit_btn.configure(state='normal')
            self._delete_btn.configure(state='normal')
        
        # Update activity
        self._session.update_activity()
    
    def _show_credential_details(self, credential: Credential) -> None:
        """Show credential details in the panel."""
        self._detail_site.configure(text=credential.site_name)
        self._detail_username.configure(text=credential.username)
        self._detail_password.configure(text="••••••••••••")
        self._detail_url.configure(text=credential.url or "-")
        self._detail_notes.configure(text=credential.notes or "-")
        self._detail_updated.configure(
            text=credential.updated_at.strftime("%Y-%m-%d %H:%M")
        )
        
        # Reset password visibility when new credential is selected
        self._password_visible = False
        self._password_toggle_btn.configure(text="👁")
    
    def _clear_selection(self) -> None:
        """Clear the current selection."""
        self._selected_credential_id = None
        
        self._detail_site.configure(text="-")
        self._detail_username.configure(text="-")
        self._detail_password.configure(text="-")
        self._detail_url.configure(text="-")
        self._detail_notes.configure(text="-")
        self._detail_updated.configure(text="-")
        
        # Reset password visibility
        self._password_visible = False
        self._password_toggle_btn.configure(text="👁")
        
        self._copy_btn.configure(state='disabled')
        self._edit_btn.configure(state='disabled')
        self._delete_btn.configure(state='disabled')
    
    # ============ Actions ============
    
    def _on_copy_password(self) -> None:
        """Copy password to clipboard."""
        if not self._selected_credential_id:
            return
        
        password = self._vault.get_decrypted_password(
            self._selected_credential_id
        )
        
        if password:
            self._clipboard.copy_to_clipboard(password, auto_clear=True)
            self._clipboard_label.configure(
                text="📋 Password copied (clears in 30s)"
            )
            
            # Clear message after timeout
            self.after(30000, lambda: self._clipboard_label.configure(text=""))
        
        self._session.update_activity()
    
    def _on_add_click(self) -> None:
        """Show add credential dialog."""
        self._show_credential_dialog()
        self._session.update_activity()
    
    def _on_edit_click(self) -> None:
        """Show edit credential dialog."""
        if not self._selected_credential_id:
            return
        
        credential = self._vault.get_credential(self._selected_credential_id)
        if credential:
            self._show_credential_dialog(credential)
        
        self._session.update_activity()
    
    def _on_delete_click(self) -> None:
        """Delete the selected credential."""
        if not self._selected_credential_id:
            return
        
        credential = self._vault.get_credential(self._selected_credential_id)
        if not credential:
            return
        
        if self.ask_yes_no(
            "Delete Credential",
            f"Are you sure you want to delete the credential for\n"
            f"{credential.site_name} ({credential.username})?"
        ):
            if self._vault.delete_credential(self._selected_credential_id):
                self._refresh_credentials()
                self.show_info("Success", "Credential deleted.")
            else:
                self.show_error("Error", "Failed to delete credential.")
        
        self._session.update_activity()
    
    def _on_security_click(self) -> None:
        """Show advanced security analysis panel."""
        from .securityPanel import AdvancedSecurityPanel
        logger.info("Opening Advanced Security Panel...")
        AdvancedSecurityPanel(self._root)
        self._session.update_activity()
    
    def _on_lock_click(self) -> None:
        """Lock the vault."""
        self._vault.lock()
        
        if self._on_lock:
            self._on_lock()
        
        self.hide()
    
    def _on_logout_click(self) -> None:
        """Log out the user."""
        if self.ask_yes_no("Logout", "Are you sure you want to logout?"):
            self._session.logout()
            
            if self._on_logout:
                self._on_logout()
            
            self.close()
    
    def _show_credential_dialog(self, 
                                 credential: Optional[Credential] = None) -> None:
        """
        Show add/edit credential dialog.
        
        Args:
            credential: Existing credential for editing (None for add)
        """
        dialog = tk.Toplevel(self._root)
        dialog.title("Add Credential" if not credential else "Edit Credential")
        dialog.geometry("480x520")
        dialog.resizable(False, False)
        dialog.transient(self._root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self._root.winfo_x() + (self._root.winfo_width() - 480) // 2
        y = self._root.winfo_y() + (self._root.winfo_height() - 520) // 2
        dialog.geometry(f"+{x}+{y}")
        
        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill='both', expand=True)
        
        # Fields - store both StringVar and Entry widgets
        fields = {}
        entries = {}
        
        for field_name, label_text, show in [
            ('site_name', 'Site Name:', None),
            ('username', 'Username:', None),
            ('password', 'Password:', '•'),
            ('url', 'URL (optional):', None),
            ('notes', 'Notes (optional):', None)
        ]:
            lbl = ttk.Label(frame, text=label_text)
            lbl.pack(anchor='w', pady=(10, 0))
            
            if field_name == 'notes':
                entry = tk.Text(frame, height=3, width=40)
                if credential and credential.notes:
                    entry.insert('1.0', credential.notes)
                fields[field_name] = entry
                entries[field_name] = entry
            else:
                entry = ttk.Entry(frame, width=40, show=show or '')
                if credential:
                    if field_name == 'password':
                        # Show current decrypted password when editing
                        current_password = self._vault.get_decrypted_password(credential.id)
                        if current_password:
                            entry.insert(0, current_password)
                    else:
                        value = getattr(credential, field_name, '') or ''
                        entry.insert(0, value)
                fields[field_name] = entry
                entries[field_name] = entry
            
            entry.pack(fill='x', pady=(2, 0))
            
            # Add generate button for password
            if field_name == 'password':
                btn_frame = ttk.Frame(frame)
                btn_frame.pack(fill='x', pady=(5, 0))
                
                def generate_password(e=entry):
                    e.delete(0, tk.END)
                    e.insert(0, self._vault.generate_password())
                
                ttk.Button(
                    btn_frame,
                    text="Generate",
                    command=generate_password
                ).pack(side='left')
                
                ttk.Button(
                    btn_frame,
                    text="Show",
                    command=lambda e=entry: e.configure(
                        show='' if e.cget('show') else '•'
                    )
                ).pack(side='left', padx=5)
        
        # Strength indicator
        password_entry = fields['password']
        strength_var = tk.StringVar(value="")
        strength_label = ttk.Label(frame, textvariable=strength_var)
        strength_label.pack(anchor='w', pady=(5, 0))
        
        def update_strength(*args):
            pwd = password_entry.get()
            if pwd:
                result = self._vault.check_password_strength(pwd)
                strength_var.set(f"Strength: {result['strength']} ({result['score']}%)")
            else:
                strength_var.set("")
        
        # Bind to key release instead of StringVar trace
        password_entry.bind('<KeyRelease>', update_strength)
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill='x', pady=(20, 0))
        
        def on_save():
            site = fields['site_name'].get()
            user = fields['username'].get()
            pwd = fields['password'].get()
            url = fields['url'].get()
            notes = fields['notes'].get('1.0', 'end').strip() if isinstance(
                fields['notes'], tk.Text
            ) else ''
            
            logger.info(f"on_save called - site='{site}', user='{user}', pwd_len={len(pwd)}")
            
            if not site or not user:
                logger.warning(f"Validation failed - site empty: {not site}, user empty: {not user}")
                tk.messagebox.showerror(
                    "Error", 
                    "Site name and username are required",
                    parent=dialog
                )
                return
            
            if not credential and not pwd:
                tk.messagebox.showerror(
                    "Error",
                    "Password is required for new credentials",
                    parent=dialog
                )
                return
            
            try:
                if credential:
                    # Update existing
                    self._vault.update_credential(
                        credential.id,
                        site_name=site,
                        username=user,
                        password=pwd if pwd else None,
                        url=url,
                        notes=notes
                    )
                else:
                    # Create new
                    self._vault.add_credential(
                        site_name=site,
                        username=user,
                        password=pwd,
                        url=url,
                        notes=notes
                    )
                
                dialog.destroy()
                self._refresh_credentials()
                
            except ValueError as e:
                tk.messagebox.showerror("Error", str(e), parent=dialog)
        
        ttk.Button(btn_frame, text="Save", command=on_save).pack(
            side='left', padx=5
        )
        ttk.Button(btn_frame, text="Cancel", 
                   command=dialog.destroy).pack(side='left')
    
    # ============ Periodic Updates ============
    
    def _start_updates(self) -> None:
        """Start periodic UI updates."""
        self._update_status()
    
    def _update_status(self) -> None:
        """Update status bar periodically."""
        if not self._is_open:
            return
        
        # Update lock timer
        time_remaining = self._session.get_time_until_lock()
        if time_remaining > 0:
            mins = time_remaining // 60
            secs = time_remaining % 60
            self._timer_label.configure(
                text=f"🔒 Auto-lock in {mins}:{secs:02d}"
            )
        else:
            self._timer_label.configure(text="")
        
        # Update clipboard status
        clip_time = self._clipboard.get_time_remaining()
        if clip_time > 0:
            self._clipboard_label.configure(
                text=f"📋 Clipboard clears in {clip_time}s"
            )
        
        # Schedule next update
        self._update_timer = self.after(1000, self._update_status)
    
    def _on_close(self) -> None:
        """Handle window close."""
        if self._update_timer:
            self.cancel_after(self._update_timer)
        
        super()._on_close()
