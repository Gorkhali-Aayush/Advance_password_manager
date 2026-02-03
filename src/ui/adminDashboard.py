"""
Admin Dashboard

Monitoring and management interface for administrators.
Displays system statistics, user management, and audit information.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional
import psutil
import logging
from pathlib import Path
from datetime import datetime

# Add parent directory to path for cross-package imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.baseWindow import BaseWindow
from ui.adminAuthDialog import AdminAuthDialog
from core.vault import get_vault
from storage.mysqlEngine import get_database

logger = logging.getLogger(__name__)


class AdminDashboard(BaseWindow):
    """
    Admin dashboard for system monitoring and user management.
    
    Features:
    - System statistics (users, credentials, etc.)
    - User management and role assignment
    - Process and thread monitoring
    - Database status
    - Activity logs
    """
    
    def __init__(self, parent: Optional[tk.Tk] = None):
        """Initialize the admin dashboard."""
        super().__init__(
            parent=parent,
            title="🛡️ Admin Dashboard - System Monitoring",
            width=1200,
            height=750
        )
        
        self._db = get_database()
        self._vault = get_vault()
        
        logger.info("Initializing Admin Dashboard...")
        self._build_ui()
        self._refresh_data()
        logger.info("Admin Dashboard initialized")
    
    def _build_ui(self) -> None:
        """Build the admin dashboard interface.
        """
        # Main container with notebook tabs
        main_frame = ttk.Frame(self._root, padding=10)
        main_frame.pack(fill='both', expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill='x', pady=(0, 10))
        
        title = ttk.Label(header_frame, text="🛡️ Admin Dashboard", style='Title.TLabel')
        title.pack(side='left')
        
        refresh_btn = ttk.Button(header_frame, text="🔄 Refresh", command=self._refresh_data)
        refresh_btn.pack(side='right')
        
        # Notebook for tabs
        self._notebook = ttk.Notebook(main_frame)
        self._notebook.pack(fill='both', expand=True)
        
        # Tab 1: System Overview
        self._overview_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(self._overview_frame, text="📊 Overview")
        self._build_overview_tab()
        
        # Tab 2: User Management
        self._users_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(self._users_frame, text="👥 Users")
        self._build_users_tab()
        
        # Tab 3: System Resources
        self._resources_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(self._resources_frame, text="⚙️ Resources")
        self._build_resources_tab()
        
        # Tab 4: Logs
        self._logs_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(self._logs_frame, text="📝 Activity Logs")
        self._build_logs_tab()
    
    def _build_overview_tab(self) -> None:
        """Build the overview statistics tab."""
        # Statistics cards
        stats_frame = ttk.Frame(self._overview_frame)
        stats_frame.pack(fill='x', pady=(0, 20))
        
        # Create 5 stat cards
        self._stat_labels = {}
        stat_names = ['Total Users', 'Admins', 'Regular Users', 'Total Credentials', 'Password Changes']
        stat_keys = ['total_users', 'admin_count', 'user_count', 'total_credentials', 'password_changes']
        
        for i, (name, key) in enumerate(zip(stat_names, stat_keys)):
            card_frame = ttk.LabelFrame(stats_frame, text=name, padding=15)
            card_frame.grid(row=0, column=i, padx=5, sticky='nsew')
            
            label = ttk.Label(card_frame, text="0", font=('Segoe UI', 20, 'bold'))
            label.pack()
            
            self._stat_labels[key] = label
        
        stats_frame.columnconfigure(tuple(range(5)), weight=1)
    
    def _build_users_tab(self) -> None:
        """Build the user management tab."""
        # Create treeview for users
        columns = ('ID', 'Username', 'Role', 'Credentials', 'Joined')
        self._users_tree = ttk.Treeview(self._users_frame, columns=columns, height=20)
        
        # Define columns
        self._users_tree.column('#0', width=0, stretch=False)
        self._users_tree.column('ID', width=40)
        self._users_tree.column('Username', width=150)
        self._users_tree.column('Role', width=80)
        self._users_tree.column('Credentials', width=100)
        self._users_tree.column('Joined', width=150)
        
        # Create headings
        self._users_tree.heading('#0', text='', anchor=tk.W)
        self._users_tree.heading('ID', text='ID', anchor=tk.W)
        self._users_tree.heading('Username', text='Username', anchor=tk.W)
        self._users_tree.heading('Role', text='Role', anchor=tk.W)
        self._users_tree.heading('Credentials', text='Credentials', anchor=tk.W)
        self._users_tree.heading('Joined', text='Joined', anchor=tk.W)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self._users_frame, orient='vertical', command=self._users_tree.yview)
        self._users_tree.configure(yscroll=scrollbar.set)
        
        # Pack
        self._users_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Action buttons
        button_frame = ttk.Frame(self._users_frame)
        button_frame.pack(fill='x', pady=(10, 0))
        
        ttk.Button(button_frame, text="👤 View Details", command=self._view_user_details).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🔐 Make Admin", command=self._make_admin).pack(side='left', padx=5)
        ttk.Button(button_frame, text="👥 Make User", command=self._make_user).pack(side='left', padx=5)
    
    def _build_resources_tab(self) -> None:
        """Build the system resources tab."""
        # CPU Usage
        cpu_frame = ttk.LabelFrame(self._resources_frame, text="CPU Usage", padding=10)
        cpu_frame.pack(fill='x', pady=5)
        
        self._cpu_label = ttk.Label(cpu_frame, text="--", font=('Segoe UI', 14, 'bold'))
        self._cpu_label.pack()
        
        # Memory Usage
        mem_frame = ttk.LabelFrame(self._resources_frame, text="Memory Usage", padding=10)
        mem_frame.pack(fill='x', pady=5)
        
        self._mem_label = ttk.Label(mem_frame, text="--", font=('Segoe UI', 14, 'bold'))
        self._mem_label.pack()
        
        # Process Count
        proc_frame = ttk.LabelFrame(self._resources_frame, text="Process Information", padding=10)
        proc_frame.pack(fill='x', pady=5)
        
        self._proc_label = ttk.Label(proc_frame, text="--", font=('Segoe UI', 12))
        self._proc_label.pack()
        
        # Thread Count
        thread_frame = ttk.LabelFrame(self._resources_frame, text="Thread Information", padding=10)
        thread_frame.pack(fill='x', pady=5)
        
        self._thread_label = ttk.Label(thread_frame, text="--", font=('Segoe UI', 12))
        self._thread_label.pack()
    
    def _build_logs_tab(self) -> None:
        """Build the activity logs tab."""
        # Create text widget for logs
        self._logs_text = tk.Text(self._logs_frame, height=25, width=100, state='disabled')
        self._logs_text.pack(fill='both', expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self._logs_frame, orient='vertical', command=self._logs_text.yview)
        self._logs_text.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
    
    def _refresh_data(self) -> None:
        """Refresh all dashboard data."""
        self._refresh_statistics()
        self._refresh_users()
        self._refresh_resources()
        self._refresh_logs()
    
    def _refresh_statistics(self) -> None:
        """Refresh system statistics."""
        stats = self._db.get_database_stats()
        
        self._stat_labels['total_users'].config(text=str(stats.get('total_users', 0)))
        self._stat_labels['admin_count'].config(text=str(stats.get('admin_count', 0)))
        self._stat_labels['user_count'].config(text=str(stats.get('user_count', 0)))
        self._stat_labels['total_credentials'].config(text=str(stats.get('total_credentials', 0)))
        self._stat_labels['password_changes'].config(text=str(stats.get('password_changes', 0)))
    
    def _refresh_users(self) -> None:
        """Refresh user list."""
        # Clear existing items
        for item in self._users_tree.get_children():
            self._users_tree.delete(item)
        
        # Get all users
        users = self._db.get_all_users()
        
        for user in users:
            values = (
                user['id'],
                user['username'],
                user['role'].upper(),
                user['credential_count'],
                user['created_at'].strftime('%Y-%m-%d %H:%M') if user['created_at'] else 'N/A'
            )
            self._users_tree.insert('', 'end', values=values)
    
    def _refresh_resources(self) -> None:
        """Refresh system resources."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self._cpu_label.config(text=f"{cpu_percent:.1f}%")
            
            # Memory usage
            memory = psutil.virtual_memory()
            self._mem_label.config(
                text=f"Used: {memory.percent:.1f}% ({memory.used / (1024**3):.1f}GB / {memory.total / (1024**3):.1f}GB)"
            )
            
            # Process info
            proc_count = len(psutil.pids())
            self._proc_label.config(text=f"Total Processes: {proc_count}")
            
            # Thread info
            import threading
            thread_count = threading.active_count()
            self._thread_label.config(text=f"Active Threads: {thread_count}")
        except Exception as e:
            logger.error(f"Error refreshing resources: {e}")
    
    def _refresh_logs(self) -> None:
        """Refresh activity logs from backups directory."""
        self._logs_text.config(state='normal')
        self._logs_text.delete('1.0', tk.END)
        
        try:
            # Read log file from backups directory
            log_file = Path('backups') / 'password_manager.log'
            
            if not log_file.exists():
                self._logs_text.insert(tk.END, '📝 No logs available yet.\n')
                self._logs_text.config(state='disabled')
                return
            
            # Parse and display logs
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Display last 100 entries (most recent at top)
            recent_lines = lines[-100:] if len(lines) > 100 else lines
            
            # Add header
            self._logs_text.insert(tk.END, '═' * 120 + '\n')
            self._logs_text.insert(tk.END, 'PASSWORD MANAGER - ACTIVITY LOG\n')
            self._logs_text.insert(tk.END, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
            self._logs_text.insert(tk.END, '═' * 120 + '\n\n')
            
            # Parse logs and add formatted entries
            for line in recent_lines:
                if line.strip():
                    formatted_entry = self._format_log_entry(line)
                    self._logs_text.insert(tk.END, formatted_entry + '\n')
        
        except Exception as e:
            logger.error(f"Error reading logs: {e}")
            self._logs_text.insert(tk.END, f'❌ Error reading logs: {e}\n')
        
        self._logs_text.config(state='disabled')
    
    def _format_log_entry(self, log_line: str) -> str:
        """Format log entry with icons and clear structure."""
        try:
            parts = log_line.strip().split(' - ')
            if len(parts) >= 3:
                timestamp = parts[0]
                module = parts[1]
                level = parts[2]
                message = ' - '.join(parts[3:]) if len(parts) > 3 else ''
                
                # Add icons based on log level and message content
                icon = '📝'
                if level == 'ERROR':
                    icon = '❌'
                elif level == 'WARNING':
                    icon = '⚠️'
                elif level == 'INFO':
                    icon = 'ℹ️'
                
                # Detect activity type from message
                message_lower = message.lower()
                if 'password' in message_lower and ('added' in message_lower or 'created' in message_lower):
                    icon = '🔐 Added'
                elif 'password' in message_lower and 'edited' in message_lower:
                    icon = '✏️ Edited'
                elif 'password' in message_lower and ('deleted' in message_lower or 'removed' in message_lower):
                    icon = '🗑️ Deleted'
                elif 'login' in message_lower or 'logged' in message_lower:
                    icon = '🔑 Login'
                elif 'logout' in message_lower:
                    icon = '🚪 Logout'
                elif 'role' in message_lower or 'admin' in message_lower:
                    icon = '👮 Admin'
                elif 'created' in message_lower or 'registered' in message_lower:
                    icon = '👤 Account'
                
                # Format output
                return f"[{timestamp}] {icon} [{module}] {message}"
            else:
                return '  ' + log_line.strip()
        except Exception as e:
            logger.error(f"Error formatting log entry: {e}")
            return '  ' + log_line.strip()
    
    def _view_user_details(self) -> None:
        """View selected user details."""
        selected = self._users_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user")
            return
        
        values = self._users_tree.item(selected[0])['values']
        user_id = values[0]
        username = values[1]
        role = values[2]
        credentials = values[3]
        
        info = f"User: {username}\nRole: {role}\nCredentials Stored: {credentials}\nUser ID: {user_id}"
        messagebox.showinfo("User Details", info)
    
    def _make_admin(self) -> None:
        """Make selected user an admin (requires password authentication)."""
        selected = self._users_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user")
            return
        
        values = self._users_tree.item(selected[0])['values']
        user_id = values[0]
        username = values[1]
        
        # Require admin password authentication
        if not AdminAuthDialog.authenticate(
            parent=self._root,
            operation=f"Promote user '{username}' to admin role"
        ):
            messagebox.showwarning("Authentication Failed", "Admin authentication required")
            logger.warning(f"Admin authentication failed for role change operation")
            return
        
        # Authentication successful - proceed with role change
        if self._db.update_user_role(user_id, 'admin'):
            messagebox.showinfo("Success", f"✅ {username} is now an admin")
            logger.info(f"User {username} promoted to admin role")
            self._refresh_users()
        else:
            messagebox.showerror("Error", "Failed to update user role")
            logger.error(f"Failed to promote user {username} to admin")
    
    def _make_user(self) -> None:
        """Make selected admin a regular user (requires password authentication)."""
        selected = self._users_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user")
            return
        
        values = self._users_tree.item(selected[0])['values']
        user_id = values[0]
        username = values[1]
        
        # Require admin password authentication
        if not AdminAuthDialog.authenticate(
            parent=self._root,
            operation=f"Demote user '{username}' to regular user role"
        ):
            messagebox.showwarning("Authentication Failed", "Admin authentication required")
            logger.warning(f"Admin authentication failed for role change operation")
            return
        
        # Authentication successful - proceed with role change
        if self._db.update_user_role(user_id, 'user'):
            messagebox.showinfo("Success", f"✅ {username} is now a regular user")
            logger.info(f"User {username} demoted to regular user role")
            self._refresh_users()
        else:
            messagebox.showerror("Error", "Failed to update user role")
            logger.error(f"Failed to demote user {username} to regular user")
