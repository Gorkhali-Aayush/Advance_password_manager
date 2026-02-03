"""
Advanced Password Manager - Main Entry Point
=============================================

This module serves as the application entry point, orchestrating the startup,
initialization, and shutdown of all components.

Application Lifecycle:
    1. Check for single instance (file lock)
    2. Initialize database connection
    3. Create session manager
    4. Launch login window
    5. On successful login, show vault window
    6. Handle graceful shutdown

OOP Concepts Demonstrated:
    - Composition: Application composes all major components
    - Dependency Injection: Components receive their dependencies
    - Factory Pattern: Window creation based on state
    - Observer Pattern: Event-driven UI transitions

Architecture Flow:
    main.py → LoginWindow → VaultWindow
       ↓           ↓            ↓
    SessionManager ← → Vault ← → Data Structures
       ↓           ↓            ↓
    ThreadManager → Crypto → Storage

Author: Advanced Password Manager Team
Date: 2024
"""

import sys
import os
import atexit
import logging
import tkinter as tk
from tkinter import messagebox
from typing import Optional

# Add src directory to path for imports (use same path as other modules)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import application components (use same import paths as other modules)
from config import get_config
from storage.mysqlEngine import MySQLEngine, set_database
from crypto.fernetEngine import FernetEngine, set_encryption_engine
from core.sessionManager import SessionManager, Session, set_session_manager, get_session_manager
from core.vault import Vault
from core.passwordPolicy import PasswordPolicy
from os_layer.fileLock import SingleInstanceGuard
from os_layer.threadManager import ThreadManager
from os_layer.clipboardManager import ClipboardManager
from ui.loginWindow import LoginWindow
from ui.vaultWindow import VaultWindow

# Ensure backups directory exists
import pathlib
backup_dir = pathlib.Path('backups')
backup_dir.mkdir(exist_ok=True)

# Configure logging to backups directory
log_file = backup_dir / 'password_manager.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(str(log_file)),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class PasswordManagerApp:
    """
    Main application controller for the Password Manager.
    
    This class follows the Application Controller pattern, managing:
        - Component lifecycle (init, run, shutdown)
        - Window transitions (login → vault)
        - Global resource management
        - Error handling and recovery
    
    Composition:
        The app composes multiple components rather than inheriting:
        - SingleInstanceGuard: Prevents multiple instances
        - MySQLEngine: Database persistence
        - FernetEngine: Encryption services
        - SessionManager: Login state management
        - ThreadManager: Background task coordination
        - ClipboardManager: Secure clipboard operations
    
    Attributes:
        _instance_guard: Single instance enforcement
        _db_engine: Database connection
        _crypto_engine: Encryption engine
        _session_manager: User session management
        _thread_manager: Background thread coordination
        _clipboard_manager: Secure clipboard operations
        _root: Tkinter root window
        _current_window: Currently displayed window
        _vault: Credential vault (created after login)
    """
    
    # Database configuration - modify these for your environment
    DB_CONFIG = {
        'host': 'localhost',
        'port': 3306,
        'user': 'root',
        'password': 'root',
        'database': 'password_manager'
    }
    
    # Application settings
    APP_NAME = "Advanced Password Manager"
    LOCK_FILE = "password_manager.lock"
    
    def __init__(self):
        """Initialize the Password Manager application."""
        # Load configuration
        config = get_config()
        self.DB_CONFIG = config.get_db_config()
        self.AUTO_LOCK_TIMEOUT = config.get('AUTO_LOCK_TIMEOUT')
        self.CLIPBOARD_CLEAR_TIMEOUT = config.get('CLIPBOARD_CLEAR_TIMEOUT')
        
        logger.info(f"Configuration loaded: {config}")
        logger.info("Initializing Password Manager Application...")
        
        # Component references (initialized in _initialize_components)
        self._instance_guard: Optional[SingleInstanceGuard] = None
        self._db_engine: Optional[MySQLEngine] = None
        self._crypto_engine: Optional[FernetEngine] = None
        self._session_manager: Optional[SessionManager] = None
        self._thread_manager: Optional[ThreadManager] = None
        self._clipboard_manager: Optional[ClipboardManager] = None
        self._root: Optional[tk.Tk] = None
        self._current_window = None
        self._vault: Optional[Vault] = None
        
        # State flags
        self._is_initialized = False
        self._is_shutting_down = False
        
        # Register cleanup handlers
        atexit.register(self._cleanup)
    
    def _check_single_instance(self) -> bool:
        """
        Ensure only one instance of the application is running.
        
        Uses file locking (FileLock class) to prevent multiple instances.
        This is important for password managers to prevent:
            - Database corruption from concurrent access
            - Clipboard conflicts
            - Session management issues
        
        Returns:
            bool: True if this is the only instance, False otherwise.
        """
        try:
            self._instance_guard = SingleInstanceGuard(self.APP_NAME)
            
            if not self._instance_guard.check():
                logger.warning("Another instance is already running")
                return False
            
            logger.info("Single instance check passed")
            return True
            
        except Exception as e:
            logger.error(f"Error checking single instance: {e}")
            # Continue anyway - better than failing completely
            return True
    
    def _initialize_components(self) -> bool:
        """
        Initialize all application components in correct order.
        
        Component initialization follows dependency order:
            1. Crypto engine (no dependencies)
            2. Database engine (no dependencies)
            3. Thread manager (no dependencies)
            4. Clipboard manager (no dependencies)
            5. Session manager (depends on thread manager)
        
        Returns:
            bool: True if all components initialized successfully.
        """
        try:
            # 1. Initialize crypto engine
            logger.info("Initializing crypto engine...")
            self._crypto_engine = FernetEngine()
            set_encryption_engine(self._crypto_engine)  # Set as global singleton
            
            # 2. Initialize database engine
            logger.info("Initializing database engine...")
            self._db_engine = MySQLEngine(self.DB_CONFIG)
            set_database(self._db_engine)  # Set as global singleton
            
            # Test database connection
            if not self._db_engine.connect():
                logger.error("Failed to connect to database")
                self._show_db_error()
                return False
            
            # Ensure tables exist
            self._db_engine.initialize_database()
            
            # 3. Initialize thread manager
            logger.info("Initializing thread manager...")
            self._thread_manager = ThreadManager()
            
            # 4. Initialize clipboard manager
            logger.info("Initializing clipboard manager...")
            self._clipboard_manager = ClipboardManager(
                clear_timeout=self.CLIPBOARD_CLEAR_TIMEOUT
            )
            
            # 5. Initialize session manager with auto-lock callback
            logger.info("Initializing session manager...")
            self._session_manager = SessionManager(
                lock_timeout=self.AUTO_LOCK_TIMEOUT
            )
            set_session_manager(self._session_manager)  # Set as global singleton
            
            self._is_initialized = True
            logger.info("All components initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing components: {e}")
            return False
    
    def _show_db_error(self):
        """Show database connection error dialog."""
        # Create a minimal root for the error dialog
        root = tk.Tk()
        root.withdraw()
        
        messagebox.showerror(
            "Database Error",
            f"Could not connect to MySQL database.\n\n"
            f"Please ensure:\n"
            f"1. MySQL server is running\n"
            f"2. Database '{self.DB_CONFIG['database']}' exists\n"
            f"3. Connection settings in main.py are correct\n\n"
            f"Connection settings:\n"
            f"  Host: {self.DB_CONFIG['host']}\n"
            f"  Port: {self.DB_CONFIG['port']}\n"
            f"  User: {self.DB_CONFIG['user']}\n"
            f"  Database: {self.DB_CONFIG['database']}"
        )
        root.destroy()
    
    def _create_root_window(self):
        """Create the main Tkinter root window."""
        # Note: We don't create a separate root here.
        # LoginWindow and VaultWindow create their own Tk() via BaseWindow.
        # We just track references to manage window transitions.
        self._root = None  # Will be set when first window is created
    
    def _show_login_window(self):
        """
        Display the login window.
        
        The login window allows:
            - User authentication with master password
            - New user registration
            - Master password creation with policy validation
        
        On successful login, transitions to vault window.
        """
        logger.info("Showing login window...")
        
        # Destroy current window if exists
        if self._current_window:
            try:
                self._current_window.destroy()
            except Exception:
                pass
            self._current_window = None
        
        # Create login window (it creates its own Tk root)
        self._current_window = LoginWindow(
            on_login_success=self._on_login_success
        )
        
        # Store reference to the root
        self._root = self._current_window.root
        
        # Set close handler
        self._root.protocol("WM_DELETE_WINDOW", self._on_close_request)
    
    def _on_login_success(self, username: str, master_key: bytes):
        """
        Handle successful login.
        
        This method is called when the user successfully authenticates.
        It:
            1. Gets the current session
            2. Initializes the vault with credentials
            3. Transitions to the vault window
        
        Args:
            username: The authenticated username.
            master_key: The derived encryption key.
        """
        logger.info(f"Login successful for user: {username}")
        
        try:
            # Get current session from the global singleton (same one used by LoginWindow)
            session_mgr = get_session_manager()
            logger.info(f"Session manager state: {session_mgr._state}, session: {session_mgr._session}")
            
            if not session_mgr.is_logged_in:
                raise ValueError("No active session found")
            
            # Initialize vault using the singletons (already set up)
            from core.vault import set_vault
            self._vault = Vault(
                session_manager=session_mgr,
                database=self._db_engine,
                crypto=self._crypto_engine
            )
            # Set as singleton so VaultWindow can access it
            set_vault(self._vault)
            
            # Load credentials into vault
            self._vault.load_credentials()
            
            # Show vault window
            self._show_vault_window()
            
        except Exception as e:
            logger.error(f"Error after login: {e}")
            messagebox.showerror(
                "Error",
                f"An error occurred while loading the vault:\n{str(e)}"
            )
            self._show_login_window()
    
    def _show_vault_window(self):
        """
        Display the main vault window.
        
        The vault window provides:
            - Credential listing and search
            - Add, edit, delete operations
            - Password generation
            - Security analysis
            - Backup/restore functionality
        """
        logger.info("Showing vault window...")
        
        # Destroy current window if exists
        if self._current_window:
            self._current_window.destroy()
        
        # Create vault window (uses singletons for vault, session, clipboard)
        self._current_window = VaultWindow(
            on_logout=self._on_logout,
            on_lock=self._on_session_locked
        )
    
    def _on_logout(self):
        """
        Handle user logout request.
        
        Performs cleanup:
            1. Clear clipboard
            2. Destroy session
            3. Clear vault data
            4. Return to login window
        """
        logger.info("User logged out")
        
        # Clear clipboard for security
        if self._clipboard_manager:
            self._clipboard_manager.clear_clipboard()
        
        # Destroy session
        if self._session_manager:
            self._session_manager.logout()
        
        # Clear vault
        self._vault = None
        
        # Return to login
        self._show_login_window()
    
    def _on_session_locked(self):
        """
        Handle session lock (auto-lock timeout or manual lock).
        
        When the session is locked:
            1. Hide the vault window
            2. Clear sensitive data from memory
            3. Show login window for re-authentication
        """
        logger.info("Session locked")
        
        # Clear clipboard
        if self._clipboard_manager:
            self._clipboard_manager.clear_clipboard()
        
        # Lock the session (preserves session but requires re-auth)
        if self._session_manager and self._session_manager.current_session:
            self._session_manager.lock()
        
        # Show message
        self._root.after(0, lambda: messagebox.showinfo(
            "Session Locked",
            "Your session has been locked due to inactivity.\n"
            "Please enter your master password to continue."
        ))
        
        # Return to login (vault data preserved in memory)
        self._show_login_window()
    
    def _on_close_request(self):
        """Handle window close request."""
        if self._is_shutting_down:
            return
        
        # Confirm exit if logged in
        if self._vault is not None:
            result = messagebox.askyesno(
                "Confirm Exit",
                "Are you sure you want to exit?\n"
                "Your session will be ended."
            )
            if not result:
                return
        
        self._shutdown()
    
    def _shutdown(self):
        """
        Perform graceful application shutdown.
        
        Cleanup order (reverse of initialization):
            1. Stop auto-lock timer
            2. Clear clipboard
            3. Destroy session
            4. Stop all threads
            5. Close database connection
            6. Release instance lock
        """
        if self._is_shutting_down:
            return
        
        self._is_shutting_down = True
        logger.info("Shutting down application...")
        
        try:
            # 1. Stop session manager
            if self._session_manager:
                self._session_manager.logout()
            
            # 2. Clear clipboard
            if self._clipboard_manager:
                self._clipboard_manager.clear_clipboard()
                self._clipboard_manager.shutdown()
            
            # 3. Stop all background threads
            if self._thread_manager:
                self._thread_manager.stop_all()
            
            # 4. Close database connection
            if self._db_engine:
                self._db_engine.disconnect()
            
            # 5. Release instance lock
            if self._instance_guard:
                self._instance_guard.release()
            
            logger.info("Shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        
        finally:
            # Destroy the root window
            if self._root:
                self._root.quit()
                self._root.destroy()
    
    def _cleanup(self):
        """Cleanup handler called by atexit."""
        if not self._is_shutting_down:
            self._shutdown()
    
    def run(self):
        """
        Run the Password Manager application.
        
        This is the main entry point that:
            1. Checks for single instance
            2. Initializes all components
            3. Creates the UI
            4. Starts the event loop
        
        Returns:
            int: Exit code (0 for success, 1 for error).
        """
        logger.info(f"Starting {self.APP_NAME}...")
        
        try:
            # Check single instance
            if not self._check_single_instance():
                # Show error in minimal dialog
                root = tk.Tk()
                root.withdraw()
                messagebox.showerror(
                    "Already Running",
                    f"{self.APP_NAME} is already running.\n"
                    "Only one instance is allowed at a time."
                )
                root.destroy()
                return 1
            
            # Initialize components
            if not self._initialize_components():
                logger.error("Failed to initialize components")
                return 1
            
            # Create root window
            self._create_root_window()
            
            # Show login window
            self._show_login_window()
            
            # Start event loop
            logger.info("Entering main event loop...")
            self._root.mainloop()
            
            logger.info("Application exited normally")
            return 0
            
        except Exception as e:
            logger.exception(f"Unhandled exception: {e}")
            
            # Show error dialog
            try:
                root = tk.Tk()
                root.withdraw()
                messagebox.showerror(
                    "Error",
                    f"An unexpected error occurred:\n{str(e)}\n\n"
                    "Please check the log file for details."
                )
                root.destroy()
            except Exception:
                pass
            
            return 1


def main():
    """
    Application entry point.
    
    Creates and runs the PasswordManagerApp instance.
    """
    app = PasswordManagerApp()
    exit_code = app.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
