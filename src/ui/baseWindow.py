"""
Base Window

Abstract base class for all application windows.
Demonstrates abstraction and inheritance.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from abc import ABC, abstractmethod
from typing import Optional, Callable, Dict, Any


class BaseWindow(ABC):
    """
    Abstract base class for all windows in the application.
    
    OOP Concepts:
    - Abstraction: Defines interface for all windows
    - Inheritance: Child classes extend this
    - Encapsulation: Window internals are private
    
    Common functionality:
    - Window setup and theming
    - Lifecycle management
    - Event handling patterns
    """
    
    # Application-wide theme colors
    COLORS = {
        'primary': '#2196F3',
        'primary_dark': '#1976D2',
        'secondary': '#4CAF50',
        'background': '#FAFAFA',
        'surface': '#FFFFFF',
        'error': '#F44336',
        'warning': '#FF9800',
        'text_primary': '#212121',
        'text_secondary': '#757575',
        'border': '#E0E0E0'
    }
    
    # Default window dimensions
    DEFAULT_WIDTH = 800
    DEFAULT_HEIGHT = 600
    
    def __init__(self, parent: Optional[tk.Tk] = None,
                 title: str = "Password Manager",
                 width: int = DEFAULT_WIDTH,
                 height: int = DEFAULT_HEIGHT,
                 resizable: bool = True):
        """
        Initialize the base window.
        
        Args:
            parent: Parent window (None for root)
            title: Window title
            width: Window width
            height: Window height
            resizable: Whether window can be resized
        """
        # Create window
        if parent is None:
            self._root = tk.Tk()
            self._is_root = True
        else:
            self._root = tk.Toplevel(parent)
            self._is_root = False
        
        self._parent = parent
        self._title = title
        self._width = width
        self._height = height
        
        # Configure window
        self._root.title(title)
        self._root.geometry(f"{width}x{height}")
        self._root.resizable(resizable, resizable)
        
        # Center window
        self._center_window()
        
        # Apply theme
        self._setup_theme()
        
        # Track if window is open
        self._is_open = True
        
        # Bind close event
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)
        
        # Callbacks
        self._on_close_callback: Optional[Callable] = None
    
    @property
    def root(self) -> tk.Tk:
        """Get the underlying Tk window."""
        return self._root
    
    @property
    def is_open(self) -> bool:
        """Check if window is open."""
        return self._is_open
    
    def _center_window(self) -> None:
        """Center the window on screen."""
        self._root.update_idletasks()
        
        screen_width = self._root.winfo_screenwidth()
        screen_height = self._root.winfo_screenheight()
        
        x = (screen_width - self._width) // 2
        y = (screen_height - self._height) // 2
        
        self._root.geometry(f"{self._width}x{self._height}+{x}+{y}")
    
    def _setup_theme(self) -> None:
        """Configure ttk styles for consistent theming."""
        style = ttk.Style()
        
        # Configure common styles
        style.configure('TFrame', background=self.COLORS['background'])
        
        style.configure('TLabel',
            background=self.COLORS['background'],
            foreground=self.COLORS['text_primary'],
            font=('Segoe UI', 10)
        )
        
        style.configure('Title.TLabel',
            font=('Segoe UI', 16, 'bold'),
            foreground=self.COLORS['primary']
        )
        
        style.configure('Subtitle.TLabel',
            font=('Segoe UI', 12),
            foreground=self.COLORS['text_secondary']
        )
        
        style.configure('TButton',
            font=('Segoe UI', 10),
            padding=(10, 5)
        )
        
        style.configure('Primary.TButton',
            background=self.COLORS['primary'],
            foreground='white'
        )
        
        style.configure('TEntry',
            padding=5,
            font=('Segoe UI', 10)
        )
        
        style.configure('Treeview',
            font=('Segoe UI', 10),
            rowheight=30
        )
        
        style.configure('Treeview.Heading',
            font=('Segoe UI', 10, 'bold')
        )
        
        # Configure root background
        self._root.configure(bg=self.COLORS['background'])
    
    @abstractmethod
    def _build_ui(self) -> None:
        """
        Build the user interface.
        
        Subclasses must implement this method to create their UI.
        """
        pass
    
    def set_on_close(self, callback: Callable) -> None:
        """
        Set callback for window close event.
        
        Args:
            callback: Function to call on close
        """
        self._on_close_callback = callback
    
    def _on_close(self) -> None:
        """Handle window close event."""
        if not self._is_open:
            return  # Already closed, prevent double-close
        
        self._is_open = False
        
        if self._on_close_callback:
            try:
                self._on_close_callback()
            except Exception as e:
                print(f"Close callback error: {e}")
        
        try:
            self._root.destroy()
        except tk.TclError:
            # Window already destroyed
            pass
    
    def show(self) -> None:
        """Show the window."""
        self._root.deiconify()
        self._root.lift()
        self._root.focus_force()
    
    def hide(self) -> None:
        """Hide the window."""
        self._root.withdraw()
    
    def close(self) -> None:
        """Close the window."""
        self._on_close()
    
    def destroy(self) -> None:
        """Destroy the window (alias for close)."""
        self.close()
    
    def run(self) -> None:
        """Run the main event loop (only for root window)."""
        if self._is_root:
            self._root.mainloop()
    
    def show_error(self, title: str, message: str) -> None:
        """
        Show an error message dialog.
        
        Args:
            title: Dialog title
            message: Error message
        """
        messagebox.showerror(title, message, parent=self._root)
    
    def show_warning(self, title: str, message: str) -> None:
        """
        Show a warning message dialog.
        
        Args:
            title: Dialog title
            message: Warning message
        """
        messagebox.showwarning(title, message, parent=self._root)
    
    def show_info(self, title: str, message: str) -> None:
        """
        Show an info message dialog.
        
        Args:
            title: Dialog title
            message: Info message
        """
        messagebox.showinfo(title, message, parent=self._root)
    
    def ask_yes_no(self, title: str, message: str) -> bool:
        """
        Show a yes/no confirmation dialog.
        
        Args:
            title: Dialog title
            message: Question message
            
        Returns:
            True if user clicked Yes
        """
        return messagebox.askyesno(title, message, parent=self._root)
    
    def create_label_entry(self, parent: tk.Widget, label_text: str,
                           show: str = None,
                           width: int = 30) -> tuple:
        """
        Create a labeled entry field.
        
        Args:
            parent: Parent widget
            label_text: Label text
            show: Character to show (for passwords)
            width: Entry width
            
        Returns:
            Tuple of (frame, label, entry, variable)
        """
        frame = ttk.Frame(parent)
        
        label = ttk.Label(frame, text=label_text)
        label.pack(anchor='w')
        
        var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=var, width=width, show=show or '')
        entry.pack(fill='x', pady=(2, 0))
        
        return frame, label, entry, var
    
    def create_button(self, parent: tk.Widget, text: str,
                      command: Callable, style: str = None) -> ttk.Button:
        """
        Create a styled button.
        
        Args:
            parent: Parent widget
            text: Button text
            command: Click handler
            style: Optional style name
            
        Returns:
            The created button
        """
        button = ttk.Button(parent, text=text, command=command)
        if style:
            button.configure(style=style)
        return button
    
    def bind_enter_key(self, widget: tk.Widget, callback: Callable) -> None:
        """
        Bind Enter key to a callback.
        
        Args:
            widget: Widget to bind to
            callback: Function to call
        """
        widget.bind('<Return>', lambda e: callback())
    
    def after(self, ms: int, callback: Callable) -> str:
        """
        Schedule a callback after delay.
        
        Args:
            ms: Milliseconds delay
            callback: Function to call
            
        Returns:
            Timer ID for cancellation
        """
        return self._root.after(ms, callback)
    
    def cancel_after(self, timer_id: str) -> None:
        """
        Cancel a scheduled callback.
        
        Args:
            timer_id: Timer ID from after()
        """
        self._root.after_cancel(timer_id)
