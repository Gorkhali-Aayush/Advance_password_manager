"""
Custom Widgets

Enhanced UI components for better user experience.
Includes rounded buttons, cards, badges, and other custom widgets.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable
from .theme import ThemeManager, get_theme


class Card(ttk.Frame):
    """
    A card widget for organizing content.
    
    Features:
    - Clean white background
    - Subtle shadow effect
    - Consistent padding
    - Border styling
    """
    
    def __init__(self, parent, **kwargs):
        """
        Initialize Card widget.
        
        Args:
            parent: Parent widget
            **kwargs: Additional frame arguments
        """
        super().__init__(parent, **kwargs)
        
        theme = get_theme()
        self.configure(
            relief='solid',
            borderwidth=1,
            background=theme.COLORS['surface']
        )
        
        # Add inner frame for padding
        self.inner_frame = ttk.Frame(self, padding=theme.get_spacing('md'))
        self.inner_frame.pack(fill='both', expand=True)


class Badge(tk.Label):
    """
    A badge widget for displaying labels/tags.
    
    Features:
    - Multiple color schemes
    - Compact size
    - Easy customization
    """
    
    def __init__(self, parent, text: str, variant: str = 'primary', **kwargs):
        """
        Initialize Badge widget.
        
        Args:
            parent: Parent widget
            text: Badge text
            variant: Color variant (primary, success, warning, error, info)
            **kwargs: Additional label arguments
        """
        super().__init__(parent, **kwargs)
        
        theme = get_theme()
        
        # Map variant to colors
        color_map = {
            'primary': (theme.COLORS['primary'], 'white'),
            'success': (theme.COLORS['success'], 'white'),
            'warning': (theme.COLORS['warning'], 'white'),
            'error': (theme.COLORS['error'], 'white'),
            'info': (theme.COLORS['info'], 'white'),
            'secondary': (theme.COLORS['secondary'], 'white'),
            'light': (theme.COLORS['primary_light'], theme.COLORS['primary']),
        }
        
        bg, fg = color_map.get(variant, (theme.COLORS['primary'], 'white'))
        
        self.configure(
            text=text,
            font=('Segoe UI', 9, 'bold'),
            bg=bg,
            fg=fg,
            padx=10,
            pady=4,
            relief='solid',
            borderwidth=0
        )


class StrengthIndicator(ttk.Frame):
    """
    Password strength indicator widget.
    
    Features:
    - Visual strength bar
    - Color coding
    - Text label
    """
    
    def __init__(self, parent, **kwargs):
        """
        Initialize StrengthIndicator widget.
        
        Args:
            parent: Parent widget
            **kwargs: Additional frame arguments
        """
        super().__init__(parent, **kwargs)
        
        theme = get_theme()
        self.theme = theme
        
        # Label
        self.label_frame = ttk.Frame(self)
        self.label_frame.pack(fill='x', pady=(0, 5))
        
        self.label = ttk.Label(
            self.label_frame,
            text="Password Strength:",
            font=('Segoe UI', 9)
        )
        self.label.pack(side='left')
        
        self.strength_text = ttk.Label(
            self.label_frame,
            text="Weak",
            font=('Segoe UI', 9, 'bold'),
            foreground=theme.COLORS['error']
        )
        self.strength_text.pack(side='right')
        
        # Progress bars container
        self.bars_frame = ttk.Frame(self)
        self.bars_frame.pack(fill='x')
        
        # Create 4 colored bars
        self.bars = []
        colors = [
            theme.COLORS['error'],
            theme.COLORS['warning'],
            theme.COLORS['info'],
            theme.COLORS['success']
        ]
        
        for i, color in enumerate(colors):
            bar = tk.Frame(
                self.bars_frame,
                bg=color,
                height=8,
                width=0
            )
            bar.pack(side='left', fill='x', expand=True, padx=1)
            self.bars.append(bar)
        
        self.set_strength(0)
    
    def set_strength(self, score: int) -> None:
        """
        Update strength indicator.
        
        Args:
            score: Strength score (0-100)
        """
        # Determine strength level
        if score < 20:
            level = "Weak"
            color = self.theme.COLORS['error']
            bars_to_show = 1
        elif score < 40:
            level = "Fair"
            color = self.theme.COLORS['warning']
            bars_to_show = 2
        elif score < 70:
            level = "Good"
            color = self.theme.COLORS['info']
            bars_to_show = 3
        else:
            level = "Strong"
            color = self.theme.COLORS['success']
            bars_to_show = 4
        
        # Update text
        self.strength_text.configure(text=level, foreground=color)
        
        # Update bars
        for i, bar in enumerate(self.bars):
            if i < bars_to_show:
                bar.configure(bg=color)
            else:
                bar.configure(bg=self.theme.COLORS['border'])


class IconButton(ttk.Button):
    """
    Button with icon support.
    
    Features:
    - Compact size
    - Icon-only or text+icon
    - Multiple variants
    """
    
    def __init__(self, parent, icon: str = "", text: str = "", 
                 command: Optional[Callable] = None,
                 variant: str = 'secondary', **kwargs):
        """
        Initialize IconButton widget.
        
        Args:
            parent: Parent widget
            icon: Icon text/emoji
            text: Button text
            command: Button command
            variant: Button style variant
            **kwargs: Additional button arguments
        """
        display_text = f"{icon} {text}".strip()
        
        super().__init__(parent, text=display_text, command=command, **kwargs)
        
        style_name = f'{variant.capitalize()}.TButton'
        self.configure(style=style_name)


class SearchEntry(ttk.Frame):
    """
    Enhanced search entry widget.
    
    Features:
    - Search icon
    - Clear button
    - Real-time search
    """
    
    def __init__(self, parent, on_search: Optional[Callable] = None, **kwargs):
        """
        Initialize SearchEntry widget.
        
        Args:
            parent: Parent widget
            on_search: Callback when search text changes
            **kwargs: Additional frame arguments
        """
        super().__init__(parent, **kwargs)
        
        theme = get_theme()
        self.on_search = on_search
        
        # Search icon + entry frame
        search_frame = ttk.Frame(self)
        search_frame.pack(fill='x', expand=True)
        
        # Icon
        icon_label = ttk.Label(
            search_frame,
            text="🔍",
            font=('Segoe UI', 11)
        )
        icon_label.pack(side='left', padx=(0, 8))
        
        # Entry
        self.var = tk.StringVar()
        self.var.trace('w', lambda *args: self._on_change())
        
        self.entry = ttk.Entry(
            search_frame,
            textvariable=self.var,
            width=30
        )
        self.entry.pack(side='left', fill='x', expand=True)
        
        # Clear button
        self.clear_btn = tk.Button(
            search_frame,
            text="✕",
            font=('Segoe UI', 10),
            bg=theme.COLORS['background'],
            fg=theme.COLORS['text_secondary'],
            border=0,
            command=self.clear
        )
        self.clear_btn.pack(side='left', padx=(8, 0))
    
    def _on_change(self) -> None:
        """Handle text change."""
        if self.on_search:
            self.on_search(self.var.get())
    
    def clear(self) -> None:
        """Clear the search entry."""
        self.var.set("")
    
    def get(self) -> str:
        """Get search text."""
        return self.var.get()


class InfoBox(ttk.Frame):
    """
    Information box widget.
    
    Features:
    - Multiple message types (info, success, warning, error)
    - Clean design
    - Icon support
    """
    
    def __init__(self, parent, message: str = "", msg_type: str = 'info', **kwargs):
        """
        Initialize InfoBox widget.
        
        Args:
            parent: Parent widget
            message: Message text
            msg_type: Message type (info, success, warning, error)
            **kwargs: Additional frame arguments
        """
        super().__init__(parent, **kwargs)
        
        theme = get_theme()
        
        # Color mapping
        type_map = {
            'info': (theme.COLORS['info_light'], theme.COLORS['info'], 'ℹ'),
            'success': (theme.COLORS['success_light'], theme.COLORS['success'], '✓'),
            'warning': (theme.COLORS['warning_light'], theme.COLORS['warning'], '⚠'),
            'error': (theme.COLORS['error_light'], theme.COLORS['error'], '✕'),
        }
        
        bg, fg, icon = type_map.get(msg_type, type_map['info'])
        
        self.configure(
            relief='solid',
            borderwidth=1,
            background=bg,
            padding=theme.get_spacing('md')
        )
        
        # Content frame
        content_frame = ttk.Frame(self)
        content_frame.pack(fill='x', expand=True)
        
        # Icon
        icon_label = tk.Label(
            content_frame,
            text=icon,
            font=('Segoe UI', 12, 'bold'),
            bg=bg,
            fg=fg
        )
        icon_label.pack(side='left', padx=(0, 10))
        
        # Message
        msg_label = tk.Label(
            content_frame,
            text=message,
            font=('Segoe UI', 10),
            bg=bg,
            fg=fg,
            wraplength=400,
            justify='left'
        )
        msg_label.pack(side='left', fill='both', expand=True)


class StatusBar(ttk.Frame):
    """
    Status bar widget.
    
    Features:
    - Left and right content areas
    - Status indicators
    - Consistent styling
    """
    
    def __init__(self, parent, **kwargs):
        """
        Initialize StatusBar widget.
        
        Args:
            parent: Parent widget
            **kwargs: Additional frame arguments
        """
        super().__init__(parent, **kwargs)
        
        theme = get_theme()
        self.configure(
            relief='solid',
            borderwidth=1,
            height=40,
            padding=(theme.get_spacing('md'), 8)
        )
        
        # Left content
        self.left_frame = ttk.Frame(self)
        self.left_frame.pack(side='left', fill='x', expand=True)
        
        # Right content
        self.right_frame = ttk.Frame(self)
        self.right_frame.pack(side='right')
        
        # Status text
        self.status_label = ttk.Label(
            self.left_frame,
            text="Ready",
            font=('Segoe UI', 9)
        )
        self.status_label.pack(side='left')
    
    def set_status(self, text: str) -> None:
        """
        Update status text.
        
        Args:
            text: Status text
        """
        self.status_label.configure(text=text)


class DialogButton(ttk.Frame):
    """
    Dialog button container.
    
    Features:
    - Consistent button layout
    - Standard button spacing
    - Easy command binding
    """
    
    def __init__(self, parent, **kwargs):
        """
        Initialize DialogButton widget.
        
        Args:
            parent: Parent widget
            **kwargs: Additional frame arguments
        """
        super().__init__(parent, **kwargs)
        
        theme = get_theme()
        self.configure(padding=(theme.get_spacing('md'), 0))
    
    def add_button(self, text: str, command: Optional[Callable] = None,
                  variant: str = 'secondary') -> ttk.Button:
        """
        Add a button to the container.
        
        Args:
            text: Button text
            command: Button command
            variant: Button style variant
            
        Returns:
            Created button widget
        """
        style_name = f'{variant.capitalize()}.TButton'
        btn = ttk.Button(
            self,
            text=text,
            command=command,
            style=style_name
        )
        btn.pack(side='right', padx=(5, 0))
        return btn
