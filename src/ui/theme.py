"""
Theme Manager

Centralized theme and styling management for the application.
Provides consistent look and feel across all UI components.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Tuple


class ThemeManager:
    """
    Centralized theme management for Material Design styling.
    
    Provides:
    - Consistent color scheme across application
    - Easy theme switching capability
    - Custom widget styles
    - Responsive design helpers
    """
    
    # Color Palette
    COLORS = {
        # Primary Colors
        'primary': '#1E88E5',           # Modern Blue
        'primary_dark': '#0D47A1',      # Dark Blue
        'primary_light': '#E3F2FD',     # Light Blue
        
        # Secondary Colors
        'secondary': '#00BCD4',         # Cyan
        'secondary_dark': '#0097A7',    # Dark Cyan
        'secondary_light': '#B2EBF2',   # Light Cyan
        
        # Semantic Colors
        'success': '#4CAF50',           # Green
        'success_light': '#E8F5E9',     # Light Green
        'warning': '#FF9800',           # Orange
        'warning_light': '#FFF3E0',     # Light Orange
        'error': '#F44336',             # Red
        'error_light': '#FFEBEE',       # Light Red
        'info': '#2196F3',              # Blue
        'info_light': '#E3F2FD',        # Light Blue
        
        # Neutral Colors
        'background': '#F5F5F5',        # Light Gray
        'surface': '#FFFFFF',           # White
        'surface_alt': '#FAFAFA',       # Very Light Gray
        'text_primary': '#212121',      # Dark Text
        'text_secondary': '#666666',    # Medium Gray
        'text_disabled': '#BDBDBD',     # Light Gray
        'border': '#E0E0E0',            # Border Gray
        'divider': '#EEEEEE',           # Divider Gray
        'hover': '#F0F0F0',             # Hover State
        'shadow': 'rgba(0,0,0,0.12)'    # Shadow
    }
    
    # Font Families
    FONTS = {
        'primary': ('Segoe UI', 10),
        'title': ('Segoe UI', 20, 'bold'),
        'heading': ('Segoe UI', 14, 'bold'),
        'subheading': ('Segoe UI', 12, 'bold'),
        'body': ('Segoe UI', 10),
        'caption': ('Segoe UI', 9),
        'monospace': ('Courier New', 10)
    }
    
    # Spacing
    SPACING = {
        'xs': 4,
        'sm': 8,
        'md': 12,
        'lg': 16,
        'xl': 24,
        'xxl': 32
    }
    
    # Border Radius (approximation using paddings)
    RADIUS = {
        'sm': 2,
        'md': 4,
        'lg': 8
    }
    
    @classmethod
    def configure_styles(cls, root: tk.Tk) -> ttk.Style:
        """
        Configure all ttk styles for the application.
        
        Args:
            root: Root Tk window
            
        Returns:
            Configured ttk.Style object
        """
        style = ttk.Style()
        
        # Configure TFrame
        style.configure('TFrame',
            background=cls.COLORS['background']
        )
        
        style.configure('Surface.TFrame',
            background=cls.COLORS['surface']
        )
        
        # Configure TLabel
        style.configure('TLabel',
            font=cls.FONTS['body'],
            background=cls.COLORS['background'],
            foreground=cls.COLORS['text_primary']
        )
        
        style.configure('Title.TLabel',
            font=cls.FONTS['title'],
            background=cls.COLORS['background'],
            foreground=cls.COLORS['primary']
        )
        
        style.configure('Subtitle.TLabel',
            font=('Segoe UI', 11),
            background=cls.COLORS['background'],
            foreground=cls.COLORS['text_secondary']
        )
        
        style.configure('Heading.TLabel',
            font=cls.FONTS['heading'],
            background=cls.COLORS['surface'],
            foreground=cls.COLORS['primary']
        )
        
        style.configure('Subheading.TLabel',
            font=cls.FONTS['subheading'],
            background=cls.COLORS['background'],
            foreground=cls.COLORS['text_primary']
        )
        
        style.configure('Caption.TLabel',
            font=cls.FONTS['caption'],
            background=cls.COLORS['background'],
            foreground=cls.COLORS['text_secondary']
        )
        
        style.configure('Success.TLabel',
            font=cls.FONTS['body'],
            background=cls.COLORS['success_light'],
            foreground=cls.COLORS['success']
        )
        
        style.configure('Warning.TLabel',
            font=cls.FONTS['body'],
            background=cls.COLORS['warning_light'],
            foreground=cls.COLORS['warning']
        )
        
        style.configure('Error.TLabel',
            font=cls.FONTS['body'],
            background=cls.COLORS['error_light'],
            foreground=cls.COLORS['error']
        )
        
        # Configure TButton
        style.configure('TButton',
            font=cls.FONTS['body'],
            padding=(12, 8)
        )
        
        style.configure('Primary.TButton',
            font=('Segoe UI', 10, 'bold'),
            padding=(12, 8)
        )
        
        style.map('Primary.TButton',
            background=[('pressed', cls.COLORS['primary_dark']),
                       ('active', cls.COLORS['primary'])]
        )
        
        style.configure('Success.TButton',
            font=('Segoe UI', 10, 'bold'),
            padding=(12, 8)
        )
        
        style.map('Success.TButton',
            background=[('pressed', '#388E3C'),
                       ('active', cls.COLORS['success'])]
        )
        
        style.configure('Danger.TButton',
            font=('Segoe UI', 10, 'bold'),
            padding=(12, 8)
        )
        
        style.map('Danger.TButton',
            background=[('pressed', '#C62828'),
                       ('active', cls.COLORS['error'])]
        )
        
        style.configure('Secondary.TButton',
            font=('Segoe UI', 10),
            padding=(12, 8)
        )
        
        style.map('Secondary.TButton',
            background=[('pressed', cls.COLORS['secondary_dark']),
                       ('active', cls.COLORS['secondary'])]
        )
        
        # Configure TEntry
        style.configure('TEntry',
            padding=10,
            font=cls.FONTS['body'],
            relief='flat',
            borderwidth=1
        )
        
        style.configure('Readonly.TEntry',
            padding=10,
            font=cls.FONTS['body'],
            relief='flat',
            borderwidth=1
        )
        
        # Configure Combobox
        style.configure('TCombobox',
            padding=10,
            font=cls.FONTS['body']
        )
        
        # Configure Treeview
        style.configure('Treeview',
            font=cls.FONTS['body'],
            rowheight=35,
            background=cls.COLORS['surface'],
            foreground=cls.COLORS['text_primary'],
            fieldbackground=cls.COLORS['surface'],
            relief='flat',
            borderwidth=1
        )
        
        style.configure('Treeview.Heading',
            font=('Segoe UI', 11, 'bold'),
            background=cls.COLORS['primary_light'],
            foreground=cls.COLORS['primary'],
            relief='flat',
            borderwidth=1
        )
        
        style.map('Treeview',
            background=[('selected', cls.COLORS['primary'])],
            foreground=[('selected', 'white')]
        )
        
        style.map('Treeview.Heading',
            background=[('active', cls.COLORS['primary_light'])]
        )
        
        # Configure Notebook
        style.configure('TNotebook',
            background=cls.COLORS['background'],
            borderwidth=0
        )
        
        style.configure('TNotebook.Tab',
            padding=(20, 12),
            font=('Segoe UI', 10)
        )
        
        # Configure Progressbar
        style.configure('Horizontal.TProgressbar',
            background=cls.COLORS['success'],
            troughcolor=cls.COLORS['border'],
            bordercolor=cls.COLORS['border'],
            lightcolor=cls.COLORS['success'],
            darkcolor=cls.COLORS['success']
        )
        
        # Configure Scale
        style.configure('Horizontal.TScale',
            background=cls.COLORS['background']
        )
        
        # Configure Panedwindow
        style.configure('TPanedwindow',
            background=cls.COLORS['background']
        )
        
        return style
    
    @classmethod
    def get_color(cls, color_name: str) -> str:
        """
        Get a color from the palette.
        
        Args:
            color_name: Name of the color
            
        Returns:
            Hex color code
        """
        return cls.COLORS.get(color_name, '#FFFFFF')
    
    @classmethod
    def get_font(cls, font_name: str) -> Tuple[str, int]:
        """
        Get a font from the palette.
        
        Args:
            font_name: Name of the font
            
        Returns:
            Font tuple
        """
        return cls.FONTS.get(font_name, ('Segoe UI', 10))
    
    @classmethod
    def get_spacing(cls, spacing_name: str) -> int:
        """
        Get spacing value.
        
        Args:
            spacing_name: Name of the spacing
            
        Returns:
            Spacing value in pixels
        """
        return cls.SPACING.get(spacing_name, 12)


# Global instance for easy access
_theme_manager = None


def get_theme() -> ThemeManager:
    """Get the global theme manager instance."""
    global _theme_manager
    if _theme_manager is None:
        _theme_manager = ThemeManager()
    return _theme_manager
