"""
Security Graph View

Visualizes password reuse relationships using a graph.
Demonstrates graph data structure usage.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk
from typing import Optional, Dict, List, Any
import math

# Add parent directory to path for cross-package imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.base_window import BaseWindow
from core.vault import get_vault


class SecurityGraphWindow(BaseWindow):
    """
    Window for visualizing password security relationships.
    
    Features:
    - Graph visualization of password reuse
    - Color-coded risk levels
    - Interactive node selection
    - Security score display
    
    Uses the Graph data structure for analysis.
    """
    
    # Node colors based on risk
    RISK_COLORS = {
        'safe': '#4CAF50',      # Green - no reuse
        'low': '#8BC34A',       # Light green
        'medium': '#FF9800',    # Orange
        'high': '#F44336',      # Red
        'critical': '#B71C1C'   # Dark red
    }
    
    def __init__(self, parent: tk.Tk):
        """
        Initialize the graph view window.
        
        Args:
            parent: Parent window
        """
        super().__init__(
            parent=parent,
            title="Security Analysis - Password Reuse Graph",
            width=800,
            height=600
        )
        
        self._vault = get_vault()
        self._node_positions: Dict[str, tuple] = {}
        self._node_widgets: Dict[str, int] = {}  # Canvas item IDs
        
        self._build_ui()
        self._load_graph_data()
    
    def _build_ui(self) -> None:
        """Build the graph visualization interface."""
        # Main container
        main_frame = ttk.Frame(self._root, padding=10)
        main_frame.pack(fill='both', expand=True)
        
        # Top - Security score
        self._build_score_panel(main_frame)
        
        # Middle - Canvas for graph
        self._build_canvas(main_frame)
        
        # Bottom - Legend and info
        self._build_legend(main_frame)
    
    def _build_score_panel(self, parent: ttk.Frame) -> None:
        """Build the security score display."""
        score_frame = ttk.Frame(parent)
        score_frame.pack(fill='x', pady=(0, 10))
        
        # Title
        ttk.Label(
            score_frame,
            text="🔐 Security Analysis",
            style='Title.TLabel'
        ).pack(side='left')
        
        # Score display
        self._score_frame = ttk.Frame(score_frame)
        self._score_frame.pack(side='right')
        
        ttk.Label(
            self._score_frame,
            text="Security Score: ",
            font=('Segoe UI', 12)
        ).pack(side='left')
        
        self._score_label = ttk.Label(
            self._score_frame,
            text="--",
            font=('Segoe UI', 16, 'bold')
        )
        self._score_label.pack(side='left')
    
    def _build_canvas(self, parent: ttk.Frame) -> None:
        """Build the graph canvas."""
        # Canvas frame with border
        canvas_frame = ttk.Frame(parent, relief='sunken', borderwidth=1)
        canvas_frame.pack(fill='both', expand=True, pady=5)
        
        self._canvas = tk.Canvas(
            canvas_frame,
            bg='white',
            highlightthickness=0
        )
        self._canvas.pack(fill='both', expand=True)
        
        # Bind events
        self._canvas.bind('<Configure>', self._on_canvas_resize)
        self._canvas.bind('<Button-1>', self._on_canvas_click)
    
    def _build_legend(self, parent: ttk.Frame) -> None:
        """Build the legend."""
        legend_frame = ttk.Frame(parent)
        legend_frame.pack(fill='x', pady=(10, 0))
        
        # Legend items
        ttk.Label(legend_frame, text="Legend:", 
                  font=('Segoe UI', 10, 'bold')).pack(side='left', padx=(0, 10))
        
        for label, color in [
            ("Safe (unique)", self.RISK_COLORS['safe']),
            ("Low risk", self.RISK_COLORS['low']),
            ("Medium risk", self.RISK_COLORS['medium']),
            ("High risk", self.RISK_COLORS['high'])
        ]:
            item_frame = ttk.Frame(legend_frame)
            item_frame.pack(side='left', padx=10)
            
            # Color box
            color_canvas = tk.Canvas(item_frame, width=16, height=16, 
                                     highlightthickness=0)
            color_canvas.pack(side='left', padx=(0, 5))
            color_canvas.create_oval(2, 2, 14, 14, fill=color, outline='')
            
            ttk.Label(item_frame, text=label).pack(side='left')
        
        # Info
        self._info_label = ttk.Label(
            legend_frame,
            text="Lines connect credentials sharing the same password",
            foreground=self.COLORS['text_secondary']
        )
        self._info_label.pack(side='right')
    
    def _load_graph_data(self) -> None:
        """Load and display graph data from vault."""
        report = self._vault.get_security_report()
        graph_data = report.get('graph_data', {})
        
        # Update score
        score = report.get('security_score', 0)
        self._update_score_display(score)
        
        # Draw graph
        nodes = graph_data.get('nodes', [])
        edges = graph_data.get('edges', [])
        
        self._draw_graph(nodes, edges)
    
    def _update_score_display(self, score: float) -> None:
        """Update the security score display."""
        score_int = int(score)
        
        if score >= 90:
            color = self.RISK_COLORS['safe']
            rating = "Excellent"
        elif score >= 70:
            color = self.RISK_COLORS['low']
            rating = "Good"
        elif score >= 50:
            color = self.RISK_COLORS['medium']
            rating = "Fair"
        else:
            color = self.RISK_COLORS['high']
            rating = "Poor"
        
        self._score_label.configure(
            text=f"{score_int}% ({rating})",
            foreground=color
        )
    
    def _draw_graph(self, nodes: List[Dict], edges: List[tuple]) -> None:
        """
        Draw the graph on canvas.
        
        Args:
            nodes: List of node data
            edges: List of (from_id, to_id) tuples
        """
        self._canvas.delete('all')
        self._node_positions.clear()
        self._node_widgets.clear()
        
        if not nodes:
            # Show empty message
            self._canvas.create_text(
                self._canvas.winfo_width() // 2,
                self._canvas.winfo_height() // 2,
                text="No credentials to analyze.\nAdd some credentials to see the security graph.",
                font=('Segoe UI', 12),
                fill=self.COLORS['text_secondary'],
                justify='center'
            )
            return
        
        # Calculate positions (force-directed layout simulation)
        self._calculate_positions(nodes, edges)
        
        # Draw edges first (behind nodes)
        for from_id, to_id in edges:
            self._draw_edge(from_id, to_id)
        
        # Draw nodes
        for node in nodes:
            self._draw_node(node)
    
    def _calculate_positions(self, nodes: List[Dict], 
                             edges: List[tuple]) -> None:
        """
        Calculate node positions using circular layout.
        
        For simplicity, we use a circular layout.
        A more advanced implementation could use force-directed layout.
        """
        width = self._canvas.winfo_width() or 780
        height = self._canvas.winfo_height() or 500
        
        center_x = width // 2
        center_y = height // 2
        radius = min(width, height) // 2 - 60
        
        n = len(nodes)
        
        for i, node in enumerate(nodes):
            if n == 1:
                # Single node at center
                x = center_x
                y = center_y
            else:
                # Distribute around circle
                angle = (2 * math.pi * i) / n - math.pi / 2
                x = center_x + radius * math.cos(angle)
                y = center_y + radius * math.sin(angle)
            
            self._node_positions[node['id']] = (x, y)
    
    def _draw_node(self, node: Dict) -> None:
        """
        Draw a single node.
        
        Args:
            node: Node data dictionary
        """
        node_id = node['id']
        risk = node.get('risk', 0)
        data = node.get('data')
        
        x, y = self._node_positions.get(node_id, (100, 100))
        
        # Determine color based on risk
        if risk == 0:
            color = self.RISK_COLORS['safe']
        elif risk < 0.3:
            color = self.RISK_COLORS['low']
        elif risk < 0.6:
            color = self.RISK_COLORS['medium']
        else:
            color = self.RISK_COLORS['high']
        
        # Node size based on degree
        degree = node.get('degree', 0)
        size = 20 + min(degree * 5, 30)  # 20-50 pixels
        
        # Draw node circle
        oval_id = self._canvas.create_oval(
            x - size, y - size,
            x + size, y + size,
            fill=color,
            outline='white',
            width=2
        )
        
        # Draw label
        label = data.site_name if data else node_id
        if len(label) > 12:
            label = label[:10] + "..."
        
        text_id = self._canvas.create_text(
            x, y + size + 15,
            text=label,
            font=('Segoe UI', 9),
            fill=self.COLORS['text_primary']
        )
        
        # Store widget IDs
        self._node_widgets[node_id] = (oval_id, text_id)
        
        # Bind click event
        self._canvas.tag_bind(oval_id, '<Button-1>', 
                              lambda e, nid=node_id: self._on_node_click(nid))
    
    def _draw_edge(self, from_id: str, to_id: str) -> None:
        """
        Draw an edge between two nodes.
        
        Args:
            from_id: Source node ID
            to_id: Target node ID
        """
        if from_id not in self._node_positions or to_id not in self._node_positions:
            return
        
        x1, y1 = self._node_positions[from_id]
        x2, y2 = self._node_positions[to_id]
        
        self._canvas.create_line(
            x1, y1, x2, y2,
            fill=self.RISK_COLORS['medium'],
            width=2,
            dash=(5, 3)
        )
    
    def _on_canvas_resize(self, event) -> None:
        """Handle canvas resize."""
        # Redraw graph with new dimensions
        self.after(100, self._load_graph_data)
    
    def _on_canvas_click(self, event) -> None:
        """Handle canvas click (deselect)."""
        self._info_label.configure(
            text="Lines connect credentials sharing the same password"
        )
    
    def _on_node_click(self, node_id: str) -> None:
        """
        Handle node click.
        
        Args:
            node_id: Clicked node ID
        """
        try:
            cred_id = int(node_id)
            credential = self._vault.get_credential(cred_id)
            
            if credential:
                self._info_label.configure(
                    text=f"Selected: {credential.site_name} ({credential.username})"
                )
        except ValueError:
            pass


class SecurityReportDialog(BaseWindow):
    """
    Dialog showing detailed security report.
    """
    
    def __init__(self, parent: tk.Tk):
        """Initialize the report dialog."""
        super().__init__(
            parent=parent,
            title="Security Report",
            width=500,
            height=400,
            resizable=False
        )
        
        self._vault = get_vault()
        self._build_ui()
    
    def _build_ui(self) -> None:
        """Build the report interface."""
        main_frame = ttk.Frame(self._root, padding=20)
        main_frame.pack(fill='both', expand=True)
        
        # Title
        ttk.Label(
            main_frame,
            text="🔐 Security Report",
            style='Title.TLabel'
        ).pack(pady=(0, 20))
        
        # Get report data
        report = self._vault.get_security_report()
        
        # Stats
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill='x', pady=10)
        
        stats = [
            ("Total Credentials", report.get('total_credentials', 0)),
            ("Unique Passwords", report.get('unique_passwords', 0)),
            ("Password Reuse Groups", report.get('reuse_clusters', 0)),
            ("Affected Credentials", report.get('affected_credentials', 0)),
            ("High Risk Count", report.get('high_risk_count', 0))
        ]
        
        for label, value in stats:
            row = ttk.Frame(stats_frame)
            row.pack(fill='x', pady=3)
            
            ttk.Label(row, text=label + ":", width=25).pack(side='left')
            ttk.Label(row, text=str(value), font=('Segoe UI', 10, 'bold')).pack(side='left')
        
        # Score
        score = report.get('security_score', 0)
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=15)
        
        score_frame = ttk.Frame(main_frame)
        score_frame.pack()
        
        ttk.Label(
            score_frame,
            text="Overall Security Score",
            font=('Segoe UI', 12)
        ).pack()
        
        ttk.Label(
            score_frame,
            text=f"{int(score)}%",
            font=('Segoe UI', 24, 'bold'),
            foreground=self._get_score_color(score)
        ).pack()
        
        # Recommendations
        if report.get('reuse_clusters', 0) > 0:
            ttk.Label(
                main_frame,
                text="⚠️ You have reused passwords! Consider changing them.",
                foreground=self.COLORS['warning']
            ).pack(pady=(20, 0))
        
        # Close button
        ttk.Button(
            main_frame,
            text="Close",
            command=self.close
        ).pack(pady=(20, 0))
    
    def _get_score_color(self, score: float) -> str:
        """Get color based on score."""
        if score >= 90:
            return '#4CAF50'
        elif score >= 70:
            return '#8BC34A'
        elif score >= 50:
            return '#FF9800'
        else:
            return '#F44336'
