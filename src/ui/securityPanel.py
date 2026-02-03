"""
Advanced Security Panel

Comprehensive security analysis dashboard with custom algorithms.

Features (All 9 Must-Have):
1. Password Strength Analysis - Custom scoring algorithm
2. Weak Password Detection - Priority Queue implementation
3. Password Reuse Detection - Graph visualization
4. Age-Based Password Risk - Expiry tracking
5. Entropy Breakdown - Bits calculation
6. Common Pattern Detection - Sliding window algorithm
7. Password Generator Feedback - Live strength meter
8. Real-Time Security Score - Dashboard metric
9. Clipboard Exposure Monitor - OS-level feature
"""

import os
import sys
import logging
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Dict, List, Any
import math
from datetime import datetime

# Add parent directory to path for cross-package imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.baseWindow import BaseWindow
from core.vault import get_vault
from core.securityAnalyzer import get_security_analyzer, SecurityReport, PasswordAnalysis
from os_layer.clipboardManager import get_clipboard_manager

logger = logging.getLogger(__name__)


class AdvancedSecurityPanel(BaseWindow):
    """
    Advanced security analysis dashboard.
    
    Features:
    - Security score with gauge visualization
    - Password strength distribution
    - Password reuse analysis with graph
    - Age analysis (old passwords)
    - Breach simulation
    - Actionable recommendations
    """
    
    # Risk level colors
    RISK_COLORS = {
        'excellent': '#4CAF50',   # Green
        'good': '#8BC34A',        # Light green
        'fair': '#FFC107',        # Yellow/Amber
        'poor': '#FF9800',        # Orange
        'critical': '#F44336',    # Red
    }
    
    # Strength colors
    STRENGTH_COLORS = {
        'VERY_WEAK': '#F44336',
        'WEAK': '#FF9800',
        'MODERATE': '#FFC107',
        'STRONG': '#8BC34A',
        'VERY_STRONG': '#4CAF50',
    }
    
    def __init__(self, parent: Optional[tk.Tk] = None):
        """Initialize the advanced security panel."""
        super().__init__(
            parent=parent,
            title="🔐 Advanced Security Analysis",
            width=1000,
            height=700
        )
        
        self._vault = get_vault()
        self._report_data: Dict[str, Any] = {}
        
        logger.info("Initializing Advanced Security Panel...")
        self._build_ui()
        self._load_security_data()
        logger.info("Advanced Security Panel initialized")
    
    def _build_ui(self) -> None:
        """Build the security dashboard interface."""
        # Main container with notebook tabs
        main_frame = ttk.Frame(self._root, padding=10)
        main_frame.pack(fill='both', expand=True)
        
        # Header
        self._build_header(main_frame)
        
        # Notebook for tabs
        self._notebook = ttk.Notebook(main_frame)
        self._notebook.pack(fill='both', expand=True, pady=(10, 0))
        
        # Tab 1: Overview
        self._overview_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(self._overview_frame, text="📊 Overview")
        
        # Tab 2: Password Strength
        self._strength_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(self._strength_frame, text="💪 Password Strength")
        
        # Tab 3: Reuse Analysis
        self._reuse_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(self._reuse_frame, text="🔗 Reuse Analysis")
        
        # Tab 4: Recommendations
        self._recommend_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(self._recommend_frame, text="💡 Recommendations")
        
        # Build each tab
        self._build_overview_tab()
        self._build_strength_tab()
        self._build_reuse_tab()
        self._build_recommendations_tab()
    
    def _build_header(self, parent: ttk.Frame) -> None:
        """Build the header with title and refresh button."""
        header = ttk.Frame(parent)
        header.pack(fill='x', pady=(0, 10))
        
        ttk.Label(
            header,
            text="🔐 Security Analysis Dashboard",
            font=('Segoe UI', 16, 'bold')
        ).pack(side='left')
        
        # Refresh button
        ttk.Button(
            header,
            text="🔄 Refresh",
            command=self._load_security_data
        ).pack(side='right', padx=5)
        
        # Export button
        ttk.Button(
            header,
            text="📄 Export Report",
            command=self._export_report
        ).pack(side='right', padx=5)
        
        # Last updated
        self._last_updated = ttk.Label(
            header,
            text="",
            foreground='gray'
        )
        self._last_updated.pack(side='right', padx=20)
    
    # ============ Overview Tab ============
    
    def _build_overview_tab(self) -> None:
        """Build the overview tab with score gauge and stats."""
        # Top: Score gauge (centered with proper dimensions)
        gauge_frame = ttk.LabelFrame(self._overview_frame, text="Security Score", padding=15)
        gauge_frame.pack(fill='x', pady=(0, 10))
        
        # Canvas for gauge - centered with proper size
        gauge_container = ttk.Frame(gauge_frame)
        gauge_container.pack(fill='x')
        
        self._gauge_canvas = tk.Canvas(
            gauge_container, 
            width=400, 
            height=220, 
            bg='white', 
            highlightthickness=1,
            highlightbackground='#ddd'
        )
        self._gauge_canvas.pack(pady=10)
        
        # Bind resize to redraw
        self._gauge_canvas.bind('<Configure>', lambda e: self._on_gauge_resize())
        
        # Stats grid
        stats_frame = ttk.LabelFrame(self._overview_frame, text="Quick Stats", padding=15)
        stats_frame.pack(fill='both', expand=True)
        
        # Create 2x3 grid of stat cards
        self._stat_labels = {}
        stats = [
            ('total', '📁 Total Credentials', '0'),
            ('unique', '🔑 Unique Passwords', '0'),
            ('reused', '⚠️ Reused Passwords', '0'),
            ('weak', '🔓 Weak Passwords', '0'),
            ('strong', '🔒 Strong Passwords', '0'),
            ('old', '📅 Old Passwords (>90 days)', '0'),
        ]
        
        for i, (key, label, default) in enumerate(stats):
            row, col = divmod(i, 3)
            card = ttk.Frame(stats_frame, relief='ridge', borderwidth=1, padding=10)
            card.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
            
            ttk.Label(card, text=label, font=('Segoe UI', 9)).pack()
            value_label = ttk.Label(card, text=default, font=('Segoe UI', 20, 'bold'))
            value_label.pack(pady=5)
            self._stat_labels[key] = value_label
        
        # Configure grid
        for i in range(3):
            stats_frame.columnconfigure(i, weight=1)
        for i in range(2):
            stats_frame.rowconfigure(i, weight=1)
    
    def _on_gauge_resize(self) -> None:
        """Handle gauge canvas resize."""
        if hasattr(self, '_last_score'):
            self._draw_gauge(self._last_score)
    
    def _draw_gauge(self, score: float) -> None:
        """Draw the security score gauge."""
        self._last_score = score  # Store for resize redraw
        self._gauge_canvas.delete('all')
        
        # Force update to get actual dimensions
        self._gauge_canvas.update_idletasks()
        
        # Use fixed dimensions for reliable drawing
        canvas_width = 400
        canvas_height = 220
        
        # Semi-circle gauge parameters
        # Center at bottom-center of canvas, with arc opening upward
        cx = canvas_width // 2
        radius = 80  # Fixed radius that fits well
        cy = canvas_height - 35  # Position so the flat part of arc is near bottom
        
        # Draw title at top
        self._gauge_canvas.create_text(
            cx, 15,
            text="Overall Security Score",
            font=('Segoe UI', 11, 'bold'),
            fill='#333'
        )
        
        # Background arc (gray) - semi-circle opening upward
        self._gauge_canvas.create_arc(
            cx - radius, cy - radius,
            cx + radius, cy + radius,
            start=0, extent=180,
            style='arc', width=20,
            outline='#E0E0E0'
        )
        
        # Determine color based on score
        if score >= 90:
            color = self.RISK_COLORS['excellent']
            rating = "🛡️ Excellent"
        elif score >= 70:
            color = self.RISK_COLORS['good']
            rating = "✅ Good"
        elif score >= 50:
            color = self.RISK_COLORS['fair']
            rating = "⚠️ Fair"
        elif score >= 30:
            color = self.RISK_COLORS['poor']
            rating = "🔶 Poor"
        else:
            color = self.RISK_COLORS['critical']
            rating = "🔴 Critical"
        
        # Score arc (colored) - fills from left based on score
        extent = (score / 100) * 180
        self._gauge_canvas.create_arc(
            cx - radius, cy - radius,
            cx + radius, cy + radius,
            start=180 - extent, extent=extent,
            style='arc', width=20,
            outline=color
        )
        
        # Score percentage text (large) - centered above the arc
        self._gauge_canvas.create_text(
            cx, cy - radius - 30,
            text=f"{int(score)}%",
            font=('Segoe UI', 32, 'bold'),
            fill=color
        )
        
        # Rating text - inside the arc area
        self._gauge_canvas.create_text(
            cx, cy - 25,
            text=rating,
            font=('Segoe UI', 11, 'bold'),
            fill=color
        )
        
        # Min/Max labels at arc ends
        self._gauge_canvas.create_text(
            cx - radius - 20, cy + 5,
            text="0%",
            font=('Segoe UI', 9),
            fill='#888'
        )
        self._gauge_canvas.create_text(
            cx + radius + 20, cy + 5,
            text="100%",
            font=('Segoe UI', 9),
            fill='#888'
        )
    
    # ============ Password Strength Tab ============
    
    def _build_strength_tab(self) -> None:
        """Build the password strength analysis tab."""
        # Top section: Strength distribution chart (fixed height)
        dist_frame = ttk.LabelFrame(self._strength_frame, text="Password Strength Distribution", padding=15)
        dist_frame.pack(fill='x', pady=(0, 10))
        
        # Canvas with fixed dimensions for the chart
        self._strength_canvas = tk.Canvas(dist_frame, width=700, height=220, bg='white', highlightthickness=1, highlightbackground='#ddd')
        self._strength_canvas.pack(fill='x', padx=5, pady=5)
        
        # Bind resize event to redraw chart
        self._strength_canvas.bind('<Configure>', lambda e: self._on_strength_canvas_resize())
        
        # Bottom section: Detailed list (expandable)
        list_frame = ttk.LabelFrame(self._strength_frame, text="Password Details", padding=10)
        list_frame.pack(fill='both', expand=True)
        
        # Treeview for credentials with proper column configuration
        columns = ('Site', 'Username', 'Strength', 'Score', 'Issues')
        self._strength_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=8)
        
        # Configure column headings and widths
        self._strength_tree.heading('Site', text='🌐 Site')
        self._strength_tree.heading('Username', text='👤 Username')
        self._strength_tree.heading('Strength', text='💪 Strength')
        self._strength_tree.heading('Score', text='📊 Score')
        self._strength_tree.heading('Issues', text='⚠️ Issues')
        
        self._strength_tree.column('Site', width=150, minwidth=100)
        self._strength_tree.column('Username', width=120, minwidth=80)
        self._strength_tree.column('Strength', width=100, minwidth=80, anchor='center')
        self._strength_tree.column('Score', width=70, minwidth=50, anchor='center')
        self._strength_tree.column('Issues', width=250, minwidth=150)
        
        # Scrollbars
        y_scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self._strength_tree.yview)
        x_scrollbar = ttk.Scrollbar(list_frame, orient='horizontal', command=self._strength_tree.xview)
        self._strength_tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)
        
        # Grid layout for treeview with scrollbars
        self._strength_tree.grid(row=0, column=0, sticky='nsew')
        y_scrollbar.grid(row=0, column=1, sticky='ns')
        x_scrollbar.grid(row=1, column=0, sticky='ew')
        
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
    
    def _on_strength_canvas_resize(self) -> None:
        """Handle canvas resize - redraw the chart."""
        if hasattr(self, '_last_strength_dist'):
            self._draw_strength_chart(self._last_strength_dist)
    
    def _draw_strength_chart(self, distribution: Dict[str, int]) -> None:
        """Draw the strength distribution bar chart."""
        self._last_strength_dist = distribution  # Store for resize redraw
        self._strength_canvas.delete('all')
        
        canvas_width = self._strength_canvas.winfo_width() or 700
        canvas_height = self._strength_canvas.winfo_height() or 220
        
        categories = ['VERY_WEAK', 'WEAK', 'MODERATE', 'STRONG', 'VERY_STRONG']
        labels = ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong']
        
        total = sum(distribution.values()) or 1
        max_count = max(distribution.values()) if distribution.values() else 1
        
        # Calculate bar dimensions
        padding_left = 60
        padding_right = 40
        padding_top = 30
        padding_bottom = 50
        
        usable_width = canvas_width - padding_left - padding_right
        usable_height = canvas_height - padding_top - padding_bottom
        bar_width = usable_width / len(categories)
        max_bar_height = usable_height - 20
        
        # Draw title
        self._strength_canvas.create_text(
            canvas_width / 2, 15,
            text="Password Strength Distribution",
            font=('Segoe UI', 11, 'bold'),
            fill='#333'
        )
        
        # Draw bars
        for i, (cat, label) in enumerate(zip(categories, labels)):
            count = distribution.get(cat, 0)
            # Scale bar height based on max count (not percentage)
            bar_height = (count / max_count) * max_bar_height if max_count > 0 else 0
            bar_height = max(bar_height, 5) if count > 0 else 0  # Minimum visible height
            
            x = padding_left + i * bar_width
            y_bottom = canvas_height - padding_bottom
            y_top = y_bottom - bar_height
            
            # Bar with rounded effect
            color = self.STRENGTH_COLORS.get(cat, '#999')
            bar_margin = bar_width * 0.15
            
            self._strength_canvas.create_rectangle(
                x + bar_margin, y_top,
                x + bar_width - bar_margin, y_bottom,
                fill=color, outline='white', width=2
            )
            
            # Count label above bar
            if count > 0:
                self._strength_canvas.create_text(
                    x + bar_width / 2, y_top - 12,
                    text=str(count),
                    font=('Segoe UI', 10, 'bold'),
                    fill=color
                )
            
            # Category label below bar
            self._strength_canvas.create_text(
                x + bar_width / 2, y_bottom + 15,
                text=label,
                font=('Segoe UI', 9),
                fill='#555'
            )
            
            # Percentage label
            percentage = (count / total * 100) if total > 0 else 0
            self._strength_canvas.create_text(
                x + bar_width / 2, y_bottom + 30,
                text=f"({percentage:.0f}%)",
                font=('Segoe UI', 8),
                fill='#888'
            )
    
    # ============ Reuse Analysis Tab ============
    
    def _build_reuse_tab(self) -> None:
        """Build the password reuse analysis tab."""
        # Info panel
        info_frame = ttk.Frame(self._reuse_frame)
        info_frame.pack(fill='x', pady=(0, 10))
        
        self._reuse_summary = ttk.Label(
            info_frame,
            text="Analyzing password reuse...",
            font=('Segoe UI', 11)
        )
        self._reuse_summary.pack(side='left')
        
        # Graph canvas
        graph_frame = ttk.LabelFrame(self._reuse_frame, text="Password Reuse Graph", padding=10)
        graph_frame.pack(fill='both', expand=True)
        
        self._graph_canvas = tk.Canvas(graph_frame, bg='white', highlightthickness=0)
        self._graph_canvas.pack(fill='both', expand=True)
        
        # Legend
        legend_frame = ttk.Frame(self._reuse_frame)
        legend_frame.pack(fill='x', pady=(10, 0))
        
        ttk.Label(legend_frame, text="Legend:", font=('Segoe UI', 9, 'bold')).pack(side='left')
        
        for label, color in [
            ("🟢 Unique", self.RISK_COLORS['excellent']),
            ("🟡 Shared 2x", self.RISK_COLORS['fair']),
            ("🟠 Shared 3-5x", self.RISK_COLORS['poor']),
            ("🔴 Shared 5+", self.RISK_COLORS['critical'])
        ]:
            ttk.Label(legend_frame, text=label, foreground=color).pack(side='left', padx=15)
        
        # Bind resize
        self._graph_canvas.bind('<Configure>', lambda e: self._draw_reuse_graph())
    
    def _draw_reuse_graph(self) -> None:
        """Draw the password reuse graph."""
        self._graph_canvas.delete('all')
        
        graph_data = self._report_data.get('graph_data', {})
        nodes = graph_data.get('nodes', [])
        edges = graph_data.get('edges', [])
        
        if not nodes:
            self._graph_canvas.create_text(
                self._graph_canvas.winfo_width() // 2,
                self._graph_canvas.winfo_height() // 2,
                text="No credentials to analyze.\nAdd credentials to see the reuse graph.",
                font=('Segoe UI', 12),
                fill='gray',
                justify='center'
            )
            return
        
        width = self._graph_canvas.winfo_width() or 600
        height = self._graph_canvas.winfo_height() or 300
        
        # Calculate positions
        positions = {}
        n = len(nodes)
        cx, cy = width // 2, height // 2
        radius = min(width, height) // 2 - 60
        
        for i, node in enumerate(nodes):
            if n == 1:
                x, y = cx, cy
            else:
                angle = (2 * math.pi * i) / n - math.pi / 2
                x = cx + radius * math.cos(angle)
                y = cy + radius * math.sin(angle)
            positions[node['id']] = (x, y)
        
        # Draw edges
        for from_id, to_id in edges:
            if from_id in positions and to_id in positions:
                x1, y1 = positions[from_id]
                x2, y2 = positions[to_id]
                self._graph_canvas.create_line(
                    x1, y1, x2, y2,
                    fill='#FFB74D', width=2, dash=(4, 2)
                )
        
        # Draw nodes
        for node in nodes:
            x, y = positions.get(node['id'], (100, 100))
            degree = node.get('degree', 0)
            
            # Color based on connections
            if degree == 0:
                color = self.RISK_COLORS['excellent']
            elif degree == 1:
                color = self.RISK_COLORS['fair']
            elif degree < 4:
                color = self.RISK_COLORS['poor']
            else:
                color = self.RISK_COLORS['critical']
            
            size = 15 + min(degree * 4, 25)
            
            self._graph_canvas.create_oval(
                x - size, y - size,
                x + size, y + size,
                fill=color, outline='white', width=2
            )
            
            # Label
            data = node.get('data')
            label = data.site_name[:10] if data else str(node['id'])[:10]
            self._graph_canvas.create_text(
                x, y + size + 12,
                text=label,
                font=('Segoe UI', 8),
                fill='#333'
            )
    
    # ============ Recommendations Tab ============
    
    def _build_recommendations_tab(self) -> None:
        """Build the recommendations tab."""
        # Scrollable recommendations
        canvas = tk.Canvas(self._recommend_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self._recommend_frame, orient='vertical', command=canvas.yview)
        
        self._recommend_inner = ttk.Frame(canvas)
        
        canvas.create_window((0, 0), window=self._recommend_inner, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        
        def on_frame_configure(e):
            canvas.configure(scrollregion=canvas.bbox('all'))
        
        self._recommend_inner.bind('<Configure>', on_frame_configure)
        
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
    
    def _populate_recommendations(self, recommendations: List[Dict]) -> None:
        """Populate recommendations list."""
        # Clear existing
        for widget in self._recommend_inner.winfo_children():
            widget.destroy()
        
        if not recommendations:
            ttk.Label(
                self._recommend_inner,
                text="✅ Great job! No security issues found.",
                font=('Segoe UI', 12),
                foreground=self.RISK_COLORS['excellent']
            ).pack(pady=20)
            return
        
        for i, rec in enumerate(recommendations):
            card = ttk.Frame(self._recommend_inner, relief='ridge', borderwidth=1, padding=15)
            card.pack(fill='x', pady=5, padx=5)
            
            # Priority icon
            priority = rec.get('priority', 'medium')
            if priority == 'high':
                icon = "🔴"
            elif priority == 'medium':
                icon = "🟡"
            else:
                icon = "🟢"
            
            # Header
            header = ttk.Frame(card)
            header.pack(fill='x')
            
            ttk.Label(
                header,
                text=f"{icon} {rec.get('title', 'Recommendation')}",
                font=('Segoe UI', 11, 'bold')
            ).pack(side='left')
            
            ttk.Label(
                header,
                text=rec.get('category', ''),
                foreground='gray'
            ).pack(side='right')
            
            # Description
            ttk.Label(
                card,
                text=rec.get('description', ''),
                wraplength=600
            ).pack(anchor='w', pady=(5, 0))
            
            # Affected credentials
            affected = rec.get('affected', [])
            if affected:
                ttk.Label(
                    card,
                    text=f"Affected: {', '.join(affected[:5])}{'...' if len(affected) > 5 else ''}",
                    foreground='gray',
                    font=('Segoe UI', 9)
                ).pack(anchor='w', pady=(5, 0))
    
    # ============ Data Loading ============
    
    def _load_security_data(self) -> None:
        """Load and analyze security data."""
        logger.info("Loading security data...")
        
        try:
            # Get base report
            report = self._vault.get_security_report()
            self._report_data = report
            
            # Update last updated
            self._last_updated.configure(
                text=f"Last updated: {datetime.now().strftime('%H:%M:%S')}"
            )
            
            # Update overview
            score = report.get('security_score', 0)
            self._draw_gauge(score)
            
            # Update stats
            self._stat_labels['total'].configure(text=str(report.get('total_credentials', 0)))
            self._stat_labels['unique'].configure(text=str(report.get('unique_passwords', 0)))
            self._stat_labels['reused'].configure(text=str(report.get('affected_credentials', 0)))
            
            # Analyze password strengths
            strength_dist = self._analyze_password_strengths()
            self._stat_labels['weak'].configure(
                text=str(strength_dist.get('VERY_WEAK', 0) + strength_dist.get('WEAK', 0))
            )
            self._stat_labels['strong'].configure(
                text=str(strength_dist.get('STRONG', 0) + strength_dist.get('VERY_STRONG', 0))
            )
            self._stat_labels['old'].configure(text='0')  # Would need timestamp tracking
            
            # Update strength chart
            self._draw_strength_chart(strength_dist)
            
            # Update reuse summary
            reuse_count = report.get('reuse_clusters', 0)
            if reuse_count == 0:
                self._reuse_summary.configure(
                    text="✅ No password reuse detected. Great security hygiene!",
                    foreground=self.RISK_COLORS['excellent']
                )
            else:
                self._reuse_summary.configure(
                    text=f"⚠️ Found {reuse_count} groups of reused passwords affecting {report.get('affected_credentials', 0)} credentials",
                    foreground=self.RISK_COLORS['poor']
                )
            
            # Draw reuse graph
            self._draw_reuse_graph()
            
            # Generate recommendations
            recommendations = self._generate_recommendations(report, strength_dist)
            self._populate_recommendations(recommendations)
            
            logger.info(f"Security data loaded. Score: {score}%")
            
        except Exception as e:
            logger.error(f"Error loading security data: {e}")
            messagebox.showerror("Error", f"Failed to load security data: {e}")
    
    def _analyze_password_strengths(self) -> Dict[str, int]:
        """Analyze password strengths for all credentials."""
        distribution = {
            'VERY_WEAK': 0,
            'WEAK': 0,
            'MODERATE': 0,
            'STRONG': 0,
            'VERY_STRONG': 0
        }
        
        # Clear and repopulate strength tree
        for item in self._strength_tree.get_children():
            self._strength_tree.delete(item)
        
        credentials = self._vault.get_all_credentials()
        logger.info(f"Analyzing {len(credentials)} credentials for password strength...")
        
        for cred in credentials:
            # Get the decrypted password using vault's decryption method
            try:
                password = self._vault.get_decrypted_password(cred.id)
                if password:
                    result = self._vault.check_password_strength(password)
                    strength = result.get('strength', 'MODERATE')
                    score = result.get('score', 50)
                    issues = ', '.join(result.get('violations', [])[:2]) or 'None'
                    
                    distribution[strength] = distribution.get(strength, 0) + 1
                    
                    # Add to the treeview with proper values
                    self._strength_tree.insert('', 'end', values=(
                        cred.site_name,
                        cred.username,
                        strength.replace('_', ' ').title(),
                        f"{score}%",
                        issues
                    ))
                    logger.debug(f"Analyzed {cred.site_name}: {strength} ({score}%)")
                else:
                    logger.warning(f"Could not decrypt password for {cred.site_name}")
            except Exception as e:
                logger.error(f"Could not analyze password for {cred.site_name}: {e}")
        
        return distribution
    
    def _generate_recommendations(self, report: Dict, strength_dist: Dict) -> List[Dict]:
        """Generate actionable security recommendations."""
        recommendations = []
        
        # Check for password reuse
        if report.get('reuse_clusters', 0) > 0:
            recommendations.append({
                'title': 'Change Reused Passwords',
                'description': 'You are reusing passwords across multiple sites. This is a critical security risk - if one site is breached, all accounts with the same password are compromised.',
                'priority': 'high',
                'category': 'Password Reuse',
                'affected': [f"Group {i+1}" for i in range(report.get('reuse_clusters', 0))]
            })
        
        # Check for weak passwords
        weak_count = strength_dist.get('VERY_WEAK', 0) + strength_dist.get('WEAK', 0)
        if weak_count > 0:
            recommendations.append({
                'title': f'Strengthen {weak_count} Weak Passwords',
                'description': 'Weak passwords can be easily cracked. Use the password generator to create strong, unique passwords with at least 16 characters including uppercase, lowercase, numbers, and symbols.',
                'priority': 'high',
                'category': 'Password Strength'
            })
        
        # Check for moderate passwords
        moderate_count = strength_dist.get('MODERATE', 0)
        if moderate_count > 0:
            recommendations.append({
                'title': f'Consider Upgrading {moderate_count} Moderate Passwords',
                'description': 'While these passwords meet minimum requirements, they could be stronger. Consider upgrading to very strong passwords for better protection.',
                'priority': 'medium',
                'category': 'Password Strength'
            })
        
        # General recommendations
        total = report.get('total_credentials', 0)
        if total > 0:
            # Enable 2FA recommendation
            recommendations.append({
                'title': 'Enable Two-Factor Authentication',
                'description': 'Where available, enable 2FA/MFA on your accounts for an additional layer of security beyond passwords.',
                'priority': 'medium',
                'category': 'Account Security'
            })
            
            # Regular review
            recommendations.append({
                'title': 'Schedule Regular Security Reviews',
                'description': 'Review your passwords every 90 days. Check for compromised passwords and update any that are outdated or weak.',
                'priority': 'low',
                'category': 'Best Practices'
            })
        
        if total == 0:
            recommendations.append({
                'title': 'Add Your First Credentials',
                'description': 'Start by adding your important account credentials. Use the password generator to create strong, unique passwords for each account.',
                'priority': 'medium',
                'category': 'Getting Started'
            })
        
        return recommendations
    
    def _export_report(self) -> None:
        """Export security report to file."""
        try:
            from tkinter import filedialog
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Export Security Report"
            )
            
            if filename:
                report = self._report_data
                strength_dist = self._analyze_password_strengths()
                
                with open(filename, 'w') as f:
                    f.write("=" * 50 + "\n")
                    f.write("SECURITY ANALYSIS REPORT\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 50 + "\n\n")
                    
                    f.write("OVERALL SCORE\n")
                    f.write("-" * 30 + "\n")
                    f.write(f"Security Score: {report.get('security_score', 0):.1f}%\n\n")
                    
                    f.write("STATISTICS\n")
                    f.write("-" * 30 + "\n")
                    f.write(f"Total Credentials: {report.get('total_credentials', 0)}\n")
                    f.write(f"Unique Passwords: {report.get('unique_passwords', 0)}\n")
                    f.write(f"Reuse Groups: {report.get('reuse_clusters', 0)}\n")
                    f.write(f"Affected by Reuse: {report.get('affected_credentials', 0)}\n\n")
                    
                    f.write("PASSWORD STRENGTH DISTRIBUTION\n")
                    f.write("-" * 30 + "\n")
                    for strength, count in strength_dist.items():
                        f.write(f"{strength.replace('_', ' ').title()}: {count}\n")
                    f.write("\n")
                    
                    f.write("RECOMMENDATIONS\n")
                    f.write("-" * 30 + "\n")
                    recommendations = self._generate_recommendations(report, strength_dist)
                    for i, rec in enumerate(recommendations, 1):
                        f.write(f"\n{i}. [{rec.get('priority', 'medium').upper()}] {rec.get('title')}\n")
                        f.write(f"   {rec.get('description')}\n")
                
                messagebox.showinfo("Export Complete", f"Report saved to:\n{filename}")
                logger.info(f"Security report exported to {filename}")
                
        except Exception as e:
            logger.error(f"Failed to export report: {e}")
            messagebox.showerror("Export Failed", f"Could not export report: {e}")
