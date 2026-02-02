"""
Test Suite: Graph Data Structure
================================

Tests for SecurityGraph and PasswordReuseAnalyzer implementations.
Tests verify password reuse detection and security analysis functionality.

Author: Advanced Password Manager Team
"""

import pytest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from datastructures.graph import SecurityGraph, PasswordReuseAnalyzer, GraphVertex


class TestGraphVertex:
    """Test cases for GraphVertex class."""
    
    def test_vertex_creation(self):
        """Test creating a vertex."""
        vertex = GraphVertex("A", data={"key": "value"})
        
        assert vertex.id == "A"
        assert vertex.data == {"key": "value"}
        assert vertex.degree == 0
    
    def test_vertex_add_edge(self):
        """Test adding edges to a vertex."""
        vertex = GraphVertex("A")
        vertex.add_edge("B")
        vertex.add_edge("C")
        
        assert vertex.degree == 2
        assert "B" in vertex.edges
        assert "C" in vertex.edges
    
    def test_vertex_remove_edge(self):
        """Test removing edges from a vertex."""
        vertex = GraphVertex("A")
        vertex.add_edge("B")
        vertex.add_edge("C")
        
        result = vertex.remove_edge("B")
        
        assert result is True
        assert vertex.degree == 1
        assert "B" not in vertex.edges
    
    def test_vertex_remove_nonexistent_edge(self):
        """Test removing edge that doesn't exist."""
        vertex = GraphVertex("A")
        
        result = vertex.remove_edge("X")
        
        assert result is False
    
    def test_vertex_has_edge_to(self):
        """Test checking for edge existence."""
        vertex = GraphVertex("A")
        vertex.add_edge("B")
        
        assert vertex.has_edge_to("B") is True
        assert vertex.has_edge_to("C") is False


class TestSecurityGraphBasic:
    """Test cases for basic SecurityGraph operations."""
    
    def test_empty_graph(self):
        """Test empty graph creation."""
        graph = SecurityGraph()
        
        assert len(graph) == 0
        assert graph.vertex_count == 0
        assert graph.edge_count == 0
        assert graph.get_all_vertices() == []
    
    def test_add_vertex(self):
        """Test adding vertices to the graph."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        graph.add_vertex("B")
        
        assert len(graph) == 2
        assert "A" in graph
        assert "B" in graph
        assert "C" not in graph
    
    def test_add_duplicate_vertex(self):
        """Test adding duplicate vertices updates data."""
        graph = SecurityGraph()
        graph.add_vertex("A", data="old")
        graph.add_vertex("A", data="new")
        
        assert len(graph) == 1
        assert graph.get_vertex("A").data == "new"
    
    def test_add_edge(self):
        """Test adding edges between vertices."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        graph.add_vertex("B")
        graph.add_edge("A", "B")
        
        assert graph.has_edge("A", "B")
        assert graph.has_edge("B", "A")  # Undirected
        assert graph.edge_count == 1
    
    def test_add_edge_no_vertices(self):
        """Test that adding edge fails if vertices don't exist."""
        graph = SecurityGraph()
        
        result = graph.add_edge("X", "Y")
        
        assert result is False
        assert graph.edge_count == 0
    
    def test_add_edge_no_self_loop(self):
        """Test that self-loops are not allowed."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        
        result = graph.add_edge("A", "A")
        
        assert result is False
        assert graph.edge_count == 0
    
    def test_remove_edge(self):
        """Test removing edges."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        graph.add_vertex("B")
        graph.add_edge("A", "B")
        
        result = graph.remove_edge("A", "B")
        
        assert result is True
        assert not graph.has_edge("A", "B")
        assert "A" in graph  # Vertices still exist
        assert "B" in graph
    
    def test_remove_vertex(self):
        """Test removing vertices and associated edges."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        graph.add_vertex("B")
        graph.add_vertex("C")
        graph.add_edge("A", "B")
        graph.add_edge("A", "C")
        
        result = graph.remove_vertex("A")
        
        assert result is True
        assert "A" not in graph
        assert "B" in graph
        assert "C" in graph
        assert not graph.has_edge("B", "A")
    
    def test_get_neighbors(self):
        """Test getting neighbors of a vertex."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        graph.add_vertex("B")
        graph.add_vertex("C")
        graph.add_vertex("D")
        graph.add_edge("A", "B")
        graph.add_edge("A", "C")
        graph.add_edge("A", "D")
        
        neighbors = graph.get_neighbors("A")
        
        assert "B" in neighbors
        assert "C" in neighbors
        assert "D" in neighbors
        assert len(neighbors) == 3
    
    def test_get_vertex_degree(self):
        """Test getting vertex degree."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        graph.add_vertex("B")
        graph.add_vertex("C")
        graph.add_edge("A", "B")
        graph.add_edge("A", "C")
        
        vertex_a = graph.get_vertex("A")
        vertex_b = graph.get_vertex("B")
        
        assert vertex_a.degree == 2
        assert vertex_b.degree == 1
    
    def test_has_vertex(self):
        """Test has_vertex method."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        
        assert graph.has_vertex("A") is True
        assert graph.has_vertex("B") is False
    
    def test_contains_operator(self):
        """Test 'in' operator for vertices."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        
        assert "A" in graph
        assert "X" not in graph


class TestSecurityGraphTraversal:
    """Test cases for graph traversal algorithms."""
    
    def test_bfs_simple(self):
        """Test BFS traversal on simple graph."""
        graph = SecurityGraph()
        for v in ["A", "B", "C", "D", "E"]:
            graph.add_vertex(v)
        graph.add_edge("A", "B")
        graph.add_edge("A", "C")
        graph.add_edge("B", "D")
        graph.add_edge("C", "E")
        
        visited = graph.bfs("A")
        
        assert visited[0] == "A"
        assert set(visited) == {"A", "B", "C", "D", "E"}
    
    def test_dfs_simple(self):
        """Test DFS traversal on simple graph."""
        graph = SecurityGraph()
        for v in ["A", "B", "C", "D"]:
            graph.add_vertex(v)
        graph.add_edge("A", "B")
        graph.add_edge("A", "C")
        graph.add_edge("B", "D")
        
        visited = graph.dfs("A")
        
        assert visited[0] == "A"
        assert set(visited) == {"A", "B", "C", "D"}
    
    def test_bfs_disconnected(self):
        """Test BFS on disconnected graph."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        graph.add_vertex("B")
        graph.add_vertex("C")  # Disconnected
        graph.add_edge("A", "B")
        
        visited = graph.bfs("A")
        
        assert "A" in visited
        assert "B" in visited
        assert "C" not in visited
    
    def test_dfs_disconnected(self):
        """Test DFS on disconnected graph."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        graph.add_vertex("B")
        graph.add_vertex("C")  # Disconnected
        graph.add_edge("A", "B")
        
        visited = graph.dfs("A")
        
        assert "A" in visited
        assert "B" in visited
        assert "C" not in visited
    
    def test_bfs_empty_graph(self):
        """Test BFS on empty graph returns empty list."""
        graph = SecurityGraph()
        
        visited = graph.bfs("A")
        
        assert visited == []
    
    def test_dfs_single_vertex(self):
        """Test DFS on single vertex."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        
        visited = graph.dfs("A")
        
        assert visited == ["A"]
    
    def test_bfs_nonexistent_start(self):
        """Test BFS with nonexistent start vertex."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        
        visited = graph.bfs("X")
        
        assert visited == []


class TestConnectedComponents:
    """Test cases for connected components."""
    
    def test_single_component(self):
        """Test graph with single connected component."""
        graph = SecurityGraph()
        for v in ["A", "B", "C"]:
            graph.add_vertex(v)
        graph.add_edge("A", "B")
        graph.add_edge("B", "C")
        
        components = graph.find_connected_components()
        
        assert len(components) == 1
        assert set(components[0]) == {"A", "B", "C"}
    
    def test_multiple_components(self):
        """Test graph with multiple connected components."""
        graph = SecurityGraph()
        for v in ["A", "B", "C", "D"]:
            graph.add_vertex(v)
        graph.add_edge("A", "B")
        graph.add_edge("C", "D")
        
        components = graph.find_connected_components()
        
        assert len(components) == 2
        component_sets = [set(c) for c in components]
        assert {"A", "B"} in component_sets
        assert {"C", "D"} in component_sets
    
    def test_empty_graph_components(self):
        """Test empty graph has no components."""
        graph = SecurityGraph()
        
        components = graph.find_connected_components()
        
        assert components == []
    
    def test_find_reuse_clusters(self):
        """Test finding reuse clusters (components > 1)."""
        graph = SecurityGraph()
        for v in ["A", "B", "C", "D", "E"]:
            graph.add_vertex(v)
        graph.add_edge("A", "B")
        graph.add_edge("C", "D")
        # E is isolated - should not be in clusters
        
        clusters = graph.find_reuse_clusters()
        
        assert len(clusters) == 2
        for cluster in clusters:
            assert len(cluster) > 1


class TestSecurityScoring:
    """Test cases for security scoring functionality."""
    
    def test_risk_score_no_reuse(self):
        """Test risk score for credential with no reuse."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        graph.add_vertex("B")
        # No edges = no reuse
        
        score = graph.calculate_risk_score("A")
        
        assert score == 0.0
    
    def test_risk_score_with_reuse(self):
        """Test risk score for credential with password reuse."""
        graph = SecurityGraph()
        for v in ["A", "B", "C"]:
            graph.add_vertex(v)
        graph.add_edge("A", "B")
        graph.add_edge("A", "C")
        
        score = graph.calculate_risk_score("A")
        
        assert score > 0.0
        assert score <= 1.0
    
    def test_risk_score_nonexistent(self):
        """Test risk score for nonexistent vertex."""
        graph = SecurityGraph()
        
        score = graph.calculate_risk_score("X")
        
        assert score == 0.0
    
    def test_overall_security_score_all_unique(self):
        """Test overall score when all passwords are unique."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        graph.add_vertex("B")
        graph.add_vertex("C")
        # No edges = all unique
        
        score = graph.get_overall_security_score()
        
        assert score == 100.0
    
    def test_overall_security_score_with_reuse(self):
        """Test overall score when there's password reuse."""
        graph = SecurityGraph()
        for v in ["A", "B", "C"]:
            graph.add_vertex(v)
        graph.add_edge("A", "B")
        
        score = graph.get_overall_security_score()
        
        # C has unique password, A and B share
        assert 0.0 < score < 100.0
    
    def test_overall_security_score_empty(self):
        """Test overall score for empty graph."""
        graph = SecurityGraph()
        
        score = graph.get_overall_security_score()
        
        assert score == 100.0


class TestPasswordReuseAnalyzer:
    """Test cases for PasswordReuseAnalyzer."""
    
    def test_add_credential_no_reuse(self):
        """Test adding credentials with unique passwords."""
        analyzer = PasswordReuseAnalyzer()
        
        analyzer.add_credential("site1", "hash1")
        analyzer.add_credential("site2", "hash2")
        
        assert analyzer.graph.vertex_count == 2
        assert analyzer.graph.edge_count == 0
    
    def test_add_credential_with_reuse(self):
        """Test adding credentials that share a password."""
        analyzer = PasswordReuseAnalyzer()
        
        analyzer.add_credential("site1", "samehash")
        analyzer.add_credential("site2", "samehash")
        
        assert analyzer.graph.vertex_count == 2
        assert analyzer.graph.edge_count == 1
        assert analyzer.graph.has_edge("site1", "site2")
    
    def test_multiple_reuse_groups(self):
        """Test multiple groups of password reuse."""
        analyzer = PasswordReuseAnalyzer()
        
        analyzer.add_credential("site1", "hash1")
        analyzer.add_credential("site2", "hash1")  # Reuses hash1
        analyzer.add_credential("site3", "hash2")
        analyzer.add_credential("site4", "hash2")  # Reuses hash2
        
        assert analyzer.graph.vertex_count == 4
        assert analyzer.graph.edge_count == 2
    
    def test_remove_credential(self):
        """Test removing a credential."""
        analyzer = PasswordReuseAnalyzer()
        analyzer.add_credential("site1", "hash1")
        analyzer.add_credential("site2", "hash1")
        
        analyzer.remove_credential("site1")
        
        assert analyzer.graph.vertex_count == 1
        assert "site1" not in analyzer.graph
    
    def test_update_password(self):
        """Test updating a credential's password."""
        analyzer = PasswordReuseAnalyzer()
        analyzer.add_credential("site1", "oldhash")
        analyzer.add_credential("site2", "oldhash")
        analyzer.add_credential("site3", "newhash")
        
        # Initially site1 and site2 share password
        assert analyzer.graph.has_edge("site1", "site2")
        
        # Update site1 to use new password
        analyzer.update_password("site1", "oldhash", "newhash")
        
        # Now site1 should be connected to site3, not site2
        assert not analyzer.graph.has_edge("site1", "site2")
        assert analyzer.graph.has_edge("site1", "site3")
    
    def test_get_reuse_report(self):
        """Test generating a reuse report."""
        analyzer = PasswordReuseAnalyzer()
        analyzer.add_credential("site1", "hash1")
        analyzer.add_credential("site2", "hash1")
        analyzer.add_credential("site3", "hash2")
        
        report = analyzer.get_reuse_report()
        
        assert report['total_credentials'] == 3
        assert report['unique_passwords'] == 2
        assert report['reuse_clusters'] == 1
        assert report['affected_credentials'] == 2
        assert 'security_score' in report
    
    def test_clear(self):
        """Test clearing the analyzer."""
        analyzer = PasswordReuseAnalyzer()
        analyzer.add_credential("site1", "hash1")
        analyzer.add_credential("site2", "hash1")
        
        analyzer.clear()
        
        assert analyzer.graph.vertex_count == 0
        assert analyzer.graph.edge_count == 0


class TestGraphUtilities:
    """Test cases for utility methods."""
    
    def test_clear(self):
        """Test clearing the graph."""
        graph = SecurityGraph()
        graph.add_vertex("A")
        graph.add_vertex("B")
        graph.add_edge("A", "B")
        
        graph.clear()
        
        assert len(graph) == 0
        assert graph.edge_count == 0
    
    def test_get_all_edges(self):
        """Test getting all edges."""
        graph = SecurityGraph()
        for v in ["A", "B", "C"]:
            graph.add_vertex(v)
        graph.add_edge("A", "B")
        graph.add_edge("B", "C")
        
        edges = graph.get_all_edges()
        
        assert len(edges) == 2
    
    def test_get_graph_data(self):
        """Test getting graph data for visualization."""
        graph = SecurityGraph()
        graph.add_vertex("A", data="data_a")
        graph.add_vertex("B", data="data_b")
        graph.add_edge("A", "B")
        
        data = graph.get_graph_data()
        
        assert 'nodes' in data
        assert 'edges' in data
        assert 'security_score' in data
        assert len(data['nodes']) == 2
        assert len(data['edges']) == 1


class TestGraphEdgeCases:
    """Test edge cases and error handling."""
    
    def test_weighted_edges_via_data(self):
        """Test using vertex data for weighted relationships."""
        graph = SecurityGraph()
        graph.add_vertex("A", data={"weight": 10})
        graph.add_vertex("B", data={"weight": 5})
        graph.add_edge("A", "B")
        
        assert graph.get_vertex("A").data["weight"] == 10
    
    def test_unicode_vertex_names(self):
        """Test graph with unicode vertex names."""
        graph = SecurityGraph()
        graph.add_vertex("网站A")
        graph.add_vertex("サイトB")
        graph.add_edge("网站A", "サイトB")
        
        assert "网站A" in graph
        assert graph.has_edge("网站A", "サイトB")
    
    def test_large_graph_performance(self):
        """Test graph with many vertices."""
        graph = SecurityGraph()
        
        # Add 100 vertices
        for i in range(100):
            graph.add_vertex(f"vertex_{i}")
        
        # Add edges
        for i in range(0, 100, 2):
            graph.add_edge(f"vertex_{i}", f"vertex_{i+1}")
        
        assert graph.vertex_count == 100
        assert graph.edge_count == 50


class TestGraphIntegration:
    """Integration tests for password manager scenarios."""
    
    def test_real_world_scenario(self):
        """Test realistic password reuse scenario."""
        analyzer = PasswordReuseAnalyzer()
        
        # Add credentials
        analyzer.add_credential("gmail.com", "hash_common")
        analyzer.add_credential("facebook.com", "hash_common")  # Reuses gmail password
        analyzer.add_credential("bank.com", "hash_secure")      # Unique
        analyzer.add_credential("twitter.com", "hash_weak")
        analyzer.add_credential("instagram.com", "hash_weak")   # Reuses twitter password
        
        report = analyzer.get_reuse_report()
        
        assert report['total_credentials'] == 5
        assert report['reuse_clusters'] == 2
        assert report['affected_credentials'] == 4
    
    def test_security_recommendations(self):
        """Test identifying high-risk credentials."""
        analyzer = PasswordReuseAnalyzer()
        
        # Site connected to many others (high risk)
        analyzer.add_credential("main_email", "shared_hash")
        analyzer.add_credential("site1", "shared_hash")
        analyzer.add_credential("site2", "shared_hash")
        analyzer.add_credential("site3", "shared_hash")
        
        report = analyzer.get_reuse_report()
        
        # main_email should be high risk since it shares password with 3 sites
        assert len(report['high_risk_credentials']) > 0
