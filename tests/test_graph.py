"""
Unittest: Graph Data Structure
==============================

Tests for SecurityGraph and PasswordReuseAnalyzer implementations.
Uses unittest with setUp() method pattern.

Run with: python -m unittest tests.unitTestGraph
or: python tests/unitTestGraph.py
"""

import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from datastructures.graph import SecurityGraph, PasswordReuseAnalyzer, GraphVertex


class TestGraphVertex(unittest.TestCase):
    """Test cases for GraphVertex class."""
    
    def setUp(self):
        """Initialize test fixtures."""
        self.vertex = GraphVertex("A", data={"key": "value"})
    
    def tearDown(self):
        """Clean up after each test."""
        self.vertex = None
    
    def test_vertex_creation(self):
        """Test creating a vertex."""
        self.assertEqual(self.vertex.id, "A")
        self.assertEqual(self.vertex.data, {"key": "value"})
        self.assertEqual(self.vertex.degree, 0)
    
    def test_vertex_add_edge(self):
        """Test adding edges to a vertex."""
        self.vertex.add_edge("B")
        self.vertex.add_edge("C")
        
        self.assertEqual(self.vertex.degree, 2)
        self.assertIn("B", self.vertex.edges)
        self.assertIn("C", self.vertex.edges)
    
    def test_vertex_remove_edge(self):
        """Test removing edges from a vertex."""
        self.vertex.add_edge("B")
        self.vertex.add_edge("C")
        
        result = self.vertex.remove_edge("B")
        
        self.assertTrue(result)
        self.assertEqual(self.vertex.degree, 1)
        self.assertNotIn("B", self.vertex.edges)
    
    def test_vertex_remove_nonexistent_edge(self):
        """Test removing edge that doesn't exist."""
        result = self.vertex.remove_edge("X")
        
        self.assertFalse(result)
    
    def test_vertex_has_edge_to(self):
        """Test checking for edge existence."""
        self.vertex.add_edge("B")
        
        self.assertTrue(self.vertex.has_edge_to("B"))
        self.assertFalse(self.vertex.has_edge_to("C"))


class TestSecurityGraphBasic(unittest.TestCase):
    """Test cases for basic SecurityGraph operations."""
    
    def setUp(self):
        """Initialize a new graph for each test."""
        self.graph = SecurityGraph()
    
    def tearDown(self):
        """Clean up after each test."""
        self.graph = None
    
    def test_empty_graph(self):
        """Test empty graph creation."""
        self.assertEqual(len(self.graph), 0)
        self.assertEqual(self.graph.vertex_count, 0)
        self.assertEqual(self.graph.edge_count, 0)
        self.assertEqual(self.graph.get_all_vertices(), [])
    
    def test_add_vertex(self):
        """Test adding vertices to the graph."""
        self.graph.add_vertex("A")
        self.graph.add_vertex("B")
        
        self.assertEqual(len(self.graph), 2)
        self.assertIn("A", self.graph)
        self.assertIn("B", self.graph)
        self.assertNotIn("C", self.graph)
    
    def test_add_duplicate_vertex(self):
        """Test adding duplicate vertices updates data."""
        self.graph.add_vertex("A", data="old")
        self.graph.add_vertex("A", data="new")
        
        self.assertEqual(len(self.graph), 1)
        self.assertEqual(self.graph.get_vertex("A").data, "new")
    
    def test_add_edge(self):
        """Test adding edges between vertices."""
        self.graph.add_vertex("A")
        self.graph.add_vertex("B")
        self.graph.add_edge("A", "B")
        
        self.assertTrue(self.graph.has_edge("A", "B"))
        self.assertTrue(self.graph.has_edge("B", "A"))  # Undirected
        self.assertEqual(self.graph.edge_count, 1)
    
    def test_add_edge_no_vertices(self):
        """Test that adding edge fails if vertices don't exist."""
        result = self.graph.add_edge("X", "Y")
        
        self.assertFalse(result)
        self.assertEqual(self.graph.edge_count, 0)
    
    def test_add_edge_no_self_loop(self):
        """Test that self-loops are not allowed."""
        self.graph.add_vertex("A")
        
        result = self.graph.add_edge("A", "A")
        
        self.assertFalse(result)
        self.assertEqual(self.graph.edge_count, 0)
    
    def test_remove_edge(self):
        """Test removing edges."""
        self.graph.add_vertex("A")
        self.graph.add_vertex("B")
        self.graph.add_edge("A", "B")
        
        result = self.graph.remove_edge("A", "B")
        
        self.assertTrue(result)
        self.assertFalse(self.graph.has_edge("A", "B"))
        self.assertIn("A", self.graph)  # Vertices still exist
        self.assertIn("B", self.graph)
    
    def test_remove_vertex(self):
        """Test removing vertices and associated edges."""
        self.graph.add_vertex("A")
        self.graph.add_vertex("B")
        self.graph.add_vertex("C")
        self.graph.add_edge("A", "B")
        self.graph.add_edge("A", "C")
        
        result = self.graph.remove_vertex("A")
        
        self.assertTrue(result)
        self.assertNotIn("A", self.graph)
        self.assertIn("B", self.graph)
        self.assertIn("C", self.graph)
        self.assertFalse(self.graph.has_edge("B", "A"))
    
    def test_get_neighbors(self):
        """Test getting neighbors of a vertex."""
        self.graph.add_vertex("A")
        self.graph.add_vertex("B")
        self.graph.add_vertex("C")
        self.graph.add_vertex("D")
        self.graph.add_edge("A", "B")
        self.graph.add_edge("A", "C")
        self.graph.add_edge("A", "D")
        
        neighbors = self.graph.get_neighbors("A")
        
        self.assertIn("B", neighbors)
        self.assertIn("C", neighbors)
        self.assertIn("D", neighbors)
        self.assertEqual(len(neighbors), 3)
    
    def test_get_vertex_degree(self):
        """Test getting vertex degree."""
        self.graph.add_vertex("A")
        self.graph.add_vertex("B")
        self.graph.add_vertex("C")
        self.graph.add_edge("A", "B")
        self.graph.add_edge("A", "C")
        
        vertex_a = self.graph.get_vertex("A")
        vertex_b = self.graph.get_vertex("B")
        
        self.assertEqual(vertex_a.degree, 2)
        self.assertEqual(vertex_b.degree, 1)
    
    def test_has_vertex(self):
        """Test has_vertex method."""
        self.graph.add_vertex("A")
        
        self.assertTrue(self.graph.has_vertex("A"))
        self.assertFalse(self.graph.has_vertex("B"))
    
    def test_contains_operator(self):
        """Test 'in' operator for vertices."""
        self.graph.add_vertex("A")
        
        self.assertIn("A", self.graph)
        self.assertNotIn("X", self.graph)


class TestSecurityGraphTraversal(unittest.TestCase):
    """Test cases for graph traversal algorithms."""
    
    def setUp(self):
        """Initialize a graph with test data."""
        self.graph = SecurityGraph()
        for v in ["A", "B", "C", "D", "E"]:
            self.graph.add_vertex(v)
        self.graph.add_edge("A", "B")
        self.graph.add_edge("A", "C")
        self.graph.add_edge("B", "D")
        self.graph.add_edge("C", "E")
    
    def tearDown(self):
        """Clean up after each test."""
        self.graph = None
    
    def test_bfs_simple(self):
        """Test BFS traversal on simple graph."""
        visited = self.graph.bfs("A")
        
        self.assertEqual(visited[0], "A")
        self.assertEqual(set(visited), {"A", "B", "C", "D", "E"})
    
    def test_dfs_simple(self):
        """Test DFS traversal on simple graph."""
        dfs_graph = SecurityGraph()
        for v in ["A", "B", "C", "D"]:
            dfs_graph.add_vertex(v)
        dfs_graph.add_edge("A", "B")
        dfs_graph.add_edge("A", "C")
        dfs_graph.add_edge("B", "D")
        
        visited = dfs_graph.dfs("A")
        
        self.assertEqual(visited[0], "A")
        self.assertEqual(set(visited), {"A", "B", "C", "D"})
    
    def test_bfs_disconnected(self):
        """Test BFS on disconnected graph."""
        disc_graph = SecurityGraph()
        disc_graph.add_vertex("A")
        disc_graph.add_vertex("B")
        disc_graph.add_vertex("C")  # Disconnected
        disc_graph.add_edge("A", "B")
        
        visited = disc_graph.bfs("A")
        
        self.assertIn("A", visited)
        self.assertIn("B", visited)
        self.assertNotIn("C", visited)
    
    def test_dfs_disconnected(self):
        """Test DFS on disconnected graph."""
        disc_graph = SecurityGraph()
        disc_graph.add_vertex("A")
        disc_graph.add_vertex("B")
        disc_graph.add_vertex("C")  # Disconnected
        disc_graph.add_edge("A", "B")
        
        visited = disc_graph.dfs("A")
        
        self.assertIn("A", visited)
        self.assertIn("B", visited)
        self.assertNotIn("C", visited)
    
    def test_bfs_empty_graph(self):
        """Test BFS on empty graph returns empty list."""
        empty_graph = SecurityGraph()
        
        visited = empty_graph.bfs("A")
        
        self.assertEqual(visited, [])
    
    def test_dfs_single_vertex(self):
        """Test DFS on single vertex."""
        single_graph = SecurityGraph()
        single_graph.add_vertex("A")
        
        visited = single_graph.dfs("A")
        
        self.assertEqual(visited, ["A"])
    
    def test_bfs_nonexistent_start(self):
        """Test BFS with nonexistent start vertex."""
        visited = self.graph.bfs("X")
        
        self.assertEqual(visited, [])


class TestConnectedComponents(unittest.TestCase):
    """Test cases for connected components."""
    
    def setUp(self):
        """Initialize graph for component tests."""
        self.graph = SecurityGraph()
    
    def tearDown(self):
        """Clean up after each test."""
        self.graph = None
    
    def test_single_component(self):
        """Test graph with single connected component."""
        for v in ["A", "B", "C"]:
            self.graph.add_vertex(v)
        self.graph.add_edge("A", "B")
        self.graph.add_edge("B", "C")
        
        components = self.graph.find_connected_components()
        
        self.assertEqual(len(components), 1)
        self.assertEqual(set(components[0]), {"A", "B", "C"})
    
    def test_multiple_components(self):
        """Test graph with multiple connected components."""
        for v in ["A", "B", "C", "D"]:
            self.graph.add_vertex(v)
        self.graph.add_edge("A", "B")
        self.graph.add_edge("C", "D")
        
        components = self.graph.find_connected_components()
        
        self.assertEqual(len(components), 2)
        component_sets = [set(c) for c in components]
        self.assertIn({"A", "B"}, component_sets)
        self.assertIn({"C", "D"}, component_sets)
    
    def test_empty_graph_components(self):
        """Test empty graph has no components."""
        components = self.graph.find_connected_components()
        
        self.assertEqual(components, [])
    
    def test_find_reuse_clusters(self):
        """Test finding reuse clusters (components > 1)."""
        for v in ["A", "B", "C", "D", "E"]:
            self.graph.add_vertex(v)
        self.graph.add_edge("A", "B")
        self.graph.add_edge("C", "D")
        # E is isolated - should not be in clusters
        
        clusters = self.graph.find_reuse_clusters()
        
        self.assertEqual(len(clusters), 2)
        for cluster in clusters:
            self.assertGreater(len(cluster), 1)


class TestSecurityScoring(unittest.TestCase):
    """Test cases for security scoring functionality."""
    
    def setUp(self):
        """Initialize graph for scoring tests."""
        self.graph = SecurityGraph()
    
    def tearDown(self):
        """Clean up after each test."""
        self.graph = None
    
    def test_risk_score_no_reuse(self):
        """Test risk score for credential with no reuse."""
        self.graph.add_vertex("A")
        self.graph.add_vertex("B")
        # No edges = no reuse
        
        score = self.graph.calculate_risk_score("A")
        
        self.assertEqual(score, 0.0)
    
    def test_risk_score_with_reuse(self):
        """Test risk score for credential with password reuse."""
        for v in ["A", "B", "C"]:
            self.graph.add_vertex(v)
        self.graph.add_edge("A", "B")
        self.graph.add_edge("A", "C")
        
        score = self.graph.calculate_risk_score("A")
        
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 1.0)
    
    def test_risk_score_nonexistent(self):
        """Test risk score for nonexistent vertex."""
        score = self.graph.calculate_risk_score("X")
        
        self.assertEqual(score, 0.0)
    
    def test_overall_security_score_all_unique(self):
        """Test overall score when all passwords are unique."""
        self.graph.add_vertex("A")
        self.graph.add_vertex("B")
        self.graph.add_vertex("C")
        # No edges = all unique
        
        score = self.graph.get_overall_security_score()
        
        self.assertEqual(score, 100.0)
    
    def test_overall_security_score_with_reuse(self):
        """Test overall score when there's password reuse."""
        for v in ["A", "B", "C"]:
            self.graph.add_vertex(v)
        self.graph.add_edge("A", "B")
        
        score = self.graph.get_overall_security_score()
        
        # C has unique password, A and B share
        self.assertGreater(score, 0.0)
        self.assertLess(score, 100.0)
    
    def test_overall_security_score_empty(self):
        """Test overall score for empty graph."""
        score = self.graph.get_overall_security_score()
        
        self.assertEqual(score, 100.0)


class TestPasswordReuseAnalyzer(unittest.TestCase):
    """Test cases for PasswordReuseAnalyzer."""
    
    def setUp(self):
        """Initialize analyzer for each test."""
        self.analyzer = PasswordReuseAnalyzer()
    
    def tearDown(self):
        """Clean up after each test."""
        self.analyzer = None
    
    def test_add_credential_no_reuse(self):
        """Test adding credentials with unique passwords."""
        self.analyzer.add_credential("site1", "hash1")
        self.analyzer.add_credential("site2", "hash2")
        
        self.assertEqual(self.analyzer.graph.vertex_count, 2)
        self.assertEqual(self.analyzer.graph.edge_count, 0)
    
    def test_add_credential_with_reuse(self):
        """Test adding credentials that share a password."""
        self.analyzer.add_credential("site1", "samehash")
        self.analyzer.add_credential("site2", "samehash")
        
        self.assertEqual(self.analyzer.graph.vertex_count, 2)
        self.assertEqual(self.analyzer.graph.edge_count, 1)
        self.assertTrue(self.analyzer.graph.has_edge("site1", "site2"))
    
    def test_multiple_reuse_groups(self):
        """Test multiple groups of password reuse."""
        self.analyzer.add_credential("site1", "hash1")
        self.analyzer.add_credential("site2", "hash1")  # Reuses hash1
        self.analyzer.add_credential("site3", "hash2")
        self.analyzer.add_credential("site4", "hash2")  # Reuses hash2
        
        self.assertEqual(self.analyzer.graph.vertex_count, 4)
        self.assertEqual(self.analyzer.graph.edge_count, 2)
    
    def test_remove_credential(self):
        """Test removing a credential."""
        self.analyzer.add_credential("site1", "hash1")
        self.analyzer.add_credential("site2", "hash1")
        
        self.analyzer.remove_credential("site1")
        
        self.assertEqual(self.analyzer.graph.vertex_count, 1)
        self.assertNotIn("site1", self.analyzer.graph)
    
    def test_update_password(self):
        """Test updating a credential's password."""
        self.analyzer.add_credential("site1", "oldhash")
        self.analyzer.add_credential("site2", "oldhash")
        self.analyzer.add_credential("site3", "newhash")
        
        # Initially site1 and site2 share password
        self.assertTrue(self.analyzer.graph.has_edge("site1", "site2"))
        
        # Update site1 to use new password
        self.analyzer.update_password("site1", "oldhash", "newhash")
        
        # Now site1 should be connected to site3, not site2
        self.assertFalse(self.analyzer.graph.has_edge("site1", "site2"))
        self.assertTrue(self.analyzer.graph.has_edge("site1", "site3"))
    
    def test_get_reuse_report(self):
        """Test generating a reuse report."""
        self.analyzer.add_credential("site1", "hash1")
        self.analyzer.add_credential("site2", "hash1")
        self.analyzer.add_credential("site3", "hash2")
        
        report = self.analyzer.get_reuse_report()
        
        self.assertEqual(report['total_credentials'], 3)
        self.assertEqual(report['unique_passwords'], 2)
        self.assertEqual(report['reuse_clusters'], 1)
        self.assertEqual(report['affected_credentials'], 2)
        self.assertIn('security_score', report)
    
    def test_clear(self):
        """Test clearing the analyzer."""
        self.analyzer.add_credential("site1", "hash1")
        self.analyzer.add_credential("site2", "hash1")
        
        self.analyzer.clear()
        
        self.assertEqual(self.analyzer.graph.vertex_count, 0)
        self.assertEqual(self.analyzer.graph.edge_count, 0)


class TestGraphUtilities(unittest.TestCase):
    """Test cases for utility methods."""
    
    def setUp(self):
        """Initialize graph for utility tests."""
        self.graph = SecurityGraph()
        self.graph.add_vertex("A")
        self.graph.add_vertex("B")
        self.graph.add_vertex("C")
        self.graph.add_edge("A", "B")
        self.graph.add_edge("B", "C")
    
    def tearDown(self):
        """Clean up after each test."""
        self.graph = None
    
    def test_clear(self):
        """Test clearing the graph."""
        self.graph.clear()
        
        self.assertEqual(len(self.graph), 0)
        self.assertEqual(self.graph.edge_count, 0)
    
    def test_get_all_edges(self):
        """Test getting all edges."""
        edges = self.graph.get_all_edges()
        
        self.assertEqual(len(edges), 2)
    
    def test_get_graph_data(self):
        """Test getting graph data for visualization."""
        graph_data = self.graph.get_graph_data()
        
        self.assertIn('nodes', graph_data)
        self.assertIn('edges', graph_data)
        self.assertIn('security_score', graph_data)
        self.assertEqual(len(graph_data['nodes']), 3)
        # Edges could be undirected, so we just check > 0
        self.assertGreater(len(graph_data['edges']), 0)


class TestGraphEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""
    
    def setUp(self):
        """Initialize graph for edge case tests."""
        self.graph = SecurityGraph()
    
    def tearDown(self):
        """Clean up after each test."""
        self.graph = None
    
    def test_weighted_edges_via_data(self):
        """Test using vertex data for weighted relationships."""
        self.graph.add_vertex("A", data={"weight": 10})
        self.graph.add_vertex("B", data={"weight": 5})
        self.graph.add_edge("A", "B")
        
        self.assertEqual(self.graph.get_vertex("A").data["weight"], 10)
    
    def test_unicode_vertex_names(self):
        """Test graph with unicode vertex names."""
        self.graph.add_vertex("网站A")
        self.graph.add_vertex("サイトB")
        self.graph.add_edge("网站A", "サイトB")
        
        self.assertIn("网站A", self.graph)
        self.assertTrue(self.graph.has_edge("网站A", "サイトB"))
    
    def test_large_graph_performance(self):
        """Test graph with many vertices."""
        # Add 100 vertices
        for i in range(100):
            self.graph.add_vertex(f"vertex_{i}")
        
        # Add edges
        for i in range(0, 100, 2):
            self.graph.add_edge(f"vertex_{i}", f"vertex_{i+1}")
        
        self.assertEqual(self.graph.vertex_count, 100)
        self.assertEqual(self.graph.edge_count, 50)


class TestGraphIntegration(unittest.TestCase):
    """Integration tests for password manager scenarios."""
    
    def setUp(self):
        """Initialize analyzer for integration tests."""
        self.analyzer = PasswordReuseAnalyzer()
    
    def tearDown(self):
        """Clean up after each test."""
        self.analyzer = None
    
    def test_real_world_scenario(self):
        """Test realistic password reuse scenario."""
        # Add credentials
        self.analyzer.add_credential("gmail.com", "hash_common")
        self.analyzer.add_credential("facebook.com", "hash_common")  # Reuses gmail password
        self.analyzer.add_credential("bank.com", "hash_secure")      # Unique
        self.analyzer.add_credential("twitter.com", "hash_weak")
        self.analyzer.add_credential("instagram.com", "hash_weak")   # Reuses twitter password
        
        report = self.analyzer.get_reuse_report()
        
        self.assertEqual(report['total_credentials'], 5)
        self.assertEqual(report['reuse_clusters'], 2)
        self.assertEqual(report['affected_credentials'], 4)
    
    def test_security_recommendations(self):
        """Test identifying high-risk credentials."""
        # Site connected to many others (high risk)
        self.analyzer.add_credential("main_email", "shared_hash")
        self.analyzer.add_credential("site1", "shared_hash")
        self.analyzer.add_credential("site2", "shared_hash")
        self.analyzer.add_credential("site3", "shared_hash")
        
        report = self.analyzer.get_reuse_report()
        
        # main_email should be high risk since it shares password with 3 sites
        self.assertGreater(len(report['high_risk_credentials']), 0)


if __name__ == '__main__':
    # Run with: python -m unittest tests.unitTestGraph
    # or: python tests/unitTestGraph.py
    unittest.main(verbosity=2)
