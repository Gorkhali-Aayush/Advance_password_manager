"""
Graph Implementation for Password Security Analysis
Models relationships between credentials to detect password reuse.

Used for:
- Detecting password reuse across sites
- Visualizing security vulnerabilities
- Risk assessment scoring
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from collections import deque


class GraphVertex:
    """
    Represents a vertex (credential) in the security graph.
    
    Attributes:
        id: Unique identifier
        data: Associated credential data
        edges: Set of connected vertex IDs
    """
    
    def __init__(self, vertex_id: str, data: Any = None):
        """
        Initialize a graph vertex.
        
        Args:
            vertex_id: Unique identifier for this vertex
            data: Optional data to associate with vertex
        """
        self._id = vertex_id
        self._data = data
        self._edges: Set[str] = set()
    
    @property
    def id(self) -> str:
        return self._id
    
    @property
    def data(self) -> Any:
        return self._data
    
    @data.setter
    def data(self, value: Any) -> None:
        self._data = value
    
    @property
    def edges(self) -> Set[str]:
        return self._edges.copy()
    
    @property
    def degree(self) -> int:
        """Number of connections this vertex has."""
        return len(self._edges)
    
    def add_edge(self, vertex_id: str) -> None:
        """Add an edge to another vertex."""
        self._edges.add(vertex_id)
    
    def remove_edge(self, vertex_id: str) -> bool:
        """Remove an edge. Returns True if edge existed."""
        if vertex_id in self._edges:
            self._edges.remove(vertex_id)
            return True
        return False
    
    def has_edge_to(self, vertex_id: str) -> bool:
        """Check if connected to another vertex."""
        return vertex_id in self._edges


class SecurityGraph:
    """
    Graph for analyzing password security relationships.
    
    Vertices: Credentials (site + username)
    Edges: Password reuse (same password hash)
    
    Used to:
    - Detect password reuse across multiple sites
    - Calculate security risk scores
    - Visualize credential relationships
    """
    
    def __init__(self):
        """Initialize an empty graph."""
        self._vertices: Dict[str, GraphVertex] = {}
        self._edge_count = 0
    
    @property
    def vertex_count(self) -> int:
        """Number of vertices in the graph."""
        return len(self._vertices)
    
    @property
    def edge_count(self) -> int:
        """Number of edges in the graph."""
        return self._edge_count
    
    def add_vertex(self, vertex_id: str, data: Any = None) -> GraphVertex:
        """
        Add a vertex to the graph.
        
        Args:
            vertex_id: Unique identifier
            data: Optional associated data
            
        Returns:
            The created or existing vertex
        """
        if vertex_id not in self._vertices:
            self._vertices[vertex_id] = GraphVertex(vertex_id, data)
        else:
            # Update data if vertex exists
            self._vertices[vertex_id].data = data
        return self._vertices[vertex_id]
    
    def remove_vertex(self, vertex_id: str) -> bool:
        """
        Remove a vertex and all its edges.
        
        Args:
            vertex_id: The vertex to remove
            
        Returns:
            True if removed, False if not found
        """
        if vertex_id not in self._vertices:
            return False
        
        # Remove all edges pointing to this vertex
        vertex = self._vertices[vertex_id]
        for connected_id in vertex.edges:
            if connected_id in self._vertices:
                self._vertices[connected_id].remove_edge(vertex_id)
                self._edge_count -= 1
        
        del self._vertices[vertex_id]
        return True
    
    def get_vertex(self, vertex_id: str) -> Optional[GraphVertex]:
        """Get a vertex by ID."""
        return self._vertices.get(vertex_id)
    
    def has_vertex(self, vertex_id: str) -> bool:
        """Check if vertex exists."""
        return vertex_id in self._vertices
    
    def add_edge(self, from_id: str, to_id: str) -> bool:
        """
        Add an undirected edge between two vertices.
        
        Args:
            from_id: First vertex ID
            to_id: Second vertex ID
            
        Returns:
            True if edge added, False if vertices don't exist
        """
        if from_id not in self._vertices or to_id not in self._vertices:
            return False
        
        if from_id == to_id:
            return False  # No self-loops
        
        # Check if edge already exists
        if not self._vertices[from_id].has_edge_to(to_id):
            self._vertices[from_id].add_edge(to_id)
            self._vertices[to_id].add_edge(from_id)
            self._edge_count += 1
        
        return True
    
    def remove_edge(self, from_id: str, to_id: str) -> bool:
        """
        Remove an edge between two vertices.
        
        Args:
            from_id: First vertex ID
            to_id: Second vertex ID
            
        Returns:
            True if removed, False if edge didn't exist
        """
        if from_id not in self._vertices or to_id not in self._vertices:
            return False
        
        if self._vertices[from_id].remove_edge(to_id):
            self._vertices[to_id].remove_edge(from_id)
            self._edge_count -= 1
            return True
        
        return False
    
    def has_edge(self, from_id: str, to_id: str) -> bool:
        """Check if an edge exists between two vertices."""
        if from_id not in self._vertices:
            return False
        return self._vertices[from_id].has_edge_to(to_id)
    
    def get_neighbors(self, vertex_id: str) -> List[str]:
        """
        Get all vertices connected to the given vertex.
        
        Args:
            vertex_id: The vertex to check
            
        Returns:
            List of connected vertex IDs
        """
        if vertex_id not in self._vertices:
            return []
        return list(self._vertices[vertex_id].edges)
    
    def get_all_vertices(self) -> List[str]:
        """Get all vertex IDs."""
        return list(self._vertices.keys())
    
    def get_all_edges(self) -> List[Tuple[str, str]]:
        """
        Get all edges as tuples.
        
        Returns:
            List of (from_id, to_id) tuples
        """
        edges = []
        seen = set()
        
        for vertex_id, vertex in self._vertices.items():
            for connected_id in vertex.edges:
                edge = tuple(sorted([vertex_id, connected_id]))
                if edge not in seen:
                    seen.add(edge)
                    edges.append((vertex_id, connected_id))
        
        return edges
    
    def bfs(self, start_id: str) -> List[str]:
        """
        Breadth-first search traversal.
        
        Args:
            start_id: Starting vertex ID
            
        Returns:
            List of vertex IDs in BFS order
        """
        if start_id not in self._vertices:
            return []
        
        visited = set()
        result = []
        queue = deque([start_id])
        
        while queue:
            vertex_id = queue.popleft()
            if vertex_id not in visited:
                visited.add(vertex_id)
                result.append(vertex_id)
                
                for neighbor in self._vertices[vertex_id].edges:
                    if neighbor not in visited:
                        queue.append(neighbor)
        
        return result
    
    def dfs(self, start_id: str) -> List[str]:
        """
        Depth-first search traversal.
        
        Args:
            start_id: Starting vertex ID
            
        Returns:
            List of vertex IDs in DFS order
        """
        if start_id not in self._vertices:
            return []
        
        visited = set()
        result = []
        self._dfs_recursive(start_id, visited, result)
        return result
    
    def _dfs_recursive(self, vertex_id: str, visited: Set[str], result: List[str]) -> None:
        """Recursive DFS helper."""
        visited.add(vertex_id)
        result.append(vertex_id)
        
        for neighbor in self._vertices[vertex_id].edges:
            if neighbor not in visited:
                self._dfs_recursive(neighbor, visited, result)
    
    def find_connected_components(self) -> List[List[str]]:
        """
        Find all connected components in the graph.
        
        Returns:
            List of components, each component is a list of vertex IDs
            
        Used for: Identifying groups of credentials sharing passwords
        """
        visited = set()
        components = []
        
        for vertex_id in self._vertices:
            if vertex_id not in visited:
                component = self.bfs(vertex_id)
                visited.update(component)
                components.append(component)
        
        return components
    
    def find_reuse_clusters(self) -> List[List[str]]:
        """
        Find clusters of credentials with shared passwords.
        
        Returns:
            List of clusters (components with more than 1 vertex)
            
        Used for: Security analysis - password reuse detection
        """
        components = self.find_connected_components()
        return [c for c in components if len(c) > 1]
    
    def calculate_risk_score(self, vertex_id: str) -> float:
        """
        Calculate security risk score for a credential.
        
        Higher score = higher risk (more password reuse)
        
        Args:
            vertex_id: The credential to assess
            
        Returns:
            Risk score from 0.0 (safe) to 1.0 (high risk)
        """
        if vertex_id not in self._vertices:
            return 0.0
        
        vertex = self._vertices[vertex_id]
        degree = vertex.degree
        
        if degree == 0:
            return 0.0  # No password reuse - safe
        
        # Risk increases with number of shared passwords
        # and the total number of credentials
        max_possible = max(1, self.vertex_count - 1)
        base_risk = degree / max_possible
        
        # Additional risk if part of large cluster
        component = self.bfs(vertex_id)
        cluster_risk = len(component) / self.vertex_count if self.vertex_count > 0 else 0
        
        # Combined risk score
        return min(1.0, (base_risk * 0.6) + (cluster_risk * 0.4))
    
    def get_overall_security_score(self) -> float:
        """
        Calculate overall security score for all credentials.
        
        Returns:
            Score from 0.0 (all passwords reused) to 100.0 (all unique)
        """
        if self.vertex_count == 0:
            return 100.0
        
        # Count vertices with no edges (unique passwords)
        unique_count = sum(1 for v in self._vertices.values() if v.degree == 0)
        
        return (unique_count / self.vertex_count) * 100
    
    def clear(self) -> None:
        """Remove all vertices and edges."""
        self._vertices.clear()
        self._edge_count = 0
    
    def get_graph_data(self) -> Dict:
        """
        Get graph data for visualization.
        
        Returns:
            Dictionary with nodes and edges for rendering
        """
        nodes = []
        for vertex_id, vertex in self._vertices.items():
            nodes.append({
                'id': vertex_id,
                'data': vertex.data,
                'degree': vertex.degree,
                'risk': self.calculate_risk_score(vertex_id)
            })
        
        edges = self.get_all_edges()
        
        return {
            'nodes': nodes,
            'edges': edges,
            'security_score': self.get_overall_security_score()
        }
    
    def __len__(self) -> int:
        return self.vertex_count
    
    def __contains__(self, vertex_id: str) -> bool:
        return self.has_vertex(vertex_id)


class PasswordReuseAnalyzer:
    """
    Analyzes password reuse across credentials using a graph.
    
    Builds a graph where edges represent shared passwords.
    """
    
    def __init__(self):
        """Initialize the analyzer with an empty graph."""
        self._graph = SecurityGraph()
        self._password_groups: Dict[str, List[str]] = {}  # hash -> [vertex_ids]
    
    @property
    def graph(self) -> SecurityGraph:
        """Get the underlying graph."""
        return self._graph
    
    def add_credential(self, credential_id: str, password_hash: str, 
                       data: Any = None) -> None:
        """
        Add a credential and update password reuse edges.
        
        Args:
            credential_id: Unique identifier for the credential
            password_hash: Hash of the password (for comparison)
            data: Optional credential data
        """
        # Add vertex
        self._graph.add_vertex(credential_id, data)
        
        # Check for password reuse
        if password_hash in self._password_groups:
            # Add edges to all credentials with same password
            for existing_id in self._password_groups[password_hash]:
                self._graph.add_edge(credential_id, existing_id)
            self._password_groups[password_hash].append(credential_id)
        else:
            self._password_groups[password_hash] = [credential_id]
    
    def remove_credential(self, credential_id: str) -> None:
        """Remove a credential from the analysis."""
        self._graph.remove_vertex(credential_id)
        
        # Clean up password groups
        for hash_key, ids in list(self._password_groups.items()):
            if credential_id in ids:
                ids.remove(credential_id)
                if not ids:
                    del self._password_groups[hash_key]
    
    def update_password(self, credential_id: str, old_hash: str, 
                        new_hash: str) -> None:
        """
        Update a credential's password and recalculate edges.
        
        Args:
            credential_id: The credential to update
            old_hash: Previous password hash
            new_hash: New password hash
        """
        # Remove old edges
        if old_hash in self._password_groups:
            for other_id in self._password_groups[old_hash]:
                if other_id != credential_id:
                    self._graph.remove_edge(credential_id, other_id)
            
            self._password_groups[old_hash].remove(credential_id)
            if not self._password_groups[old_hash]:
                del self._password_groups[old_hash]
        
        # Add new edges
        if new_hash in self._password_groups:
            for other_id in self._password_groups[new_hash]:
                self._graph.add_edge(credential_id, other_id)
            self._password_groups[new_hash].append(credential_id)
        else:
            self._password_groups[new_hash] = [credential_id]
    
    def get_reuse_report(self) -> Dict:
        """
        Generate a password reuse report.
        
        Returns:
            Dictionary with reuse statistics and recommendations
        """
        clusters = self._graph.find_reuse_clusters()
        
        return {
            'total_credentials': self._graph.vertex_count,
            'unique_passwords': len(self._password_groups),
            'reuse_clusters': len(clusters),
            'affected_credentials': sum(len(c) for c in clusters),
            'security_score': self._graph.get_overall_security_score(),
            'high_risk_credentials': [
                v for v in self._graph.get_all_vertices()
                if self._graph.calculate_risk_score(v) > 0.5
            ]
        }
    
    def clear(self) -> None:
        """Clear all analysis data."""
        self._graph.clear()
        self._password_groups.clear()
