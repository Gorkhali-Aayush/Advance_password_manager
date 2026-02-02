"""
Binary Search Tree (BST) Implementation
Used for efficient sorted credential search by name.

Time Complexity:
- Insert: O(log n) average, O(n) worst case
- Search: O(log n) average, O(n) worst case
- Traversal: O(n)
"""

from typing import Any, Optional, List, Callable


class BSTNode:
    """
    Represents a single node in the Binary Search Tree.
    
    Attributes:
        key: The search key (e.g., site name)
        value: The associated data (e.g., credential object)
        left: Left child node
        right: Right child node
    """
    
    def __init__(self, key: str, value: Any):
        """
        Initialize a BST node.
        
        Args:
            key: The search key for comparison
            value: The data to store
        """
        self._key = key.lower()  # Case-insensitive comparison
        self._value = value
        self._left: Optional['BSTNode'] = None
        self._right: Optional['BSTNode'] = None
    
    @property
    def key(self) -> str:
        """Get the node's key."""
        return self._key
    
    @property
    def value(self) -> Any:
        """Get the node's value."""
        return self._value
    
    @value.setter
    def value(self, new_value: Any) -> None:
        """Set the node's value."""
        self._value = new_value
    
    @property
    def left(self) -> Optional['BSTNode']:
        """Get left child."""
        return self._left
    
    @left.setter
    def left(self, node: Optional['BSTNode']) -> None:
        """Set left child."""
        self._left = node
    
    @property
    def right(self) -> Optional['BSTNode']:
        """Get right child."""
        return self._right
    
    @right.setter
    def right(self, node: Optional['BSTNode']) -> None:
        """Set right child."""
        self._right = node


class BinarySearchTree:
    """
    Binary Search Tree for efficient credential lookup.
    
    Used in the password manager for:
    - Fast searching of credentials by site name
    - Sorted display of all credentials
    - Prefix-based search for autocomplete
    """
    
    def __init__(self):
        """Initialize an empty BST."""
        self._root: Optional[BSTNode] = None
        self._size: int = 0
    
    @property
    def size(self) -> int:
        """Return the number of nodes in the tree."""
        return self._size
    
    @property
    def is_empty(self) -> bool:
        """Check if tree is empty."""
        return self._root is None
    
    def insert(self, key: str, value: Any) -> None:
        """
        Insert a key-value pair into the BST.
        
        Args:
            key: The search key
            value: The data to store
            
        Time Complexity: O(log n) average, O(n) worst case
        """
        if self._root is None:
            self._root = BSTNode(key, value)
            self._size += 1
        else:
            self._insert_recursive(self._root, key, value)
    
    def _insert_recursive(self, node: BSTNode, key: str, value: Any) -> None:
        """
        Recursively insert a node into the tree.
        
        Args:
            node: Current node in traversal
            key: Key to insert
            value: Value to store
        """
        key_lower = key.lower()
        
        if key_lower == node.key:
            # Update existing node
            node.value = value
        elif key_lower < node.key:
            if node.left is None:
                node.left = BSTNode(key, value)
                self._size += 1
            else:
                self._insert_recursive(node.left, key, value)
        else:
            if node.right is None:
                node.right = BSTNode(key, value)
                self._size += 1
            else:
                self._insert_recursive(node.right, key, value)
    
    def search(self, key: str) -> Optional[Any]:
        """
        Search for a value by key.
        
        Args:
            key: The key to search for
            
        Returns:
            The associated value, or None if not found
            
        Time Complexity: O(log n) average
        """
        node = self._search_node(self._root, key.lower())
        return node.value if node else None
    
    def _search_node(self, node: Optional[BSTNode], key: str) -> Optional[BSTNode]:
        """
        Recursively search for a node.
        
        Args:
            node: Current node
            key: Key to find
            
        Returns:
            The node if found, None otherwise
        """
        if node is None:
            return None
        
        if key == node.key:
            return node
        elif key < node.key:
            return self._search_node(node.left, key)
        else:
            return self._search_node(node.right, key)
    
    def contains(self, key: str) -> bool:
        """
        Check if a key exists in the tree.
        
        Args:
            key: The key to check
            
        Returns:
            True if key exists, False otherwise
        """
        return self.search(key) is not None
    
    def delete(self, key: str) -> bool:
        """
        Delete a node by key.
        
        Args:
            key: The key to delete
            
        Returns:
            True if deleted, False if not found
            
        Time Complexity: O(log n) average
        """
        if not self.contains(key):
            return False
        
        self._root = self._delete_recursive(self._root, key.lower())
        self._size -= 1
        return True
    
    def _delete_recursive(self, node: Optional[BSTNode], key: str) -> Optional[BSTNode]:
        """
        Recursively delete a node.
        
        Args:
            node: Current node
            key: Key to delete
            
        Returns:
            The updated subtree root
        """
        if node is None:
            return None
        
        if key < node.key:
            node.left = self._delete_recursive(node.left, key)
        elif key > node.key:
            node.right = self._delete_recursive(node.right, key)
        else:
            # Node to delete found
            if node.left is None:
                return node.right
            elif node.right is None:
                return node.left
            else:
                # Node has two children - find inorder successor
                successor = self._find_min(node.right)
                node._key = successor.key
                node._value = successor.value
                node.right = self._delete_recursive(node.right, successor.key)
        
        return node
    
    def _find_min(self, node: BSTNode) -> BSTNode:
        """Find the minimum node in a subtree."""
        current = node
        while current.left is not None:
            current = current.left
        return current
    
    def inorder_traversal(self) -> List[Any]:
        """
        Return all values in sorted order.
        
        Returns:
            List of values sorted by key
            
        Time Complexity: O(n)
        """
        result = []
        self._inorder_recursive(self._root, result)
        return result
    
    def _inorder_recursive(self, node: Optional[BSTNode], result: List[Any]) -> None:
        """Recursively perform inorder traversal."""
        if node is not None:
            self._inorder_recursive(node.left, result)
            result.append(node.value)
            self._inorder_recursive(node.right, result)
    
    def prefix_search(self, prefix: str) -> List[Any]:
        """
        Find all values whose keys start with the given prefix.
        
        Args:
            prefix: The prefix to search for
            
        Returns:
            List of matching values
            
        Used for: Autocomplete feature
        """
        results = []
        prefix_lower = prefix.lower()
        self._prefix_search_recursive(self._root, prefix_lower, results)
        return results
    
    def _prefix_search_recursive(self, node: Optional[BSTNode], 
                                  prefix: str, results: List[Any]) -> None:
        """Recursively find nodes matching prefix."""
        if node is None:
            return
        
        if node.key.startswith(prefix):
            results.append(node.value)
        
        # Search left if prefix could be there
        if node.left and prefix <= node.key:
            self._prefix_search_recursive(node.left, prefix, results)
        
        # Search right if prefix could be there
        if node.right and prefix >= node.key[:len(prefix)]:
            self._prefix_search_recursive(node.right, prefix, results)
    
    
    def clear(self) -> None:
        """Clear all nodes from the tree."""
        self._root = None
        self._size = 0
    
    
    def __len__(self) -> int:
        """Return the size of the tree."""
        return self._size
    
    def __contains__(self, key: str) -> bool:
        """Support 'in' operator."""
        return self.contains(key)
    
    def __iter__(self):
        """Iterate over values in sorted order."""
        return iter(self.inorder_traversal())
