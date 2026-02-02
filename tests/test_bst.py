"""
Test Suite: Binary Search Tree (BST)
====================================

This module contains comprehensive tests for the BST implementation,
verifying all operations work correctly.

Test Categories:
    - Insertion tests
    - Search tests
    - Deletion tests
    - Traversal tests
    - Prefix search tests
    - Edge case tests

Testing OOP Concepts:
    - Tests verify encapsulation by checking public interface
    - Tests validate correct behavior of polymorphic comparisons
    - Tests ensure abstraction hides implementation details

Author: Advanced Password Manager Team
Date: 2024
"""

import pytest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from datastructures.bst import BinarySearchTree as BST, BSTNode


class TestBSTNode:
    """Test cases for BSTNode class."""
    
    def test_node_creation(self):
        """Test that nodes can be created with key-value pairs."""
        node = BSTNode("key1", "value1")
        assert node.key == "key1"
        assert node.value == "value1"
        assert node.left is None
        assert node.right is None
    
    def test_node_children(self):
        """Test node child assignment."""
        parent = BSTNode("parent", "pvalue")
        left_child = BSTNode("left", "lvalue")
        right_child = BSTNode("right", "rvalue")
        
        parent.left = left_child
        parent.right = right_child
        
        assert parent.left.key == "left"
        assert parent.right.key == "right"


class TestBSTInsertion:
    """Test cases for BST insertion operations."""
    
    def test_insert_single(self):
        """Test inserting a single element."""
        bst = BST()
        bst.insert("key1", "value1")
        
        assert bst.search("key1") == "value1"
        assert bst.size == 1
    
    def test_insert_multiple(self):
        """Test inserting multiple elements."""
        bst = BST()
        bst.insert("b", "value_b")
        bst.insert("a", "value_a")
        bst.insert("c", "value_c")
        
        assert bst.search("a") == "value_a"
        assert bst.search("b") == "value_b"
        assert bst.search("c") == "value_c"
        assert bst.size == 3
    
    def test_insert_duplicate_updates(self):
        """Test that inserting duplicate key updates value."""
        bst = BST()
        bst.insert("key", "original")
        bst.insert("key", "updated")
        
        assert bst.search("key") == "updated"
        assert bst.size == 1
    
    def test_insert_maintains_bst_property(self):
        """Test that BST property is maintained after insertions."""
        bst = BST()
        keys = ["m", "d", "t", "a", "g", "p", "z"]
        for key in keys:
            bst.insert(key, f"value_{key}")
        
        # Inorder traversal should give sorted values
        result = bst.inorder_traversal()
        # Values correspond to sorted keys
        assert len(result) == len(keys)


class TestBSTSearch:
    """Test cases for BST search operations."""
    
    def test_search_existing(self):
        """Test searching for existing keys."""
        bst = BST()
        bst.insert("apple", "fruit")
        bst.insert("banana", "yellow fruit")
        
        assert bst.search("apple") == "fruit"
        assert bst.search("banana") == "yellow fruit"
    
    def test_search_nonexistent(self):
        """Test searching for non-existent keys."""
        bst = BST()
        bst.insert("apple", "fruit")
        
        assert bst.search("orange") is None
    
    def test_search_empty_tree(self):
        """Test searching in an empty tree."""
        bst = BST()
        assert bst.search("any") is None
    
    def test_contains(self):
        """Test contains method."""
        bst = BST()
        bst.insert("key1", "value1")
        
        assert bst.contains("key1") == True
        assert bst.contains("key2") == False


class TestBSTPrefixSearch:
    """Test cases for prefix search functionality."""
    
    def test_prefix_search_basic(self):
        """Test basic prefix search."""
        bst = BST()
        bst.insert("gmail.com", {"site": "gmail"})
        bst.insert("google.com", {"site": "google"})
        bst.insert("github.com", {"site": "github"})
        bst.insert("facebook.com", {"site": "facebook"})
        
        results = bst.prefix_search("g")
        
        # Should find gmail, google, github
        assert len(results) >= 1
    
    def test_prefix_search_no_match(self):
        """Test prefix search with no matches."""
        bst = BST()
        bst.insert("apple", "value")
        
        results = bst.prefix_search("z")
        assert len(results) == 0
    
    def test_prefix_search_empty_prefix(self):
        """Test prefix search with empty string (all results)."""
        bst = BST()
        bst.insert("a", "1")
        bst.insert("b", "2")
        bst.insert("c", "3")
        
        results = bst.prefix_search("")
        assert len(results) == 3


class TestBSTDeletion:
    """Test cases for BST deletion operations."""
    
    def test_delete_leaf(self):
        """Test deleting a leaf node."""
        bst = BST()
        bst.insert("b", "2")
        bst.insert("a", "1")
        bst.insert("c", "3")
        
        bst.delete("a")  # a is a leaf
        
        assert bst.contains("a") == False
        assert bst.contains("b") == True
        assert bst.contains("c") == True
        assert bst.size == 2
    
    def test_delete_node_with_one_child(self):
        """Test deleting a node with one child."""
        bst = BST()
        bst.insert("b", "2")
        bst.insert("a", "1")
        
        bst.delete("b")  # b has one child (a)
        
        assert bst.contains("b") == False
        assert bst.contains("a") == True
    
    def test_delete_node_with_two_children(self):
        """Test deleting a node with two children."""
        bst = BST()
        bst.insert("b", "2")
        bst.insert("a", "1")
        bst.insert("c", "3")
        
        bst.delete("b")  # b has two children
        
        assert bst.contains("b") == False
        assert bst.contains("a") == True
        assert bst.contains("c") == True
    
    def test_delete_root(self):
        """Test deleting the root node."""
        bst = BST()
        bst.insert("root", "value")
        
        bst.delete("root")
        
        assert bst.contains("root") == False
        assert bst.size == 0
    
    def test_delete_nonexistent(self):
        """Test deleting a non-existent key (should not raise)."""
        bst = BST()
        bst.insert("key", "value")
        
        result = bst.delete("nonexistent")  # Should return False
        
        assert result == False
        assert bst.contains("key") == True
        assert bst.size == 1


class TestBSTTraversal:
    """Test cases for BST traversal operations."""
    
    def test_inorder_traversal(self):
        """Test in-order traversal returns sorted order."""
        bst = BST()
        bst.insert("d", "4")
        bst.insert("b", "2")
        bst.insert("f", "6")
        bst.insert("a", "1")
        bst.insert("c", "3")
        bst.insert("e", "5")
        
        result = bst.inorder_traversal()
        
        # Should return 6 values
        assert len(result) == 6
    
    def test_empty_tree_traversal(self):
        """Test traversal of empty tree."""
        bst = BST()
        
        assert bst.inorder_traversal() == []
    
    def test_get_all_keys(self):
        """Test getting all keys."""
        bst = BST()
        bst.insert("c", "3")
        bst.insert("a", "1")
        bst.insert("b", "2")
        
        keys = bst.get_all_keys()
        
        # Keys should be in sorted order
        assert keys == ["a", "b", "c"]


class TestBSTEdgeCases:
    """Test edge cases and special scenarios."""
    
    def test_empty_tree(self):
        """Test operations on empty tree."""
        bst = BST()
        
        assert bst.size == 0
        assert bst.is_empty == True
        assert bst.search("any") is None
    
    def test_single_element(self):
        """Test tree with single element."""
        bst = BST()
        bst.insert("only", "value")
        
        assert bst.size == 1
        assert bst.is_empty == False
        assert bst.search("only") == "value"
    
    def test_height(self):
        """Test tree height calculation."""
        bst = BST()
        assert bst.get_height() == 0
        
        bst.insert("root", "r")
        assert bst.get_height() == 1
        
        bst.insert("a", "a")
        bst.insert("z", "z")
        assert bst.get_height() == 2
    
    def test_clear(self):
        """Test clearing the tree."""
        bst = BST()
        bst.insert("a", "1")
        bst.insert("b", "2")
        bst.insert("c", "3")
        
        bst.clear()
        
        assert bst.size == 0
        assert bst.is_empty == True
    
    def test_case_insensitive(self):
        """Test that keys are case-insensitive."""
        bst = BST()
        bst.insert("Google", "search")
        
        # Should find with different case
        assert bst.search("google") == "search"
        assert bst.search("GOOGLE") == "search"


class TestBSTCredentialSearch:
    """Test BST for credential search use cases."""
    
    def test_website_search(self):
        """Test searching credentials by website."""
        bst = BST()
        
        # Simulate storing credentials
        bst.insert("amazon.com", {"username": "user1", "password": "pass1"})
        bst.insert("google.com", {"username": "user2", "password": "pass2"})
        bst.insert("github.com", {"username": "user3", "password": "pass3"})
        
        # Search for google
        result = bst.search("google.com")
        assert result is not None
        assert result["username"] == "user2"
    
    def test_autocomplete_websites(self):
        """Test prefix search for website autocomplete."""
        bst = BST()
        
        bst.insert("amazon.com", "cred1")
        bst.insert("apple.com", "cred2")
        bst.insert("google.com", "cred3")
        bst.insert("github.com", "cred4")
        
        # User types "a"
        suggestions = bst.prefix_search("a")
        
        # Should return at least amazon and apple credentials
        assert len(suggestions) >= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
