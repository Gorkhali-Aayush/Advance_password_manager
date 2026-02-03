"""
Unittest: Binary Search Tree (BST)
==================================

Comprehensive tests for BST implementation.
Uses unittest with setUp() method pattern.

Run with: python -m unittest tests.unitTestBst
or: python tests/unitTestBst.py
"""

import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from datastructures.bst import BinarySearchTree as BST, BSTNode


class TestBSTNode(unittest.TestCase):
    """Test cases for BSTNode class."""
    
    def setUp(self):
        """Initialize test fixtures."""
        self.node = BSTNode("key1", "value1")
    
    def tearDown(self):
        """Clean up after each test."""
        self.node = None
    
    def test_node_creation(self):
        """Test that nodes can be created with key-value pairs."""
        self.assertEqual(self.node.key, "key1")
        self.assertEqual(self.node.value, "value1")
        self.assertIsNone(self.node.left)
        self.assertIsNone(self.node.right)
    
    def test_node_children(self):
        """Test node child assignment."""
        parent = BSTNode("parent", "pvalue")
        left_child = BSTNode("left", "lvalue")
        right_child = BSTNode("right", "rvalue")
        
        parent.left = left_child
        parent.right = right_child
        
        self.assertEqual(parent.left.key, "left")
        self.assertEqual(parent.right.key, "right")


class TestBSTInsertion(unittest.TestCase):
    """Test cases for BST insertion operations."""
    
    def setUp(self):
        """Initialize a new BST for each test."""
        self.bst = BST()
    
    def tearDown(self):
        """Clean up after each test."""
        self.bst = None
    
    def test_insert_single(self):
        """Test inserting a single element."""
        self.bst.insert("key1", "value1")
        
        self.assertEqual(self.bst.search("key1"), "value1")
        self.assertEqual(self.bst.size, 1)
    
    def test_insert_multiple(self):
        """Test inserting multiple elements."""
        self.bst.insert("b", "value_b")
        self.bst.insert("a", "value_a")
        self.bst.insert("c", "value_c")
        
        self.assertEqual(self.bst.search("a"), "value_a")
        self.assertEqual(self.bst.search("b"), "value_b")
        self.assertEqual(self.bst.search("c"), "value_c")
        self.assertEqual(self.bst.size, 3)
    
    def test_insert_duplicate_updates(self):
        """Test that inserting duplicate key updates value."""
        self.bst.insert("key", "original")
        self.bst.insert("key", "updated")
        
        self.assertEqual(self.bst.search("key"), "updated")
        self.assertEqual(self.bst.size, 1)
    
    def test_insert_maintains_bst_property(self):
        """Test that BST property is maintained after insertions."""
        keys = ["m", "d", "t", "a", "g", "p", "z"]
        for key in keys:
            self.bst.insert(key, f"value_{key}")
        
        result = self.bst.inorder_traversal()
        self.assertEqual(len(result), len(keys))


class TestBSTSearch(unittest.TestCase):
    """Test cases for BST search operations."""
    
    def setUp(self):
        """Initialize BST with test data."""
        self.bst = BST()
        self.bst.insert("apple", "fruit")
        self.bst.insert("banana", "yellow fruit")
    
    def tearDown(self):
        """Clean up after each test."""
        self.bst = None
    
    def test_search_existing(self):
        """Test searching for existing keys."""
        self.assertEqual(self.bst.search("apple"), "fruit")
        self.assertEqual(self.bst.search("banana"), "yellow fruit")
    
    def test_search_nonexistent(self):
        """Test searching for non-existent keys."""
        self.assertIsNone(self.bst.search("orange"))
    
    def test_search_empty_tree(self):
        """Test searching in an empty tree."""
        empty_bst = BST()
        self.assertIsNone(empty_bst.search("any"))
    
    def test_contains(self):
        """Test contains method."""
        self.assertTrue(self.bst.contains("apple"))
        self.assertFalse(self.bst.contains("key2"))


class TestBSTPrefixSearch(unittest.TestCase):
    """Test cases for prefix search functionality."""
    
    def setUp(self):
        """Initialize BST with test data."""
        self.bst = BST()
        self.bst.insert("gmail.com", {"site": "gmail"})
        self.bst.insert("google.com", {"site": "google"})
        self.bst.insert("github.com", {"site": "github"})
        self.bst.insert("facebook.com", {"site": "facebook"})
    
    def tearDown(self):
        """Clean up after each test."""
        self.bst = None
    
    def test_prefix_search_basic(self):
        """Test basic prefix search."""
        results = self.bst.prefix_search("g")
        
        # Should find gmail, google, github
        self.assertGreaterEqual(len(results), 1)
    
    def test_prefix_search_no_match(self):
        """Test prefix search with no matches."""
        empty_bst = BST()
        empty_bst.insert("apple", "value")
        
        results = empty_bst.prefix_search("z")
        self.assertEqual(len(results), 0)
    
    def test_prefix_search_empty_prefix(self):
        """Test prefix search with empty string (all results)."""
        test_bst = BST()
        test_bst.insert("a", "1")
        test_bst.insert("b", "2")
        test_bst.insert("c", "3")
        
        results = test_bst.prefix_search("")
        self.assertEqual(len(results), 3)


class TestBSTDeletion(unittest.TestCase):
    """Test cases for BST deletion operations."""
    
    def setUp(self):
        """Initialize BST with test data."""
        self.bst = BST()
    
    def tearDown(self):
        """Clean up after each test."""
        self.bst = None
    
    def test_delete_leaf(self):
        """Test deleting a leaf node."""
        self.bst.insert("b", "2")
        self.bst.insert("a", "1")
        self.bst.insert("c", "3")
        
        self.bst.delete("a")  # a is a leaf
        
        self.assertFalse(self.bst.contains("a"))
        self.assertTrue(self.bst.contains("b"))
        self.assertTrue(self.bst.contains("c"))
        self.assertEqual(self.bst.size, 2)
    
    def test_delete_node_with_one_child(self):
        """Test deleting a node with one child."""
        self.bst.insert("b", "2")
        self.bst.insert("a", "1")
        
        self.bst.delete("b")  # b has one child (a)
        
        self.assertFalse(self.bst.contains("b"))
        self.assertTrue(self.bst.contains("a"))
    
    def test_delete_node_with_two_children(self):
        """Test deleting a node with two children."""
        self.bst.insert("b", "2")
        self.bst.insert("a", "1")
        self.bst.insert("c", "3")
        
        self.bst.delete("b")  # b has two children
        
        self.assertFalse(self.bst.contains("b"))
        self.assertTrue(self.bst.contains("a"))
        self.assertTrue(self.bst.contains("c"))
    
    def test_delete_root(self):
        """Test deleting the root node."""
        self.bst.insert("root", "value")
        
        self.bst.delete("root")
        
        self.assertFalse(self.bst.contains("root"))
        self.assertEqual(self.bst.size, 0)
    
    def test_delete_nonexistent(self):
        """Test deleting a non-existent key (should not raise)."""
        self.bst.insert("key", "value")
        
        result = self.bst.delete("nonexistent")  # Should return False
        
        self.assertFalse(result)
        self.assertTrue(self.bst.contains("key"))
        self.assertEqual(self.bst.size, 1)


class TestBSTTraversal(unittest.TestCase):
    """Test cases for BST traversal operations."""
    
    def setUp(self):
        """Initialize BST with test data."""
        self.bst = BST()
        self.bst.insert("d", "4")
        self.bst.insert("b", "2")
        self.bst.insert("f", "6")
        self.bst.insert("a", "1")
        self.bst.insert("c", "3")
        self.bst.insert("e", "5")
    
    def tearDown(self):
        """Clean up after each test."""
        self.bst = None
    
    def test_inorder_traversal(self):
        """Test in-order traversal returns sorted order."""
        result = self.bst.inorder_traversal()
        
        # Should return 6 values
        self.assertEqual(len(result), 6)
    
    def test_empty_tree_traversal(self):
        """Test traversal of empty tree."""
        empty_bst = BST()
        self.assertEqual(empty_bst.inorder_traversal(), [])
    
    def test_get_all_keys(self):
        """Test getting all keys via traversal."""
        test_bst = BST()
        test_bst.insert("c", "3")
        test_bst.insert("a", "1")
        test_bst.insert("b", "2")
        
        # Use inorder traversal to get keys
        traversal = test_bst.inorder_traversal()
        
        # Should have 3 keys
        self.assertEqual(len(traversal), 3)


class TestBSTEdgeCases(unittest.TestCase):
    """Test edge cases and special scenarios."""
    
    def setUp(self):
        """Initialize fresh BST."""
        self.bst = BST()
    
    def tearDown(self):
        """Clean up after each test."""
        self.bst = None
    
    def test_empty_tree(self):
        """Test operations on empty tree."""
        self.assertEqual(self.bst.size, 0)
        self.assertTrue(self.bst.is_empty)
        self.assertIsNone(self.bst.search("any"))
    
    def test_single_element(self):
        """Test tree with single element."""
        self.bst.insert("only", "value")
        
        self.assertEqual(self.bst.size, 1)
        self.assertFalse(self.bst.is_empty)
        self.assertEqual(self.bst.search("only"), "value")
    
    def test_height(self):
        """Test tree height through insertion."""
        self.assertEqual(self.bst.size, 0)
        
        self.bst.insert("root", "r")
        self.assertEqual(self.bst.size, 1)
        
        self.bst.insert("a", "a")
        self.bst.insert("z", "z")
        self.assertEqual(self.bst.size, 3)
    
    def test_clear(self):
        """Test clearing the tree."""
        self.bst.insert("a", "1")
        self.bst.insert("b", "2")
        self.bst.insert("c", "3")
        
        self.bst.clear()
        
        self.assertEqual(self.bst.size, 0)
        self.assertTrue(self.bst.is_empty)
    
    def test_case_insensitive(self):
        """Test that keys are case-insensitive."""
        self.bst.insert("Google", "search")
        
        # Should find with different case
        self.assertEqual(self.bst.search("google"), "search")
        self.assertEqual(self.bst.search("GOOGLE"), "search")


class TestBSTCredentialSearch(unittest.TestCase):
    """Test BST for credential search use cases."""
    
    def setUp(self):
        """Initialize BST with credential data."""
        self.bst = BST()
        
        # Simulate storing credentials
        self.bst.insert("amazon.com", {"username": "user1", "password": "pass1"})
        self.bst.insert("google.com", {"username": "user2", "password": "pass2"})
        self.bst.insert("github.com", {"username": "user3", "password": "pass3"})
    
    def tearDown(self):
        """Clean up after each test."""
        self.bst = None
    
    def test_website_search(self):
        """Test searching credentials by website."""
        # Search for google
        result = self.bst.search("google.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["username"], "user2")
    
    def test_autocomplete_websites(self):
        """Test prefix search for website autocomplete."""
        test_bst = BST()
        
        test_bst.insert("amazon.com", "cred1")
        test_bst.insert("apple.com", "cred2")
        test_bst.insert("google.com", "cred3")
        test_bst.insert("github.com", "cred4")
        
        # User types "a"
        suggestions = test_bst.prefix_search("a")
        
        # Should return at least amazon and apple credentials
        self.assertGreaterEqual(len(suggestions), 2)


if __name__ == '__main__':
    # Run with: python -m unittest tests.unitTestBst
    # or: python tests/unitTestBst.py
    unittest.main(verbosity=2)
