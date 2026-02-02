"""
Data Structures Package

Custom implementations of fundamental data structures
used for in-memory credential management.
"""

from .bst import BinarySearchTree, BSTNode
from .hashtable import HashTable, generate_composite_key
from .graph import SecurityGraph, PasswordReuseAnalyzer, GraphVertex
from .linked_list import LinkedList, PasswordHistory

__all__ = [
    'BinarySearchTree',
    'BSTNode',
    'HashTable',
    'generate_composite_key',
    'SecurityGraph',
    'PasswordReuseAnalyzer',
    'GraphVertex',
    'LinkedList',
    'PasswordHistory'
]
