"""
Hash Table Implementation with Separate Chaining
Used for fast O(1) credential lookup and duplicate detection.

Time Complexity:
- Insert: O(1) average
- Search: O(1) average
- Delete: O(1) average
"""

from typing import Any, Optional, List, Tuple


class HashNode:
    """
    Node for the hash table's linked list chains.
    
    Attributes:
        key: The hash key
        value: The stored value
        next: Pointer to next node in chain
    """
    
    def __init__(self, key: str, value: Any):
        """
        Initialize a hash node.
        
        Args:
            key: The key for hashing
            value: The data to store
        """
        self._key = key
        self._value = value
        self._next: Optional['HashNode'] = None
    
    @property
    def key(self) -> str:
        return self._key
    
    @property
    def value(self) -> Any:
        return self._value
    
    @value.setter
    def value(self, new_value: Any) -> None:
        self._value = new_value
    
    @property
    def next(self) -> Optional['HashNode']:
        return self._next
    
    @next.setter
    def next(self, node: Optional['HashNode']) -> None:
        self._next = node


class HashTable:
    """
    Hash Table with separate chaining for collision resolution.
    
    Used in the password manager for:
    - Fast duplicate credential detection
    - O(1) lookup by site name + username
    - Caching decrypted credentials in memory
    """
    
    # Default number of buckets
    DEFAULT_CAPACITY = 16
    
    # Load factor threshold for resizing
    LOAD_FACTOR_THRESHOLD = 0.75
    
    def __init__(self, capacity: int = DEFAULT_CAPACITY):
        """
        Initialize the hash table.
        
        Args:
            capacity: Initial number of buckets
        """
        self._capacity = capacity
        self._buckets: List[Optional[HashNode]] = [None] * capacity
        self._size = 0
    
    @property
    def size(self) -> int:
        """Return number of entries."""
        return self._size
    
    @property
    def capacity(self) -> int:
        """Return current capacity."""
        return self._capacity
    
    @property
    def is_empty(self) -> bool:
        """Check if table is empty."""
        return self._size == 0
    
    def _hash(self, key: str) -> int:
        """
        Compute hash index for a key.
        
        Uses Python's built-in hash function with modulo.
        
        Args:
            key: The key to hash
            
        Returns:
            Bucket index
        """
        # Use polynomial rolling hash for better distribution
        hash_value = 0
        prime = 31
        
        for char in key:
            hash_value = (hash_value * prime + ord(char)) % self._capacity
        
        return hash_value
    
    def _get_load_factor(self) -> float:
        """Calculate current load factor."""
        return self._size / self._capacity
    
    def _resize(self) -> None:
        """
        Double the capacity and rehash all entries.
        
        Called when load factor exceeds threshold.
        """
        old_buckets = self._buckets
        self._capacity *= 2
        self._buckets = [None] * self._capacity
        self._size = 0
        
        # Rehash all existing entries
        for bucket in old_buckets:
            current = bucket
            while current is not None:
                self.put(current.key, current.value)
                current = current.next
    
    def put(self, key: str, value: Any) -> None:
        """
        Insert or update a key-value pair.
        
        Args:
            key: The key to insert
            value: The value to store
            
        Time Complexity: O(1) average
        """
        # Check if resize needed
        if self._get_load_factor() >= self.LOAD_FACTOR_THRESHOLD:
            self._resize()
        
        index = self._hash(key)
        
        # Check if key already exists
        current = self._buckets[index]
        while current is not None:
            if current.key == key:
                current.value = value  # Update existing
                return
            current = current.next
        
        # Insert new node at head of chain
        new_node = HashNode(key, value)
        new_node.next = self._buckets[index]
        self._buckets[index] = new_node
        self._size += 1
    
    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve a value by key.
        
        Args:
            key: The key to look up
            
        Returns:
            The value, or None if not found
            
        Time Complexity: O(1) average
        """
        index = self._hash(key)
        current = self._buckets[index]
        
        while current is not None:
            if current.key == key:
                return current.value
            current = current.next
        
        return None
    
    def contains(self, key: str) -> bool:
        """
        Check if a key exists.
        
        Args:
            key: The key to check
            
        Returns:
            True if exists, False otherwise
        """
        return self.get(key) is not None
    
    def remove(self, key: str) -> Optional[Any]:
        """
        Remove a key-value pair.
        
        Args:
            key: The key to remove
            
        Returns:
            The removed value, or None if not found
            
        Time Complexity: O(1) average
        """
        index = self._hash(key)
        current = self._buckets[index]
        prev = None
        
        while current is not None:
            if current.key == key:
                if prev is None:
                    self._buckets[index] = current.next
                else:
                    prev.next = current.next
                self._size -= 1
                return current.value
            prev = current
            current = current.next
        
        return None
    
    def keys(self) -> List[str]:
        """
        Get all keys in the table.
        
        Returns:
            List of all keys
        """
        all_keys = []
        for bucket in self._buckets:
            current = bucket
            while current is not None:
                all_keys.append(current.key)
                current = current.next
        return all_keys
    
    def values(self) -> List[Any]:
        """
        Get all values in the table.
        
        Returns:
            List of all values
        """
        all_values = []
        for bucket in self._buckets:
            current = bucket
            while current is not None:
                all_values.append(current.value)
                current = current.next
        return all_values
    
    def items(self) -> List[Tuple[str, Any]]:
        """
        Get all key-value pairs.
        
        Returns:
            List of (key, value) tuples
        """
        all_items = []
        for bucket in self._buckets:
            current = bucket
            while current is not None:
                all_items.append((current.key, current.value))
                current = current.next
        return all_items
    
    def clear(self) -> None:
        """Remove all entries from the table."""
        self._buckets = [None] * self._capacity
        self._size = 0
    
    
    def __len__(self) -> int:
        """Return size of table."""
        return self._size
    
    def __contains__(self, key: str) -> bool:
        """Support 'in' operator."""
        return self.contains(key)
    
    def __getitem__(self, key: str) -> Any:
        """Support bracket notation for get."""
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value
    
    def __setitem__(self, key: str, value: Any) -> None:
        """Support bracket notation for set."""
        self.put(key, value)
    
    def __delitem__(self, key: str) -> None:
        """Support del statement."""
        if self.remove(key) is None:
            raise KeyError(key)
    
    def __iter__(self):
        """Iterate over keys."""
        return iter(self.keys())
    
    def __repr__(self) -> str:
        """String representation."""
        items = self.items()
        return f"HashTable({dict(items)})"


def generate_composite_key(site_name: str, username: str) -> str:
    """
    Generate a composite key for credential lookup.
    
    Args:
        site_name: The website/service name
        username: The username
        
    Returns:
        A unique composite key
    """
    return f"{site_name.lower()}::{username.lower()}"
