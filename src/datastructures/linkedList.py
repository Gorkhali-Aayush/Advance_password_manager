"""
Linked List Implementation for Password History
Stores historical passwords for each credential.

Used for:
- Tracking password changes over time
- Preventing password reuse (last N passwords)
- Rollback capability
"""

from typing import Any, Optional, List, Iterator
from datetime import datetime


class LinkedListNode:
    """
    Node for the linked list.
    
    Attributes:
        data: The stored data
        timestamp: When this node was created
        next: Pointer to the next node
    """
    
    def __init__(self, data: Any):
        """
        Initialize a linked list node.
        
        Args:
            data: The data to store
        """
        self._data = data
        self._timestamp = datetime.now()
        self._next: Optional['LinkedListNode'] = None
    
    @property
    def data(self) -> Any:
        return self._data
    
    @property
    def timestamp(self) -> datetime:
        return self._timestamp
    
    @property
    def next(self) -> Optional['LinkedListNode']:
        return self._next
    
    @next.setter
    def next(self, node: Optional['LinkedListNode']) -> None:
        self._next = node


class LinkedList:
    """
    Singly Linked List for sequential data storage.
    
    Used in the password manager for:
    - Password history (last N passwords)
    - Action history / audit log
    - Undo functionality
    """
    
    def __init__(self, max_size: Optional[int] = None):
        """
        Initialize an empty linked list.
        
        Args:
            max_size: Optional maximum size (oldest items removed when exceeded)
        """
        self._head: Optional[LinkedListNode] = None
        self._tail: Optional[LinkedListNode] = None
        self._size = 0
        self._max_size = max_size
    
    @property
    def size(self) -> int:
        """Return the number of nodes."""
        return self._size
    
    @property
    def is_empty(self) -> bool:
        """Check if list is empty."""
        return self._head is None
    
    @property
    def head(self) -> Optional[Any]:
        """Get data from the first node."""
        return self._head.data if self._head else None
    
    @property
    def tail(self) -> Optional[Any]:
        """Get data from the last node."""
        return self._tail.data if self._tail else None
    
    def prepend(self, data: Any) -> None:
        """
        Add data to the front of the list.
        
        Args:
            data: The data to add
            
        Time Complexity: O(1)
        """
        new_node = LinkedListNode(data)
        new_node.next = self._head
        self._head = new_node
        
        if self._tail is None:
            self._tail = new_node
        
        self._size += 1
        self._enforce_max_size()
    
    def append(self, data: Any) -> None:
        """
        Add data to the end of the list.
        
        Args:
            data: The data to add
            
        Time Complexity: O(1) with tail pointer
        """
        new_node = LinkedListNode(data)
        
        if self._tail is None:
            self._head = new_node
            self._tail = new_node
        else:
            self._tail.next = new_node
            self._tail = new_node
        
        self._size += 1
        self._enforce_max_size()
    
    def _enforce_max_size(self) -> None:
        """Remove oldest items if max size exceeded."""
        if self._max_size is not None:
            while self._size > self._max_size:
                self.remove_first()
    
    def remove_first(self) -> Optional[Any]:
        """
        Remove and return the first element.
        
        Returns:
            The removed data, or None if empty
            
        Time Complexity: O(1)
        """
        if self._head is None:
            return None
        
        data = self._head.data
        self._head = self._head.next
        
        if self._head is None:
            self._tail = None
        
        self._size -= 1
        return data
    
    def remove_last(self) -> Optional[Any]:
        """
        Remove and return the last element.
        
        Returns:
            The removed data, or None if empty
            
        Time Complexity: O(n) - must traverse to find second-to-last
        """
        if self._head is None:
            return None
        
        if self._head == self._tail:
            data = self._head.data
            self._head = None
            self._tail = None
            self._size -= 1
            return data
        
        # Find second-to-last node
        current = self._head
        while current.next != self._tail:
            current = current.next
        
        data = self._tail.data
        self._tail = current
        self._tail.next = None
        self._size -= 1
        return data
    
    def get(self, index: int) -> Optional[Any]:
        """
        Get data at a specific index.
        
        Args:
            index: The index to access (0-based)
            
        Returns:
            The data at that index, or None if out of bounds
            
        Time Complexity: O(n)
        """
        if index < 0 or index >= self._size:
            return None
        
        current = self._head
        for _ in range(index):
            current = current.next
        
        return current.data
    
    def contains(self, data: Any) -> bool:
        """
        Check if data exists in the list.
        
        Args:
            data: The data to search for
            
        Returns:
            True if found, False otherwise
            
        Time Complexity: O(n)
        """
        current = self._head
        while current is not None:
            if current.data == data:
                return True
            current = current.next
        return False
    
    def find(self, predicate) -> Optional[Any]:
        """
        Find the first element matching a predicate.
        
        Args:
            predicate: Function that returns True for matching element
            
        Returns:
            The matching element, or None
        """
        current = self._head
        while current is not None:
            if predicate(current.data):
                return current.data
            current = current.next
        return None
    
    def to_list(self) -> List[Any]:
        """
        Convert to a Python list.
        
        Returns:
            List containing all elements
            
        Time Complexity: O(n)
        """
        result = []
        current = self._head
        while current is not None:
            result.append(current.data)
            current = current.next
        return result
    
    def to_list_with_timestamps(self) -> List[tuple]:
        """
        Convert to a list with timestamps.
        
        Returns:
            List of (data, timestamp) tuples
        """
        result = []
        current = self._head
        while current is not None:
            result.append((current.data, current.timestamp))
            current = current.next
        return result
    
    def clear(self) -> None:
        """Remove all elements."""
        self._head = None
        self._tail = None
        self._size = 0
    
    def reverse(self) -> None:
        """
        Reverse the list in-place.
        
        Time Complexity: O(n)
        """
        if self._size <= 1:
            return
        
        prev = None
        current = self._head
        self._tail = self._head
        
        while current is not None:
            next_node = current.next
            current.next = prev
            prev = current
            current = next_node
        
        self._head = prev
    
    
    def __len__(self) -> int:
        return self._size
    
    def __contains__(self, data: Any) -> bool:
        return self.contains(data)
    
    def __iter__(self) -> Iterator[Any]:
        current = self._head
        while current is not None:
            yield current.data
            current = current.next
    
    def __getitem__(self, index: int) -> Any:
        data = self.get(index)
        if data is None:
            raise IndexError("List index out of range")
        return data
    
    def __repr__(self) -> str:
        items = self.to_list()
        return f"LinkedList({items})"


class PasswordHistory:
    """
    Specialized linked list for password history.
    
    Features:
    - Stores encrypted password hashes
    - Limits history to configurable size
    - Checks for password reuse
    """
    
    # Default number of passwords to remember
    DEFAULT_HISTORY_SIZE = 5
    
    def __init__(self, max_history: int = DEFAULT_HISTORY_SIZE):
        """
        Initialize password history.
        
        Args:
            max_history: Maximum number of passwords to remember
        """
        self._history = LinkedList(max_size=max_history)
        self._max_history = max_history
    
    @property
    def size(self) -> int:
        """Number of passwords in history."""
        return self._history.size
    
    def add_password(self, password_hash: str) -> None:
        """
        Add a password to history.
        
        Args:
            password_hash: The hashed password to store
        """
        self._history.prepend(password_hash)
    
    def is_password_used(self, password_hash: str) -> bool:
        """
        Check if a password was used recently.
        
        Args:
            password_hash: The hash to check
            
        Returns:
            True if password is in history
        """
        return password_hash in self._history
    
    def get_history(self) -> List[tuple]:
        """
        Get password history with timestamps.
        
        Returns:
            List of (hash, timestamp) tuples
        """
        return self._history.to_list_with_timestamps()
    
    def get_last_changed(self) -> Optional[datetime]:
        """
        Get timestamp of last password change.
        
        Returns:
            Datetime of last change, or None if no history
        """
        if self._history.is_empty:
            return None
        
        # Head node has the most recent password
        current = self._history._head
        return current.timestamp if current else None
    
    def clear(self) -> None:
        """Clear password history."""
        self._history.clear()
    
    def __len__(self) -> int:
        return self._history.size
    
    def __contains__(self, password_hash: str) -> bool:
        return self.is_password_used(password_hash)
