# Advanced Password Manager - Architecture Documentation

## Overview

This document describes the architecture of the Advanced Password Manager application,
demonstrating key Object-Oriented Programming (OOP) concepts and design patterns.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PRESENTATION LAYER                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │  LoginWindow    │  │  VaultWindow    │  │  SecurityGraphWindow        │  │
│  │  (Tkinter)      │  │  (Tkinter)      │  │  (Matplotlib + NetworkX)    │  │
│  └────────┬────────┘  └────────┬────────┘  └──────────────┬──────────────┘  │
│           │                    │                          │                  │
│           └────────────────────┴──────────────────────────┘                  │
│                                │                                             │
└────────────────────────────────┼─────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                               CORE LAYER                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │  Vault          │  │  SessionManager │  │  PasswordPolicy             │  │
│  │  (Controller)   │  │  (Auth State)   │  │  (Validation)               │  │
│  └────────┬────────┘  └────────┬────────┘  └──────────────┬──────────────┘  │
│           │                    │                          │                  │
│  ┌────────┴────────────────────┴──────────────────────────┴──────────────┐  │
│  │                          Credential                                    │  │
│  │                     (Data Transfer Object)                             │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
         │                          │                         │
         ▼                          ▼                         ▼
┌─────────────────┐    ┌─────────────────────┐    ┌─────────────────────────┐
│  CRYPTO LAYER   │    │   STORAGE LAYER     │    │      OS LAYER           │
│ ┌─────────────┐ │    │ ┌─────────────────┐ │    │ ┌─────────────────────┐ │
│ │ FernetEngine│ │    │ │ MySQLEngine     │ │    │ │ ThreadManager       │ │
│ │ (Fernet/AES)│ │    │ │ (Connection     │ │    │ │ (Background Tasks)  │ │
│ │ (PBKDF2)    │ │    │ │  Pooling)       │ │    │ └─────────────────────┘ │
│ └─────────────┘ │    │ └─────────────────┘ │    │ ┌─────────────────────┐ │
│                 │    │ ┌─────────────────┐ │    │ │ ClipboardManager    │ │
│                 │    │ │ BackupManager   │ │    │ │ (Auto-Clear)        │ │
│                 │    │ │ (Encrypted File)│ │    │ └─────────────────────┘ │
│                 │    │ └─────────────────┘ │    │ ┌─────────────────────┐ │
│                 │    │                     │    │ │ FileLock            │ │
│                 │    │                     │    │ │ (Single Instance)   │ │
│                 │    │                     │    │ └─────────────────────┘ │
└─────────────────┘    └─────────────────────┘    └─────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DATA STRUCTURES LAYER                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │  BST            │  │  HashTable      │  │  Graph + PasswordReuse     │  │
│  │  (O(log n)      │  │  (O(1) lookup)  │  │  Analyzer (BFS/DFS)         │  │
│  │  search)        │  │                 │  │                             │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                      LinkedList (Password History)                      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

## OOP Concepts Demonstrated

### 1. Abstraction

Abstraction hides complex implementation details and exposes only necessary functionality.

**Examples in the codebase:**

- **`EncryptionEngine` (Abstract Base Class)**: Defines the interface for encryption operations
  without specifying how encryption is implemented.
  
  ```python
  class EncryptionEngine(ABC):
      @abstractmethod
      def encrypt(self, plaintext: str, key: bytes) -> bytes: ...
      
      @abstractmethod
      def decrypt(self, ciphertext: bytes, key: bytes) -> str: ...
  ```

- **`DatabaseEngine` (Abstract Base Class)**: Abstracts database operations so different
  databases (MySQL, SQLite, PostgreSQL) can be swapped without changing core logic.

- **`BaseWindow` (Abstract Base Class)**: Defines common window behavior without specifying
  the actual UI layout.

### 2. Encapsulation

Encapsulation bundles data with methods that operate on that data, restricting direct access.

**Examples in the codebase:**

- **`Credential` class**: Uses private attributes with properties for controlled access.
  
  ```python
  class Credential:
      def __init__(self):
          self._website = None      # Private
          self._username = None     # Private
          self._encrypted_password = None  # Private
      
      @property
      def website(self) -> str:
          return self._website
      
      @website.setter
      def website(self, value: str):
          self._validate_website(value)  # Validation before setting
          self._website = value
  ```

- **`FernetEngine`**: Encapsulates encryption key and operations, preventing direct
  manipulation of cryptographic primitives.

- **`SessionManager`**: Encapsulates session state, providing controlled access through
  methods like `create_session()` and `destroy_session()`.

### 3. Inheritance

Inheritance allows a class to inherit attributes and methods from a parent class.

**Examples in the codebase:**

- **`FernetEngine extends EncryptionEngine`**: Inherits the abstract interface and provides
  concrete implementation.
  
  ```python
  class FernetEngine(EncryptionEngine):
      def encrypt(self, plaintext: str, key: bytes) -> bytes:
          # Concrete implementation using Fernet
          f = Fernet(key)
          return f.encrypt(plaintext.encode())
  ```

- **`MySQLEngine extends DatabaseEngine`**: Inherits database interface, implements MySQL-specific logic.

- **`LoginWindow extends BaseWindow`**: Inherits common window functionality, adds login-specific UI.

- **`SecurityGraph extends Graph`**: Extends basic graph with password-reuse-specific operations.

### 4. Polymorphism

Polymorphism allows objects of different types to be treated as objects of a common parent type.

**Examples in the codebase:**

- **Encryption Engine Polymorphism**: The `Vault` class works with any `EncryptionEngine`,
  allowing easy substitution:
  
  ```python
  class Vault:
      def __init__(self, crypto_engine: EncryptionEngine):
          self._crypto = crypto_engine  # Could be FernetEngine, AESEngine, etc.
      
      def save_credential(self, credential: Credential):
          # Works regardless of which encryption engine is used
          encrypted = self._crypto.encrypt(credential.password, self._master_key)
  ```

- **Database Engine Polymorphism**: `Vault` works with any `DatabaseEngine`, enabling
  different database backends:
  
  ```python
  # Can use MySQL
  vault = Vault(db_engine=MySQLEngine(...))
  
  # Or SQLite (if implemented)
  vault = Vault(db_engine=SQLiteEngine(...))
  ```

- **Window Polymorphism**: Different windows can be managed uniformly through `BaseWindow` interface.

## Design Patterns Used

### 1. Singleton Pattern
- `ThreadManager`: Only one instance manages all threads
- `SessionManager`: Single session manager for the application

### 2. Factory Pattern
- Window creation based on application state (login → vault)

### 3. Observer Pattern
- Session lock callbacks notify UI when session times out
- Auto-clear callbacks for clipboard

### 4. Strategy Pattern
- Different encryption strategies can be swapped
- Different database backends can be swapped

### 5. Template Method Pattern
- `BaseWindow.setup()` defines the skeleton, subclasses fill in details

### 6. Composition over Inheritance
- `Vault` composes multiple engines rather than inheriting from them
- `PasswordManagerApp` composes all components

## Data Structures

### Binary Search Tree (BST)
- **Purpose**: Fast credential lookup by website name
- **Time Complexity**: O(log n) average for search, insert, delete
- **Key Features**: Prefix search for autocomplete, in-order traversal for sorted listing

### Hash Table
- **Purpose**: O(1) lookup for duplicate password detection
- **Implementation**: Separate chaining for collision resolution
- **Key Features**: Password hash comparison, quick existence check

### Graph
- **Purpose**: Visualize password reuse relationships
- **Algorithms**: BFS/DFS for traversal, connected components for reuse groups
- **Key Features**: Risk scoring, security recommendations

### Linked List
- **Purpose**: Track password history for each credential
- **Key Features**: Ordered history, limit enforcement, change tracking

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY MEASURES                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Key Derivation: PBKDF2 with SHA-256, 100,000 iterations  │   │
│  │ Random Salt: 16 bytes per user                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Encryption: Fernet (AES-128-CBC + HMAC-SHA256)           │   │
│  │ Each credential encrypted with derived master key        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Auto-Lock: Session locks after 5 minutes of inactivity  │   │
│  │ Clipboard Clear: Passwords auto-clear after 30 seconds  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Single Instance: File lock prevents multiple instances   │   │
│  │ Parameterized Queries: SQL injection prevention          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Module Dependencies

```
main.py
├── ui/
│   ├── login_window.py      → crypto/, storage/
│   ├── vault_window.py      → core/, os_layer/
│   └── graph_view.py        → datastructures/
├── core/
│   ├── vault.py             → crypto/, storage/, datastructures/
│   ├── session_manager.py   → os_layer/
│   ├── credential.py        → (standalone)
│   └── password_policy.py   → (standalone)
├── crypto/
│   ├── fernet_engine.py     → cryptography library
│   └── encryption_base.py   → (abstract)
├── storage/
│   ├── mysql_engine.py      → mysql-connector
│   ├── backup_file.py       → crypto/
│   └── db_base.py           → (abstract)
├── os_layer/
│   ├── thread_manager.py    → threading
│   ├── clipboard_manager.py → pyperclip, pywin32
│   └── file_lock.py         → os, msvcrt
└── datastructures/
    ├── bst.py               → (standalone)
    ├── hashtable.py         → (standalone)
    ├── graph.py             → (standalone)
    └── linked_list.py       → (standalone)
```

## Testing Strategy

1. **Unit Tests**: Each module tested in isolation with mocks
2. **Integration Tests**: Database and encryption integration
3. **UI Tests**: Manual testing of Tkinter windows (optional: pytest-tk)
4. **Security Tests**: Verify encryption/decryption, tamper detection

## Future Enhancements

1. **Browser Extension**: Auto-fill credentials in browsers
2. **Mobile App**: Companion mobile application
3. **Two-Factor Authentication**: TOTP support
4. **Password Sharing**: Secure credential sharing between users
5. **Cloud Sync**: Optional encrypted cloud backup
