# Advanced Password Manager

A secure, modular password manager application built with Python, demonstrating advanced programming concepts including custom data structures, cryptography, multi-threading, and OOP principles.

## 🏗️ Architecture Overview

### System Architecture Diagram
```
UI Layer (Tkinter) → Core Layer → Crypto Layer → Storage Layer
                          ↓
                   Data Structures
                          ↓
                      OS Layer
```

### Workflow Overview

The Advanced Password Manager follows a **layered architecture** with clear separation of concerns:

1. **User Interface Layer (UI)**: Tkinter-based graphical interface that handles user interactions including login, credential management, and security analysis visualization.

2. **Core Logic Layer**: Business logic controllers that orchestrate operations between the UI and lower layers, managing authentication, session management, credential operations, and security policies.

3. **Cryptography Layer**: Handles all encryption/decryption operations using AES-256 (Fernet) with PBKDF2-derived keys. Ensures all passwords are encrypted before storage.

4. **Data Structures Layer**: Implements custom structures (BST, HashTable, Graph, LinkedList) for efficient searching, duplicate detection, and security risk visualization.

5. **Storage Layer**: Manages persistent data through MySQL database and file backup systems, with support for password history and audit trails.

6. **OS Layer**: Provides system-level utilities for multi-threading (session monitoring, auto-lock), clipboard management (secure copy/paste with auto-clear), and file locking (single instance enforcement).

### Key Workflow Examples

- **Login Workflow**: User credentials → PBKDF2 validation → Session creation → Background auto-lock thread started
- **Credential Management**: User adds password → Encryption via Fernet → Storage in MySQL → BST indexing for search
- **Security Analysis**: Password lookup → Graph construction → Reuse detection → Visual risk report
- **Clipboard Operations**: Copy password → System clipboard → Auto-clear thread → Clipboard wiped after timeout

## 📁 Project Structure

- **src/** - Main application source code
  - **ui/** - Tkinter-based user interface
  - **core/** - Business logic and controllers
  - **crypto/** - Encryption and security
  - **datastructures/** - Custom BST, HashTable, Graph, LinkedList
  - **storage/** - MySQL database and file backup
  - **os_layer/** - Thread management, clipboard, file locking

- **tests/** - Unit and integration tests
- **docs/** - Documentation and diagrams

## 🔑 Key Features

- **Secure Authentication**: PBKDF2-based master password verification
- **AES-256 Encryption**: Fernet (AES-CBC) for credential encryption
- **Custom Data Structures**: BST for search, HashTable for lookup, Graph for security analysis
- **Auto-Lock**: Background thread monitors inactivity
- **Clipboard Security**: Auto-clear after timeout
- **Password Reuse Detection**: Graph visualization of security risks

## 🚀 Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up MySQL database:
```sql
CREATE DATABASE password_manager;
USE password_manager;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    master_password_hash VARCHAR(512) NOT NULL,
    salt VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    site_name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    encrypted_password TEXT NOT NULL,
    url VARCHAR(512),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE password_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    credential_id INT NOT NULL,
    encrypted_password TEXT NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
);
```

3. Configure database connection in `src/storage/mysql_engine.py`

4. Run the application:
```bash
python src/main.py
```

## 🧪 Testing

```bash
pytest tests/ --cov=src -v
```

## 🔐 Security Features

- Master password never stored in plain text
- Encryption keys derived using PBKDF2 (100,000 iterations)
- In-memory decryption only
- Auto-lock on inactivity
- Clipboard auto-clear
- Single instance enforcement

## 📚 OOP Concepts Demonstrated

- **Abstraction**: Abstract base classes for encryption and database
- **Encapsulation**: Private attributes for sensitive data
- **Inheritance**: Window hierarchy, engine implementations
- **Polymorphism**: Swappable encryption/storage backends

## 📊 Data Structures Used

| Structure | Purpose | Time Complexity |
|-----------|---------|-----------------|
| BST | Sorted credential search | O(log n) |
| HashTable | Fast duplicate detection | O(1) average |
| Graph | Password reuse analysis | O(V + E) |
| LinkedList | Password history | O(1) insert |

## 👤 Author

Programming and Algorithms 2 - Coursework Project
