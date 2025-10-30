# 🔮 Hecate Pyx - credential Management System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![GitHub release](https://img.shields.io/github/release/aldomach/hecate-pyx.svg)](https://github.com/aldomach/hecate-pyx/releases)
[![Documentation](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://aldo.net.ar/hecate-pyx)

## Overview

**Hecate Pyx** is a credential management system designed for Cybersecurity and Development Operations (SecOps/DevOps) architectures. Its primary function extends beyond passive storage to focus on secure creation, structured organization, and controlled access to sensitive credentials including API keys, tokens, passwords, and certificates.

Unlike systems that generate ephemeral credentials, Hecate Pyx operates as a persistent local vault where connection configurations to servers are defined—currently supporting SQL Server—and credentials are stored using AES-256 encryption. The system supports multiple authentication methods including SQL, Windows, certificates, JWT, SSH tunnels, and TOTP.

Any script or application running in the local environment can integrate with Hecate Pyx through its programmatic interface, accessing authorized credentials via master password, API key, or TOTP token. This enables process automation without exposing secrets directly in code or environment variables.

In critical infrastructure environments, credential management involves more than security: it requires traceability, legal uniqueness, and regulatory compliance. The application of principles such as least privilege and identity-based access control (IAM) is fundamental to ensure that each access is properly authenticated, authorized, and logged.

---

## 📋 Table of Contents

- [🏗️ Architecture](#️-architecture)
- [🔧 Installation](#-installation)
- [🚀 Quick Start](#-quick-start)
- [📡 API Reference](#-api-reference)
- [🔐 Security Features](#-security-features)
- [🛠️ Technical Stack](#️-technical-stack)
- [📁 Project Structure](#-project-structure)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)
- [🔗 Links](#-links)

---

## 🏗️ Architecture

### Core Components

Hecate Pyx implements a modular architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
├─────────────────────┬─────────────────────┬─────────────────┤
│    GUI Interface    │    CLI Interface    │   API Gateway   │
├─────────────────────┼─────────────────────┼─────────────────┤
│                    Security Layer                           │
├─────────────────────────────────────────────────────────────┤
│  TOTP Manager  │  API Key Manager  │  Audit Logger        │
├─────────────────────────────────────────────────────────────┤
│                 Authentication Providers                    │
├─────────────────────────────────────────────────────────────┤
│   SQL Auth   │ Windows Auth │ Certificate │ JWT │ SSH      │
├─────────────────────────────────────────────────────────────┤
│                  Database Connectivity                      │
├─────────────────────────────────────────────────────────────┤
│ Connection Pool │    Retry Handler    │   Circuit Breaker │
├─────────────────────────────────────────────────────────────┤
│                     Storage Layer                           │
├─────────────────────────────────────────────────────────────┤
│      AES-256-CBC Encryption    │      PBKDF2 Key Derivation │
└─────────────────────────────────────────────────────────────┘
```

### Design Patterns

- **Provider Pattern**: Extensible authentication mechanisms
- **Pool Pattern**: Optimized connection management  
- **Circuit Breaker**: Fault tolerance for unreliable services
- **Observer Pattern**: Comprehensive audit logging
- **Factory Pattern**: Dynamic provider instantiation

---

## 🔧 Installation

### Prerequisites

- **Python 3.8+** (3.10+ recommended)
- **SQL Server** access (local or remote)
- **Operating System**: Windows, Linux, or macOS

### Basic Installation

```bash
# Clone repository
git clone https://github.com/aldomach/hecate-pyx.git
cd hecate-pyx

# Install core dependencies
pip install pyodbc cryptography
```

### Full Installation (All Features)

```bash
# Install all dependencies for complete functionality
pip install pyodbc cryptography pyotp qrcode[pil] sshtunnel psutil
```

### Automated Installation

```bash
# Use the intelligent installer
python install_dependencies.py
```

### Migration from Legacy Systems

```bash
# Migrate from previous versions
python migrate_from_old.py
```

---

## 🚀 Quick Start

### 1. Initialize Application

```bash
# Launch GUI
python hecate_pyx.py

# Launch CLI
python hecate_pyx.py --cli
```

### 2. Configure First Server

**Via GUI:**
1. Set master password on first launch
2. Click "➕ New Server" 
3. Configure connection parameters
4. Test connectivity

**Via CLI:**
```bash
python -m hecate_pyx.cli add MyServer
```

### 3. Programmatic Access

```python
from hecate_connector import connect_to_sql

# Simple connection
conn = connect_to_sql('MyServer')
cursor = conn.cursor()
cursor.execute("SELECT @@VERSION")
result = cursor.fetchone()
conn.close()
```

---

## 📡 API Reference

### Core API

```python
# Import core components
from hecate_pyx.core.storage import CredentialsStorage
from hecate_pyx.database.connector import DatabaseConnector
from hecate_pyx.security.totp_manager import TOTPManager

# Initialize storage
storage = CredentialsStorage()
credentials = storage.load_credentials(master_password)

# Establish connection
connector = DatabaseConnector()
conn = connector.connect(server_config, master_password)
```

### Simple API

```python
from hecate_connector import connect_to_sql, execute_query

# Direct connection
conn = connect_to_sql('ServerName')

# Execute query with results
results = execute_query('ServerName', 'SELECT * FROM sys.tables')

# With 2FA
conn = connect_to_sql('ServerName', totp_code='123456')

# With API Key  
conn = connect_to_sql('ServerName', api_key='hectepyx_...')
```

### CLI Operations

```bash
# Server management
hecate-pyx list                              # List servers
hecate-pyx add ServerName                    # Add server
hecate-pyx test ServerName                   # Test connection
hecate-pyx remove ServerName                 # Remove server

# Security operations
hecate-pyx 2fa setup ServerName              # Configure TOTP
hecate-pyx apikeys create KeyName ServerName # Create API key
hecate-pyx apikeys list                      # List API keys

# Query execution
hecate-pyx query ServerName "SELECT @@VERSION"
```

### Authentication Provider Configuration

```python
# SQL Authentication
config = {
    'auth_type': 'sql_auth',
    'server': 'localhost',
    'database': 'mydb',
    'username': 'user',
    'password': 'secure_password',
    'port': 1433
}

# Windows Authentication
config = {
    'auth_type': 'windows_auth',
    'server': 'localhost',
    'database': 'mydb',
    'port': 1433
}

# Certificate Authentication
config = {
    'auth_type': 'certificate_auth',
    'server': 'localhost',
    'database': 'mydb',
    'certificate_path': '/path/to/cert.pfx',
    'certificate_password': 'cert_password',
    'port': 1433
}

# SSH Tunnel Authentication
config = {
    'auth_type': 'ssh_tunnel',
    'server': 'remote-server',
    'database': 'mydb',
    'ssh_host': 'bastion-host',
    'ssh_username': 'ssh_user',
    'ssh_password': 'ssh_password',
    'sql_username': 'db_user',
    'sql_password': 'db_password',
    'port': 1433
}
```

---

## 🔐 Security Features

### Cryptographic Implementation

- **Encryption Algorithm**: AES-256-CBC
- **Key Derivation**: PBKDF2 with SHA-256
- **Iterations**: 100,000 (configurable)
- **Salt Generation**: Cryptographically secure random
- **IV Generation**: Unique per encryption operation

### Multi-Factor Authentication

- **TOTP Implementation**: RFC 6238 compliant
- **Compatible Apps**: Google Authenticator, Authy, Microsoft Authenticator
- **Time Window**: 30-second intervals with ±1 period tolerance
- **QR Code Generation**: Automatic provisioning URI creation

### API Key Management

- **Format**: `hectepyx_` prefix with cryptographically secure random suffix
- **Expiration**: Configurable per key (days, hours, or permanent)
- **Scope**: Server-specific authorization
- **Revocation**: Immediate invalidation capability

### Audit and Compliance

- **Comprehensive Logging**: All authentication attempts and data access
- **Structured Format**: JSON-based log entries with ISO 8601 timestamps
- **Tamper Resistance**: Append-only log files with integrity checks
- **Retention Policies**: Configurable log rotation and archival

### Access Control

- **Principle of Least Privilege**: Granular permission system
- **Role-Based Access**: Server-specific authentication requirements
- **Session Management**: Secure token handling and expiration
- **Failed Attempt Handling**: Configurable lockout policies

---

## 🛠️ Technical Stack

### Core Technologies

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Language** | Python 3.8+ | Primary implementation language |
| **Encryption** | `cryptography` library | AES-256-CBC implementation |
| **Database** | `pyodbc` | SQL Server connectivity |
| **2FA** | `pyotp` | TOTP implementation |
| **SSH** | `sshtunnel` | Secure tunnel connections |
| **GUI** | `tkinter` | Cross-platform interface |
| **QR Codes** | `qrcode` | 2FA setup automation |

### Architecture Patterns

- **Modular Design**: Clear separation of concerns
- **Plugin Architecture**: Extensible authentication providers
- **Event-Driven**: Audit logging through observer pattern
- **Resource Pooling**: Connection optimization
- **Circuit Breaker**: Fault tolerance implementation

### Security Libraries

```python
# Cryptographic operations
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# TOTP implementation
import pyotp

# Secure random generation
import secrets
```

---

## 📁 Project Structure

```
hecate-pyx/
├── 🔮 hecate_pyx.py                    # Main entry point
├── 🔌 hecate_connector.py              # Simple API for scripts
├── 🛠️ install_dependencies.py         # Dependency installer
├── 📦 migrate_from_old.py             # Legacy migration tool
├── 📁 hecate_pyx/                     # Core system modules
│   ├── 📁 core/                       # Fundamental components
│   │   ├── 🔐 crypto.py               # AES-256 encryption engine
│   │   ├── 💾 storage.py              # Secure data persistence
│   │   ├── ⚙️ config.py               # System configuration
│   │   └── ⚠️ exceptions.py           # Custom exception hierarchy
│   ├── 📁 auth_providers/             # Authentication implementations
│   │   ├── 🏗️ base_provider.py        # Abstract provider interface
│   │   ├── 🔑 sql_provider.py         # SQL Server authentication
│   │   ├── 🖥️ windows_provider.py     # Integrated Windows auth
│   │   ├── 📜 certificate_provider.py # X.509 certificate auth
│   │   ├── 🎫 jwt_provider.py         # JWT/OAuth token auth
│   │   └── 🚇 ssh_tunnel_provider.py  # SSH tunnel connectivity
│   ├── 📁 security/                   # Security subsystems
│   │   ├── 🔐 totp_manager.py         # TOTP/2FA implementation
│   │   ├── 🗝️ api_key_manager.py      # API key lifecycle
│   │   └── 📊 audit_logger.py         # Security event logging
│   ├── 📁 database/                   # Database connectivity
│   │   ├── 🔌 connector.py            # Main database interface
│   │   ├── 🏊 connection_pool.py      # Connection pooling
│   │   └── 🔄 retry_handler.py        # Fault tolerance
│   ├── 📁 gui/                        # Graphical interface
│   │   ├── 🖼️ main_window.py          # Primary UI components
│   │   └── 📁 dialogs/                # Modal dialog components
│   ├── 📁 backup/                     # Data backup systems
│   ├── 📁 utils/                      # Utility functions
│   └── 📄 requirements.txt            # Python dependencies
├── 📋 README.md                       # Project documentation
├── ⚖️ LICENSE                         # MIT license
└── 📚 docs/                          # Additional documentation
```

### Module Descriptions

#### Core Modules (`hecate_pyx/core/`)

- **`crypto.py`**: Implements AES-256-CBC encryption with PBKDF2 key derivation, secure random salt generation, and PKCS7 padding
- **`storage.py`**: Manages encrypted persistence of credentials with atomic operations and corruption detection
- **`config.py`**: Centralizes system configuration including paths, encryption parameters, and default values
- **`exceptions.py`**: Defines custom exception hierarchy for precise error handling and debugging

#### Authentication Providers (`hecate_pyx/auth_providers/`)

- **`base_provider.py`**: Abstract base class defining the authentication provider interface and registry pattern
- **`sql_provider.py`**: Standard SQL Server username/password authentication
- **`windows_provider.py`**: Windows Integrated Security using current user context
- **`certificate_provider.py`**: X.509 certificate-based authentication for enhanced security
- **`jwt_provider.py`**: JSON Web Token authentication for modern cloud environments
- **`ssh_tunnel_provider.py`**: Secure Shell tunnel for accessing databases through bastion hosts

#### Security Components (`hecate_pyx/security/`)

- **`totp_manager.py`**: Time-based One-Time Password implementation following RFC 6238
- **`api_key_manager.py`**: Manages API key generation, validation, expiration, and revocation
- **`audit_logger.py`**: Comprehensive security event logging with structured JSON format

---

## 🔬 Advanced Features

### Connection Pool Management

```python
from hecate_pyx.database.connection_pool import pool_manager

# Get optimized connection pool
pool = pool_manager.get_pool('ServerName', config, connector, master_password)

# Use with context manager for automatic cleanup
with pool.connection() as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sensitive_table")
    results = cursor.fetchall()
# Connection automatically returned to pool
```

### Fault Tolerance

```python
from hecate_pyx.database.retry_handler import retry_on_failure

@retry_on_failure(max_attempts=3, base_delay=1.0)
def robust_database_operation():
    conn = connect_to_sql('ServerName')
    # Database operations with automatic retry on failure
    return conn.execute("SELECT critical_data FROM important_table")
```

### Security Event Monitoring

```python
from hecate_pyx.security.audit_logger import AuditLogger

logger = AuditLogger()

# Log security events
logger.log_access('ServerName', 'username', 'SUCCESS', 'Query execution')
logger.log_access('ServerName', 'username', 'FAILED', 'Invalid credentials')

# Retrieve audit trail
recent_events = logger.get_recent_logs(limit=100)
security_failures = logger.get_failed_attempts(hours=24)
```

---

## 🤝 Contributing

### Development Environment Setup

```bash
# Clone repository
git clone https://github.com/aldomach/hecate-pyx.git
cd hecate-pyx

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements-dev.txt
```

### Code Standards

- **PEP 8**: Python style guide compliance
- **Type Hints**: Required for all public functions
- **Docstrings**: Google-style documentation format
- **Security**: OWASP secure coding practices
- **Testing**: Minimum 80% code coverage

### Pull Request Process

1. Fork the repository
2. Create feature branch: `git checkout -b feature/enhancement-name`
3. Implement changes with tests
4. Ensure all tests pass: `python -m pytest`
5. Update documentation if needed
6. Submit pull request with detailed description

### Security Vulnerability Reporting

For security issues, please email directly to: **security@aldo.net.ar**

Do not create public issues for security vulnerabilities.

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### Commercial Use

Hecate Pyx is free for commercial use. The MIT license permits:

- ✅ Commercial use
- ✅ Modification and distribution
- ✅ Private use
- ✅ Patent use (where applicable)

**Requirements:**
- Include original license in distributions
- Include copyright notice

**Limitations:**
- No warranty provided
- No liability accepted

---

## 🔗 Links

- **🏠 Project Homepage**: [aldo.net.ar/hecate-pyx](https://aldo.net.ar/hecate-pyx)
- **📊 GitHub Repository**: [github.com/aldomach/hecate-pyx](https://github.com/aldomach/hecate-pyx)
- **📚 Documentation**: [aldo.net.ar/hecate-pyx/docs](https://aldo.net.ar/hecate-pyx/docs)
- **🐛 Issue Tracker**: [GitHub Issues](https://github.com/aldomach/hecate-pyx/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/aldomach/hecate-pyx/discussions)
- **📧 Contact**: security@aldo.net.ar

---

## 🏆 Acknowledgments

This project was developed with assistance from advanced AI systems:

- **Claude (Anthropic)**: Architecture design and security best practices
- **GitHub Copilot**: Development acceleration and code completion
- **Gemini (Google)**: Optimization strategies and code review

Special thanks to the cybersecurity and DevOps communities for their valuable feedback and contributions to secure software development practices.

---

**Hecate Pyx** - Secure Credential Management for the Modern Enterprise

*Version 3.0 | Last Updated: October 2024*
