"""
Hecate Pyx - Secret Management System
====================================
Enterprise-grade secret management for SecOps/DevOps architectures.

This package provides secure creation, structured organization, and controlled
access to sensitive credentials including API keys, tokens, passwords, and certificates.

Core modules:
- core: Encryption, storage, and configuration
- auth_providers: Multiple authentication mechanisms  
- security: 2FA, API keys, and audit logging
- database: Connection management and fault tolerance
- gui: Graphical user interface
- cli: Command-line interface

Repository: https://github.com/aldomach/hecate-pyx
Website: https://aldo.net.ar/hecate-pyx
"""

__version__ = "3.0.0"
__author__ = "Aldo Machado"
__email__ = "aldo@aldo.net.ar"
__license__ = "MIT"

# Core imports for easy access
try:
    from .core.storage import CredentialsStorage
    from .database.connector import DatabaseConnector
    from .security.totp_manager import TOTPManager
    from .security.api_key_manager import APIKeyManager
    from .core.config import ensure_directories
    
    __all__ = [
        'CredentialsStorage',
        'DatabaseConnector', 
        'TOTPManager',
        'APIKeyManager',
        'ensure_directories'
    ]
except ImportError:
    # Handle missing dependencies gracefully
    __all__ = []
