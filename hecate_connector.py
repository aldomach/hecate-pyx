#!/usr/bin/env python3
"""
Hecate Connector - Simple API for Secret Management Integration
==============================================================

Simple integration API for connecting to SQL Server using stored credentials
from Hecate Pyx secret management system.

This is the simplest API for script integration. Only requires server name
and optionally the master password.

Usage:
    from hecate_connector import connect_to_sql, load_sql_credentials
    
    # Direct connection
    conn = connect_to_sql('MyServer')
    cursor = conn.cursor()
    cursor.execute("SELECT 1")
    conn.close()
    
    # Load credentials only
    creds = load_sql_credentials('MyServer')
    print(f"Server: {creds['server']}")

Repository: https://github.com/aldomach/hecate-pyx
Website: https://aldo.net.ar/hecate-pyx
"""

import sys
from pathlib import Path
from typing import Optional, Dict, Any
import pyodbc
from getpass import getpass

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from hecate_pyx.core.storage import CredentialsStorage
from hecate_pyx.core.config import CREDENTIALS_FILE
from hecate_pyx.database.connector import DatabaseConnector
from hecate_pyx.security.totp_manager import TOTPManager


def load_sql_credentials(
    server_name: str, 
    master_password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Load credentials for a server from Hecate Pyx vault.
    
    Args:
        server_name: Name of the server (e.g., 'MyServer')
        master_password: Master password (optional, will prompt if not provided)
        
    Returns:
        dict: Server credentials configuration
        
    Raises:
        FileNotFoundError: If no stored credentials found
        ValueError: If master password is incorrect
        KeyError: If server doesn't exist
    """
    storage = CredentialsStorage(CREDENTIALS_FILE)
    
    if not CREDENTIALS_FILE.exists():
        raise FileNotFoundError("No stored credentials found. "
                              "Run 'python hecate_pyx.py' to configure.")
    
    if not master_password:
        master_password = getpass("Master password: ")
    
    try:
        credentials = storage.load_credentials(master_password)
    except Exception as e:
        raise ValueError(f"Incorrect master password or corrupted file: {e}")
    
    if server_name not in credentials:
        available = ', '.join(credentials.keys())
        raise KeyError(f"Server '{server_name}' not found. "
                      f"Available: {available}")
    
    return credentials[server_name]


def connect_to_sql(
    server_name: str,
    master_password: Optional[str] = None,
    totp_code: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: int = 30
) -> pyodbc.Connection:
    """
    Connect to SQL Server using stored credentials from Hecate Pyx.
    
    Args:
        server_name: Name of configured server
        master_password: Master password (optional)
        totp_code: 2FA code if enabled (optional)
        api_key: API key for authentication (optional)
        timeout: Connection timeout in seconds
        
    Returns:
        pyodbc.Connection: Database connection
        
    Raises:
        Exception: If connection fails
        
    Examples:
        # Simple connection
        conn = connect_to_sql('MyServer')
        
        # With master password from environment
        import os
        master_pass = os.getenv('HECATE_MASTER_PASSWORD')
        conn = connect_to_sql('MyServer', master_password=master_pass)
        
        # With 2FA
        conn = connect_to_sql('MyServer', totp_code='123456')
        
        # With API Key
        conn = connect_to_sql('MyServer', api_key='hectepyx_...')
    """
    storage = CredentialsStorage(CREDENTIALS_FILE)
    connector = DatabaseConnector()
    
    if not master_password:
        master_password = getpass("Master password: ")
    
    # Load server configuration
    try:
        credentials = storage.load_credentials(master_password)
    except Exception as e:
        raise ValueError(f"Error loading credentials: {e}")
    
    if server_name not in credentials:
        available = ', '.join(credentials.keys())
        raise KeyError(f"Server '{server_name}' not found. "
                      f"Available: {available}")
    
    server_config = credentials[server_name]
    
    # Check if 2FA is required
    if not totp_code and not api_key:
        totp_manager = TOTPManager()
        if totp_manager.is_enabled(server_name, master_password):
            totp_code = input(f"2FA code for '{server_name}': ").strip()
    
    # Connect
    return connector.connect(
        server_config,
        master_password,
        totp_code=totp_code,
        api_key=api_key,
        timeout=timeout
    )


def execute_query(
    server_name: str,
    query: str,
    master_password: Optional[str] = None,
    **kwargs
) -> list:
    """
    Execute SQL query and return results.
    
    Args:
        server_name: Name of the server
        query: SQL query to execute
        master_password: Master password (optional)
        **kwargs: Additional arguments (totp_code, api_key, etc.)
        
    Returns:
        list: Query results
        
    Examples:
        # Simple query
        results = execute_query('MyServer', 'SELECT TOP 5 * FROM Users')
        for row in results:
            print(row)
        
        # With parameters
        results = execute_query(
            'MyServer', 
            'SELECT * FROM Users WHERE id = ?',
            params=[123]
        )
    """
    storage = CredentialsStorage(CREDENTIALS_FILE)
    connector = DatabaseConnector()
    
    if not master_password:
        master_password = getpass("Master password: ")
    
    credentials = storage.load_credentials(master_password)
    server_config = credentials[server_name]
    
    return connector.execute_query(
        server_config,
        master_password,
        query,
        **kwargs
    )


def list_servers(master_password: Optional[str] = None) -> list:
    """
    List all configured servers.
    
    Args:
        master_password: Master password (optional)
        
    Returns:
        list: List of server names
    """
    storage = CredentialsStorage(CREDENTIALS_FILE)
    
    if not master_password:
        master_password = getpass("Master password: ")
    
    return storage.list_servers(master_password)


def get_server_info(
    server_name: str,
    master_password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get server information (without sensitive credentials).
    
    Args:
        server_name: Name of the server
        master_password: Master password (optional)
        
    Returns:
        dict: Server information
    """
    config = load_sql_credentials(server_name, master_password)
    
    # Filter sensitive information
    safe_info = {
        'server': config.get('server'),
        'database': config.get('database'),
        'port': config.get('port'),
        'auth_type': config.get('auth_type'),
        'username': config.get('username', ''),  # Username only, no password
    }
    
    # For specific auth types, show only non-sensitive info
    if config.get('auth_type') == 'certificate_auth':
        safe_info['certificate_path'] = config.get('certificate_path')
    elif config.get('auth_type') == 'ssh_tunnel':
        safe_info['ssh_host'] = config.get('ssh_host')
        safe_info['ssh_port'] = config.get('ssh_port')
        safe_info['ssh_username'] = config.get('ssh_username')
        safe_info['sql_username'] = config.get('sql_username')
    
    return safe_info


# Example usage if run directly
if __name__ == "__main__":
    import os
    
    print("=" * 60)
    print("🔮 Hecate Connector - Simple API Examples")
    print("=" * 60)
    
    try:
        # List available servers
        print("\n1. Available servers:")
        servers = list_servers()
        for server in servers:
            print(f"  - {server}")
        
        if not servers:
            print("  No servers configured.")
            print("  Run 'python hecate_pyx.py' to add servers.")
            sys.exit(1)
        
        # Show info for first server
        server_name = servers[0]
        print(f"\n2. Information for '{server_name}':")
        info = get_server_info(server_name)
        for key, value in info.items():
            print(f"  {key}: {value}")
        
        # Test connection example
        print(f"\n3. Testing connection to '{server_name}':")
        try:
            conn = connect_to_sql(server_name)
            cursor = conn.cursor()
            cursor.execute("SELECT @@VERSION")
            version = cursor.fetchone()[0]
            print(f"  ✅ Connection successful!")
            print(f"  SQL Server Version: {version[:50]}...")
            conn.close()
        except Exception as e:
            print(f"  ❌ Connection error: {e}")
        
        # Example code for scripts
        print(f"\n4. Example code for your scripts:")
        print(f"# File: my_script.py")
        print(f"from hecate_connector import connect_to_sql")
        print(f"")
        print(f"# Connect and execute query")
        print(f"conn = connect_to_sql('{server_name}')")
        print(f"cursor = conn.cursor()")
        print(f"cursor.execute('SELECT TOP 5 * FROM INFORMATION_SCHEMA.TABLES')")
        print(f"")
        print(f"for row in cursor.fetchall():")
        print(f"    print(row)")
        print(f"")
        print(f"conn.close()")
        
    except Exception as e:
        print(f"❌ Error: {e}")
