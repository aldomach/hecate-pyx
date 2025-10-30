#!/usr/bin/env python3
"""
Hecate Pyx - Interfaz de Línea de Comandos
==========================================
CLI completa para el guardián de credenciales SQL Server.

🏛️ Hecate Pyx - Tu guardián de credenciales SQL Server
Sitio web: aldo.net.ar/hecate-pyx
GitHub: github.com/aldomach/hecate-pyx
"""
import argparse
import sys
import getpass
from pathlib import Path

# Agregar el directorio padre al path
sys.path.insert(0, str(Path(__file__).parent))

from hecate_pyx.core.storage import CredentialsStorage
from hecate_pyx.core.config import CREDENTIALS_FILE, ensure_directories
from hecate_pyx.database.connector import DatabaseConnector
from hecate_pyx.security.totp_manager import TOTPManager
from hecate_pyx.security.api_key_manager import APIKeyManager
from hecate_pyx.auth_providers.base_provider import ProviderRegistry


class CLI:
    """Interfaz de línea de comandos para Hecate Pyx."""
    
    def __init__(self):
        self.storage = CredentialsStorage(CREDENTIALS_FILE)
        self.connector = DatabaseConnector()
        self.totp_manager = TOTPManager()
        self.api_key_manager = APIKeyManager()
        self.master_password = None
    
    def authenticate(self) -> bool:
        """Authenticate with master password."""
        try:
            self.master_password = getpass.getpass("Master password: ")
            # Test by trying to load credentials
            self.storage.load_credentials(self.master_password)
            return True
        except Exception as e:
            print(f"❌ Authentication failed: {e}")
            return False
    
    def list_servers(self):
        """List all configured servers."""
        try:
            credentials = self.storage.load_credentials(self.master_password)
            
            if not credentials:
                print("📝 No servers configured")
                return
            
            print("\n🖥️  Configured Servers:")
            print("-" * 80)
            print(f"{'Name':<20} {'Server':<25} {'Database':<20} {'Auth Type':<15}")
            print("-" * 80)
            
            for name, config in credentials.items():
                auth_type = config.get('auth_type', 'sql_auth')
                display_name = ProviderRegistry.get_provider_display_name(auth_type)
                
                print(f"{name:<20} {config.get('server', ''):<25} "
                      f"{config.get('database', ''):<20} {display_name:<15}")
            
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def add_server(self, name: str):
        """Add new server configuration."""
        print(f"\n➕ Adding server: {name}")
        
        # Basic info
        server = input("Server address: ").strip()
        database = input("Database name: ").strip()
        port = input("Port [1433]: ").strip() or "1433"
        
        try:
            port = int(port)
        except ValueError:
            print("❌ Invalid port number")
            return
        
        # Auth type
        providers = ProviderRegistry.list_providers()
        print("\nAvailable authentication types:")
        for i, (_, display) in enumerate(providers, 1):
            print(f"{i}. {display}")
        
        try:
            choice = int(input("Select auth type [1]: ") or "1")
            auth_type = providers[choice - 1][0]
        except (ValueError, IndexError):
            auth_type = "sql_auth"
        
        # Build config
        config = {
            'server': server,
            'database': database,
            'port': port,
            'auth_type': auth_type
        }
        
        # Auth-specific fields
        if auth_type == 'sql_auth':
            config['username'] = input("Username: ").strip()
            config['password'] = getpass.getpass("Password: ")
        elif auth_type == 'certificate_auth':
            config['certificate_path'] = input("Certificate path (.pfx): ").strip()
            config['certificate_password'] = getpass.getpass("Certificate password: ")
        elif auth_type == 'jwt_auth':
            config['access_token'] = getpass.getpass("Access token: ")
        elif auth_type == 'ssh_tunnel':
            print("\nSSH Configuration:")
            config['ssh_host'] = input("SSH host: ").strip()
            config['ssh_port'] = int(input("SSH port [22]: ") or "22")
            config['ssh_username'] = input("SSH username: ").strip()
            config['ssh_password'] = getpass.getpass("SSH password: ")
            print("\nSQL Configuration (through tunnel):")
            config['sql_username'] = input("SQL username: ").strip()
            config['sql_password'] = getpass.getpass("SQL password: ")
        
        try:
            self.storage.add_server(name, config, self.master_password)
            print(f"✅ Server '{name}' added successfully")
        except Exception as e:
            print(f"❌ Error adding server: {e}")
    
    def test_connection(self, server_name: str):
        """Test connection to a server."""
        try:
            credentials = self.storage.load_credentials(self.master_password)
            
            if server_name not in credentials:
                print(f"❌ Server '{server_name}' not found")
                return
            
            server_config = credentials[server_name]
            
            # Check if 2FA is enabled
            totp_code = None
            if self.totp_manager.is_enabled(server_name, self.master_password):
                totp_code = input("Enter 2FA code: ").strip()
            
            print(f"🔌 Testing connection to '{server_name}'...")
            
            success, message = self.connector.test_connection(
                server_config,
                self.master_password,
                totp_code=totp_code
            )
            
            if success:
                print(f"✅ Connection successful!")
            else:
                print(f"❌ Connection failed: {message}")
                
        except Exception as e:
            print(f"❌ Error testing connection: {e}")
    
    def remove_server(self, server_name: str):
        """Remove a server configuration."""
        try:
            credentials = self.storage.load_credentials(self.master_password)
            
            if server_name not in credentials:
                print(f"❌ Server '{server_name}' not found")
                return
            
            confirm = input(f"⚠️  Remove '{server_name}'? (y/N): ").strip().lower()
            if confirm == 'y':
                self.storage.remove_server(server_name, self.master_password)
                print(f"✅ Server '{server_name}' removed")
            else:
                print("Cancelled")
                
        except Exception as e:
            print(f"❌ Error removing server: {e}")
    
    def list_api_keys(self, server_name: str = None):
        """List API keys."""
        try:
            keys = self.api_key_manager.list_keys(self.master_password, server_name)
            
            if not keys:
                print("📝 No API keys found")
                return
            
            print("\n🔑 API Keys:")
            print("-" * 80)
            print(f"{'Name':<20} {'Server':<20} {'Created':<20} {'Status':<10}")
            print("-" * 80)
            
            for key in keys:
                status = "Active" if key['active'] else "Revoked"
                created = key['created_at'][:10] if key['created_at'] else "Unknown"
                
                print(f"{key['name']:<20} {key['server_name']:<20} "
                      f"{created:<20} {status:<10}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def create_api_key(self, name: str, server_name: str):
        """Create new API key."""
        try:
            # Check if server exists
            credentials = self.storage.load_credentials(self.master_password)
            if server_name not in credentials:
                print(f"❌ Server '{server_name}' not found")
                return
            
            expires_days = input("Expiration days (empty for no expiration): ").strip()
            expires_days = int(expires_days) if expires_days else None
            
            key_info = self.api_key_manager.create_key(
                name,
                server_name,
                self.master_password,
                expires_days=expires_days
            )
            
            print(f"\n✅ API Key created:")
            print(f"Name: {key_info['name']}")
            print(f"Server: {key_info['server_name']}")
            print(f"🔑 Key: {key_info['api_key']}")
            print("\n⚠️  Save this key securely - it won't be shown again!")
            
        except Exception as e:
            print(f"❌ Error creating API key: {e}")
    
    def setup_2fa(self, server_name: str):
        """Setup 2FA for a server."""
        try:
            credentials = self.storage.load_credentials(self.master_password)
            if server_name not in credentials:
                print(f"❌ Server '{server_name}' not found")
                return
            
            if self.totp_manager.is_enabled(server_name, self.master_password):
                print(f"⚠️  2FA already enabled for '{server_name}'")
                return
            
            # Generate secret
            secret = self.totp_manager.generate_secret(server_name)
            server_config = credentials[server_name]
            username = server_config.get('username', '')
            
            # Show provisioning URI for manual entry
            provisioning_uri = self.totp_manager.get_provisioning_uri(
                server_name, secret, username
            )
            
            print(f"\n🔐 Setting up 2FA for '{server_name}':")
            print("1. Open Google Authenticator (or similar TOTP app)")
            print("2. Add account manually with this secret:")
            print(f"   Secret: {secret}")
            print("3. Or scan QR code (if GUI available)")
            print(f"4. Provisioning URI: {provisioning_uri}")
            
            # Verify setup
            code = input("\nEnter 6-digit code from your app: ").strip()
            
            if self.totp_manager.verify_code(secret, code):
                self.totp_manager.save_secret(server_name, secret, self.master_password)
                print(f"✅ 2FA enabled for '{server_name}'")
            else:
                print("❌ Invalid code. 2FA setup cancelled.")
                
        except Exception as e:
            print(f"❌ Error setting up 2FA: {e}")
    
    def run_query(self, server_name: str, query: str):
        """Execute SQL query."""
        try:
            credentials = self.storage.load_credentials(self.master_password)
            
            if server_name not in credentials:
                print(f"❌ Server '{server_name}' not found")
                return
            
            server_config = credentials[server_name]
            
            # Check if 2FA is enabled
            totp_code = None
            if self.totp_manager.is_enabled(server_name, self.master_password):
                totp_code = input("Enter 2FA code: ").strip()
            
            print(f"🔍 Executing query on '{server_name}'...")
            
            results = self.connector.execute_query(
                server_config,
                self.master_password,
                query,
                totp_code=totp_code
            )
            
            if results:
                print(f"\n📊 Results ({len(results)} rows):")
                for i, row in enumerate(results[:10], 1):  # Limit to 10 rows
                    print(f"{i:3d}: {row}")
                
                if len(results) > 10:
                    print(f"... and {len(results) - 10} more rows")
            else:
                print("✅ Query executed successfully (no results)")
                
        except Exception as e:
            print(f"❌ Error executing query: {e}")


def main():
    """Punto de entrada principal del CLI."""
    parser = argparse.ArgumentParser(
        description="Hecate Pyx - CLI del Guardián de Credenciales SQL Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🏛️ Hecate Pyx - CLI Examples:
  hectepyx list                           # Listar servidores
  hectepyx add MyServer                   # Agregar servidor  
  hectepyx test MyServer                  # Probar conexión
  hectepyx remove MyServer                # Eliminar servidor
  hectepyx apikeys list                   # Listar API keys
  hectepyx apikeys create MyKey MyServer  # Crear API key
  hectepyx 2fa setup MyServer             # Configurar 2FA
  hectepyx query MyServer "SELECT 1"      # Ejecutar query

🌐 Sitio: aldo.net.ar/hecate-pyx
📂 GitHub: github.com/aldomach/hecate-pyx
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List servers
    subparsers.add_parser('list', help='List all configured servers')
    
    # Add server
    add_parser = subparsers.add_parser('add', help='Add new server')
    add_parser.add_argument('name', help='Server name')
    
    # Test connection
    test_parser = subparsers.add_parser('test', help='Test server connection')
    test_parser.add_argument('server', help='Server name')
    
    # Remove server
    remove_parser = subparsers.add_parser('remove', help='Remove server')
    remove_parser.add_argument('server', help='Server name')
    
    # API Keys
    apikeys_parser = subparsers.add_parser('apikeys', help='Manage API keys')
    apikeys_subparsers = apikeys_parser.add_subparsers(dest='apikeys_command')
    
    apikeys_list = apikeys_subparsers.add_parser('list', help='List API keys')
    apikeys_list.add_argument('--server', help='Filter by server')
    
    apikeys_create = apikeys_subparsers.add_parser('create', help='Create API key')
    apikeys_create.add_argument('name', help='Key name')
    apikeys_create.add_argument('server', help='Server name')
    
    # 2FA
    twofa_parser = subparsers.add_parser('2fa', help='Manage 2FA')
    twofa_subparsers = twofa_parser.add_subparsers(dest='twofa_command')
    
    twofa_setup = twofa_subparsers.add_parser('setup', help='Setup 2FA')
    twofa_setup.add_argument('server', help='Server name')
    
    # Query
    query_parser = subparsers.add_parser('query', help='Execute SQL query')
    query_parser.add_argument('server', help='Server name')
    query_parser.add_argument('sql', help='SQL query')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Ensure directories exist
    ensure_directories()
    
    # Initialize CLI
    cli = CLI()
    
    # Authenticate
    if not cli.authenticate():
        sys.exit(1)
    
    # Execute command
    try:
        if args.command == 'list':
            cli.list_servers()
            
        elif args.command == 'add':
            cli.add_server(args.name)
            
        elif args.command == 'test':
            cli.test_connection(args.server)
            
        elif args.command == 'remove':
            cli.remove_server(args.server)
            
        elif args.command == 'apikeys':
            if args.apikeys_command == 'list':
                cli.list_api_keys(getattr(args, 'server', None))
            elif args.apikeys_command == 'create':
                cli.create_api_key(args.name, args.server)
            else:
                apikeys_parser.print_help()
                
        elif args.command == '2fa':
            if args.twofa_command == 'setup':
                cli.setup_2fa(args.server)
            else:
                twofa_parser.print_help()
                
        elif args.command == 'query':
            cli.run_query(args.server, args.sql)
            
    except KeyboardInterrupt:
        print("\n\n👋 Cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
