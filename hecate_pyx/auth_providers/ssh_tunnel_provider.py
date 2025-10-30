"""
SSH Tunnel Authentication Provider.
"""
import pyodbc
from typing import Optional
from .base_provider import AuthProvider, ProviderRegistry

# Importación opcional de sshtunnel
try:
    from sshtunnel import SSHTunnelForwarder
    SSHTUNNEL_AVAILABLE = True
except ImportError:
    SSHTunnelForwarder = None
    SSHTUNNEL_AVAILABLE = False


class SSHTunnelAuthProvider(AuthProvider):
    """Autenticación a través de túnel SSH."""
    
    def __init__(self, config):
        super().__init__(config)
        self.tunnel: Optional[SSHTunnelForwarder] = None
        self.local_port: Optional[int] = None
    
    @property
    def provider_name(self) -> str:
        return "ssh_tunnel"
    
    @property
    def display_name(self) -> str:
        return "SSH Tunnel + SQL Authentication"
    
    def get_connection_string(self, odbc_driver: str) -> str:
        # Usar puerto local del túnel en lugar del puerto remoto
        sql_username = self.config.get('sql_username', '')
        sql_password = self.config.get('sql_password', '')
        
        conn_str = (
            f"DRIVER={{{odbc_driver}}};"
            f"SERVER=localhost,{self.local_port};"  # Conectar al túnel local
            f"DATABASE={self.database};"
            f"UID={sql_username};"
            f"PWD={sql_password};"
            "Encrypt=yes;"
            "TrustServerCertificate=yes;"  # Necesario para túneles locales
        )
        return conn_str
    
    def validate_credentials(self) -> tuple[bool, str]:
        if not SSHTUNNEL_AVAILABLE:
            return False, "SSH Tunnel requires 'sshtunnel' package. Install with: pip install sshtunnel"
        
        required_fields = [
            'ssh_host', 'ssh_username', 'ssh_password',
            'sql_username', 'sql_password'
        ]
        
        for field in required_fields:
            if not self.config.get(field):
                return False, f"{field} is required for SSH tunnel"
        
        ssh_port = self.config.get('ssh_port', 22)
        try:
            ssh_port = int(ssh_port)
        except ValueError:
            return False, "SSH port must be a number"
        
        return True, ""
    
    def prepare_connection(self) -> None:
        """Establecer túnel SSH antes de conectar a SQL Server."""
        if not SSHTUNNEL_AVAILABLE:
            raise Exception("SSH Tunnel requires 'sshtunnel' package. Install with: pip install sshtunnel")
        
        ssh_host = self.config.get('ssh_host')
        ssh_port = int(self.config.get('ssh_port', 22))
        ssh_username = self.config.get('ssh_username')
        ssh_password = self.config.get('ssh_password')
        
        # Crear túnel SSH
        self.tunnel = SSHTunnelForwarder(
            (ssh_host, ssh_port),
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            remote_bind_address=(self.server, self.port),
            local_bind_address=('127.0.0.1', 0),  # Puerto local automático
        )
        
        # Iniciar túnel
        self.tunnel.start()
        self.local_port = self.tunnel.local_bind_port
    
    def cleanup_connection(self) -> None:
        """Cerrar túnel SSH."""
        if self.tunnel:
            self.tunnel.stop()
            self.tunnel = None
            self.local_port = None
    
    def get_connection(self, odbc_driver: str, timeout: int = 30) -> pyodbc.Connection:
        """Conectar a través del túnel SSH."""
        if not self.tunnel or not self.tunnel.is_active:
            raise Exception("SSH tunnel is not active")
        
        conn_str = self.get_connection_string(odbc_driver)
        return pyodbc.connect(conn_str, timeout=timeout)
    
    def requires_password(self) -> bool:
        return True
    
    def supports_2fa(self) -> bool:
        return True
    
    def get_required_fields(self) -> list[str]:
        return [
            'ssh_host', 'ssh_port', 'ssh_username', 'ssh_password',
            'sql_username', 'sql_password'
        ]


# Registrar el provider
ProviderRegistry.register(SSHTunnelAuthProvider)
