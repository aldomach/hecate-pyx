"""
SQL Server Authentication Provider.
"""
from .base_provider import AuthProvider, ProviderRegistry


class SQLAuthProvider(AuthProvider):
    """Autenticación SQL Server estándar (usuario/contraseña)."""
    
    @property
    def provider_name(self) -> str:
        return "sql_auth"
    
    @property
    def display_name(self) -> str:
        return "SQL Server Authentication"
    
    def get_connection_string(self, odbc_driver: str) -> str:
        username = self.config.get('username', '')
        password = self.config.get('password', '')
        
        conn_str = (
            f"DRIVER={{{odbc_driver}}};"
            f"SERVER={self.server},{self.port};"
            f"DATABASE={self.database};"
            f"UID={username};"
            f"PWD={password};"
            "Encrypt=yes;"
            "TrustServerCertificate=no;"
        )
        return conn_str
    
    def validate_credentials(self) -> tuple[bool, str]:
        if not self.config.get('username'):
            return False, "Username is required"
        if not self.config.get('password'):
            return False, "Password is required"
        return True, ""
    
    def requires_password(self) -> bool:
        return True
    
    def supports_2fa(self) -> bool:
        return True
    
    def get_required_fields(self) -> list[str]:
        return ['username', 'password']


# Registrar el provider
ProviderRegistry.register(SQLAuthProvider)