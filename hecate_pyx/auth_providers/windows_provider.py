"""
Windows Authentication Provider (Trusted Connection).
"""
from .base_provider import AuthProvider, ProviderRegistry


class WindowsAuthProvider(AuthProvider):
    """Autenticación Windows (Trusted Connection)."""
    
    @property
    def provider_name(self) -> str:
        return "windows_auth"
    
    @property
    def display_name(self) -> str:
        return "Windows Authentication (Trusted Connection)"
    
    def get_connection_string(self, odbc_driver: str) -> str:
        conn_str = (
            f"DRIVER={{{odbc_driver}}};"
            f"SERVER={self.server},{self.port};"
            f"DATABASE={self.database};"
            "Trusted_Connection=yes;"
            "Encrypt=yes;"
            "TrustServerCertificate=no;"
        )
        return conn_str
    
    def validate_credentials(self) -> tuple[bool, str]:
        # Windows auth no requiere credenciales explícitas
        return True, ""
    
    def requires_password(self) -> bool:
        return False
    
    def supports_2fa(self) -> bool:
        return False
    
    def get_required_fields(self) -> list[str]:
        return []  # No requiere username/password


# Registrar el provider
ProviderRegistry.register(WindowsAuthProvider)