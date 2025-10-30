"""
JWT/OAuth Token Authentication Provider.
"""
from .base_provider import AuthProvider, ProviderRegistry


class JWTAuthProvider(AuthProvider):
    """Autenticación por token JWT/OAuth."""
    
    @property
    def provider_name(self) -> str:
        return "jwt_auth"
    
    @property
    def display_name(self) -> str:
        return "JWT/OAuth Token Authentication"
    
    def get_connection_string(self, odbc_driver: str) -> str:
        access_token = self.config.get('access_token', '')
        
        conn_str = (
            f"DRIVER={{{odbc_driver}}};"
            f"SERVER={self.server},{self.port};"
            f"DATABASE={self.database};"
            f"AccessToken={access_token};"
            "Encrypt=yes;"
            "TrustServerCertificate=no;"
        )
        return conn_str
    
    def validate_credentials(self) -> tuple[bool, str]:
        access_token = self.config.get('access_token', '')
        if not access_token:
            return False, "Access token is required"
        
        if len(access_token) < 50:
            return False, "Access token appears to be too short"
        
        return True, ""
    
    def requires_token(self) -> bool:
        return True
    
    def supports_2fa(self) -> bool:
        return False  # OAuth ya maneja autenticación
    
    def get_required_fields(self) -> list[str]:
        return ['access_token']


# Registrar el provider
ProviderRegistry.register(JWTAuthProvider)
