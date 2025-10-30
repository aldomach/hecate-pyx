"""
Certificate Authentication Provider.
"""
from .base_provider import AuthProvider, ProviderRegistry


class CertificateAuthProvider(AuthProvider):
    """Autenticación por certificado (.pfx/.p12)."""
    
    @property
    def provider_name(self) -> str:
        return "certificate_auth"
    
    @property
    def display_name(self) -> str:
        return "Certificate Authentication (.pfx/.p12)"
    
    def get_connection_string(self, odbc_driver: str) -> str:
        cert_path = self.config.get('certificate_path', '')
        cert_password = self.config.get('certificate_password', '')
        
        conn_str = (
            f"DRIVER={{{odbc_driver}}};"
            f"SERVER={self.server},{self.port};"
            f"DATABASE={self.database};"
            f"Certificate={cert_path};"
            f"CertificatePassword={cert_password};"
            "Encrypt=yes;"
            "TrustServerCertificate=no;"
        )
        return conn_str
    
    def validate_credentials(self) -> tuple[bool, str]:
        cert_path = self.config.get('certificate_path', '')
        if not cert_path:
            return False, "Certificate path is required"
        
        from pathlib import Path
        if not Path(cert_path).exists():
            return False, f"Certificate file not found: {cert_path}"
        
        return True, ""
    
    def requires_certificate(self) -> bool:
        return True
    
    def supports_2fa(self) -> bool:
        return True
    
    def get_required_fields(self) -> list[str]:
        return ['certificate_path', 'certificate_password']


# Registrar el provider
ProviderRegistry.register(CertificateAuthProvider)
