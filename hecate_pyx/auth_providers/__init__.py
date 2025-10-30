"""
Authentication providers for different SQL Server auth methods.
"""
from .base_provider import AuthProvider, ProviderRegistry
from .sql_provider import SQLAuthProvider
from .windows_provider import WindowsAuthProvider
from .certificate_provider import CertificateAuthProvider
from .jwt_provider import JWTAuthProvider

# Importaciones opcionales
try:
    from .ssh_tunnel_provider import SSHTunnelAuthProvider
    SSH_TUNNEL_AVAILABLE = True
except ImportError:
    SSHTunnelAuthProvider = None
    SSH_TUNNEL_AVAILABLE = False

__all__ = [
    'AuthProvider',
    'ProviderRegistry',
    'SQLAuthProvider',
    'WindowsAuthProvider', 
    'CertificateAuthProvider',
    'JWTAuthProvider'
]

# Solo agregar SSH si está disponible
if SSH_TUNNEL_AVAILABLE:
    __all__.append('SSHTunnelAuthProvider')
