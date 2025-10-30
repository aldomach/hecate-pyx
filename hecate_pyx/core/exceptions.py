"""
Excepciones personalizadas del sistema.
"""

class SQLCredentialsError(Exception):
    """Excepción base del sistema."""
    pass


class AuthenticationError(SQLCredentialsError):
    """Error de autenticación."""
    pass


class EncryptionError(SQLCredentialsError):
    """Error de encriptación/desencriptación."""
    pass


class StorageError(SQLCredentialsError):
    """Error de almacenamiento."""
    pass


class ConnectionError(SQLCredentialsError):
    """Error de conexión a base de datos."""
    pass


class ProviderNotFoundError(SQLCredentialsError):
    """Provider de autenticación no encontrado."""
    pass


class TOTPError(SQLCredentialsError):
    """Error de 2FA/TOTP."""
    pass


class APIKeyError(SQLCredentialsError):
    """Error de API Key."""
    pass


class BackupError(SQLCredentialsError):
    """Error de backup/restore."""
    pass


class ValidationError(SQLCredentialsError):
    """Error de validación de datos."""
    pass