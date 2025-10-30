"""
Configuraciones globales para Hecate Pyx.
"""
import os
from pathlib import Path

# Directorio base para datos de Hecate Pyx
BASE_DIR = Path.home() / ".hecate_pyx"

# Archivos principales
CREDENTIALS_FILE = BASE_DIR / "credentials.enc"
TOTP_SECRETS_FILE = BASE_DIR / "totp_secrets.enc"
API_KEYS_FILE = BASE_DIR / "api_keys.enc"
AUDIT_LOG_FILE = BASE_DIR / "audit.log"
BACKUP_DIR = BASE_DIR / "backups"

# Configuraciones de seguridad
PBKDF2_ITERATIONS = 100000
AES_KEY_SIZE = 32  # 256 bits
SALT_SIZE = 32
IV_SIZE = 16

# Configuraciones de TOTP
TOTP_ISSUER = "Hecate Pyx"
TOTP_DIGITS = 6
TOTP_INTERVAL = 30

# Configuraciones de API Keys
API_KEY_PREFIX = "hectepyx_"
API_KEY_LENGTH = 32
DEFAULT_API_KEY_EXPIRY_DAYS = 90

# Configuraciones de conexión
DEFAULT_CONNECTION_TIMEOUT = 30
POOL_SIZE = 5
POOL_MAX_OVERFLOW = 10
MAX_RETRY_ATTEMPTS = 3
RETRY_DELAY = 1.0

# Driver ODBC por defecto
DEFAULT_ODBC_DRIVER = "ODBC Driver 17 for SQL Server"

# Configuraciones de backup
BACKUP_RETENTION_DAYS = 30
BACKUP_COMPRESSION = True


def ensure_directories():
    """Crear directorios necesarios si no existen."""
    BASE_DIR.mkdir(exist_ok=True)
    BACKUP_DIR.mkdir(exist_ok=True)


def get_odbc_drivers():
    """Obtener lista de drivers ODBC disponibles."""
    import pyodbc
    drivers = [d for d in pyodbc.drivers() if 'SQL Server' in d]
    if not drivers:
        drivers = ['SQL Server']  # Fallback
    return drivers


def get_available_odbc_driver():
    """Obtener el primer driver ODBC disponible para SQL Server."""
    import pyodbc
    
    # Lista de drivers en orden de preferencia
    preferred_drivers = [
        "ODBC Driver 18 for SQL Server",
        "ODBC Driver 17 for SQL Server",
        "ODBC Driver 13 for SQL Server",
        "ODBC Driver 11 for SQL Server",
        "SQL Server Native Client 11.0",
        "SQL Server"
    ]
    
    available_drivers = pyodbc.drivers()
    
    # Buscar el primer driver preferido que esté disponible
    for driver in preferred_drivers:
        if driver in available_drivers:
            return driver
    
    # Si no se encuentra ninguno, buscar cualquiera que contenga "SQL Server"
    for driver in available_drivers:
        if "SQL Server" in driver:
            return driver
    
    # Fallback al driver por defecto
    return DEFAULT_ODBC_DRIVER