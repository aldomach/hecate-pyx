"""
Conector principal a SQL Server usando providers.
"""
import pyodbc
from typing import Optional, Dict, Any
from contextlib import contextmanager

from ..auth_providers.base_provider import ProviderRegistry
from ..security.totp_manager import TOTPManager
from ..security.api_key_manager import APIKeyManager
from ..security.audit_logger import AuditLogger
from ..core.config import get_available_odbc_driver, DEFAULT_CONNECTION_TIMEOUT
from ..core.exceptions import ConnectionError, AuthenticationError, TOTPError, ProviderNotFoundError


class DatabaseConnector:
    """Conector principal que integra providers y seguridad."""
    
    def __init__(self):
        self.totp_manager = TOTPManager()
        self.api_key_manager = APIKeyManager()
        self.audit_logger = AuditLogger()
        self.odbc_driver = None
    
    def _get_odbc_driver(self) -> str:
        """Obtiene el driver ODBC disponible (cached)."""
        if not self.odbc_driver:
            self.odbc_driver = get_available_odbc_driver()
        return self.odbc_driver
    
    def connect(
        self,
        server_config: Dict[str, Any],
        master_password: str,
        totp_code: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = DEFAULT_CONNECTION_TIMEOUT
    ) -> pyodbc.Connection:
        """
        Establece conexión a SQL Server con autenticación completa.
        
        Args:
            server_config: Configuración del servidor
            master_password: Contraseña maestra (para desencriptar)
            totp_code: Código 2FA (si está habilitado)
            api_key: API key (alternativa a credenciales)
            timeout: Timeout de conexión
            
        Returns:
            Conexión pyodbc
            
        Raises:
            ConnectionError: Si falla la conexión
            AuthenticationError: Si falla la autenticación
            TOTPError: Si falla 2FA
        """
        server_name = server_config.get('server', 'unknown')
        auth_type = server_config.get('auth_type', 'sql_auth')
        username = server_config.get('username', '')
        
        try:
            # Validar API Key si se proporciona
            if api_key:
                if not self.api_key_manager.validate_key(api_key, server_name, master_password):
                    self.audit_logger.log_api_key_usage(server_name, 'unknown', False)
                    raise AuthenticationError("Invalid or expired API key")
                
                self.audit_logger.log_api_key_usage(server_name, 'api_key', True)
            
            # Validar 2FA si está habilitado
            if self.totp_manager.is_enabled(server_name, master_password):
                if not totp_code:
                    raise TOTPError("2FA is enabled but no code provided")
                
                secret = self.totp_manager.load_secret(server_name, master_password)
                if not self.totp_manager.verify_code(secret, totp_code):
                    self.audit_logger.log_2fa_attempt(server_name, username, False)
                    raise TOTPError("Invalid 2FA code")
                
                self.audit_logger.log_2fa_attempt(server_name, username, True)
            
            # Obtener provider de autenticación
            provider = ProviderRegistry.get_provider(auth_type, server_config)
            if not provider:
                raise ProviderNotFoundError(f"Authentication provider not found: {auth_type}")
            
            # Validar credenciales del provider
            is_valid, error_msg = provider.validate_credentials()
            if not is_valid:
                raise AuthenticationError(f"Invalid credentials: {error_msg}")
            
            # Preparar conexión (ej: establecer SSH tunnel)
            provider.prepare_connection()
            
            try:
                # Obtener driver ODBC
                odbc_driver = self._get_odbc_driver()
                
                # Conectar
                connection = provider.get_connection(odbc_driver, timeout)
                
                # Log exitoso
                self.audit_logger.log_connection_attempt(
                    server_name,
                    username,
                    auth_type,
                    True
                )
                
                return connection
                
            except Exception as conn_error:
                # Limpiar conexión en caso de error
                provider.cleanup_connection()
                raise conn_error
                
        except (AuthenticationError, TOTPError, ProviderNotFoundError):
            raise
        except Exception as e:
            # Log fallo
            self.audit_logger.log_connection_attempt(
                server_name,
                username,
                auth_type,
                False,
                str(e)
            )
            raise ConnectionError(f"Failed to connect to {server_name}: {e}")
    
    @contextmanager
    def get_connection(
        self,
        server_config: Dict[str, Any],
        master_password: str,
        **kwargs
    ):
        """
        Context manager para conexiones (auto-cierre).
        
        Usage:
            with connector.get_connection(config, password) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
        """
        connection = None
        provider = None
        
        try:
            auth_type = server_config.get('auth_type', 'sql_auth')
            provider = ProviderRegistry.get_provider(auth_type, server_config)
            
            connection = self.connect(server_config, master_password, **kwargs)
            yield connection
            
        finally:
            if connection:
                try:
                    connection.close()
                except Exception:
                    pass
            
            if provider:
                try:
                    provider.cleanup_connection()
                except Exception:
                    pass
    
    def test_connection(
        self,
        server_config: Dict[str, Any],
        master_password: str,
        **kwargs
    ) -> tuple[bool, str]:
        """
        Prueba una conexión.
        
        Returns:
            (success, message)
        """
        try:
            with self.get_connection(server_config, master_password, **kwargs) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
            
            return True, "Connection successful"
            
        except Exception as e:
            return False, str(e)
    
    def execute_query(
        self,
        server_config: Dict[str, Any],
        master_password: str,
        query: str,
        **kwargs
    ) -> list:
        """
        Ejecuta una query y retorna resultados.
        
        Args:
            server_config: Configuración del servidor
            master_password: Contraseña maestra
            query: Query SQL
            **kwargs: Argumentos adicionales (totp_code, api_key, etc.)
            
        Returns:
            Lista de filas
        """
        with self.get_connection(server_config, master_password, **kwargs) as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            
            # Intentar obtener resultados
            try:
                return cursor.fetchall()
            except pyodbc.ProgrammingError:
                # Query no retorna resultados (INSERT, UPDATE, etc.)
                conn.commit()
                return []