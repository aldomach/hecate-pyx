"""
Clase base abstracta para providers de autenticación.
Este diseño permite agregar nuevos tipos de autenticación fácilmente.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import pyodbc


class AuthProvider(ABC):
    """
    Clase base para todos los providers de autenticación.
    
    Para crear un nuevo provider:
    1. Heredar de AuthProvider
    2. Implementar get_connection_string()
    3. Implementar validate_credentials()
    4. Opcionalmente sobrescribir requires_password(), requires_certificate(), etc.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Args:
            config: Configuración del servidor con credenciales
        """
        self.config = config
        self.server = config.get('server', '')
        self.database = config.get('database', '')
        self.port = config.get('port', 1433)
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Nombre único del provider (ej: 'sql_auth', 'windows_auth')."""
        pass
    
    @property
    @abstractmethod
    def display_name(self) -> str:
        """Nombre para mostrar en UI (ej: 'SQL Server Authentication')."""
        pass
    
    @abstractmethod
    def get_connection_string(self, odbc_driver: str) -> str:
        """
        Construye la cadena de conexión ODBC.
        
        Args:
            odbc_driver: Driver ODBC a usar
            
        Returns:
            Connection string completo
        """
        pass
    
    @abstractmethod
    def validate_credentials(self) -> tuple[bool, str]:
        """
        Valida que las credenciales requeridas estén presentes.
        
        Returns:
            (is_valid, error_message)
        """
        pass
    
    def get_connection(self, odbc_driver: str, timeout: int = 30) -> pyodbc.Connection:
        """
        Establece conexión a la base de datos.
        
        Args:
            odbc_driver: Driver ODBC a usar
            timeout: Timeout en segundos
            
        Returns:
            Conexión pyodbc
            
        Raises:
            Exception: Si falla la conexión
        """
        conn_str = self.get_connection_string(odbc_driver)
        return pyodbc.connect(conn_str, timeout=timeout)
    
    # Métodos opcionales para características específicas
    def requires_password(self) -> bool:
        """Indica si este provider requiere contraseña."""
        return False
    
    def requires_certificate(self) -> bool:
        """Indica si este provider requiere certificado."""
        return False
    
    def requires_token(self) -> bool:
        """Indica si este provider requiere token."""
        return False
    
    def supports_2fa(self) -> bool:
        """Indica si este provider soporta 2FA."""
        return False
    
    def get_required_fields(self) -> list[str]:
        """
        Retorna lista de campos requeridos para este provider.
        
        Returns:
            Lista de nombres de campos (ej: ['username', 'password'])
        """
        return []
    
    def prepare_connection(self) -> None:
        """
        Preparación previa a la conexión (ej: establecer SSH tunnel).
        Sobrescribir si es necesario.
        """
        pass
    
    def cleanup_connection(self) -> None:
        """
        Limpieza posterior a la conexión (ej: cerrar SSH tunnel).
        Sobrescribir si es necesario.
        """
        pass
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.server}/{self.database}>"


class ProviderRegistry:
    """Registro global de providers disponibles."""
    
    _providers: Dict[str, type[AuthProvider]] = {}
    
    @classmethod
    def register(cls, provider_class: type[AuthProvider]) -> None:
        """
        Registra un nuevo provider.
        
        Args:
            provider_class: Clase del provider a registrar
        """
        # Obtener el provider_name de una instancia temporal
        temp_instance = provider_class({})
        provider_name = temp_instance.provider_name
        cls._providers[provider_name] = provider_class
    
    @classmethod
    def get_provider(cls, provider_name: str, config: Dict[str, Any]) -> Optional[AuthProvider]:
        """
        Obtiene una instancia de un provider.
        
        Args:
            provider_name: Nombre del provider
            config: Configuración del servidor
            
        Returns:
            Instancia del provider o None
        """
        provider_class = cls._providers.get(provider_name)
        if provider_class:
            return provider_class(config)
        return None
    
    @classmethod
    def list_providers(cls) -> list[tuple[str, str]]:
        """
        Lista todos los providers disponibles.
        
        Returns:
            Lista de tuplas (provider_name, display_name)
        """
        providers = []
        for provider_class in cls._providers.values():
            temp_instance = provider_class({})
            providers.append((temp_instance.provider_name, temp_instance.display_name))
        return sorted(providers, key=lambda x: x[1])
    
    @classmethod
    def get_provider_display_name(cls, provider_name: str) -> str:
        """Obtiene el display_name de un provider."""
        provider_class = cls._providers.get(provider_name)
        if provider_class:
            temp_instance = provider_class({})
            return temp_instance.display_name
        return provider_name