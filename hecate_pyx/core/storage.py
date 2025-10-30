"""
Gestión de almacenamiento encriptado de credenciales.
"""
import json
from pathlib import Path
from typing import Dict, Any, Optional

from .crypto import CryptoManager
from .exceptions import StorageError


class SecureStorage:
    """Almacenamiento seguro de datos encriptados."""
    
    def __init__(self, file_path: Path):
        """
        Args:
            file_path: Ruta del archivo de almacenamiento
        """
        self.file_path = file_path
        self.crypto = CryptoManager()
    
    def save(self, data: Dict[str, Any], password: str) -> None:
        """
        Guarda datos encriptados.
        
        Args:
            data: Diccionario de datos a guardar
            password: Contraseña maestra para encriptación
            
        Raises:
            StorageError: Si falla el guardado
        """
        try:
            # Serializar a JSON
            json_data = json.dumps(data, indent=2)
            
            # Encriptar
            encrypted = self.crypto.encrypt(json_data.encode('utf-8'), password)
            
            # Guardar en archivo
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.file_path, 'wb') as f:
                f.write(encrypted)
                
        except Exception as e:
            raise StorageError(f"Error al guardar datos: {e}")
    
    def load(self, password: str) -> Dict[str, Any]:
        """
        Carga datos desencriptados.
        
        Args:
            password: Contraseña maestra para desencriptación
            
        Returns:
            Diccionario de datos
            
        Raises:
            StorageError: Si falla la carga o el archivo no existe
        """
        try:
            if not self.file_path.exists():
                return {}
            
            # Leer archivo
            with open(self.file_path, 'rb') as f:
                encrypted = f.read()
            
            # Desencriptar
            decrypted = self.crypto.decrypt(encrypted, password)
            
            # Deserializar JSON
            data = json.loads(decrypted.decode('utf-8'))
            
            return data
            
        except FileNotFoundError:
            return {}
        except Exception as e:
            raise StorageError(f"Error al cargar datos: {e}")
    
    def exists(self) -> bool:
        """Verifica si el archivo existe."""
        return self.file_path.exists()
    
    def delete(self) -> None:
        """Elimina el archivo de almacenamiento."""
        if self.file_path.exists():
            self.file_path.unlink()


class CredentialsStorage:
    """Gestor especializado para credenciales de servidores."""
    
    def __init__(self, file_path: Path):
        self.storage = SecureStorage(file_path)
    
    def save_credentials(self, credentials: Dict[str, Dict[str, Any]], password: str) -> None:
        """
        Guarda credenciales de múltiples servidores.
        
        Args:
            credentials: Dict con server_name como key y config como value
            password: Contraseña maestra
        """
        self.storage.save(credentials, password)
    
    def load_credentials(self, password: str) -> Dict[str, Dict[str, Any]]:
        """
        Carga todas las credenciales.
        
        Args:
            password: Contraseña maestra
            
        Returns:
            Diccionario de credenciales por servidor
        """
        return self.storage.load(password)
    
    def add_server(self, server_name: str, config: Dict[str, Any], password: str) -> None:
        """
        Agrega o actualiza un servidor.
        
        Args:
            server_name: Nombre del servidor
            config: Configuración del servidor
            password: Contraseña maestra
        """
        credentials = self.load_credentials(password)
        credentials[server_name] = config
        self.save_credentials(credentials, password)
    
    def remove_server(self, server_name: str, password: str) -> None:
        """
        Elimina un servidor.
        
        Args:
            server_name: Nombre del servidor
            password: Contraseña maestra
        """
        credentials = self.load_credentials(password)
        if server_name in credentials:
            del credentials[server_name]
            self.save_credentials(credentials, password)
    
    def get_server(self, server_name: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene la configuración de un servidor.
        
        Args:
            server_name: Nombre del servidor
            password: Contraseña maestra
            
        Returns:
            Configuración del servidor o None
        """
        credentials = self.load_credentials(password)
        return credentials.get(server_name)
    
    def list_servers(self, password: str) -> list:
        """
        Lista todos los nombres de servidores.
        
        Args:
            password: Contraseña maestra
            
        Returns:
            Lista de nombres de servidores
        """
        credentials = self.load_credentials(password)
        return list(credentials.keys())