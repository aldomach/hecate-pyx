"""
Gestor de API Keys para automatización.
"""
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path

from ..core.storage import SecureStorage
from ..core.crypto import CryptoManager
from ..core.config import API_KEY_LENGTH, API_KEY_PREFIX, API_KEYS_FILE
from ..core.exceptions import APIKeyError


class APIKeyManager:
    """Gestor de API keys para acceso programático."""
    
    def __init__(self, storage_file: Path = API_KEYS_FILE):
        """
        Args:
            storage_file: Archivo para guardar API keys
        """
        self.storage = SecureStorage(storage_file)
        self.crypto = CryptoManager()
    
    def generate_key(
        self,
        name: str,
        server_name: str,
        expires_days: Optional[int] = None,
        scopes: Optional[List[str]] = None
    ) -> str:
        """
        Genera una nueva API key.
        
        Args:
            name: Nombre descriptivo de la key
            server_name: Servidor al que da acceso
            expires_days: Días hasta expiración (None = sin expiración)
            scopes: Lista de permisos (ej: ['read', 'write'])
            
        Returns:
            API key generada
        """
        # Generar key aleatoria
        random_part = secrets.token_hex(API_KEY_LENGTH)
        api_key = f"{API_KEY_PREFIX}{random_part}"
        
        return api_key
    
    def create_key(
        self,
        name: str,
        server_name: str,
        password: str,
        expires_days: Optional[int] = None,
        scopes: Optional[List[str]] = None
    ) -> Dict[str, any]:
        """
        Crea y guarda una nueva API key.
        
        Args:
            name: Nombre descriptivo
            server_name: Servidor asociado
            password: Contraseña maestra
            expires_days: Días hasta expiración
            scopes: Permisos
            
        Returns:
            Diccionario con info de la key
        """
        try:
            # Generar key
            api_key = self.generate_key(name, server_name, expires_days, scopes)
            
            # Hash de la key (guardamos el hash, no la key)
            key_hash = self.crypto.hash_password(api_key)
            
            # Calcular fecha de expiración
            created_at = datetime.now()
            expires_at = None
            if expires_days:
                expires_at = created_at + timedelta(days=expires_days)
            
            # Metadata
            key_data = {
                'name': name,
                'server_name': server_name,
                'key_hash': key_hash,
                'created_at': created_at.isoformat(),
                'expires_at': expires_at.isoformat() if expires_at else None,
                'scopes': scopes or ['read'],
                'last_used': None,
                'active': True
            }
            
            # Guardar
            keys = self.storage.load(password)
            
            # Generar ID único
            key_id = f"{name}_{created_at.strftime('%Y%m%d%H%M%S')}"
            keys[key_id] = key_data
            
            self.storage.save(keys, password)
            
            return {
                'key_id': key_id,
                'api_key': api_key,  # Solo se muestra al crear
                **key_data
            }
            
        except Exception as e:
            raise APIKeyError(f"Error creating API key: {e}")
    
    def validate_key(self, api_key: str, server_name: str, password: str) -> bool:
        """
        Valida una API key.
        
        Args:
            api_key: Key a validar
            server_name: Servidor al que intenta acceder
            password: Contraseña maestra
            
        Returns:
            True si la key es válida
        """
        try:
            # Hash de la key proporcionada
            key_hash = self.crypto.hash_password(api_key)
            
            # Buscar en keys guardadas
            keys = self.storage.load(password)
            
            for key_id, key_data in keys.items():
                if (key_data.get('key_hash') == key_hash and
                    key_data.get('server_name') == server_name and
                    key_data.get('active')):
                    
                    # Verificar expiración
                    expires_at = key_data.get('expires_at')
                    if expires_at:
                        if datetime.fromisoformat(expires_at) < datetime.now():
                            return False
                    
                    # Actualizar último uso
                    key_data['last_used'] = datetime.now().isoformat()
                    self.storage.save(keys, password)
                    
                    return True
            
            return False
            
        except Exception:
            return False
    
    def list_keys(self, password: str, server_name: Optional[str] = None) -> List[Dict]:
        """
        Lista API keys.
        
        Args:
            password: Contraseña maestra
            server_name: Filtrar por servidor (opcional)
            
        Returns:
            Lista de keys (sin el hash)
        """
        try:
            keys = self.storage.load(password)
            result = []
            
            for key_id, key_data in keys.items():
                if server_name and key_data.get('server_name') != server_name:
                    continue
                
                # No incluir el hash en la respuesta
                safe_data = {
                    'key_id': key_id,
                    'name': key_data.get('name'),
                    'server_name': key_data.get('server_name'),
                    'created_at': key_data.get('created_at'),
                    'expires_at': key_data.get('expires_at'),
                    'last_used': key_data.get('last_used'),
                    'scopes': key_data.get('scopes'),
                    'active': key_data.get('active')
                }
                result.append(safe_data)
            
            return sorted(result, key=lambda x: x['created_at'], reverse=True)
            
        except Exception as e:
            raise APIKeyError(f"Error listing API keys: {e}")
    
    def revoke_key(self, key_id: str, password: str) -> None:
        """
        Revoca (desactiva) una API key.
        
        Args:
            key_id: ID de la key
            password: Contraseña maestra
        """
        try:
            keys = self.storage.load(password)
            
            if key_id in keys:
                keys[key_id]['active'] = False
                self.storage.save(keys, password)
            else:
                raise APIKeyError(f"API key not found: {key_id}")
                
        except Exception as e:
            raise APIKeyError(f"Error revoking API key: {e}")
    
    def delete_key(self, key_id: str, password: str) -> None:
        """
        Elimina permanentemente una API key.
        
        Args:
            key_id: ID de la key
            password: Contraseña maestra
        """
        try:
            keys = self.storage.load(password)
            
            if key_id in keys:
                del keys[key_id]
                self.storage.save(keys, password)
            else:
                raise APIKeyError(f"API key not found: {key_id}")
                
        except Exception as e:
            raise APIKeyError(f"Error deleting API key: {e}")
    
    def get_key_info(self, key_id: str, password: str) -> Optional[Dict]:
        """
        Obtiene información de una API key.
        
        Args:
            key_id: ID de la key
            password: Contraseña maestra
            
        Returns:
            Información de la key o None
        """
        try:
            keys = self.storage.load(password)
            key_data = keys.get(key_id)
            
            if key_data:
                return {
                    'key_id': key_id,
                    'name': key_data.get('name'),
                    'server_name': key_data.get('server_name'),
                    'created_at': key_data.get('created_at'),
                    'expires_at': key_data.get('expires_at'),
                    'last_used': key_data.get('last_used'),
                    'scopes': key_data.get('scopes'),
                    'active': key_data.get('active')
                }
            return None
            
        except Exception:
            return None