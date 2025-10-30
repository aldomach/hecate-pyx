"""
Gestor de backup y restore de credenciales.
"""
import shutil
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..core.config import (
    CREDENTIALS_FILE, API_KEYS_FILE, TOTP_SECRETS_FILE,
    BACKUP_DIR, AUDIT_LOG_FILE
)
from ..core.storage import SecureStorage
from ..core.exceptions import BackupError
from ..security.audit_logger import AuditLogger


class BackupManager:
    """Gestor de backups encriptados de credenciales."""
    
    def __init__(self, backup_dir: Path = BACKUP_DIR):
        """
        Args:
            backup_dir: Directorio de backups
        """
        self.backup_dir = backup_dir
        self.audit_logger = AuditLogger()
        
        # Asegurar que el directorio existe
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def create_backup(
        self,
        password: str,
        include_api_keys: bool = True,
        include_totp: bool = True,
        backup_name: Optional[str] = None
    ) -> Path:
        """
        Crea un backup completo.
        
        Args:
            password: Contraseña maestra
            include_api_keys: Incluir API keys
            include_totp: Incluir secrets TOTP
            backup_name: Nombre del backup (auto-generado si es None)
            
        Returns:
            Path del archivo de backup
            
        Raises:
            BackupError: Si falla el backup
        """
        try:
            # Generar nombre del backup
            if not backup_name:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"backup_{timestamp}"
            
            backup_path = self.backup_dir / backup_name
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Copiar archivos
            files_to_backup = [
                ('credentials.enc', CREDENTIALS_FILE),
            ]
            
            if include_api_keys:
                files_to_backup.append(('api_keys.enc', API_KEYS_FILE))
            
            if include_totp:
                files_to_backup.append(('totp_secrets.enc', TOTP_SECRETS_FILE))
            
            # Copiar cada archivo
            backed_up = []
            for filename, source_file in files_to_backup:
                if source_file.exists():
                    dest_file = backup_path / filename
                    shutil.copy2(source_file, dest_file)
                    backed_up.append(filename)
            
            # Crear metadata
            metadata = {
                'created_at': datetime.now().isoformat(),
                'files': backed_up,
                'include_api_keys': include_api_keys,
                'include_totp': include_totp
            }
            
            metadata_file = backup_path / 'metadata.json'
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Log del backup
            self.audit_logger.log_backup_created(backup_name)
            
            return backup_path
            
        except Exception as e:
            raise BackupError(f"Failed to create backup: {e}")
    
    def restore_backup(
        self,
        backup_name: str,
        password: str,
        restore_credentials: bool = True,
        restore_api_keys: bool = True,
        restore_totp: bool = True
    ) -> None:
        """
        Restaura un backup.
        
        Args:
            backup_name: Nombre del backup
            password: Contraseña maestra (para validar)
            restore_credentials: Restaurar credenciales
            restore_api_keys: Restaurar API keys
            restore_totp: Restaurar TOTP secrets
            
        Raises:
            BackupError: Si falla la restauración
        """
        try:
            backup_path = self.backup_dir / backup_name
            
            if not backup_path.exists():
                raise BackupError(f"Backup not found: {backup_name}")
            
            # Leer metadata
            metadata_file = backup_path / 'metadata.json'
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            else:
                metadata = {}
            
            # Validar contraseña con el archivo de credenciales del backup
            backup_creds = backup_path / 'credentials.enc'
            if backup_creds.exists():
                try:
                    storage = SecureStorage(backup_creds)
                    storage.load(password)  # Esto fallará si la contraseña es incorrecta
                except Exception:
                    raise BackupError("Incorrect master password for this backup")
            
            # Restaurar archivos
            if restore_credentials:
                src = backup_path / 'credentials.enc'
                if src.exists():
                    shutil.copy2(src, CREDENTIALS_FILE)
            
            if restore_api_keys:
                src = backup_path / 'api_keys.enc'
                if src.exists():
                    shutil.copy2(src, API_KEYS_FILE)
            
            if restore_totp:
                src = backup_path / 'totp_secrets.enc'
                if src.exists():
                    shutil.copy2(src, TOTP_SECRETS_FILE)
            
            # Log de restauración
            self.audit_logger.log_backup_restored(backup_name)
            
        except BackupError:
            raise
        except Exception as e:
            raise BackupError(f"Failed to restore backup: {e}")
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """
        Lista todos los backups disponibles.
        
        Returns:
            Lista de diccionarios con info de backups
        """
        backups = []
        
        for backup_path in self.backup_dir.iterdir():
            if not backup_path.is_dir():
                continue
            
            metadata_file = backup_path / 'metadata.json'
            
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            else:
                metadata = {}
            
            backup_info = {
                'name': backup_path.name,
                'created_at': metadata.get('created_at', 'Unknown'),
                'files': metadata.get('files', []),
                'size_mb': self._get_dir_size(backup_path) / (1024 * 1024)
            }
            
            backups.append(backup_info)
        
        # Ordenar por fecha (más reciente primero)
        backups.sort(key=lambda x: x['created_at'], reverse=True)
        
        return backups
    
    def delete_backup(self, backup_name: str) -> None:
        """
        Elimina un backup.
        
        Args:
            backup_name: Nombre del backup
            
        Raises:
            BackupError: Si falla la eliminación
        """
        try:
            backup_path = self.backup_dir / backup_name
            
            if not backup_path.exists():
                raise BackupError(f"Backup not found: {backup_name}")
            
            shutil.rmtree(backup_path)
            
        except Exception as e:
            raise BackupError(f"Failed to delete backup: {e}")
    
    def _get_dir_size(self, path: Path) -> int:
        """Calcula el tamaño total de un directorio."""
        total = 0
        for entry in path.rglob('*'):
            if entry.is_file():
                total += entry.stat().st_size
        return total
    
    def export_backup(
        self,
        backup_name: str,
        export_path: Path,
        password: str
    ) -> Path:
        """
        Exporta un backup a un archivo ZIP.
        
        Args:
            backup_name: Nombre del backup
            export_path: Ruta de destino (sin extensión)
            password: Contraseña maestra (para validar)
            
        Returns:
            Path del archivo ZIP creado
        """
        try:
            backup_path = self.backup_dir / backup_name
            
            if not backup_path.exists():
                raise BackupError(f"Backup not found: {backup_name}")
            
            # Validar contraseña
            backup_creds = backup_path / 'credentials.enc'
            if backup_creds.exists():
                try:
                    storage = SecureStorage(backup_creds)
                    storage.load(password)
                except Exception:
                    raise BackupError("Incorrect master password")
            
            # Crear ZIP
            zip_path = shutil.make_archive(
                str(export_path),
                'zip',
                backup_path
            )
            
            return Path(zip_path)
            
        except BackupError:
            raise
        except Exception as e:
            raise BackupError(f"Failed to export backup: {e}")
    
    def import_backup(
        self,
        zip_path: Path,
        backup_name: Optional[str] = None
    ) -> str:
        """
        Importa un backup desde un archivo ZIP.
        
        Args:
            zip_path: Path del archivo ZIP
            backup_name: Nombre del backup (auto-generado si es None)
            
        Returns:
            Nombre del backup importado
        """
        try:
            if not zip_path.exists():
                raise BackupError(f"ZIP file not found: {zip_path}")
            
            # Generar nombre si no se proporciona
            if not backup_name:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"imported_{timestamp}"
            
            backup_path = self.backup_dir / backup_name
            
            # Descomprimir
            shutil.unpack_archive(str(zip_path), str(backup_path), 'zip')
            
            return backup_name
            
        except Exception as e:
            raise BackupError(f"Failed to import backup: {e}")