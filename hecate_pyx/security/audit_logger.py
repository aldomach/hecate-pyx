"""
Sistema de auditoría y logging de accesos.
"""
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from ..core.config import AUDIT_LOG_FILE


class AuditLogger:
    """Logger para auditoría de accesos y eventos de seguridad."""
    
    def __init__(self, log_file: Path = AUDIT_LOG_FILE):
        """
        Args:
            log_file: Archivo de log
        """
        self.log_file = log_file
        self._setup_logger()
    
    def _setup_logger(self) -> None:
        """Configura el logger."""
        # Crear directorio si no existe
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Configurar logger
        self.logger = logging.getLogger('SQLCredentials.Audit')
        self.logger.setLevel(logging.INFO)
        
        # Evitar duplicar handlers
        if not self.logger.handlers:
            # Handler para archivo
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.INFO)
            
            # Formato detallado
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(formatter)
            
            self.logger.addHandler(file_handler)
    
    def _format_event(
        self,
        event_type: str,
        server_name: str,
        username: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Formatea un evento para el log."""
        parts = [
            f"EVENT={event_type}",
            f"SERVER={server_name}",
        ]
        
        if username:
            parts.append(f"USER={username}")
        
        parts.append(f"SUCCESS={success}")
        
        if details:
            details_str = " | ".join(f"{k}={v}" for k, v in details.items())
            parts.append(details_str)
        
        return " | ".join(parts)
    
    def log_connection_attempt(
        self,
        server_name: str,
        username: str,
        auth_type: str,
        success: bool,
        error: Optional[str] = None
    ) -> None:
        """
        Registra intento de conexión.
        
        Args:
            server_name: Nombre del servidor
            username: Usuario
            auth_type: Tipo de autenticación
            success: Si fue exitoso
            error: Mensaje de error (si falló)
        """
        details = {'auth_type': auth_type}
        if error:
            details['error'] = error
        
        message = self._format_event(
            'CONNECTION_ATTEMPT',
            server_name,
            username,
            success,
            details
        )
        
        if success:
            self.logger.info(message)
        else:
            self.logger.warning(message)
    
    def log_2fa_attempt(
        self,
        server_name: str,
        username: str,
        success: bool
    ) -> None:
        """Registra intento de 2FA."""
        message = self._format_event(
            '2FA_ATTEMPT',
            server_name,
            username,
            success
        )
        
        if success:
            self.logger.info(message)
        else:
            self.logger.warning(message)
    
    def log_api_key_usage(
        self,
        server_name: str,
        key_name: str,
        success: bool
    ) -> None:
        """Registra uso de API key."""
        message = self._format_event(
            'API_KEY_USAGE',
            server_name,
            details={'key_name': key_name},
            success=success
        )
        
        self.logger.info(message)
    
    def log_api_key_created(
        self,
        server_name: str,
        key_name: str,
        creator: str
    ) -> None:
        """Registra creación de API key."""
        message = self._format_event(
            'API_KEY_CREATED',
            server_name,
            details={'key_name': key_name, 'creator': creator}
        )
        
        self.logger.info(message)
    
    def log_api_key_revoked(
        self,
        server_name: str,
        key_name: str,
        revoker: str
    ) -> None:
        """Registra revocación de API key."""
        message = self._format_event(
            'API_KEY_REVOKED',
            server_name,
            details={'key_name': key_name, 'revoker': revoker}
        )
        
        self.logger.warning(message)
    
    def log_credentials_added(self, server_name: str) -> None:
        """Registra agregado de credenciales."""
        message = self._format_event('CREDENTIALS_ADDED', server_name)
        self.logger.info(message)
    
    def log_credentials_updated(self, server_name: str) -> None:
        """Registra actualización de credenciales."""
        message = self._format_event('CREDENTIALS_UPDATED', server_name)
        self.logger.info(message)
    
    def log_credentials_deleted(self, server_name: str) -> None:
        """Registra eliminación de credenciales."""
        message = self._format_event('CREDENTIALS_DELETED', server_name)
        self.logger.warning(message)
    
    def log_master_password_changed(self) -> None:
        """Registra cambio de contraseña maestra."""
        self.logger.warning("EVENT=MASTER_PASSWORD_CHANGED")
    
    def log_backup_created(self, backup_file: str) -> None:
        """Registra creación de backup."""
        self.logger.info(f"EVENT=BACKUP_CREATED | FILE={backup_file}")
    
    def log_backup_restored(self, backup_file: str) -> None:
        """Registra restauración de backup."""
        self.logger.warning(f"EVENT=BACKUP_RESTORED | FILE={backup_file}")
    
    def log_security_event(
        self,
        event_type: str,
        server_name: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Registra evento de seguridad genérico."""
        message = self._format_event(event_type, server_name, details=details)
        self.logger.warning(message)
    
    def get_recent_logs(self, lines: int = 100) -> list[str]:
        """
        Obtiene las últimas líneas del log.
        
        Args:
            lines: Número de líneas a obtener
            
        Returns:
            Lista de líneas del log
        """
        try:
            if not self.log_file.exists():
                return []
            
            with open(self.log_file, 'r') as f:
                all_lines = f.readlines()
                return all_lines[-lines:]
        except Exception:
            return []