"""
Validadores de entrada para el sistema.
"""
import re
from pathlib import Path
from typing import Tuple


class Validator:
    """Validadores de datos de entrada."""
    
    @staticmethod
    def validate_server_name(server: str) -> Tuple[bool, str]:
        """
        Valida nombre/dirección de servidor.
        
        Returns:
            (is_valid, error_message)
        """
        if not server or not server.strip():
            return False, "Server name cannot be empty"
        
        # Permitir: hostnames, IPs, FQDNs
        # Patrón básico para validar
        if len(server) > 255:
            return False, "Server name too long"
        
        return True, ""
    
    @staticmethod
    def validate_database_name(database: str) -> Tuple[bool, str]:
        """Valida nombre de base de datos."""
        if not database or not database.strip():
            return False, "Database name cannot be empty"
        
        # SQL Server permite casi cualquier carácter en nombres
        if len(database) > 128:
            return False, "Database name too long (max 128 characters)"
        
        return True, ""
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """Valida username."""
        if not username or not username.strip():
            return False, "Username cannot be empty"
        
        if len(username) > 128:
            return False, "Username too long"
        
        return True, ""
    
    @staticmethod
    def validate_password(password: str, min_length: int = 1) -> Tuple[bool, str]:
        """Valida password."""
        if not password:
            return False, "Password cannot be empty"
        
        if len(password) < min_length:
            return False, f"Password must be at least {min_length} characters"
        
        return True, ""
    
    @staticmethod
    def validate_master_password(password: str) -> Tuple[bool, str]:
        """
        Valida contraseña maestra (requisitos más estrictos).
        
        Requisitos:
        - Mínimo 8 caracteres
        - Al menos una mayúscula
        - Al menos una minúscula
        - Al menos un número
        """
        if len(password) < 8:
            return False, "Master password must be at least 8 characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Master password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Master password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Master password must contain at least one number"
        
        return True, ""
    
    @staticmethod
    def validate_port(port: int) -> Tuple[bool, str]:
        """Valida número de puerto."""
        if not isinstance(port, int):
            try:
                port = int(port)
            except (ValueError, TypeError):
                return False, "Port must be a number"
        
        if port < 1 or port > 65535:
            return False, "Port must be between 1 and 65535"
        
        return True, ""
    
    @staticmethod
    def validate_totp_code(code: str) -> Tuple[bool, str]:
        """Valida código TOTP (6 dígitos)."""
        if not code:
            return False, "TOTP code cannot be empty"
        
        if not code.isdigit():
            return False, "TOTP code must contain only digits"
        
        if len(code) != 6:
            return False, "TOTP code must be 6 digits"
        
        return True, ""
    
    @staticmethod
    def validate_api_key(api_key: str) -> Tuple[bool, str]:
        """Valida formato de API key."""
        if not api_key:
            return False, "API key cannot be empty"
        
        if not api_key.startswith("sqlcred_"):
            return False, "Invalid API key format"
        
        if len(api_key) < 20:
            return False, "API key too short"
        
        return True, ""
    
    @staticmethod
    def validate_file_path(path: str, must_exist: bool = True) -> Tuple[bool, str]:
        """Valida path de archivo."""
        if not path:
            return False, "File path cannot be empty"
        
        try:
            file_path = Path(path)
            
            if must_exist and not file_path.exists():
                return False, f"File not found: {path}"
            
            return True, ""
            
        except Exception as e:
            return False, f"Invalid file path: {e}"
    
    @staticmethod
    def validate_ip_address(ip: str) -> Tuple[bool, str]:
        """Valida dirección IP."""
        import ipaddress
        
        try:
            ipaddress.ip_address(ip)
            return True, ""
        except ValueError:
            return False, "Invalid IP address"
    
    @staticmethod
    def sanitize_server_name(name: str) -> str:
        """Sanitiza nombre de servidor para uso como key."""
        # Remover espacios y caracteres especiales
        sanitized = re.sub(r'[^\w\-.]', '_', name)
        return sanitized.strip('_')