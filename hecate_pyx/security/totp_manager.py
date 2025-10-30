"""
Gestor de 2FA/TOTP (Google Authenticator compatible).
"""
from io import BytesIO
from typing import Optional, Dict, Any
from pathlib import Path

from ..core.storage import SecureStorage
from ..core.config import TOTP_ISSUER, TOTP_DIGITS, TOTP_INTERVAL, TOTP_SECRETS_FILE
from ..core.exceptions import TOTPError

# Importaciones opcionales
try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    pyotp = None
    PYOTP_AVAILABLE = False

try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    qrcode = None
    QRCODE_AVAILABLE = False


class TOTPManager:
    """Gestor de autenticación de dos factores (2FA) usando TOTP."""
    
    def __init__(self, storage_file: Path = TOTP_SECRETS_FILE):
        """
        Args:
            storage_file: Archivo para guardar secrets TOTP
        """
        self.storage = SecureStorage(storage_file)
    
    def generate_secret(self, server_name: str) -> str:
        """
        Genera un nuevo secret TOTP.
        
        Args:
            server_name: Nombre del servidor
            
        Returns:
            Secret en base32
        """
        if not PYOTP_AVAILABLE:
            raise TOTPError("2FA requires 'pyotp' package. Install with: pip install pyotp")
        
        return pyotp.random_base32()
    
    def get_provisioning_uri(self, server_name: str, secret: str, username: str = "") -> str:
        """
        Genera URI para provisioning (usado en QR code).
        
        Args:
            server_name: Nombre del servidor
            secret: Secret TOTP
            username: Usuario (opcional)
            
        Returns:
            URI de provisioning
        """
        if not PYOTP_AVAILABLE:
            raise TOTPError("2FA requires 'pyotp' package. Install with: pip install pyotp")
        
        account_name = f"{username}@{server_name}" if username else server_name
        totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
        return totp.provisioning_uri(
            name=account_name,
            issuer_name=TOTP_ISSUER
        )
    
    def generate_qr_code(self, provisioning_uri: str) -> bytes:
        """
        Genera código QR para configuración en app móvil.
        
        Args:
            provisioning_uri: URI de provisioning
            
        Returns:
            Imagen QR en bytes (PNG)
        """
        if not QRCODE_AVAILABLE:
            raise TOTPError("QR code generation requires 'qrcode[pil]' package. Install with: pip install qrcode[pil]")
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        return buffer.getvalue()
    
    def verify_code(self, secret: str, code: str) -> bool:
        """
        Verifica un código TOTP.
        
        Args:
            secret: Secret TOTP
            code: Código de 6 dígitos
            
        Returns:
            True si el código es válido
        """
        if not PYOTP_AVAILABLE:
            return False
        
        try:
            totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
            return totp.verify(code, valid_window=1)  # Acepta ±30 segundos
        except Exception:
            return False
    
    def save_secret(self, server_name: str, secret: str, password: str) -> None:
        """
        Guarda un secret TOTP encriptado.
        
        Args:
            server_name: Nombre del servidor
            secret: Secret TOTP
            password: Contraseña maestra para encriptar
        """
        try:
            secrets = self.storage.load(password)
            secrets[server_name] = {
                'secret': secret,
                'enabled': True
            }
            self.storage.save(secrets, password)
        except Exception as e:
            raise TOTPError(f"Error saving TOTP secret: {e}")
    
    def load_secret(self, server_name: str, password: str) -> Optional[str]:
        """
        Carga un secret TOTP.
        
        Args:
            server_name: Nombre del servidor
            password: Contraseña maestra
            
        Returns:
            Secret TOTP o None si no existe
        """
        try:
            secrets = self.storage.load(password)
            server_data = secrets.get(server_name)
            if server_data and server_data.get('enabled'):
                return server_data.get('secret')
            return None
        except Exception:
            return None
    
    def is_enabled(self, server_name: str, password: str) -> bool:
        """
        Verifica si 2FA está habilitado para un servidor.
        
        Args:
            server_name: Nombre del servidor
            password: Contraseña maestra
            
        Returns:
            True si está habilitado
        """
        return self.load_secret(server_name, password) is not None
    
    def disable_2fa(self, server_name: str, password: str) -> None:
        """
        Deshabilita 2FA para un servidor.
        
        Args:
            server_name: Nombre del servidor
            password: Contraseña maestra
        """
        try:
            secrets = self.storage.load(password)
            if server_name in secrets:
                secrets[server_name]['enabled'] = False
                self.storage.save(secrets, password)
        except Exception as e:
            raise TOTPError(f"Error disabling 2FA: {e}")
    
    def delete_secret(self, server_name: str, password: str) -> None:
        """
        Elimina completamente un secret TOTP.
        
        Args:
            server_name: Nombre del servidor
            password: Contraseña maestra
        """
        try:
            secrets = self.storage.load(password)
            if server_name in secrets:
                del secrets[server_name]
                self.storage.save(secrets, password)
        except Exception as e:
            raise TOTPError(f"Error deleting TOTP secret: {e}")
    
    def list_servers_with_2fa(self, password: str) -> list[str]:
        """
        Lista servidores con 2FA habilitado.
        
        Args:
            password: Contraseña maestra
            
        Returns:
            Lista de nombres de servidores
        """
        try:
            secrets = self.storage.load(password)
            return [
                name for name, data in secrets.items()
                if data.get('enabled', False)
            ]
        except Exception:
            return []
