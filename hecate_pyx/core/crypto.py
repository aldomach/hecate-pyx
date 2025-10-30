"""
Sistema de encriptación AES-256 con PBKDF2 para derivación de claves.
"""
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .config import PBKDF2_ITERATIONS, AES_KEY_SIZE, SALT_SIZE, IV_SIZE
from .exceptions import EncryptionError


class CryptoManager:
    """Gestor de encriptación/desencriptación AES-256."""
    
    @staticmethod
    def generate_salt() -> bytes:
        """Genera un salt aleatorio."""
        return os.urandom(SALT_SIZE)
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Deriva una clave AES-256 desde una contraseña usando PBKDF2.
        
        Args:
            password: Contraseña maestra
            salt: Salt único
            
        Returns:
            Clave de 32 bytes
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def encrypt(data: bytes, password: str) -> bytes:
        """
        Encripta datos usando AES-256-CBC.
        
        Args:
            data: Datos a encriptar
            password: Contraseña maestra
            
        Returns:
            Salt (32) + IV (16) + Datos encriptados
            
        Raises:
            EncryptionError: Si falla la encriptación
        """
        try:
            # Generar salt e IV
            salt = CryptoManager.generate_salt()
            iv = os.urandom(IV_SIZE)
            
            # Derivar clave
            key = CryptoManager.derive_key(password, salt)
            
            # Aplicar padding PKCS7
            padded_data = CryptoManager._apply_padding(data)
            
            # Encriptar
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            
            # Retornar: salt + iv + encrypted_data
            return salt + iv + encrypted
            
        except Exception as e:
            raise EncryptionError(f"Error al encriptar: {e}")
    
    @staticmethod
    def decrypt(encrypted_data: bytes, password: str) -> bytes:
        """
        Desencripta datos usando AES-256-CBC.
        
        Args:
            encrypted_data: Salt + IV + Datos encriptados
            password: Contraseña maestra
            
        Returns:
            Datos desencriptados
            
        Raises:
            EncryptionError: Si falla la desencriptación
        """
        try:
            # Extraer componentes
            salt = encrypted_data[:SALT_SIZE]
            iv = encrypted_data[SALT_SIZE:SALT_SIZE + IV_SIZE]
            ciphertext = encrypted_data[SALT_SIZE + IV_SIZE:]
            
            # Derivar clave
            key = CryptoManager.derive_key(password, salt)
            
            # Desencriptar
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remover padding
            data = CryptoManager._remove_padding(padded_data)
            
            return data
            
        except Exception as e:
            raise EncryptionError(f"Error al desencriptar (contraseña incorrecta?): {e}")
    
    @staticmethod
    def _apply_padding(data: bytes) -> bytes:
        """Aplica padding PKCS7."""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def _remove_padding(data: bytes) -> bytes:
        """Remueve padding PKCS7."""
        padding_length = data[-1]
        return data[:-padding_length]
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Genera hash SHA-256 de una contraseña (para verificación)."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    @staticmethod
    def generate_random_key(length: int = 32) -> str:
        """Genera una clave aleatoria en hexadecimal."""
        return os.urandom(length).hex()