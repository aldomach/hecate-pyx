#!/usr/bin/env python3
"""
Migrador de Credenciales - Versión Antigua a v3.0
=================================================
Convierte credenciales del formato Fernet (v2.0) al formato AES-256-CBC (v3.0)

Uso:
    python migrate_from_old.py
"""

import json
import os
import sys
from pathlib import Path
from getpass import getpass
import hashlib
import base64

# Verificar dependencias
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import pyodbc
except ImportError as e:
    print(f"❌ Falta dependencia: {e}")
    print("Instala con: pip install cryptography pyodbc")
    sys.exit(1)

# Agregar path del sistema
sys.path.insert(0, str(Path(__file__).parent))

class OldFormatDecryptor:
    """Desencriptador para formato antiguo (Fernet)."""
    
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.credentials_file = self.data_dir / "credentials.enc"
        self.key_file = self.data_dir / "master.key"
        self.salt_file = self.data_dir / "salt.bin"
        
    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derivar clave como en la versión antigua."""
        kdf_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,  # 100k iteraciones
            dklen=32
        )
        return base64.urlsafe_b64encode(kdf_key)
    
    def hash_password(self, password: str, salt: bytes) -> bytes:
        """Hash de contraseña como en la versión antigua."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
    
    def verify_password(self, password: str) -> bool:
        """Verificar contraseña maestra."""
        if not self.salt_file.exists() or not self.key_file.exists():
            return False
        
        # Cargar salt
        with open(self.salt_file, 'rb') as f:
            salt = f.read()
        
        # Cargar hash almacenado
        with open(self.key_file, 'rb') as f:
            stored_hash = f.read()
        
        # Verificar
        computed_hash = self.hash_password(password, salt)
        return computed_hash == stored_hash
    
    def decrypt_old_credentials(self, password: str) -> dict:
        """Desencriptar credenciales del formato antiguo."""
        if not self.credentials_file.exists():
            return {}
        
        # Cargar salt
        with open(self.salt_file, 'rb') as f:
            salt = f.read()
        
        # Derivar clave
        key = self.derive_key_from_password(password, salt)
        cipher_suite = Fernet(key)
        
        # Cargar y desencriptar
        with open(self.credentials_file, 'rb') as f:
            encrypted_data = f.read()
        
        if not encrypted_data:
            return {}
        
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8'))


class NewFormatEncryptor:
    """Encriptador para nuevo formato (AES-256-CBC)."""
    
    def __init__(self):
        self.pbkdf2_iterations = 100000
        self.aes_key_size = 32
        self.salt_size = 32
        self.iv_size = 16
    
    def generate_salt(self) -> bytes:
        """Generar salt aleatorio."""
        import os
        return os.urandom(self.salt_size)
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derivar clave AES-256 desde contraseña."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.aes_key_size,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def apply_padding(self, data: bytes) -> bytes:
        """Aplicar padding PKCS7."""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def encrypt(self, data: bytes, password: str) -> bytes:
        """Encriptar con AES-256-CBC."""
        import os
        
        # Generar salt e IV
        salt = self.generate_salt()
        iv = os.urandom(self.iv_size)
        
        # Derivar clave
        key = self.derive_key(password, salt)
        
        # Aplicar padding
        padded_data = self.apply_padding(data)
        
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


def detect_old_format(directory: str) -> bool:
    """Detectar si hay archivos del formato antiguo."""
    data_dir = Path(directory)
    
    old_files = [
        data_dir / "credentials.enc",
        data_dir / "master.key", 
        data_dir / "salt.bin"
    ]
    
    return all(f.exists() for f in old_files)


def migrate_credentials(old_dir: str, new_dir: str = None):
    """Migrar credenciales del formato antiguo al nuevo."""
    if new_dir is None:
        new_dir = old_dir
    
    old_dir = Path(old_dir)
    new_dir = Path(new_dir)
    
    print("🔄 Migrando credenciales del formato v2.0 a v3.0...")
    print(f"📁 Directorio origen: {old_dir}")
    print(f"📁 Directorio destino: {new_dir}")
    
    # Verificar formato antiguo
    if not detect_old_format(old_dir):
        print("❌ No se encontraron archivos del formato antiguo")
        return False
    
    # Inicializar desencriptador antiguo
    old_decryptor = OldFormatDecryptor(old_dir)
    
    # Pedir contraseña maestra
    password = getpass("Contraseña maestra actual: ")
    
    # Verificar contraseña
    if not old_decryptor.verify_password(password):
        print("❌ Contraseña incorrecta")
        return False
    
    try:
        # Desencriptar credenciales antiguas
        print("🔓 Desencriptando credenciales antiguas...")
        old_credentials = old_decryptor.decrypt_old_credentials(password)
        
        if not old_credentials:
            print("⚠️  No se encontraron credenciales para migrar")
            return True
        
        print(f"📋 Encontradas {len(old_credentials)} configuraciones de servidores")
        
        # Convertir al nuevo formato
        print("🔄 Convirtiendo al nuevo formato...")
        new_credentials = {}
        
        for server_name, config in old_credentials.items():
            # Convertir formato antiguo al nuevo
            new_config = {
                'server': config.get('server', ''),
                'database': config.get('database', ''),
                'port': config.get('port', 1433),
                'username': config.get('username', ''),
                'password': config.get('password', ''),
            }
            
            # Determinar tipo de autenticación
            if config.get('trusted_connection', False):
                new_config['auth_type'] = 'windows_auth'
                # Para Windows auth, no necesitamos username/password
                new_config.pop('username', None)
                new_config.pop('password', None)
            else:
                new_config['auth_type'] = 'sql_auth'
            
            new_credentials[server_name] = new_config
            print(f"  ✅ {server_name} ({new_config['auth_type']})")
        
        # Encriptar con nuevo formato
        print("🔐 Encriptando con nuevo formato AES-256-CBC...")
        new_encryptor = NewFormatEncryptor()
        
        json_data = json.dumps(new_credentials, indent=2)
        encrypted_data = new_encryptor.encrypt(json_data.encode('utf-8'), password)
        
        # Crear directorio de destino
        new_dir.mkdir(parents=True, exist_ok=True)
        
        # Guardar credenciales en nuevo formato
        new_credentials_file = new_dir / "credentials.enc"
        with open(new_credentials_file, 'wb') as f:
            f.write(encrypted_data)
        
        # Crear backup de archivos antiguos
        backup_dir = new_dir / "backup_old_format"
        backup_dir.mkdir(exist_ok=True)
        
        old_files = ["credentials.enc", "master.key", "salt.bin", "key.key"]
        backed_up = []
        
        for filename in old_files:
            old_file = old_dir / filename
            if old_file.exists():
                backup_file = backup_dir / filename
                import shutil
                shutil.copy2(old_file, backup_file)
                backed_up.append(filename)
        
        print(f"\n✅ Migración completada exitosamente!")
        print(f"📁 Credenciales nuevas: {new_credentials_file}")
        print(f"💾 Backup archivos antiguos: {backup_dir}")
        print(f"📂 Archivos respaldados: {', '.join(backed_up)}")
        
        print(f"\n🚀 Ahora puedes usar:")
        print(f"   python secure_credentials_manager.py")
        
        return True
        
    except Exception as e:
        print(f"❌ Error durante migración: {e}")
        return False


def main():
    """Función principal del migrador."""
    print("=" * 60)
    print("🔄 Migrador de Credenciales SQL - v2.0 → v3.0")
    print("=" * 60)
    
    # Detectar directorio actual
    current_dir = Path.cwd()
    
    # Buscar en directorios comunes
    possible_dirs = [
        current_dir,
        Path.home() / ".sql_credentials_secure",
        current_dir / ".sql_credentials_secure"
    ]
    
    found_dir = None
    for dir_path in possible_dirs:
        if detect_old_format(dir_path):
            found_dir = dir_path
            break
    
    if found_dir:
        print(f"📁 Formato antiguo encontrado en: {found_dir}")
        
        # Confirmar migración
        response = input("\n¿Migrar credenciales al nuevo formato? (s/N): ").strip().lower()
        if response in ['s', 'si', 'sí', 'y', 'yes']:
            
            # Directorio destino para el nuevo formato
            new_dir = Path.home() / ".sql_credentials"
            
            if migrate_credentials(found_dir, new_dir):
                print(f"\n🎉 ¡Migración completada!")
                print(f"✅ Tus credenciales están ahora en formato v3.0")
                print(f"✅ Los archivos antiguos están respaldados")
            else:
                print(f"\n❌ Migración falló")
        else:
            print("Migración cancelada")
    else:
        print("❌ No se encontraron archivos del formato antiguo")
        print("\nBuscado en:")
        for dir_path in possible_dirs:
            print(f"  - {dir_path}")
        
        # Permitir especificar directorio manualmente
        custom_dir = input("\n📁 ¿Especificar directorio manualmente? (ruta o Enter para salir): ").strip()
        if custom_dir and Path(custom_dir).exists():
            if detect_old_format(custom_dir):
                migrate_credentials(custom_dir)
            else:
                print(f"❌ No se encontraron archivos del formato antiguo en: {custom_dir}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Migración cancelada por el usuario")
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
