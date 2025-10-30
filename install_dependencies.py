#!/usr/bin/env python3
"""
Instalador inteligente para SQL Credentials Manager.
Instala dependencias por prioridad y maneja dependencias opcionales.
"""
import subprocess
import sys
import importlib

def install_package(package):
    """Instala un paquete usando pip."""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        return True
    except subprocess.CalledProcessError:
        return False

def check_package(package_name):
    """Verifica si un paquete está instalado."""
    try:
        importlib.import_module(package_name)
        return True
    except ImportError:
        return False

def main():
    print("🔧 Instalador SQL Credentials Manager v3.0")
    print("=" * 50)
    
    # Dependencias básicas (obligatorias)
    basic_packages = [
        ("pyodbc", "pyodbc"),
        ("cryptography", "cryptography")
    ]
    
    # Dependencias opcionales
    optional_packages = [
        ("pyotp", "pyotp", "2FA/TOTP functionality"),
        ("qrcode", "qrcode[pil]", "QR code generation for 2FA"),
        ("sshtunnel", "sshtunnel", "SSH tunnel connections"),
        ("psutil", "psutil", "Performance monitoring")
    ]
    
    print("📦 Instalando dependencias básicas...")
    basic_failed = []
    
    for module_name, package_name in basic_packages:
        if not check_package(module_name):
            print(f"  Instalando {package_name}...")
            if install_package(package_name):
                print(f"  ✅ {package_name} instalado")
            else:
                print(f"  ❌ Error al instalar {package_name}")
                basic_failed.append(package_name)
        else:
            print(f"  ✅ {package_name} ya instalado")
    
    if basic_failed:
        print(f"\n❌ Error: No se pudieron instalar dependencias básicas: {', '.join(basic_failed)}")
        print("El sistema no funcionará sin estas dependencias.")
        return False
    
    print("\n📦 Instalando dependencias opcionales...")
    optional_failed = []
    
    for module_name, package_name, description in optional_packages:
        if not check_package(module_name):
            print(f"  Instalando {package_name} ({description})...")
            if install_package(package_name):
                print(f"  ✅ {package_name} instalado")
            else:
                print(f"  ⚠️  {package_name} falló - {description} no estará disponible")
                optional_failed.append((package_name, description))
        else:
            print(f"  ✅ {package_name} ya instalado")
    
    print("\n🎉 Instalación completada!")
    print("=" * 50)
    
    if optional_failed:
        print("\n⚠️  Características no disponibles por dependencias faltantes:")
        for package, desc in optional_failed:
            print(f"  - {desc} (requiere {package})")
        
        print(f"\nPuedes instalar manualmente con:")
        for package, desc in optional_failed:
            print(f"  pip install {package}")
    
    print("\n🚀 Para ejecutar el sistema:")
    print("  python secure_credentials_manager.py")
    print("  python secure_credentials_manager.py --cli")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n❌ Instalación cancelada por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        sys.exit(1)
