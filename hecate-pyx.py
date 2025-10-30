#!/usr/bin/env python3
"""
Hécate Pyx - Secret Management System
====================================
Sistema modular de gestión de secretos para arquitecturas SecOps/DevOps.

Características:
- Encriptación AES-256 con PBKDF2
- Múltiples tipos de autenticación (SQL, Windows, Certificate, JWT, SSH Tunnel)
- 2FA/TOTP (Google Authenticator)
- API Keys para automatización
- Audit logging
- Connection pooling
- Backup/Restore

Uso:
    python hecate-pyx.py           # GUI
    python hecate-pyx.py --cli     # CLI
    python hecate-pyx.py --help    # Ayuda

Repositorio: https://github.com/aldomach/hecate-pyx
Documentación: https://aldo.net.ar/hecate-pyx
Versión: 3.0
"""

import sys
import argparse
from pathlib import Path

# Agregar el directorio actual al path
sys.path.insert(0, str(Path(__file__).parent))

def check_dependencies():
    """Verificar dependencias básicas y mostrar info sobre opcionales."""
    missing_basic = []
    missing_optional = []
    
    # Dependencias básicas
    try:
        import pyodbc
    except ImportError:
        missing_basic.append("pyodbc")
    
    try:
        import cryptography
    except ImportError:
        missing_basic.append("cryptography")
    
    # Dependencias opcionales
    try:
        import pyotp
    except ImportError:
        missing_optional.append(("pyotp", "2FA/TOTP"))
    
    try:
        import qrcode
    except ImportError:
        missing_optional.append(("qrcode[pil]", "QR codes para 2FA"))
    
    try:
        import sshtunnel
    except ImportError:
        missing_optional.append(("sshtunnel", "Túneles SSH"))
    
    if missing_basic:
        print("❌ ERROR: Faltan dependencias básicas obligatorias:")
        for dep in missing_basic:
            print(f"  - {dep}")
        print("\n🔧 Para instalar:")
        print("  pip install pyodbc cryptography")
        print("  O ejecuta: python install_dependencies.py")
        return False
    
    if missing_optional:
        print("⚠️  Dependencias opcionales no instaladas:")
        for dep, desc in missing_optional:
            print(f"  - {dep} ({desc})")
        print(f"\n💡 Estas características estarán deshabilitadas.")
        print(f"   Para instalar: pip install {' '.join([dep for dep, _ in missing_optional])}")
        print()
    
    return True

def main():
    """Punto de entrada principal."""
    parser = argparse.ArgumentParser(
        description="Hécate Pyx v3.0 - Secret Management System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python hecate-pyx.py           # Abrir GUI
  python hecate-pyx.py --cli     # Usar CLI
  python hecate-pyx.py --help    # Esta ayuda

Características principales:
  ✅ Encriptación AES-256 con PBKDF2 (100k iteraciones)
  ✅ Múltiples tipos de autenticación
  ✅ 2FA/TOTP (Google Authenticator)
  ✅ API Keys para scripts automatizados
  ✅ Audit logging completo
  ✅ Connection pooling
  ✅ Backup/Restore seguro

Repositorio: https://github.com/aldomach/hecate-pyx
Documentación: https://aldo.net.ar/hecate-pyx
        """
    )
    
    parser.add_argument(
        '--cli',
        action='store_true',
        help='Usar interfaz de línea de comandos en lugar de GUI'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Hécate Pyx v3.0 - Secret Management System'
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("Hécate Pyx v3.0 - Secret Management System")
    print("=" * 70)
    print("\n✨ Características:")
    print("  ✅ Encriptación AES-256 con PBKDF2 (100k iteraciones)")
    print("  ✅ Múltiples tipos de autenticación")
    print("  ✅ 2FA/TOTP (Google Authenticator)")
    print("  ✅ API Keys para scripts automatizados")
    print("  ✅ Audit logging completo")
    print("  ✅ Connection pooling")
    print("  ✅ Backup/Restore seguro")
    print()
    
    # Verificar dependencias
    if not check_dependencies():
        sys.exit(1)
    
    # Crear directorios necesarios
    try:
        from hecate_pyx.core.config import ensure_directories
        ensure_directories()
    except ImportError as e:
        print(f"❌ Error al importar configuración: {e}")
        sys.exit(1)
    
    if args.cli:
        print("🖥️  Iniciando interfaz CLI...\n")
        try:
            from hecate_pyx.cli import main as cli_main
            cli_main()
        except ImportError as e:
            print(f"❌ Error al cargar CLI: {e}")
            print("Verifica que todas las dependencias estén instaladas.")
            sys.exit(1)
    else:
        print("🚀 Iniciando aplicación GUI...\n")
        try:
            from hecate_pyx.gui.main_window import HecatePyxGUI
            app = HecatePyxGUI()
            app.run()
        except ImportError as e:
            print(f"❌ Error al cargar GUI: {e}")
            print("Verifica que todas las dependencias estén instaladas.")
            sys.exit(1)


if __name__ == "__main__":
    main()