# Hécate Pyx

**Secret Management System for SecOps/DevOps Environments**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/aldomach/hecate-pyx)

Hécate Pyx es un software de gestión de secretos orientado a arquitecturas de Ciberseguridad y Desarrollo de Operaciones (SecOps/DevOps). Su función principal no se limita al almacenamiento pasivo, sino que se centra en la creación segura, organización estructurada y acceso controlado a credenciales sensibles como claves API, tokens, contraseñas y certificados.

A diferencia de sistemas que generan credenciales efímeras, Hécate Pyx actúa como una bóveda local persistente, donde se definen configuraciones de conexión a servidores —actualmente con soporte para SQL Server— y se almacenan credenciales cifradas mediante AES-256. El sistema permite múltiples métodos de autenticación, incluyendo SQL, Windows, certificados, JWT, túneles SSH y TOTP.

Cualquier script o aplicación que se ejecute en el entorno local puede integrarse con Hécate Pyx mediante su interfaz programática, accediendo a las credenciales autorizadas mediante una contraseña maestra, API key o token TOTP. Esto permite automatizar procesos sin exponer secretos directamente en el código o en variables de entorno.

En entornos de infraestructura crítica, la gestión de secretos implica más que seguridad: requiere trazabilidad, auditoría y cumplimiento normativo. La aplicación de principios como el mínimo privilegio y el control de acceso basado en identidad es fundamental para garantizar que cada acceso esté debidamente autenticado, autorizado y registrado.

---

## Tabla de Contenidos

- [Características Principales](#características-principales)
- [Arquitectura del Sistema](#arquitectura-del-sistema)
- [Instalación](#instalación)
- [Configuración Inicial](#configuración-inicial)
- [Uso del Sistema](#uso-del-sistema)
- [Interfaz Programática](#interfaz-programática)
- [Seguridad y Cumplimiento](#seguridad-y-cumplimiento)
- [Documentación Técnica](#documentación-técnica)
- [Contribuciones](#contribuciones)
- [Licencia](#licencia)

---

## Características Principales

### 🔐 Criptografía y Seguridad
- **Cifrado AES-256-CBC** con derivación de claves PBKDF2 (100,000 iteraciones)
- **Autenticación multifactor (TOTP)** compatible con estándares RFC 6238
- **Gestión de claves API** con expiración configurable y revocación inmediata
- **Separación de privilegios** mediante contraseña maestra y tokens de acceso

### 🔌 Conectividad y Protocolos
- **SQL Server Authentication** - Credenciales nativas de SQL Server
- **Windows Integrated Security** - Autenticación transparente del sistema
- **Certificate-based Authentication** - Soporte para certificados X.509 (.pfx/.p12)
- **JWT/OAuth Token Authentication** - Integración con sistemas de identidad modernos
- **SSH Tunnel Authentication** - Conexiones seguras a través de túneles encriptados

### 🏗️ Arquitectura Modular
- **Provider Pattern** para extensibilidad de métodos de autenticación
- **Connection Pooling** con gestión automática de recursos
- **Circuit Breaker Pattern** para tolerancia a fallos
- **Retry Mechanisms** con backoff exponencial
- **Audit Trail** completo para cumplimiento normativo

### 🎛️ Interfaces de Usuario
- **GUI Desktop** desarrollada en Tkinter para configuración interactiva
- **CLI (Command Line Interface)** para automatización e integración en pipelines
- **API Programática** simple para integración en aplicaciones Python
- **SDK Modular** para desarrollo de extensiones personalizadas

---

## Arquitectura del Sistema

### Componentes Centrales

```
hecate_pyx/
├── core/                    # Componentes fundamentales
│   ├── crypto.py           # Motor criptográfico AES-256
│   ├── storage.py          # Almacenamiento persistente seguro  
│   ├── config.py           # Configuración del sistema
│   └── exceptions.py       # Manejo de excepciones
├── auth_providers/         # Métodos de autenticación
│   ├── base_provider.py    # Interfaz abstracta
│   ├── sql_provider.py     # SQL Server Authentication
│   ├── windows_provider.py # Windows Integrated Security
│   ├── certificate_provider.py # Certificate Authentication
│   ├── jwt_provider.py     # JWT/OAuth Authentication
│   └── ssh_tunnel_provider.py # SSH Tunnel Authentication
├── security/               # Componentes de seguridad
│   ├── totp_manager.py     # Autenticación multifactor
│   ├── api_key_manager.py  # Gestión de claves API
│   └── audit_logger.py     # Registro de auditoría
├── database/               # Conectividad avanzada
│   ├── connector.py        # Motor de conexiones
│   ├── connection_pool.py  # Pool de conexiones
│   └── retry_handler.py    # Gestión de reintentos
└── interfaces/             # Interfaces de usuario
    ├── gui/               # Interfaz gráfica
    └── cli/               # Interfaz de línea de comandos
```

### Flujo de Datos

1. **Autenticación**: Verificación de contraseña maestra o token API
2. **Descifrado**: Acceso seguro al almacén de credenciales local
3. **Autorización**: Validación de permisos para el recurso solicitado
4. **Conexión**: Establecimiento de sesión con el servidor de destino
5. **Auditoría**: Registro del acceso para trazabilidad y cumplimiento

---

## Instalación

### Requisitos del Sistema

- **Python 3.8+** (recomendado 3.10 o superior)
- **Sistema Operativo**: Windows 10+, Linux (Ubuntu 18.04+), macOS 10.14+
- **Memoria RAM**: Mínimo 256 MB disponibles
- **Espacio en disco**: 50 MB para instalación completa

### Dependencias Principales

```bash
# Dependencias básicas (obligatorias)
pip install pyodbc>=4.0.35 cryptography>=41.0.0

# Dependencias opcionales (características avanzadas)
pip install pyotp>=2.9.0 qrcode[pil]>=7.4.2 sshtunnel>=0.4.0 psutil>=5.9.0
```

### Instalación desde Código Fuente

```bash
# Clonar repositorio
git clone https://github.com/aldomach/hecate-pyx.git
cd hecate-pyx

# Instalar dependencias básicas
pip install -r requirements_basic.txt

# Instalar dependencias completas (opcional)
pip install -r requirements.txt

# Verificar instalación
python hecate-pyx.py --version
```

### Instalación Automatizada

```bash
# Ejecutar instalador inteligente
python install_dependencies.py

# El instalador detectará automáticamente las dependencias disponibles
# y configurará el sistema según las capacidades del entorno
```

---

## Configuración Inicial

### Primera Ejecución

```bash
# Inicializar sistema con interfaz gráfica
python hecate-pyx.py

# Inicializar sistema con interfaz CLI
python hecate-pyx.py --cli
```

### Estructura de Directorios

El sistema crea automáticamente la siguiente estructura en el directorio del usuario:

```
~/.hecate_pyx/
├── credentials.enc         # Almacén principal de credenciales (AES-256)
├── totp_secrets.enc        # Secretos TOTP para autenticación multifactor
├── api_keys.enc           # Claves API para automatización
├── audit.log              # Registro de auditoría
└── backups/               # Respaldos automáticos cifrados
    ├── backup_YYYYMMDD_HHMMSS.enc
    └── ...
```

### Configuración de Contraseña Maestra

La contraseña maestra es el punto de entrada principal al sistema. Debe cumplir con los siguientes criterios de seguridad:

- **Longitud mínima**: 12 caracteres
- **Complejidad**: Combinación de mayúsculas, minúsculas, números y símbolos
- **Unicidad**: No reutilizar contraseñas de otros sistemas
- **Almacenamiento**: Solo se almacena un hash derivado (PBKDF2) para verificación

---

## Uso del Sistema

### Interfaz Gráfica (GUI)

La interfaz gráfica proporciona acceso completo a todas las funcionalidades del sistema mediante una aplicación desktop intuitiva.

```bash
# Ejecutar interfaz gráfica
python hecate-pyx.py
```

**Funcionalidades principales:**
- Gestión visual de configuraciones de servidores
- Configuración de autenticación multifactor con códigos QR
- Gestión de claves API con interface drag-and-drop
- Visualización de logs de auditoría en tiempo real
- Creación y restauración de respaldos cifrados

### Interfaz de Línea de Comandos (CLI)

La CLI está diseñada para automatización, integración en pipelines CI/CD y administración remota.

```bash
# Gestión de servidores
hecate-pyx server list                              # Listar servidores configurados
hecate-pyx server add MyServer                      # Agregar nueva configuración
hecate-pyx server test MyServer                     # Probar conectividad
hecate-pyx server remove MyServer                   # Eliminar configuración

# Gestión de claves API
hecate-pyx apikey create "AutomationKey" MyServer   # Crear clave para automatización
hecate-pyx apikey list --server MyServer            # Listar claves por servidor
hecate-pyx apikey revoke "AutomationKey"            # Revocar clave específica

# Autenticación multifactor
hecate-pyx totp setup MyServer                      # Configurar TOTP para servidor
hecate-pyx totp verify MyServer 123456              # Verificar código TOTP

# Operaciones de datos
hecate-pyx query MyServer "SELECT @@VERSION"        # Ejecutar consulta SQL
hecate-pyx backup create --include-all              # Crear respaldo completo
hecate-pyx audit show --last 50                     # Mostrar últimos registros
```

### Migración desde Sistemas Anteriores

Para organizaciones que migran desde sistemas de credenciales previos:

```bash
# Migrar desde versión anterior de Hecate Pyx
python migrate_from_old.py

# El migrador detecta automáticamente formatos compatibles y convierte
# las credenciales manteniendo la integridad criptográfica
```

---

## Interfaz Programática

### API Simple para Integración Rápida

```python
from hecate_pyx import connect_to_sql, execute_query

# Conexión directa con manejo automático de credenciales
connection = connect_to_sql('ProductionServer')
cursor = connection.cursor()
cursor.execute("SELECT COUNT(*) FROM critical_table")
result = cursor.fetchone()
connection.close()

# Ejecución de consultas con contexto automático
results = execute_query('ProductionServer', 
                       'SELECT * FROM user_activity WHERE date > ?',
                       params=['2024-01-01'])
```

### SDK Completo para Desarrollo Avanzado

```python
from hecate_pyx.core.storage import CredentialsStorage
from hecate_pyx.database.connector import DatabaseConnector
from hecate_pyx.security.totp_manager import TOTPManager

# Inicialización del sistema
storage = CredentialsStorage('~/.hecate_pyx/credentials.enc')
connector = DatabaseConnector()
totp_manager = TOTPManager()

# Autenticación con contraseña maestra
master_password = get_secure_password()  # Implementar según políticas de seguridad
credentials = storage.load_credentials(master_password)

# Conexión con autenticación multifactor
server_config = credentials['ProductionServer']
totp_code = input("Código TOTP: ")
connection = connector.connect(server_config, master_password, totp_code=totp_code)

# Pool de conexiones para aplicaciones de alto rendimiento
from hecate_pyx.database.connection_pool import pool_manager

pool = pool_manager.get_pool('ProductionServer', server_config, connector, master_password)
with pool.connection() as conn:
    # Conexión reutilizable con gestión automática de recursos
    cursor = conn.cursor()
    cursor.execute("EXEC complex_stored_procedure")
    results = cursor.fetchall()
```

### Integración con Sistemas de Automatización

```python
# Script para pipelines CI/CD
import os
from hecate_pyx import connect_to_sql

def deploy_database_changes():
    # Usar API key desde variable de entorno segura
    api_key = os.environ.get('HECATE_PYX_API_KEY')
    
    # Conexión sin interacción humana
    conn = connect_to_sql('DeploymentTarget', api_key=api_key)
    
    # Ejecutar scripts de migración
    with open('migration_script.sql', 'r') as f:
        migration_sql = f.read()
    
    cursor = conn.cursor()
    cursor.execute(migration_sql)
    conn.commit()
    conn.close()
    
    print("Database migration completed successfully")

if __name__ == "__main__":
    deploy_database_changes()
```

---

## Seguridad y Cumplimiento

### Criptografía Implementada

**Algoritmos de Cifrado:**
- **AES-256-CBC** para cifrado simétrico de datos sensibles
- **PBKDF2-HMAC-SHA256** para derivación de claves (100,000 iteraciones)
- **HMAC-SHA256** para integridad y autenticación de mensajes
- **Secure Random** para generación de sales y vectores de inicialización

**Gestión de Claves:**
- Derivación determinística de claves desde contraseña maestra
- Sales únicas por instalación para prevenir ataques rainbow table
- Rotación automática de vectores de inicialización por operación
- Separación criptográfica entre diferentes tipos de secretos

### Cumplimiento Normativo

**Auditoría y Trazabilidad:**
- Registro temporal de todos los accesos a credenciales
- Identificación única de cada sesión y operación
- Logs estructurados en formato JSON para análisis automatizado
- Retención configurable según políticas organizacionales

**Control de Acceso:**
- Implementación del principio de menor privilegio
- Autenticación multifactor obligatoria para recursos críticos
- Expiración automática de claves API según políticas
- Revocación inmediata de accesos comprometidos

### Consideraciones de Despliegue Seguro

**Ambiente de Producción:**
```bash
# Variables de entorno recomendadas
export HECATE_PYX_HOME="/secure/path/.hecate_pyx"
export HECATE_PYX_LOG_LEVEL="INFO"
export HECATE_PYX_BACKUP_RETENTION="90"  # días

# Permisos restrictivos del sistema de archivos
chmod 700 ~/.hecate_pyx/
chmod 600 ~/.hecate_pyx/*.enc
```

**Integración con HSM (Hardware Security Modules):**
El sistema está diseñado para futuras integraciones con HSM para almacenamiento de claves maestras en ambientes de alta seguridad.

---

## Documentación Técnica

### Especificaciones de Protocolo

**Formato de Almacenamiento Cifrado:**
```
[32 bytes: Salt] + [16 bytes: IV] + [Variable: Encrypted Data] + [32 bytes: HMAC]
```

**Estructura de Metadatos:**
```json
{
  "version": "3.0",
  "encryption": "AES-256-CBC",
  "kdf": "PBKDF2-HMAC-SHA256",
  "iterations": 100000,
  "timestamp": "2024-01-01T00:00:00Z",
  "servers": {
    "server_id": {
      "server": "hostname",
      "database": "database_name",
      "port": 1433,
      "auth_type": "sql_auth|windows_auth|certificate_auth|jwt_auth|ssh_tunnel",
      "credentials": "encrypted_blob"
    }
  }
}
```

### API Reference

La documentación completa de la API está disponible en: [aldo.net.ar/hecate-pyx](https://aldo.net.ar/hecate-pyx)

**Módulos Principales:**
- `hecate_pyx.core` - Componentes fundamentales y criptografía
- `hecate_pyx.auth_providers` - Métodos de autenticación extensibles
- `hecate_pyx.security` - Autenticación multifactor y gestión de API keys
- `hecate_pyx.database` - Conectividad y gestión de pools
- `hecate_pyx.interfaces` - GUI y CLI para interacción de usuario

### Extensibilidad

**Desarrollo de Auth Providers Personalizados:**
```python
from hecate_pyx.auth_providers.base_provider import AuthProvider

class CustomAuthProvider(AuthProvider):
    @property
    def provider_name(self) -> str:
        return "custom_auth"
    
    def get_connection_string(self, odbc_driver: str) -> str:
        # Implementar lógica de conexión personalizada
        pass
    
    def validate_credentials(self) -> tuple[bool, str]:
        # Implementar validación específica
        pass

# Registro automático del provider
ProviderRegistry.register(CustomAuthProvider)
```

---

## Contribuciones

### Proceso de Desarrollo

Hecate Pyx utiliza un flujo de desarrollo basado en Git Flow con las siguientes ramas:

- `main` - Versión estable en producción
- `develop` - Rama de desarrollo activo
- `feature/*` - Nuevas características en desarrollo
- `hotfix/*` - Correcciones críticas para producción

### Estándares de Código

**Python Code Style:**
- Adherencia estricta a PEP 8
- Type hints obligatorios para todas las funciones públicas
- Docstrings en formato Google para documentación automática
- Cobertura de pruebas mínima del 80%

**Seguridad:**
- Revisión obligatoria de código para cambios criptográficos
- Análisis estático de seguridad con bandit
- Pruebas de penetración para nuevas funcionalidades de autenticación

### Guías de Contribución

```bash
# Configurar entorno de desarrollo
git clone https://github.com/aldomach/hecate-pyx.git
cd hecate-pyx
python -m venv hecate_pyx_dev
source hecate_pyx_dev/bin/activate  # Linux/macOS
# hecate_pyx_dev\Scripts\activate    # Windows

# Instalar dependencias de desarrollo
pip install -r requirements_dev.txt

# Ejecutar suite de pruebas
python -m pytest tests/ --cov=hecate_pyx --cov-report=html

# Ejecutar análisis de seguridad
bandit -r hecate_pyx/ -f json -o security_report.json
```

**Pull Request Checklist:**
- [ ] Pruebas unitarias para nueva funcionalidad
- [ ] Documentación actualizada
- [ ] Análisis de seguridad sin vulnerabilidades críticas
- [ ] Compatibilidad con versiones soportadas de Python
- [ ] Actualización del CHANGELOG.md

---

## Licencia

Este proyecto está licenciado bajo la [Licencia MIT](LICENSE) - consulte el archivo LICENSE para más detalles.

### Términos de Uso

La Licencia MIT permite:
- ✅ Uso comercial sin restricciones
- ✅ Modificación y redistribución
- ✅ Uso privado en organizaciones
- ✅ Sublicenciamiento

Requiere:
- 📄 Inclusión del aviso de copyright en distribuciones
- 📄 Inclusión del texto completo de la licencia

**Nota Legal:** Este software se proporciona "tal como está", sin garantías de ningún tipo. Los usuarios son responsables de evaluar la idoneidad del software para sus casos de uso específicos y de implementar controles de seguridad adicionales según sus políticas organizacionales.

---

## Información del Proyecto

**Repositorio:** [github.com/aldomach/hecate-pyx](https://github.com/aldomach/hecate-pyx)  
**Documentación:** [aldo.net.ar/hecate-pyx](https://aldo.net.ar/hecate-pyx)  
**Versión Actual:** 3.0  
**Estado:** Estable - Listo para Producción  

**Mantenedor:** [Aldo Machado](https://github.com/aldomach)  
**Licencia:** MIT  
**Lenguaje Principal:** Python 3.8+  

---

*Hécate Pyx - Gestión de Secretos para Infraestructuras Críticas*
