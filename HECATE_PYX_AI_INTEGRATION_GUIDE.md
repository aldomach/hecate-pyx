# HÉCATE PYX v3.0 - AI INTEGRATION GUIDE
# =======================================
# Secret Management System for SecOps/DevOps Environments
# Repository: https://github.com/aldomach/hecate-pyx
# Documentation: https://aldo.net.ar/hecate-pyx

## SYSTEM OVERVIEW
# Modular secret management system with AES-256 encryption, 5 auth types, 2FA, API keys, CLI/GUI
# Designed for SecOps/DevOps environments requiring secure credential management and automation

## DEPENDENCIES
pip install pyodbc cryptography  # BASIC (required)
pip install pyotp qrcode[pil] sshtunnel psutil  # OPTIONAL (advanced features)

## QUICK START API
from hecate_connector import connect_to_sql, execute_query, load_credentials, list_servers

# Simple connection using Hecate Pyx vault
conn = connect_to_sql('ServerName')
cursor = conn.cursor()
cursor.execute("SELECT @@VERSION")
result = cursor.fetchone()
conn.close()

# Execute query directly
results = execute_query('ServerName', 'SELECT TOP 10 * FROM sys.tables')

# List available servers from vault
servers = list_servers(master_password='your_password')

## AUTHENTICATION TYPES SUPPORTED
auth_types = {
    'sql_auth': {'username': 'user', 'password': 'pass'},
    'windows_auth': {},  # Uses Windows Integrated Security
    'certificate_auth': {'certificate_path': 'cert.pfx', 'certificate_password': 'pass'},
    'jwt_auth': {'access_token': 'token'},
    'ssh_tunnel': {
        'ssh_host': 'host', 'ssh_username': 'user', 'ssh_password': 'pass',
        'sql_username': 'sqluser', 'sql_password': 'sqlpass'
    }
}

## FULL SYSTEM API
import sys; sys.path.append('.')
from hecate_pyx.core.storage import CredentialsStorage
from hecate_pyx.database.connector import DatabaseConnector
from hecate_pyx.security.totp_manager import TOTPManager
from hecate_pyx.security.api_key_manager import APIKeyManager

# Initialize components
storage = CredentialsStorage('~/.hecate_pyx/credentials.enc')
connector = DatabaseConnector()
totp_manager = TOTPManager()
api_manager = APIKeyManager()

# Load credentials from encrypted vault
master_password = 'your_master_password'
credentials = storage.load_credentials(master_password)

# Connect to server with auth provider
server_config = credentials['ServerName']
conn = connector.connect(server_config, master_password)

# Connect with 2FA/TOTP
totp_code = '123456'
conn = connector.connect(server_config, master_password, totp_code=totp_code)

# Connect with API Key for automation
api_key = 'hecate_...'
conn = connector.connect(server_config, master_password, api_key=api_key)

## CONNECTION POOLING FOR PERFORMANCE
from hecate_pyx.database.connection_pool import pool_manager

pool = pool_manager.get_pool('ServerName', server_config, connector, master_password)
with pool.connection() as conn:
    cursor = conn.cursor()
    cursor.execute("SELECT 1")

## CREDENTIALS MANAGEMENT
# Add new server configuration
server_config = {
    'server': 'localhost',
    'database': 'mydb', 
    'port': 1433,
    'auth_type': 'sql_auth',
    'username': 'user',
    'password': 'pass'
}
storage.add_server('ServerName', server_config, master_password)

# Remove server
storage.remove_server('ServerName', master_password)

# List all configured servers
server_names = storage.list_servers(master_password)

## 2FA/TOTP MANAGEMENT (Google Authenticator Compatible)
# Setup 2FA for a server
secret = totp_manager.generate_secret('ServerName')
provisioning_uri = totp_manager.get_provisioning_uri('ServerName', secret, 'username')
qr_code_bytes = totp_manager.generate_qr_code(provisioning_uri)  # For mobile apps
totp_manager.save_secret('ServerName', secret, master_password)

# Verify TOTP code
is_valid = totp_manager.verify_code(secret, '123456')

# Check if 2FA is enabled
has_2fa = totp_manager.is_enabled('ServerName', master_password)

## API KEY MANAGEMENT FOR AUTOMATION
# Create API key for script automation
key_info = api_manager.create_key('AutomationKey', 'ServerName', master_password, expires_days=90)
api_key = key_info['api_key']  # Format: hecate_...

# List API keys
keys = api_manager.list_keys(master_password, 'ServerName')

# Validate API key
is_valid, server_name = api_manager.validate_key(api_key, master_password)

## CLI INTERFACE COMMANDS
# python hecate-pyx.py --cli
# python -m hecate_pyx.cli server list
# python -m hecate_pyx.cli server add ServerName
# python -m hecate_pyx.cli server test ServerName
# python -m hecate_pyx.cli query ServerName "SELECT 1"
# python -m hecate_pyx.cli apikey create "AutoKey" ServerName
# python -m hecate_pyx.cli totp setup ServerName

## BACKUP/RESTORE SYSTEM
from hecate_pyx.backup.backup_manager import BackupManager

backup_manager = BackupManager()
backup_path = backup_manager.create_backup(master_password, include_api_keys=True, include_totp=True)
backup_manager.restore_backup(backup_path, master_password)

## ERROR HANDLING WITH RETRIES
from hecate_pyx.database.retry_handler import retry_on_failure, CircuitBreaker

@retry_on_failure(max_attempts=3, base_delay=1.0)
def robust_query(server_name, query):
    conn = connect_to_sql(server_name)
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

## AUDIT LOGGING FOR COMPLIANCE
from hecate_pyx.security.audit_logger import AuditLogger

logger = AuditLogger()
logger.log_access('ServerName', 'username', 'SUCCESS', 'Connected via API')
recent_logs = logger.get_recent_logs(100)

## SYSTEM CONFIGURATION PATHS
# Base directory: ~/.hecate_pyx/
# Credentials: ~/.hecate_pyx/credentials.enc
# TOTP secrets: ~/.hecate_pyx/totp_secrets.enc
# API keys: ~/.hecate_pyx/api_keys.enc
# Backups: ~/.hecate_pyx/backups/
# Audit logs: ~/.hecate_pyx/audit.log

## EXAMPLE COMPLETE WORKFLOW
def hecate_pyx_automation_workflow():
    """Complete workflow for automated database operations."""
    # 1. System setup
    master_password = 'secure_password'
    
    # 2. Add server to vault
    storage.add_server('ProductionServer', {
        'server': 'prod.company.com',
        'database': 'analytics',
        'port': 1433,
        'auth_type': 'sql_auth',
        'username': 'analytics_user',
        'password': 'secure_db_password'
    }, master_password)
    
    # 3. Setup 2FA for critical server
    secret = totp_manager.generate_secret('ProductionServer')
    totp_manager.save_secret('ProductionServer', secret, master_password)
    
    # 4. Create API key for automation scripts
    key_info = api_manager.create_key('ETL_Pipeline', 'ProductionServer', master_password)
    automation_key = key_info['api_key']
    
    # 5. Automated connection and operations
    results = execute_query('ProductionServer', 
                           'SELECT COUNT(*) FROM user_events WHERE date = CAST(GETDATE() AS DATE)',
                           api_key=automation_key)
    
    # 6. Create encrypted backup
    backup_path = backup_manager.create_backup(master_password)
    
    return results, backup_path, automation_key

## SECURITY FEATURES
# - AES-256-CBC encryption with PBKDF2 (100k iterations)
# - TOTP 2FA compatible with Google Authenticator/Authy
# - API keys with configurable expiration
# - Complete audit trail for compliance
# - Encrypted backups with integrity validation
# - Connection pooling with resource management
# - Circuit breaker pattern for fault tolerance
# - Input validation and SQL injection prevention

## ENTRY POINTS AND COMMANDS
# GUI Application: python hecate-pyx.py
# CLI Interface: python hecate-pyx.py --cli
# Simple API: from hecate_connector import connect_to_sql
# Full SDK: from hecate_pyx import *
# Migration: python migrate_from_old.py

## PROVIDER PATTERN FOR EXTENSIBILITY
# Add custom authentication providers by extending AuthProvider base class
# Automatic registration with ProviderRegistry
# Support for custom connection strings and validation logic

## ENVIRONMENT VARIABLES
# HECATE_PYX_HOME - Custom base directory
# HECATE_PYX_MASTER_PASSWORD - Master password for automation
# HECATE_PYX_LOG_LEVEL - Logging verbosity
# HECATE_PYX_BACKUP_RETENTION - Backup retention in days

## ERROR HANDLING PATTERNS
try:
    conn = connect_to_sql('ServerName')
    # Database operations
except FileNotFoundError:
    # Hecate Pyx not configured
    print("Run 'python hecate-pyx.py' to configure")
except ValueError:
    # Invalid master password
    print("Check master password")
except KeyError:
    # Server not found
    print("Server not configured in Hecate Pyx")

## INTEGRATION WITH CI/CD PIPELINES
# Use API keys for automated deployments
# Store master password in secure CI/CD secrets
# Leverage audit logging for deployment tracking
# Use backup/restore for environment synchronization
