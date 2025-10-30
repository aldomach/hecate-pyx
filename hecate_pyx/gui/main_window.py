"""
Ventana principal de la aplicación GUI.
"""
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional

from ..core.storage import CredentialsStorage
from ..core.config import CREDENTIALS_FILE, BASE_DIR
from ..database.connector import DatabaseConnector
from ..auth_providers.base_provider import ProviderRegistry
from .dialogs.password_dialog import MasterPasswordDialog
from .dialogs.server_dialog import ServerDialog
from .dialogs.apikey_dialog import APIKeyDialog
from .dialogs.totp_setup_dialog import TOTPSetupDialog


class HecatePyxGUI:
    """Main window for Hecate Pyx secret management system."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔮 Hecate Pyx - Secret Management System v3.0")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        
        # Storage
        self.storage = CredentialsStorage(CREDENTIALS_FILE)
        self.connector = DatabaseConnector()
        
        # Variables
        self.master_password: Optional[str] = None
        self.credentials = {}
        
        self.create_widgets()
        self.center_window()
    
    def center_window(self):
        """Centrar ventana en pantalla."""
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (self.root.winfo_width() // 2)
        y = (self.root.winfo_screenheight() // 2) - (self.root.winfo_height() // 2)
        self.root.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        """Crear interfaz gráfica."""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Título
        title_label = ttk.Label(
            main_frame,
            text="🔮 Hecate Pyx - Secret Management System",
            font=('Arial', 14, 'bold')
        )
        title_label.grid(row=0, column=0, pady=(0, 15))
        
        # Frame de botones
        self.create_button_frame(main_frame)
        
        # Lista de servidores
        self.create_server_list(main_frame)
        
        # Info footer
        self.create_footer(main_frame)
    
    def create_button_frame(self, parent):
        """Crear frame con botones de acción."""
        btn_frame = ttk.Frame(parent)
        btn_frame.grid(row=1, column=0, pady=(0, 10), sticky=(tk.W, tk.E))
        
        # Fila 1: Operaciones de servidores
        row1 = ttk.Frame(btn_frame)
        row1.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(row1, text="➕ Nuevo Servidor",
                  command=self.add_server).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="✏️ Editar",
                  command=self.edit_server).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="🗑️ Eliminar",
                  command=self.delete_server).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="🔌 Probar Conexión",
                  command=self.test_connection).pack(side=tk.LEFT, padx=2)
        ttk.Button(row1, text="📄 Ver Código de Ejemplo",
                  command=self.show_usage_example).pack(side=tk.RIGHT, padx=2)
        
        # Fila 2: Seguridad y herramientas
        row2 = ttk.Frame(btn_frame)
        row2.pack(fill=tk.X)
        
        ttk.Button(row2, text="🔑 Gestionar API Keys",
                  command=self.manage_api_keys).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2, text="🔐 Configurar 2FA",
                  command=self.configure_2fa).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2, text="🔒 Cambiar Contraseña Maestra",
                  command=self.change_master_password).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2, text="📋 Ver Logs",
                  command=self.view_logs).pack(side=tk.LEFT, padx=2)
        ttk.Button(row2, text="💾 Backup",
                  command=self.create_backup).pack(side=tk.LEFT, padx=2)
    
    def create_server_list(self, parent):
        """Crear lista de servidores."""
        list_frame = ttk.LabelFrame(parent, text="Servidores Configurados", padding="5")
        list_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        columns = ('Nombre', 'Servidor', 'Base de Datos', 'Usuario', 'Puerto', 'Tipo Auth', '2FA')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # Configurar columnas
        widths = {'Nombre': 120, 'Servidor': 150, 'Base de Datos': 120,
                 'Usuario': 100, 'Puerto': 60, 'Tipo Auth': 120, '2FA': 50}
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=widths.get(col, 100))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
    
    def create_footer(self, parent):
        """Crear footer con información."""
        info_text = (
            f"✅ Encriptación AES-256 | 📁 Ubicación: {BASE_DIR}\n"
            f"🔧 Tipos de auth: SQL, Windows, Certificate, JWT, SSH Tunnel"
        )
        info_label = ttk.Label(parent, text=info_text, foreground="gray", font=('Arial', 8))
        info_label.grid(row=3, column=0, sticky=(tk.W, tk.E))
    
    def refresh_list(self):
        """Actualizar lista de servidores."""
        # Limpiar
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        if not self.master_password:
            return
        
        # Cargar credenciales
        try:
            self.credentials = self.storage.load_credentials(self.master_password)
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar credenciales:\n{e}")
            return
        
        # Llenar lista
        from ..security.totp_manager import TOTPManager
        totp_manager = TOTPManager()
        
        for name, config in self.credentials.items():
            auth_type = config.get('auth_type', 'sql_auth')
            provider = ProviderRegistry.get_provider_display_name(auth_type)
            
            # Verificar si tiene 2FA
            has_2fa = "✓" if totp_manager.is_enabled(name, self.master_password) else ""
            
            username = config.get('username', '')
            if auth_type == 'windows_auth':
                username = 'Windows Auth'
            
            self.tree.insert('', tk.END, values=(
                name,
                config.get('server', ''),
                config.get('database', ''),
                username,
                config.get('port', 1433),
                provider,
                has_2fa
            ))
    
    def add_server(self):
        """Agregar nuevo servidor."""
        if not self.master_password:
            messagebox.showwarning("Advertencia", "Primero debe autenticarse")
            return
        
        dialog = ServerDialog(self.root, "Agregar Servidor")
        if dialog.result:
            name = dialog.result['name']
            if name in self.credentials:
                messagebox.showerror("Error", f"El servidor '{name}' ya existe")
                return
            
            # Guardar
            try:
                self.storage.add_server(name, dialog.result, self.master_password)
                self.refresh_list()
                messagebox.showinfo("✅ Éxito", f"Servidor '{name}' agregado")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar:\n{e}")
    
    def edit_server(self):
        """Editar servidor seleccionado."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Advertencia", "Seleccione un servidor")
            return
        
        server_name = self.tree.item(selection[0])['values'][0]
        current_data = self.credentials[server_name].copy()
        current_data['name'] = server_name
        
        dialog = ServerDialog(self.root, f"Editar: {server_name}", current_data)
        if dialog.result:
            try:
                self.storage.add_server(server_name, dialog.result, self.master_password)
                self.refresh_list()
                messagebox.showinfo("✅ Éxito", "Servidor actualizado")
            except Exception as e:
                messagebox.showerror("Error", f"Error al actualizar:\n{e}")
    
    def delete_server(self):
        """Eliminar servidor."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Advertencia", "Seleccione un servidor")
            return
        
        server_name = self.tree.item(selection[0])['values'][0]
        
        if messagebox.askyesno("Confirmar", f"¿Eliminar '{server_name}'?"):
            try:
                self.storage.remove_server(server_name, self.master_password)
                self.refresh_list()
                messagebox.showinfo("✅ Éxito", "Servidor eliminado")
            except Exception as e:
                messagebox.showerror("Error", f"Error al eliminar:\n{e}")
    
    def test_connection(self):
        """Probar conexión al servidor."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Advertencia", "Seleccione un servidor")
            return
        
        server_name = self.tree.item(selection[0])['values'][0]
        server_config = self.credentials[server_name]
        
        try:
            success, message = self.connector.test_connection(
                server_config,
                self.master_password
            )
            
            if success:
                messagebox.showinfo("✅ Éxito", f"Conexión exitosa a '{server_name}'")
            else:
                messagebox.showerror("❌ Error", f"Falló la conexión:\n{message}")
                
        except Exception as e:
            messagebox.showerror("❌ Error", f"Error al conectar:\n{e}")
    
    def manage_api_keys(self):
        """Abrir diálogo de gestión de API keys."""
        if not self.master_password:
            messagebox.showwarning("Advertencia", "Primero debe autenticarse")
            return
        
        APIKeyDialog(self.root, self.master_password)
    
    def configure_2fa(self):
        """Configurar 2FA para un servidor."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Advertencia", "Seleccione un servidor")
            return
        
        server_name = self.tree.item(selection[0])['values'][0]
        server_config = self.credentials[server_name]
        
        TOTPSetupDialog(self.root, server_name, server_config, self.master_password)
        self.refresh_list()
    
    def change_master_password(self):
        """Cambiar contraseña maestra."""
        from .dialogs.password_dialog import ChangeMasterPasswordDialog
        
        dialog = ChangeMasterPasswordDialog(self.root, self.master_password)
        if dialog.success:
            # Actualizar todas las credenciales con nueva contraseña
            try:
                # Cargar con contraseña actual
                credentials = self.storage.load_credentials(self.master_password)
                
                # Guardar con nueva contraseña
                self.storage.save_credentials(credentials, dialog.new_password)
                
                # Actualizar contraseña maestra
                self.master_password = dialog.new_password
                
                messagebox.showinfo("✅ Éxito", "Contraseña maestra cambiada correctamente")
                
            except Exception as e:
                messagebox.showerror("Error", f"Error al cambiar contraseña:\n{e}")
    
    def view_logs(self):
        """Ver logs de auditoría."""
        from ..security.audit_logger import AuditLogger
        
        try:
            audit_logger = AuditLogger()
            logs = audit_logger.get_recent_logs(50)
            
            if not logs:
                messagebox.showinfo("Info", "No hay logs disponibles")
                return
            
            # Crear ventana de logs
            log_window = tk.Toplevel(self.root)
            log_window.title("Logs de Auditoría")
            log_window.geometry("800x600")
            log_window.transient(self.root)
            
            # Text widget con scrollbar
            frame = ttk.Frame(log_window, padding="10")
            frame.pack(fill=tk.BOTH, expand=True)
            
            text_widget = tk.Text(frame, wrap=tk.WORD, font=('Courier', 9))
            scrollbar = ttk.Scrollbar(frame, command=text_widget.yview)
            text_widget.configure(yscrollcommand=scrollbar.set)
            
            text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Insertar logs
            for log_line in logs:
                text_widget.insert(tk.END, log_line)
            
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar logs:\n{e}")
    
    def create_backup(self):
        """Crear backup."""
        if not self.master_password:
            messagebox.showwarning("Advertencia", "Primero debe autenticarse")
            return
        
        try:
            from ..backup.backup_manager import BackupManager
            
            backup_manager = BackupManager()
            backup_path = backup_manager.create_backup(
                self.master_password,
                include_api_keys=True,
                include_totp=True
            )
            
            messagebox.showinfo(
                "✅ Éxito",
                f"Backup creado exitosamente:\n{backup_path}"
            )
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al crear backup:\n{e}")
    
    def show_usage_example(self):
        """Mostrar ventana con código de ejemplo."""
        ExampleCodeWindow(self.root, str(BASE_DIR))
    
    def authenticate(self) -> bool:
        """Autenticar con contraseña maestra."""
        dialog = MasterPasswordDialog(self.root)
        if dialog.password:
            self.master_password = dialog.password
            return True
        return False
    
    def run(self):
        """Ejecutar aplicación."""
        if self.authenticate():
            self.refresh_list()
            self.root.mainloop()
        else:
            self.root.destroy()


class ExampleCodeWindow:
    """Ventana para mostrar código de ejemplo."""
    
    def __init__(self, parent, data_dir):
        self.window = tk.Toplevel(parent)
        self.window.title("Código de Ejemplo - Cómo usar en tus scripts")
        self.window.geometry("900x700")
        self.window.transient(parent)
        
        self.create_widgets(data_dir)
    
    def create_widgets(self, data_dir):
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="📄 Copia este código en tus scripts", 
                 font=('Arial', 12, 'bold')).pack(pady=(0, 10))
        
        # Notebook para diferentes ejemplos
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Tab 1: API Simple
        simple_frame = ttk.Frame(notebook)
        notebook.add(simple_frame, text="API Simple (db_connector)")
        
        simple_text = tk.Text(simple_frame, wrap=tk.WORD, font=('Courier', 9))
        simple_text.pack(fill=tk.BOTH, expand=True)
        
        simple_scrollbar = ttk.Scrollbar(simple_text, command=simple_text.yview)
        simple_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        simple_text.config(yscrollcommand=simple_scrollbar.set)
        
        simple_code = f'''# ===================================================================
# API SIMPLE - USA db_connector.py
# ===================================================================

from db_connector import connect_to_sql, load_sql_credentials

# Ejemplo 1: Conexión simple
# --------------------------
try:
    conn = connect_to_sql('MiServidor')
    cursor = conn.cursor()
    cursor.execute("SELECT TOP 5 * FROM INFORMATION_SCHEMA.TABLES")
    
    for row in cursor.fetchall():
        print(row)
    
    conn.close()
    print("✅ Consulta exitosa")
    
except Exception as e:
    print(f"❌ Error: {{e}}")


# Ejemplo 2: Con contraseña en variable de entorno
# ------------------------------------------------
import os
master_pass = os.getenv('SQL_MASTER_PASSWORD')
conn = connect_to_sql('MiServidor', master_password=master_pass)


# Ejemplo 3: Solo cargar credenciales (sin conectar)
# --------------------------------------------------
creds = load_sql_credentials('MiServidor')
print(f"Servidor: {{creds['server']}}")
print(f"Base de datos: {{creds['database']}}")


# Ejemplo 4: Con 2FA
# ------------------
conn = connect_to_sql('MiServidor', totp_code='123456')


# Ejemplo 5: Con API Key
# ----------------------
conn = connect_to_sql('MiServidor', api_key='sqlcred_...')
'''
        
        simple_text.insert('1.0', simple_code)
        simple_text.config(state=tk.DISABLED)
        
        # Tab 2: API Completa
        advanced_frame = ttk.Frame(notebook)
        notebook.add(advanced_frame, text="API Completa (Sistema Modular)")
        
        advanced_text = tk.Text(advanced_frame, wrap=tk.WORD, font=('Courier', 9))
        advanced_text.pack(fill=tk.BOTH, expand=True)
        
        advanced_scrollbar = ttk.Scrollbar(advanced_text, command=advanced_text.yview)
        advanced_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        advanced_text.config(yscrollcommand=advanced_scrollbar.set)
        
        advanced_code = f'''# ===================================================================
# API COMPLETA - SISTEMA MODULAR
# ===================================================================

import sys
from pathlib import Path

# Agregar al path
sys.path.insert(0, str(Path(__file__).parent))

from sql_credentials_system.core.storage import CredentialsStorage
from sql_credentials_system.core.config import CREDENTIALS_FILE
from sql_credentials_system.database.connector import DatabaseConnector
from sql_credentials_system.security.totp_manager import TOTPManager
from sql_credentials_system.security.api_key_manager import APIKeyManager


# Ejemplo 1: Conexión con el conector completo
# --------------------------------------------
def conectar_con_sistema_completo():
    storage = CredentialsStorage(CREDENTIALS_FILE)
    connector = DatabaseConnector()
    
    # Cargar credenciales
    master_password = input("Contraseña maestra: ")
    credentials = storage.load_credentials(master_password)
    
    server_config = credentials['MiServidor']
    
    # Verificar 2FA si está habilitado
    totp_manager = TOTPManager()
    totp_code = None
    if totp_manager.is_enabled('MiServidor', master_password):
        totp_code = input("Código 2FA: ")
    
    # Conectar
    conn = connector.connect(
        server_config,
        master_password,
        totp_code=totp_code
    )
    
    return conn


# Ejemplo 2: Usar connection pool
# ------------------------------
from sql_credentials_system.database.connection_pool import pool_manager

def usar_connection_pool():
    storage = CredentialsStorage(CREDENTIALS_FILE)
    connector = DatabaseConnector()
    master_password = input("Contraseña maestra: ")
    
    credentials = storage.load_credentials(master_password)
    server_config = credentials['MiServidor']
    
    # Obtener pool
    pool = pool_manager.get_pool(
        'MiServidor',
        server_config,
        connector,
        master_password
    )
    
    # Usar con context manager
    with pool.connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        print(f"Resultado: {{result}}")


# Ejemplo 3: Ejecutar query con reintentos
# ----------------------------------------
from sql_credentials_system.database.retry_handler import retry_on_failure

@retry_on_failure(max_attempts=3, base_delay=1.0)
def query_con_reintentos():
    conn = conectar_con_sistema_completo()
    cursor = conn.cursor()
    cursor.execute("SELECT @@VERSION")
    return cursor.fetchone()


# Ejemplo 4: Gestionar API Keys
# -----------------------------
def crear_api_key():
    from sql_credentials_system.security.api_key_manager import APIKeyManager
    
    api_manager = APIKeyManager()
    master_password = input("Contraseña maestra: ")
    
    key_info = api_manager.create_key(
        name="MiScript_Automatizado",
        server_name="MiServidor",
        password=master_password,
        expires_days=90
    )
    
    print(f"🔑 API Key creada: {{key_info['api_key']}}")
    return key_info['api_key']


# Ejemplo 5: Script completo de ejemplo
# -------------------------------------
if __name__ == "__main__":
    try:
        # Opción 1: API Simple
        from db_connector import connect_to_sql
        conn = connect_to_sql('MiServidor')
        
        # Opción 2: Sistema completo
        # conn = conectar_con_sistema_completo()
        
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES")
        count = cursor.fetchone()[0]
        print(f"Total de tablas: {{count}}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error: {{e}}")
'''
        
        advanced_text.insert('1.0', advanced_code)
        advanced_text.config(state=tk.DISABLED)
        
        # Tab 3: CLI Examples
        cli_frame = ttk.Frame(notebook)
        notebook.add(cli_frame, text="Ejemplos CLI")
        
        cli_text = tk.Text(cli_frame, wrap=tk.WORD, font=('Courier', 9))
        cli_text.pack(fill=tk.BOTH, expand=True)
        
        cli_scrollbar = ttk.Scrollbar(cli_text, command=cli_text.yview)
        cli_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        cli_text.config(yscrollcommand=cli_scrollbar.set)
        
        cli_code = '''# ===================================================================
# EJEMPLOS DE USO CLI
# ===================================================================

# Ejecutar desde terminal/command prompt:

# Listar servidores configurados
python -m sql_credentials_system.cli list

# Agregar nuevo servidor
python -m sql_credentials_system.cli add MiNuevoServidor

# Probar conexión
python -m sql_credentials_system.cli test MiServidor

# Ejecutar query SQL
python -m sql_credentials_system.cli query MiServidor "SELECT TOP 5 * FROM Users"

# Gestionar API Keys
python -m sql_credentials_system.cli apikeys list
python -m sql_credentials_system.cli apikeys create MiKey MiServidor

# Configurar 2FA
python -m sql_credentials_system.cli 2fa setup MiServidor

# Usar CLI desde Python
# ---------------------
import subprocess

# Ejecutar comando CLI
result = subprocess.run([
    'python', '-m', 'sql_credentials_system.cli', 
    'query', 'MiServidor', 'SELECT 1'
], capture_output=True, text=True)

print(result.stdout)


# Alternativa: usar entry point principal
# ---------------------------------------
# Ejecutar en terminal:
python secure_credentials_manager.py --cli
'''
        
        cli_text.insert('1.0', cli_code)
        cli_text.config(state=tk.DISABLED)
        
        # Botones
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="📋 Copiar Código Simple", 
                  command=lambda: self.copy_to_clipboard(simple_code)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="💾 Guardar ejemplo como archivo", 
                  command=lambda: self.save_to_file(simple_code, data_dir)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cerrar", 
                  command=self.window.destroy).pack(side=tk.LEFT, padx=5)
    
    def copy_to_clipboard(self, text):
        self.window.clipboard_clear()
        self.window.clipboard_append(text)
        messagebox.showinfo("✅ Éxito", "Código copiado al portapapeles")
    
    def save_to_file(self, text, data_dir):
        import os
        filepath = os.path.join(data_dir, "ejemplo_conexion_db.py")
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(text)
            messagebox.showinfo("✅ Éxito", f"Archivo guardado en:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar:\n{str(e)}")
