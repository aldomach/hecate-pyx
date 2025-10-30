"""
Diálogo para agregar/editar servidores con soporte multi-autenticación.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Optional, Dict

from ...auth_providers.base_provider import ProviderRegistry


class ServerDialog:
    """Diálogo para configurar un servidor."""
    
    def __init__(self, parent, title: str, data: Optional[Dict] = None):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("550x600")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.current_auth_type = data.get('auth_type', 'sql_auth') if data else 'sql_auth'
        self.dynamic_fields = {}
        
        self.center_dialog(parent)
        self.create_widgets(data)
        self.dialog.wait_window()
    
    def center_dialog(self, parent):
        """Centrar diálogo."""
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def create_widgets(self, data):
        """Crear widgets."""
        main_frame = ttk.Frame(self.dialog, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Variables básicas
        self.name_var = tk.StringVar(value=data.get('name', '') if data else '')
        self.server_var = tk.StringVar(value=data.get('server', '') if data else '')
        self.database_var = tk.StringVar(value=data.get('database', '') if data else '')
        self.port_var = tk.StringVar(value=str(data.get('port', 1433)) if data else '1433')
        
        # Frame fijo (siempre visible)
        fixed_frame = ttk.LabelFrame(main_frame, text="Configuración Básica", padding="10")
        fixed_frame.pack(fill=tk.X, pady=(0, 10))
        
        row = 0
        ttk.Label(fixed_frame, text="Nombre identificador:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(fixed_frame, textvariable=self.name_var, width=40).grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5)
        
        row += 1
        ttk.Label(fixed_frame, text="Servidor:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(fixed_frame, textvariable=self.server_var, width=40).grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5)
        
        row += 1
        ttk.Label(fixed_frame, text="Base de datos:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(fixed_frame, textvariable=self.database_var, width=40).grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5)
        
        row += 1
        ttk.Label(fixed_frame, text="Puerto:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(fixed_frame, textvariable=self.port_var, width=40).grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5)
        
        fixed_frame.columnconfigure(1, weight=1)
        
        # Tipo de autenticación
        auth_frame = ttk.LabelFrame(main_frame, text="Tipo de Autenticación", padding="10")
        auth_frame.pack(fill=tk.X, pady=(0, 10))
        
        providers = ProviderRegistry.list_providers()
        provider_names = [display for _, display in providers]
        provider_map = {display: name for name, display in providers}
        
        self.auth_type_var = tk.StringVar(
            value=ProviderRegistry.get_provider_display_name(self.current_auth_type)
        )
        
        ttk.Label(auth_frame, text="Tipo:").pack(side=tk.LEFT, padx=(0, 10))
        auth_combo = ttk.Combobox(
            auth_frame,
            textvariable=self.auth_type_var,
            values=provider_names,
            state='readonly',
            width=35
        )
        auth_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        auth_combo.bind('<<ComboboxSelected>>', lambda e: self.on_auth_type_changed(provider_map))
        
        # Frame dinámico (campos según tipo de auth)
        self.dynamic_frame = ttk.LabelFrame(main_frame, text="Credenciales", padding="10")
        self.dynamic_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Crear campos dinámicos iniciales
        self.create_dynamic_fields(data, provider_map)
        
        # Botones
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=(10, 0))
        
        ttk.Button(btn_frame, text="Guardar", command=lambda: self.save(provider_map)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancelar", command=self.cancel).pack(side=tk.LEFT)
    
    def on_auth_type_changed(self, provider_map):
        """Cambiar campos dinámicos según tipo de auth."""
        display_name = self.auth_type_var.get()
        self.current_auth_type = provider_map.get(display_name, 'sql_auth')
        self.create_dynamic_fields(None, provider_map)
    
    def create_dynamic_fields(self, data, provider_map):
        """Crear campos según tipo de autenticación."""
        # Limpiar campos existentes
        for widget in self.dynamic_frame.winfo_children():
            widget.destroy()
        
        self.dynamic_fields.clear()
        
        # Obtener tipo actual
        display_name = self.auth_type_var.get()
        auth_type = provider_map.get(display_name, 'sql_auth')
        
        # Crear campos según auth_type
        if auth_type == 'sql_auth':
            self.create_sql_fields(data)
        elif auth_type == 'windows_auth':
            self.create_windows_fields()
        elif auth_type == 'certificate_auth':
            self.create_certificate_fields(data)
        elif auth_type == 'jwt_auth':
            self.create_jwt_fields(data)
        elif auth_type == 'ssh_tunnel':
            self.create_ssh_tunnel_fields(data)
    
    def create_sql_fields(self, data):
        """Campos para SQL Authentication."""
        self.dynamic_fields['username'] = tk.StringVar(value=data.get('username', '') if data else '')
        self.dynamic_fields['password'] = tk.StringVar(value=data.get('password', '') if data else '')
        
        ttk.Label(self.dynamic_frame, text="Usuario:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(self.dynamic_frame, textvariable=self.dynamic_fields['username'], width=40).grid(row=0, column=1, pady=5)
        
        ttk.Label(self.dynamic_frame, text="Contraseña:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(self.dynamic_frame, textvariable=self.dynamic_fields['password'], show='*', width=40).grid(row=1, column=1, pady=5)
    
    def create_windows_fields(self):
        """Campos para Windows Authentication."""
        info_label = ttk.Label(
            self.dynamic_frame,
            text="Windows Authentication usa las credenciales del usuario actual.\nNo se requieren credenciales adicionales.",
            foreground="gray"
        )
        info_label.pack(pady=20)
    
    def create_certificate_fields(self, data):
        """Campos para Certificate Authentication."""
        self.dynamic_fields['certificate_path'] = tk.StringVar(value=data.get('certificate_path', '') if data else '')
        self.dynamic_fields['certificate_password'] = tk.StringVar(value=data.get('certificate_password', '') if data else '')
        
        ttk.Label(self.dynamic_frame, text="Certificado (.pfx):").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        cert_frame = ttk.Frame(self.dynamic_frame)
        cert_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        ttk.Entry(cert_frame, textvariable=self.dynamic_fields['certificate_path'], width=30).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(cert_frame, text="...", width=3, command=self.browse_certificate).pack(side=tk.LEFT, padx=(5, 0))
        
        ttk.Label(self.dynamic_frame, text="Contraseña Cert:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(self.dynamic_frame, textvariable=self.dynamic_fields['certificate_password'], show='*', width=40).grid(row=1, column=1, pady=5)
    
    def create_jwt_fields(self, data):
        """Campos para JWT Authentication."""
        self.dynamic_fields['access_token'] = tk.StringVar(value=data.get('access_token', '') if data else '')
        
        ttk.Label(self.dynamic_frame, text="Access Token:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        token_text = tk.Text(self.dynamic_frame, height=4, width=40, wrap=tk.WORD)
        token_text.grid(row=0, column=1, pady=5)
        if data and data.get('access_token'):
            token_text.insert('1.0', data.get('access_token'))
        
        self.dynamic_fields['access_token_widget'] = token_text
    
    def create_ssh_tunnel_fields(self, data):
        """Campos para SSH Tunnel."""
        fields = {
            'ssh_host': data.get('ssh_host', '') if data else '',
            'ssh_port': str(data.get('ssh_port', 22)) if data else '22',
            'ssh_username': data.get('ssh_username', '') if data else '',
            'ssh_password': data.get('ssh_password', '') if data else '',
            'sql_username': data.get('sql_username', '') if data else '',
            'sql_password': data.get('sql_password', '') if data else ''
        }
        
        # SSH Config
        ssh_frame = ttk.LabelFrame(self.dynamic_frame, text="Configuración SSH", padding="5")
        ssh_frame.pack(fill=tk.X, pady=(0, 10))
        
        row = 0
        for field, label in [('ssh_host', 'Host SSH:'), ('ssh_port', 'Puerto SSH:'),
                             ('ssh_username', 'Usuario SSH:'), ('ssh_password', 'Password SSH:')]:
            self.dynamic_fields[field] = tk.StringVar(value=fields[field])
            ttk.Label(ssh_frame, text=label).grid(row=row, column=0, sticky=tk.W, pady=3)
            entry = ttk.Entry(ssh_frame, textvariable=self.dynamic_fields[field], width=35)
            if 'password' in field:
                entry.config(show='*')
            entry.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=3)
            row += 1
        
        # SQL Config
        sql_frame = ttk.LabelFrame(self.dynamic_frame, text="Credenciales SQL (a través del túnel)", padding="5")
        sql_frame.pack(fill=tk.X)
        
        row = 0
        for field, label in [('sql_username', 'Usuario SQL:'), ('sql_password', 'Password SQL:')]:
            self.dynamic_fields[field] = tk.StringVar(value=fields[field])
            ttk.Label(sql_frame, text=label).grid(row=row, column=0, sticky=tk.W, pady=3)
            entry = ttk.Entry(sql_frame, textvariable=self.dynamic_fields[field], width=35)
            if 'password' in field:
                entry.config(show='*')
            entry.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=3)
            row += 1
    
    def browse_certificate(self):
        """Buscar archivo de certificado."""
        filename = filedialog.askopenfilename(
            title="Seleccionar certificado",
            filetypes=[("Certificados", "*.pfx *.p12"), ("Todos", "*.*")]
        )
        if filename:
            self.dynamic_fields['certificate_path'].set(filename)
    
    def save(self, provider_map):
        """Guardar configuración."""
        # Validar campos básicos
        if not self.name_var.get().strip():
            messagebox.showerror("Error", "El nombre es obligatorio")
            return
        
        if not self.server_var.get().strip():
            messagebox.showerror("Error", "El servidor es obligatorio")
            return
        
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Error", "El puerto debe ser un número")
            return
        
        # Obtener auth_type
        display_name = self.auth_type_var.get()
        auth_type = provider_map.get(display_name, 'sql_auth')
        
        # Construir resultado
        self.result = {
            'name': self.name_var.get().strip(),
            'server': self.server_var.get().strip(),
            'database': self.database_var.get().strip(),
            'port': port,
            'auth_type': auth_type
        }
        
        # Agregar campos dinámicos
        for field_name, field_var in self.dynamic_fields.items():
            if field_name == 'access_token_widget':
                # Campo de texto especial
                self.result['access_token'] = field_var.get('1.0', tk.END).strip()
            else:
                self.result[field_name] = field_var.get()
        
        self.dialog.destroy()
    
    def cancel(self):
        """Cancelar."""
        self.dialog.destroy()