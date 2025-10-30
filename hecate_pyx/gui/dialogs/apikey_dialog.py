"""
Diálogo para gestionar API Keys.
"""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Optional

from ...security.api_key_manager import APIKeyManager
from ...core.storage import CredentialsStorage
from ...core.config import CREDENTIALS_FILE


class APIKeyDialog:
    """Diálogo de gestión de API Keys."""
    
    def __init__(self, parent, master_password: str):
        self.master_password = master_password
        self.api_key_manager = APIKeyManager()
        self.storage = CredentialsStorage(CREDENTIALS_FILE)
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Gestión de API Keys")
        self.dialog.geometry("800x500")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.create_widgets()
        self.center_dialog(parent)
        self.refresh_list()
    
    def center_dialog(self, parent):
        """Centrar diálogo."""
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        """Crear widgets."""
        main_frame = ttk.Frame(self.dialog, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        title_label = ttk.Label(
            main_frame,
            text="🔑 Gestión de API Keys",
            font=('Arial', 12, 'bold')
        )
        title_label.pack(pady=(0, 10))
        
        # Info
        info_text = (
            "Las API Keys permiten acceso programático sin contraseña interactiva.\n"
            "⚠️ Guarda la key cuando la generes - solo se muestra una vez."
        )
        info_label = ttk.Label(main_frame, text=info_text, foreground="gray")
        info_label.pack(pady=(0, 10))
        
        # Botones
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(btn_frame, text="➕ Generar Nueva Key",
                  command=self.generate_key).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="❌ Revocar Key",
                  command=self.revoke_key).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="🗑️ Eliminar Key",
                  command=self.delete_key).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="ℹ️ Ver Detalles",
                  command=self.view_details).pack(side=tk.LEFT, padx=2)
        
        # Lista de keys
        list_frame = ttk.LabelFrame(main_frame, text="API Keys Activas", padding="5")
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('ID', 'Nombre', 'Servidor', 'Creada', 'Expira', 'Último Uso', 'Estado')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        widths = {'ID': 150, 'Nombre': 100, 'Servidor': 120, 'Creada': 130,
                 'Expira': 130, 'Último Uso': 130, 'Estado': 70}
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=widths.get(col, 100))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Botón cerrar
        ttk.Button(main_frame, text="Cerrar", command=self.dialog.destroy).pack(pady=(10, 0))
    
    def refresh_list(self):
        """Actualizar lista de API keys."""
        # Limpiar
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        try:
            keys = self.api_key_manager.list_keys(self.master_password)
            
            for key_data in keys:
                status = "✓ Activa" if key_data.get('active') else "✗ Revocada"
                
                self.tree.insert('', tk.END, values=(
                    key_data.get('key_id', ''),
                    key_data.get('name', ''),
                    key_data.get('server_name', ''),
                    key_data.get('created_at', '')[:19] if key_data.get('created_at') else '',
                    key_data.get('expires_at', '')[:19] if key_data.get('expires_at') else 'Nunca',
                    key_data.get('last_used', '')[:19] if key_data.get('last_used') else 'Nunca',
                    status
                ))
        
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar API keys:\n{e}")
    
    def generate_key(self):
        """Generar nueva API key."""
        # Obtener lista de servidores
        try:
            servers = self.storage.list_servers(self.master_password)
            if not servers:
                messagebox.showwarning("Advertencia", "No hay servidores configurados")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar servidores:\n{e}")
            return
        
        # Diálogo de configuración
        dialog = GenerateKeyDialog(self.dialog, servers, self.api_key_manager, self.master_password)
        
        if dialog.result:
            self.refresh_list()
    
    def revoke_key(self):
        """Revocar API key seleccionada."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Advertencia", "Seleccione una API key")
            return
        
        key_id = self.tree.item(selection[0])['values'][0]
        
        if messagebox.askyesno("Confirmar", f"¿Revocar la key '{key_id}'?\n\nNo podrá usarse más."):
            try:
                self.api_key_manager.revoke_key(key_id, self.master_password)
                self.refresh_list()
                messagebox.showinfo("✅ Éxito", "API key revocada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al revocar:\n{e}")
    
    def delete_key(self):
        """Eliminar API key permanentemente."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Advertencia", "Seleccione una API key")
            return
        
        key_id = self.tree.item(selection[0])['values'][0]
        
        if messagebox.askyesno("Confirmar", f"¿Eliminar permanentemente '{key_id}'?\n\nEsta acción no se puede deshacer."):
            try:
                self.api_key_manager.delete_key(key_id, self.master_password)
                self.refresh_list()
                messagebox.showinfo("✅ Éxito", "API key eliminada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al eliminar:\n{e}")
    
    def view_details(self):
        """Ver detalles de una API key."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Advertencia", "Seleccione una API key")
            return
        
        key_id = self.tree.item(selection[0])['values'][0]
        
        try:
            key_info = self.api_key_manager.get_key_info(key_id, self.master_password)
            
            if key_info:
                details = (
                    f"ID: {key_info.get('key_id')}\n"
                    f"Nombre: {key_info.get('name')}\n"
                    f"Servidor: {key_info.get('server_name')}\n"
                    f"Creada: {key_info.get('created_at')}\n"
                    f"Expira: {key_info.get('expires_at') or 'Nunca'}\n"
                    f"Último uso: {key_info.get('last_used') or 'Nunca'}\n"
                    f"Permisos: {', '.join(key_info.get('scopes', []))}\n"
                    f"Estado: {'Activa' if key_info.get('active') else 'Revocada'}"
                )
                messagebox.showinfo("Detalles de API Key", details)
            else:
                messagebox.showerror("Error", "No se encontró la key")
        
        except Exception as e:
            messagebox.showerror("Error", f"Error al obtener detalles:\n{e}")


class GenerateKeyDialog:
    """Diálogo para generar una nueva API key."""
    
    def __init__(self, parent, servers: list, api_key_manager: APIKeyManager, master_password: str):
        self.result = None
        self.api_key_manager = api_key_manager
        self.master_password = master_password
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Generar Nueva API Key")
        self.dialog.geometry("450x350")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.create_widgets(servers)
        self.center_dialog(parent)
        self.dialog.wait_window()
    
    def center_dialog(self, parent):
        """Centrar diálogo."""
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def create_widgets(self, servers):
        """Crear widgets."""
        main_frame = ttk.Frame(self.dialog, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Variables
        self.name_var = tk.StringVar()
        self.server_var = tk.StringVar(value=servers[0] if servers else '')
        self.expires_var = tk.StringVar(value="30")
        self.no_expiry_var = tk.BooleanVar(value=False)
        
        # Campos
        row = 0
        ttk.Label(main_frame, text="Nombre descriptivo:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Entry(main_frame, textvariable=self.name_var, width=35).grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5)
        
        row += 1
        ttk.Label(main_frame, text="Servidor:").grid(row=row, column=0, sticky=tk.W, pady=5)
        ttk.Combobox(main_frame, textvariable=self.server_var, values=servers, state='readonly', width=33).grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5)
        
        row += 1
        ttk.Checkbutton(main_frame, text="Sin expiración", variable=self.no_expiry_var, command=self.toggle_expiry).grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=10)
        
        row += 1
        self.expires_label = ttk.Label(main_frame, text="Expira en (días):")
        self.expires_label.grid(row=row, column=0, sticky=tk.W, pady=5)
        self.expires_entry = ttk.Entry(main_frame, textvariable=self.expires_var, width=35)
        self.expires_entry.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=5)
        
        row += 1
        ttk.Separator(main_frame, orient='horizontal').grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=15)
        
        row += 1
        info_text = "⚠️ La API key solo se mostrará una vez.\nGuárdala en un lugar seguro."
        ttk.Label(main_frame, text=info_text, foreground="red").grid(row=row, column=0, columnspan=2, pady=10)
        
        # Botones
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=row+1, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Generar", command=self.generate).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancelar", command=self.cancel).pack(side=tk.LEFT)
        
        main_frame.columnconfigure(1, weight=1)
    
    def toggle_expiry(self):
        """Alternar campo de expiración."""
        if self.no_expiry_var.get():
            self.expires_entry.config(state='disabled')
        else:
            self.expires_entry.config(state='normal')
    
    def generate(self):
        """Generar API key."""
        name = self.name_var.get().strip()
        server_name = self.server_var.get()
        
        if not name:
            messagebox.showerror("Error", "El nombre es obligatorio")
            return
        
        if not server_name:
            messagebox.showerror("Error", "Debe seleccionar un servidor")
            return
        
        # Expiración
        expires_days = None
        if not self.no_expiry_var.get():
            try:
                expires_days = int(self.expires_var.get())
                if expires_days <= 0:
                    raise ValueError()
            except ValueError:
                messagebox.showerror("Error", "Los días de expiración deben ser un número positivo")
                return
        
        try:
            # Generar key
            key_data = self.api_key_manager.create_key(
                name=name,
                server_name=server_name,
                password=self.master_password,
                expires_days=expires_days,
                scopes=['read', 'write']
            )
            
            api_key = key_data['api_key']
            
            # Mostrar key
            ShowKeyDialog(self.dialog, api_key, name)
            
            self.result = key_data
            self.dialog.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar API key:\n{e}")
    
    def cancel(self):
        """Cancelar."""
        self.dialog.destroy()


class ShowKeyDialog:
    """Diálogo para mostrar la API key generada."""
    
    def __init__(self, parent, api_key: str, name: str):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("API Key Generada")
        self.dialog.geometry("550x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.create_widgets(api_key, name)
        self.center_dialog(parent)
        self.dialog.wait_window()
    
    def center_dialog(self, parent):
        """Centrar diálogo."""
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def create_widgets(self, api_key: str, name: str):
        """Crear widgets."""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text=f"✅ API Key '{name}' generada con éxito",
                 font=('Arial', 12, 'bold')).pack(pady=(0, 15))
        
        warning_text = "⚠️ IMPORTANTE: Esta es la única vez que verás esta key.\nGuárdala en un lugar seguro."
        ttk.Label(main_frame, text=warning_text, foreground="red").pack(pady=(0, 10))
        
        # Mostrar key
        key_frame = ttk.LabelFrame(main_frame, text="API Key", padding="10")
        key_frame.pack(fill=tk.X, pady=(0, 15))
        
        key_text = tk.Text(key_frame, height=3, width=60, wrap=tk.WORD)
        key_text.pack()
        key_text.insert('1.0', api_key)
        key_text.config(state='disabled')
        
        # Botones
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack()
        
        ttk.Button(btn_frame, text="📋 Copiar al Portapapeles",
                  command=lambda: self.copy_to_clipboard(api_key)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cerrar", command=self.dialog.destroy).pack(side=tk.LEFT)
    
    def copy_to_clipboard(self, text):
        """Copiar al portapapeles."""
        self.dialog.clipboard_clear()
        self.dialog.clipboard_append(text)
        messagebox.showinfo("✅ Éxito", "API key copiada al portapapeles")