"""
Diálogo de contraseña maestra.
"""
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

from ...core.crypto import CryptoManager
from ...core.config import BASE_DIR


class MasterPasswordDialog:
    """Diálogo para contraseña maestra (crear o verificar)."""
    
    def __init__(self, parent):
        self.password = None
        self.crypto = CryptoManager()
        
        # Archivos de autenticación
        self.key_file = BASE_DIR / "master.key"
        self.salt_file = BASE_DIR / "salt.bin"
        
        # Verificar si es primera vez
        self.is_first_time = not self.key_file.exists()
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Autenticación" if not self.is_first_time else "Configuración Inicial")
        self.dialog.geometry("450x340" if self.is_first_time else "400x200")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.center_dialog(parent)
        self.create_widgets()
        self.dialog.wait_window()
    
    def center_dialog(self, parent):
        """Centrar diálogo."""
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        """Crear widgets."""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        if self.is_first_time:
            self.create_setup_widgets(main_frame)
        else:
            self.create_verify_widgets(main_frame)
    
    def create_setup_widgets(self, parent):
        """Widgets para configuración inicial."""
        ttk.Label(parent, text="🔐 Configuración Inicial",
                 font=('Arial', 14, 'bold')).pack(pady=(0, 10))
        
        info_text = (
            "Crea una contraseña maestra para proteger tus credenciales.\n\n"
            "Requisitos:\n"
            "• Mínimo 8 caracteres\n"
            "• Al menos una mayúscula\n"
            "• Al menos una minúscula\n"
            "• Al menos un número"
        )
        ttk.Label(parent, text=info_text, justify=tk.LEFT).pack(pady=(0, 15))
        
        # Campos
        ttk.Label(parent, text="Contraseña maestra:").pack(anchor=tk.W)
        self.pass1_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.pass1_var, show="*", width=40).pack(pady=(0, 10), fill=tk.X)
        
        ttk.Label(parent, text="Confirmar contraseña:").pack(anchor=tk.W)
        self.pass2_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.pass2_var, show="*", width=40).pack(pady=(0, 20), fill=tk.X)
        
        # Botones
        btn_frame = ttk.Frame(parent)
        btn_frame.pack()
        
        ttk.Button(btn_frame, text="Crear", command=self.setup_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancelar", command=self.cancel).pack(side=tk.LEFT)
    
    def create_verify_widgets(self, parent):
        """Widgets para verificar contraseña."""
        ttk.Label(parent, text="🔐 Autenticación",
                 font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        ttk.Label(parent, text="Ingrese contraseña maestra:").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(parent, textvariable=self.password_var, show="*", width=40)
        password_entry.pack(pady=(0, 20), fill=tk.X)
        password_entry.focus()
        
        # Enter para verificar
        password_entry.bind('<Return>', lambda e: self.verify_password())
        
        # Botones
        btn_frame = ttk.Frame(parent)
        btn_frame.pack()
        
        ttk.Button(btn_frame, text="Ingresar", command=self.verify_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancelar", command=self.cancel).pack(side=tk.LEFT)
    
    def setup_password(self):
        """Configurar contraseña maestra inicial."""
        pass1 = self.pass1_var.get()
        pass2 = self.pass2_var.get()
        
        # Validar
        from ...utils.validators import Validator
        is_valid, error = Validator.validate_master_password(pass1)
        
        if not is_valid:
            messagebox.showerror("Error", error)
            return
        
        if pass1 != pass2:
            messagebox.showerror("Error", "Las contraseñas no coinciden")
            return
        
        try:
            # Generar salt
            salt = self.crypto.generate_salt()
            
            # Guardar salt
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            
            # Guardar hash de contraseña
            password_hash = self.crypto.hash_password(pass1)
            with open(self.key_file, 'w') as f:
                f.write(password_hash)
            
            self.password = pass1
            
            messagebox.showinfo(
                "✅ Éxito",
                "Contraseña maestra configurada correctamente.\n\n"
                "⚠️ IMPORTANTE: No olvides esta contraseña.\n"
                "No hay forma de recuperarla si la pierdes."
            )
            
            self.dialog.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al configurar contraseña:\n{e}")
    
    def verify_password(self):
        """Verificar contraseña maestra existente."""
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Ingrese la contraseña")
            return
        
        try:
            # Cargar hash almacenado
            with open(self.key_file, 'r') as f:
                stored_hash = f.read().strip()
            
            # Verificar
            computed_hash = self.crypto.hash_password(password)
            
            if computed_hash == stored_hash:
                self.password = password
                self.dialog.destroy()
            else:
                messagebox.showerror("Error", "Contraseña incorrecta")
                self.password_var.set('')
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar contraseña:\n{e}")
    
    def cancel(self):
        """Cancelar."""
        self.dialog.destroy()


class ChangeMasterPasswordDialog:
    """Diálogo para cambiar contraseña maestra."""
    
    def __init__(self, parent, current_password: str):
        self.current_password = current_password
        self.new_password = None
        self.success = False
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Cambiar Contraseña Maestra")
        self.dialog.geometry("450x320")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.create_widgets()
        self.center_dialog(parent)
        self.dialog.wait_window()
    
    def center_dialog(self, parent):
        """Centrar diálogo."""
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def create_widgets(self):
        """Crear widgets."""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="🔒 Cambiar Contraseña Maestra",
                 font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Contraseña actual
        ttk.Label(main_frame, text="Contraseña actual:").pack(anchor=tk.W)
        self.old_pass_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.old_pass_var, show="*", width=40).pack(pady=(0, 10), fill=tk.X)
        
        ttk.Separator(main_frame, orient='horizontal').pack(fill=tk.X, pady=10)
        
        # Nueva contraseña
        ttk.Label(main_frame, text="Nueva contraseña:").pack(anchor=tk.W)
        self.new_pass1_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.new_pass1_var, show="*", width=40).pack(pady=(0, 10), fill=tk.X)
        
        ttk.Label(main_frame, text="Confirmar nueva contraseña:").pack(anchor=tk.W)
        self.new_pass2_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.new_pass2_var, show="*", width=40).pack(pady=(0, 20), fill=tk.X)
        
        # Botones
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack()
        
        ttk.Button(btn_frame, text="Cambiar", command=self.change_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancelar", command=self.cancel).pack(side=tk.LEFT)
    
    def change_password(self):
        """Cambiar contraseña."""
        old_pass = self.old_pass_var.get()
        new_pass1 = self.new_pass1_var.get()
        new_pass2 = self.new_pass2_var.get()
        
        # Validar contraseña actual
        if old_pass != self.current_password:
            messagebox.showerror("Error", "La contraseña actual es incorrecta")
            return
        
        # Validar nueva contraseña
        from ...utils.validators import Validator
        is_valid, error = Validator.validate_master_password(new_pass1)
        
        if not is_valid:
            messagebox.showerror("Error", error)
            return
        
        if new_pass1 != new_pass2:
            messagebox.showerror("Error", "Las contraseñas nuevas no coinciden")
            return
        
        if old_pass == new_pass1:
            messagebox.showerror("Error", "La nueva contraseña debe ser diferente a la actual")
            return
        
        self.new_password = new_pass1
        self.success = True
        self.dialog.destroy()
    
    def cancel(self):
        """Cancelar."""
        self.dialog.destroy()