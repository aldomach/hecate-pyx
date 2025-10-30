"""
Diálogo para configurar 2FA/TOTP (Google Authenticator).
"""
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
from io import BytesIO

from ...security.totp_manager import TOTPManager


class TOTPSetupDialog:
    """Diálogo para configurar 2FA."""
    
    def __init__(self, parent, server_name: str, server_config: dict, master_password: str):
        self.server_name = server_name
        self.server_config = server_config
        self.master_password = master_password
        self.totp_manager = TOTPManager()
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"Configurar 2FA - {server_name}")
        self.dialog.geometry("500x650")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.check_existing_2fa()
        self.center_dialog(parent)
        self.dialog.wait_window()
    
    def center_dialog(self, parent):
        """Centrar diálogo."""
        self.dialog.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def check_existing_2fa(self):
        """Verificar si ya tiene 2FA configurado."""
        if self.totp_manager.is_enabled(self.server_name, self.master_password):
            self.show_existing_2fa()
        else:
            self.show_setup_2fa()
    
    def show_existing_2fa(self):
        """Mostrar opciones si ya tiene 2FA."""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="✅ 2FA ya configurado",
                 font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        info_text = (
            f"El servidor '{self.server_name}' ya tiene\n"
            "autenticación de dos factores (2FA) habilitada."
        )
        ttk.Label(main_frame, text=info_text).pack(pady=(0, 30))
        
        # Botones
        ttk.Button(main_frame, text="🔄 Reconfigurar 2FA",
                  command=self.reconfigure_2fa).pack(pady=5, fill=tk.X)
        ttk.Button(main_frame, text="❌ Deshabilitar 2FA",
                  command=self.disable_2fa).pack(pady=5, fill=tk.X)
        ttk.Button(main_frame, text="🗑️ Eliminar Secret",
                  command=self.delete_secret).pack(pady=5, fill=tk.X)
        ttk.Button(main_frame, text="Cerrar",
                  command=self.dialog.destroy).pack(pady=(20, 0))
    
    def show_setup_2fa(self):
        """Mostrar configuración de 2FA."""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        ttk.Label(main_frame, text="🔐 Configurar Autenticación 2FA",
                 font=('Arial', 14, 'bold')).pack(pady=(0, 10))
        
        # Instrucciones
        instructions = (
            "1. Instala Google Authenticator o similar en tu móvil\n"
            "2. Escanea el código QR con la app\n"
            "3. Ingresa el código de 6 dígitos para verificar"
        )
        ttk.Label(main_frame, text=instructions, justify=tk.LEFT).pack(pady=(0, 15))
        
        # Generar secret y QR
        self.secret = self.totp_manager.generate_secret(self.server_name)
        username = self.server_config.get('username', '')
        provisioning_uri = self.totp_manager.get_provisioning_uri(
            self.server_name,
            self.secret,
            username
        )
        
        # Mostrar QR code
        try:
            qr_bytes = self.totp_manager.generate_qr_code(provisioning_uri)
            qr_image = Image.open(BytesIO(qr_bytes))
            qr_image = qr_image.resize((300, 300), Image.Resampling.LANCZOS)
            self.qr_photo = ImageTk.PhotoImage(qr_image)
            
            qr_label = ttk.Label(main_frame, image=self.qr_photo)
            qr_label.pack(pady=10)
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar QR:\n{e}")
        
        # Mostrar secret manual
        secret_frame = ttk.LabelFrame(main_frame, text="Secret (manual)", padding="10")
        secret_frame.pack(fill=tk.X, pady=10)
        
        secret_text = tk.Text(secret_frame, height=2, width=40, wrap=tk.WORD)
        secret_text.pack()
        secret_text.insert('1.0', self.secret)
        secret_text.config(state='disabled')
        
        ttk.Button(secret_frame, text="📋 Copiar Secret",
                  command=lambda: self.copy_to_clipboard(self.secret)).pack(pady=5)
        
        # Verificación
        verify_frame = ttk.LabelFrame(main_frame, text="Verificar Configuración", padding="10")
        verify_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(verify_frame, text="Código de 6 dígitos:").pack()
        self.code_var = tk.StringVar()
        code_entry = ttk.Entry(verify_frame, textvariable=self.code_var, width=15, font=('Arial', 14))
        code_entry.pack(pady=5)
        
        # Botones
        btn_frame = ttk.Frame(verify_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="✓ Verificar y Activar",
                  command=self.verify_and_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancelar",
                  command=self.dialog.destroy).pack(side=tk.LEFT)
    
    def verify_and_save(self):
        """Verificar código y guardar secret."""
        code = self.code_var.get().strip()
        
        if len(code) != 6 or not code.isdigit():
            messagebox.showerror("Error", "El código debe tener 6 dígitos")
            return
        
        # Verificar código
        if not self.totp_manager.verify_code(self.secret, code):
            messagebox.showerror("Error", "Código incorrecto. Intenta nuevamente.")
            return
        
        # Guardar secret
        try:
            self.totp_manager.save_secret(
                self.server_name,
                self.secret,
                self.master_password
            )
            
            messagebox.showinfo(
                "✅ Éxito",
                f"2FA configurado correctamente para '{self.server_name}'.\n\n"
                "Ahora necesitarás un código de 6 dígitos cada vez que te conectes."
            )
            
            self.dialog.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar:\n{e}")
    
    def reconfigure_2fa(self):
        """Reconfigurar 2FA."""
        if messagebox.askyesno("Confirmar", "¿Reconfigurar 2FA?\n\nDeberás escanear un nuevo código QR."):
            # Limpiar contenido y mostrar configuración
            for widget in self.dialog.winfo_children():
                widget.destroy()
            self.show_setup_2fa()
    
    def disable_2fa(self):
        """Deshabilitar 2FA."""
        if messagebox.askyesno("Confirmar", "¿Deshabilitar 2FA?\n\nPodrás conectarte sin código 2FA."):
            try:
                self.totp_manager.disable_2fa(self.server_name, self.master_password)
                messagebox.showinfo("✅ Éxito", "2FA deshabilitado")
                self.dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Error al deshabilitar:\n{e}")
    
    def delete_secret(self):
        """Eliminar secret completamente."""
        if messagebox.askyesno("Confirmar", "¿Eliminar secret permanentemente?\n\nEsta acción no se puede deshacer."):
            try:
                self.totp_manager.delete_secret(self.server_name, self.master_password)
                messagebox.showinfo("✅ Éxito", "Secret eliminado")
                self.dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Error al eliminar:\n{e}")
    
    def copy_to_clipboard(self, text):
        """Copiar al portapapeles."""
        self.dialog.clipboard_clear()
        self.dialog.clipboard_append(text)
        messagebox.showinfo("✅ Éxito", "Secret copiado al portapapeles")