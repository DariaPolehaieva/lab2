import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(input_file, output_file, password):
    try:
        with open(input_file, 'rb') as f:
            data = f.read()

        salt = os.urandom(16)
        key = generate_key(password, salt)
        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_data)
        mac = h.finalize()

        with open(output_file, 'wb') as f:
            f.write(salt + iv + mac + encrypted_data)

        messagebox.showinfo("success", "file successfully encrypted!")
    except Exception as e:
        messagebox.showerror("error", f"encryption error: {str(e)}")

def decrypt_file(input_file, output_file, password):
    try:
        with open(input_file, 'rb') as f:
            file_data = f.read()

        salt = file_data[:16]
        iv = file_data[16:32]
        mac = file_data[32:64]
        encrypted_data = file_data[64:]

        key = generate_key(password, salt)

        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_data)
        h.verify(mac)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        with open(output_file, 'wb') as f:
            f.write(data)

        messagebox.showinfo("success", "file successfully decrypted!")
    except Exception as e:
        messagebox.showerror("error", f"decryption error: {str(e)}")

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("AES encryption/decryption")

        self.password_label = tk.Label(root, text="password:")
        self.password_label.grid(row=0, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(root, show="*", width=30)
        self.password_entry.grid(row=0, column=1, padx=5, pady=5)

        self.encrypt_button = tk.Button(root, text="encrypt file", command=self.encrypt)
        self.encrypt_button.grid(row=1, column=0, padx=5, pady=5)

        self.decrypt_button = tk.Button(root, text="decrypt file", command=self.decrypt)
        self.decrypt_button.grid(row=1, column=1, padx=5, pady=5)

    def encrypt(self):
        input_file = filedialog.askopenfilename(title="select file to encrypt")
        if not input_file:
            return

        output_file = filedialog.asksaveasfilename(title="save encrypted file")
        if not output_file:
            return

        password = self.password_entry.get().encode()
        if not password:
            messagebox.showerror("error", "password cannot be empty!")
            return

        encrypt_file(input_file, output_file, password)

    def decrypt(self):
        input_file = filedialog.askopenfilename(title="select file to decrypt")
        if not input_file:
            return

        output_file = filedialog.asksaveasfilename(title="save decrypted file")
        if not output_file:
            return

        password = self.password_entry.get().encode()
        if not password:
            messagebox.showerror("error", "password cannot be empty!")
            return

        decrypt_file(input_file, output_file, password)

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
