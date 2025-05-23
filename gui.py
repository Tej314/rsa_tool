import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from rsa import generate_keypair, encrypt_string, decrypt_string, save_key_to_file, load_key_from_file

class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption Tool")
        self.public_key = None
        self.private_key = None
        self.build_gui()

    def build_gui(self):
        tk.Label(self.root, text="Message:").grid(row=0, column=0, sticky="w")
        self.message_entry = scrolledtext.ScrolledText(self.root, height=5, width=60)
        self.message_entry.grid(row=0, column=1, columnspan=3, pady=5)

        tk.Button(self.root, text="Generate Keys", command=self.generate_keys).grid(row=1, column=0, pady=5)
        tk.Button(self.root, text="Encrypt", command=self.encrypt_message).grid(row=1, column=1)
        tk.Button(self.root, text="Decrypt", command=self.decrypt_message).grid(row=1, column=2)
        tk.Button(self.root, text="Clear", command=self.clear_text).grid(row=1, column=3)

        self.output_label = tk.Label(self.root, text="Output:")
        self.output_label.grid(row=2, column=0, sticky="nw")
        self.output_text = scrolledtext.ScrolledText(self.root, height=8, width=60)
        self.output_text.grid(row=2, column=1, columnspan=3, pady=5)

        tk.Button(self.root, text="Save Public Key", command=lambda: self.save_key(self.public_key)).grid(row=3, column=1)
        tk.Button(self.root, text="Save Private Key", command=lambda: self.save_key(self.private_key)).grid(row=3, column=2)
        tk.Button(self.root, text="Load Public Key", command=lambda: self.load_key("public")).grid(row=4, column=1)
        tk.Button(self.root, text="Load Private Key", command=lambda: self.load_key("private")).grid(row=4, column=2)

    def generate_keys(self):
        self.public_key, self.private_key = generate_keypair()
        messagebox.showinfo("Key Generation", "Keys generated successfully.")

    def encrypt_message(self):
        if not self.public_key:
            messagebox.showwarning("Missing Key", "Please generate or load a public key.")
            return
        message = self.message_entry.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Input Error", "Enter a message to encrypt.")
            return
        ciphertext = encrypt_string(message, self.public_key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, str(ciphertext))

    def decrypt_message(self):
        if not self.private_key:
            messagebox.showwarning("Missing Key", "Please generate or load a private key.")
            return
        try:
            cipher_int = int(self.message_entry.get("1.0", tk.END).strip())
            plaintext = decrypt_string(cipher_int, self.private_key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, plaintext)
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    def save_key(self, key):
        if not key:
            messagebox.showwarning("No Key", "Generate a key first.")
            return
        filepath = filedialog.asksaveasfilename(defaultextension=".txt")
        if filepath:
            save_key_to_file(key, filepath)
            messagebox.showinfo("Saved", f"Key saved to {filepath}")

    def load_key(self, key_type):
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filepath:
            key = load_key_from_file(filepath)
            if key_type == "public":
                self.public_key = key
            else:
                self.private_key = key
            messagebox.showinfo("Loaded", f"{key_type.capitalize()} key loaded from {filepath}")

    def clear_text(self):
        self.message_entry.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()

