import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from encryption.aes_cipher import AESCipher
from messaging_queue.message_queue import MessageQueue
import datetime

class SecureMessengerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Messaging App")
        self.root.geometry("700x500")
        self.root.configure(bg="#788fb3")
        self.queue = MessageQueue()

        style = ttk.Style()
        style.configure("TLabel", font=("Segoe UI", 12))
        style.configure("TButton", font=("Segoe UI", 11))

        ttk.Label(root, text="🔑 Secret Key:").pack(pady=(10, 0))
        self.key_entry = ttk.Entry(root, show="*", width=60)
        self.key_entry.pack(pady=(0, 10))

        ttk.Label(root, text="✉️ Message:").pack()
        self.msg_entry = ttk.Entry(root, width=60)
        self.msg_entry.pack(pady=(0, 10))

        btn_frame = ttk.Frame(root)
        btn_frame.pack()

        self.encrypt_button = ttk.Button(btn_frame, text="🔐 Encrypt & Queue", command=self.encrypt_message)
        self.encrypt_button.pack(side=tk.LEFT, padx=5)

        self.decrypt_button = ttk.Button(btn_frame, text="🔓 Decrypt Next", command=self.decrypt_message)
        self.decrypt_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(btn_frame, text="🧹 Clear Log", command=self.clear_output)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.output_text = scrolledtext.ScrolledText(root, height=15, width=85, wrap=tk.WORD, font=("Consolas", 10))
        self.output_text.pack(pady=(10, 0))

    def encrypt_message(self):
        key = self.key_entry.get()
        msg = self.msg_entry.get()
        if not key or not msg:
            messagebox.showwarning("Input Missing", "Please provide both key and message.")
            return
        try:
            cipher = AESCipher(key)
            encrypted = cipher.encrypt(msg)
            self.queue.enqueue(encrypted)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            self.output_text.insert(tk.END, f"[{timestamp}] 🔒 Encrypted & Queued: {encrypted}\n")
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_message(self):
        key = self.key_entry.get()
        if not key:
            messagebox.showwarning("Key Missing", "Please enter the key for decryption.")
            return
        if self.queue.is_empty():
            self.output_text.insert(tk.END, "⚠️ Queue is empty.\n")
            return
        encrypted = self.queue.dequeue()
        try:
            cipher = AESCipher(key)
            decrypted = cipher.decrypt(encrypted)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            self.output_text.insert(tk.END, f"[{timestamp}] ✅ Decrypted: {decrypted}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"❌ Decryption failed: {str(e)}\n")

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)

if __name__ == '__main__':
    root = tk.Tk()
    app = SecureMessengerApp(root)
    root.mainloop()