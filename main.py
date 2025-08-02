import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from encryption.aes_cipher import AESCipher
import datetime

# === Configuration ===
SERVER_IP = '127.0.0.1'
SERVER_PORT = 5000
KEY = "12345"
aes = AESCipher(KEY)

# === Socket Setup ===
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, SERVER_PORT))

username = input("Enter your username: ").strip()
client_socket.sendall(username.encode())

class SecureMessengerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Messaging App")
        self.root.geometry("700x500")
        self.root.configure(bg="#788fb3")

        style = ttk.Style()
        style.configure("TLabel", font=("Segoe UI", 12))
        style.configure("TButton", font=("Segoe UI", 11))

        ttk.Label(root, text="✉️ Message:").pack(pady=(10, 0))
        self.msg_entry = ttk.Entry(root, width=60)
        self.msg_entry.pack(pady=(0, 10))

        btn_frame = ttk.Frame(root)
        btn_frame.pack()

        self.send_button = ttk.Button(btn_frame, text="📤 Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(btn_frame, text="🧹 Clear Log", command=self.clear_output)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.output_text = scrolledtext.ScrolledText(root, height=20, width=85, wrap=tk.WORD, font=("Consolas", 10))
        self.output_text.pack(pady=(10, 0))

        self.msg_entry.bind("<Return>", lambda event: self.send_message())

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self):
        msg = self.msg_entry.get()
        if not msg:
            return
        try:
            nonce, ciphertext, tag = aes.encrypt(msg)
            client_socket.sendall(nonce + tag + ciphertext)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            self.output_text.insert(tk.END, f"[{timestamp}] You: {msg}\n")
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    def receive_messages(self):
        while True:
            try:
                data = client_socket.recv(2048)
                if data:
                    try:
                        nonce = data[:16]
                        tag = data[16:32]
                        ciphertext = data[32:]
                        decrypted = aes.decrypt(nonce, ciphertext, tag).decode()
                        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                        self.output_text.insert(tk.END, f"[{timestamp}] {decrypted}\n")
                    except:
                        self.output_text.insert(tk.END, "❌ Failed to decrypt message.\n")
            except:
                break

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)

if __name__ == '__main__':
    root = tk.Tk()
    app = SecureMessengerApp(root)
    root.mainloop()