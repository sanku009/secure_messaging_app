import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from encryption.aes_cipher import AESCipher

HOST = '127.0.0.1'  # Change this to server IP
PORT = 5000

SECRET_KEY = b'mysecretaeskey12'  # Must match server key

cipher = AESCipher(SECRET_KEY)

class SecureMessengerClient:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Messaging Client")
        self.root.geometry("600x400")

        self.chat_area = scrolledtext.ScrolledText(root, state='disabled')
        self.chat_area.pack(expand=True, fill='both')

        self.entry_message = tk.Entry(root)
        self.entry_message.pack(fill='x', padx=10, pady=10)
        self.entry_message.bind("<Return>", self.send_message)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.nickname = simpledialog.askstring("Nickname", "Please enter your nickname", parent=root)
        if not self.nickname:
            messagebox.showerror("Error", "Nickname required")
            root.destroy()
            return

        try:
            self.sock.connect((HOST, PORT))
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            root.destroy()
            return

        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def send_message(self, event=None):
        message = self.entry_message.get()
        if not message:
            return
        full_message = f"{self.nickname}: {message}"
        try:
            encrypted_msg = cipher.encrypt(full_message.encode())
            msg_len = len(encrypted_msg).to_bytes(4, byteorder='big')
            self.sock.sendall(msg_len + encrypted_msg)
            self.entry_message.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    def receive_messages(self):
        while self.running:
            try:
                raw_msglen = self.recvall(4)
                if not raw_msglen:
                    break
                msglen = int.from_bytes(raw_msglen, byteorder='big')
                encrypted_msg = self.recvall(msglen)
                if not encrypted_msg:
                    break

                decrypted_msg = cipher.decrypt(encrypted_msg).decode()
                self.display_message(decrypted_msg)
            except Exception as e:
                print(f"Receive error: {e}")
                break

        self.sock.close()

    def recvall(self, n):
        data = b''
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def display_message(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + '\n')
        self.chat_area.config(state='disabled')
        self.chat_area.see(tk.END)

    def on_close(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    client = SecureMessengerClient(root)
    root.mainloop()
