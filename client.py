import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from encryption.aes_cipher import AESCipher

# === Configuration ===
SERVER_IP = '127.0.0.1'
SERVER_PORT = 5000
KEY = "12345"  # Must match server.py
aes = AESCipher(KEY)

# === Socket Setup ===
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, SERVER_PORT))

# === GUI Mode ===
def launch_gui():
    root = tk.Tk()
    root.title("🔐 Secure Chat")
    root.geometry("500x400")

    chat_display = scrolledtext.ScrolledText(root, state='disabled')
    chat_display.pack(fill='both', expand=True)

    entry = tk.Entry(root)
    entry.pack(fill='x', padx=5, pady=5)

    send_button = tk.Button(root, text="Send")
    send_button.pack(pady=5)

    def send_callback(event=None):
        msg = entry.get()
        if msg:
            nonce, ciphertext, tag = aes.encrypt(msg.encode())
            client_socket.sendall(nonce + tag + ciphertext)

            chat_display.config(state='normal')
            chat_display.insert('end', f"You: {msg}\n")
            chat_display.config(state='disabled')
            entry.delete(0, 'end')

    def receive_messages():
        while True:
            try:
                data = client_socket.recv(1024)
                if data:
                    nonce = data[:16]
                    tag = data[16:32]
                    ciphertext = data[32:]
                    try:
                        decrypted = aes.decrypt(nonce, ciphertext, tag).decode()
                        chat_display.config(state='normal')
                        chat_display.insert('end', f"Friend: {decrypted}\n")
                        chat_display.config(state='disabled')
                    except:
                        chat_display.config(state='normal')
                        chat_display.insert('end', "❌ Failed to decrypt message.\n")
                        chat_display.config(state='disabled')
            except:
                break

    entry.bind("<Return>", send_callback)
    send_button.config(command=send_callback)

    threading.Thread(target=receive_messages, daemon=True).start()
    root.mainloop()

# === CLI Mode ===
def launch_cli():
    def receive_messages():
        while True:
            try:
                data = client_socket.recv(1024)
                if data:
                    nonce = data[:16]
                    tag = data[16:32]
                    ciphertext = data[32:]
                    try:
                        decrypted = aes.decrypt(nonce, ciphertext, tag).decode()
                        print(f"\nFriend: {decrypted}")
                    except:
                        print("\n❌ Failed to decrypt message.")
            except:
                break

    def send_messages():
        while True:
            msg = input("You: ")
            if msg:
                nonce, ciphertext, tag = aes.encrypt(msg.encode())
                client_socket.sendall(nonce + tag + ciphertext)

    threading.Thread(target=receive_messages, daemon=True).start()
    send_messages()

# === Mode Selection ===
if __name__ == "__main__":
    print("Choose mode:")
    print("1. GUI Chat")
    print("2. CLI Chat")
    mode = input("Enter 1 or 2: ").strip()

    if mode == "1":
        launch_gui()
    elif mode == "2":
        launch_cli()
    else:
        print("❌ Invalid choice. Exiting.")