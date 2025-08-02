import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from encryption.aes_cipher import AESCipher

root = tk.Tk()
root.title("🔐 Secure Chat")
root.geometry("500x400")

chat_display = scrolledtext.ScrolledText(root, state='disabled')
chat_display.pack(fill='both', expand=True)

entry = tk.Entry(root)
entry.pack(fill='x', padx=5, pady=5)

key = b'12345'  # Use the same key in server.py
aes = AESCipher(key)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 5000))  # Replace with your server IP and port

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

entry.bind("<Return>", send_callback)
send_button.config(command=send_callback)


def receive_messages(sock):
    while True:
        try:
            data = sock.recv(1024)
            if data:
                print(f"\n[Server] {data.decode()}")
        except:
            break

def send_messages(sock):
    while True:
        msg = input("You: ")
        sock.sendall(msg.encode())

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 9999))

    recv_thread = threading.Thread(target=receive_messages, args=(client,))
    send_thread = threading.Thread(target=send_messages, args=(client,))
    recv_thread.start()
    send_thread.start()

if __name__ == "__main__":
    start_client()