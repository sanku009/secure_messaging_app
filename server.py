import socket
import threading
from encryption.aes_cipher import AESCipher

key = b'hellosanketkarki'  # Must match client.py
aes = AESCipher(key)

HOST = '0.0.0.0'
PORT = 9999

clients = []

# Broadcast to all connected clients
def broadcast(sender_socket, message):
    for client in clients:
        if client != sender_socket:
            try:
                client.sendall(message)
            except:
                client.close()
                clients.remove(client)

# Handle each client in a separate thread
def handle_client(client_socket, address):
    print(f"[+] New connection from {address}")
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break

            # Extract nonce, tag, and ciphertext
            nonce = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]

            try:
                decrypted = aes.decrypt(nonce, ciphertext, tag).decode()
                print(f"[{address}] {decrypted}")
                
                # Re-encrypt message before broadcasting
                new_nonce, new_cipher, new_tag = aes.encrypt(decrypted.encode())
                outgoing = new_nonce + new_tag + new_cipher
                broadcast(client_socket, outgoing)
            except:
                print(f"[!] Message from {address} failed to decrypt.")
        except:
            break

    print(f"[-] Connection closed from {address}")
    clients.remove(client_socket)
    client_socket
