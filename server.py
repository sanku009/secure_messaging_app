import socket
import threading
from encryption.aes_cipher import AESCipher

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 5000))
server_socket.listen(5)
print("✅ Server is running and listening on port 5000...")

key = "12345"  # Must match client.py
aes = AESCipher(key)

clients = []  # List of sockets
usernames = {}  # socket -> username

def broadcast(sender_socket, message):
    for client in clients:
        if client != sender_socket:
            try:
                client.sendall(message)
            except:
                client.close()
                clients.remove(client)
                usernames.pop(client, None)

def handle_client(client_socket, address):
    try:
        username = client_socket.recv(1024).decode().strip()
        usernames[client_socket] = username
        clients.append(client_socket)
        print(f"[+] {username} connected from {address}")

        while True:
            data = client_socket.recv(2048)
            if not data:
                break

            nonce = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]

            try:
                decrypted = aes.decrypt(nonce, ciphertext, tag).decode()
                print(f"[{username}] {decrypted}")

                # Broadcast to all other clients
                new_nonce, new_cipher, new_tag = aes.encrypt(f"{username}: {decrypted}")
                outgoing = new_nonce + new_tag + new_cipher
                broadcast(client_socket, outgoing)

            except:
                print(f"[!] Message from {username} failed to decrypt.")
    finally:
        print(f"[-] Connection closed from {address}")
        clients.remove(client_socket)
        usernames.pop(client_socket, None)
        client_socket.close()

# Accept loop
while True:
    client_socket, address = server_socket.accept()
    thread = threading.Thread(target=handle_client, args=(client_socket, address))
    thread.start()