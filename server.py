import socket
import threading
from encryption.aes_cipher import AESCipher

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 5000))  # Accept connections from any IP
server_socket.listen(5)
print("✅ Server is running and listening on port 5000...")

key = "12345"  # Must match client.py
aes = AESCipher(key)

clients = []

def broadcast(sender_socket, message):
    for client in clients:
        if client != sender_socket:
            try:
                client.sendall(message)
            except:
                client.close()
                clients.remove(client)

def handle_client(client_socket, address):
    print(f"[+] New connection from {address}")
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break

            nonce = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]

            try:
                decrypted = aes.decrypt(nonce, ciphertext, tag).decode()
                print(f"[{address}] {decrypted}")

                new_nonce, new_cipher, new_tag = aes.encrypt(decrypted.encode())
                outgoing = new_nonce + new_tag + new_cipher
                broadcast(client_socket, outgoing)
            except:
                print(f"[!] Message from {address} failed to decrypt.")
        except:
            break

    print(f"[-] Connection closed from {address}")
    clients.remove(client_socket)
    client_socket.close()

# Accept loop
while True:
    client_socket, address = server_socket.accept()
    clients.append(client_socket)
    thread = threading.Thread(target=handle_client, args=(client_socket, address))
    thread.start()