import socket
import threading
from encryption.aes_cipher import AESCipher

# Server config
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 5000

# AES key - must be same for all clients and server
SECRET_KEY = b'mysecretaeskey12'  # 16 bytes key for AES-128

cipher = AESCipher(SECRET_KEY)

clients = []
clients_lock = threading.Lock()

def broadcast_message(sender_socket, message):
    """Send message to all connected clients except sender."""
    with clients_lock:
        for client in clients:
            if client != sender_socket:
                try:
                    client.send(message)
                except:
                    client.close()
                    clients.remove(client)

def handle_client(client_socket, address):
    print(f"[+] New connection from {address}")
    with clients_lock:
        clients.append(client_socket)

    try:
        while True:
            # Receive encrypted message length first (4 bytes)
            raw_msglen = recvall(client_socket, 4)
            if not raw_msglen:
                break
            msglen = int.from_bytes(raw_msglen, byteorder='big')

            # Receive the actual encrypted message data
            encrypted_msg = recvall(client_socket, msglen)
            if not encrypted_msg:
                break

            # Decrypt message
            try:
                decrypted_msg = cipher.decrypt(encrypted_msg).decode()
            except Exception as e:
                print(f"Decryption failed: {e}")
                continue

            print(f"[{address}] {decrypted_msg}")

            # Broadcast encrypted message to others
            broadcast_message(client_socket, raw_msglen + encrypted_msg)

    except Exception as e:
        print(f"Connection error with {address}: {e}")

    finally:
        with clients_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        client_socket.close()
        print(f"[-] Connection closed {address}")

def recvall(sock, n):
    """Helper function to receive n bytes or return None if EOF."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"[*] Server listening on {HOST}:{PORT}")

    while True:
        client_socket, address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.daemon = True
        client_thread.start()

if __name__ == "__main__":
    start_server()
