import socket
from encryption.aes_cipher import AESCipher

HOST = '127.0.0.1'
PORT = 65432

def start_client():
    key = input("Enter your encryption key: ")
    cipher = AESCipher(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Receive server key hash
        server_key_hash = s.recv(1024)

        # Send client key hash
        client_key_hash = key.encode()
        s.sendall(client_key_hash)

        if client_key_hash != server_key_hash:
            print("Error: Server encryption key mismatch. Closing connection.")
            s.close()
            return
        else:
            print("Encryption keys matched. Starting secure chat.")

        print("Connected to server. Type your messages.")
        while True:
            msg = input("You: ")
            encrypted = cipher.encrypt(msg)
            s.sendall(encrypted.encode())

            data = s.recv(1024)
            try:
                decrypted = cipher.decrypt(data.decode())
                print("Server:", decrypted)
            except Exception as e:
                print("Failed to decrypt message:", e)

if __name__ == '__main__':
    start_client()
