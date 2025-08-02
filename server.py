import socket
from encryption.aes_cipher import AESCipher

HOST = '127.0.0.1'
PORT = 65432

def start_server():
    key = input("Enter your encryption key: ")
    cipher = AESCipher(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("Server listening on port", PORT)
        conn, addr = s.accept()
        with conn:
            print("Connected by", addr)

            # Send server key hash for verification
            server_key_hash = key.encode()
            conn.sendall(server_key_hash)

            # Receive client key hash
            client_key_hash = conn.recv(1024)
            if client_key_hash != server_key_hash:
                print("Error: Client encryption key mismatch. Closing connection.")
                conn.close()
                return
            else:
                print("Encryption keys matched. Starting secure chat.")

            while True:
                data = conn.recv(1024)
                if not data:
                    break
                try:
                    decrypted = cipher.decrypt(data.decode())
                    print("Client:", decrypted)
                except Exception as e:
                    print("Failed to decrypt message:", e)
                    continue

                response = input("You: ")
                encrypted = cipher.encrypt(response)
                conn.sendall(encrypted.encode())

if __name__ == '__main__':
    start_server()
