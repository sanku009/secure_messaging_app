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


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

class AESCipher:
    def __init__(self, key: str):
        # Hash key to 256-bit (32 bytes)
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw: str) -> str:
        raw_bytes = raw.encode('utf-8')
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(raw_bytes)
        
        # Concatenate nonce, tag, and ciphertext, then base64 encode
        encrypted_data = cipher.nonce + tag + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')  # base64 encode to send over network

    def decrypt(self, enc: str) -> str:
        enc = base64.b64decode(enc)  # Decode the base64 encoded string from the network
        nonce = enc[:16]  # First 16 bytes are the nonce
        tag = enc[16:32]  # Next 16 bytes are the tag
        ciphertext = enc[32:]  # Remaining bytes are the ciphertext

        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8')
        except ValueError:
            raise ValueError("MAC check failed")
