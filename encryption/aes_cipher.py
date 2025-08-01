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
