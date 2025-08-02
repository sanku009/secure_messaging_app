from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64

class AESCipher:
    def __init__(self, password):
        # Accept either str or bytes
        if isinstance(password, str):
            password_bytes = password.encode()
        elif isinstance(password, bytes):
            password_bytes = password
        else:
            raise TypeError("Password must be str or bytes")

        self.key = SHA256.new(data=password_bytes).digest()

    def encrypt(self, plaintext: str) -> str:
        # Ensure plaintext is bytes
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Combine nonce, tag, and ciphertext for storage/transmission
        encrypted_data = nonce + tag + ciphertext
        return base64.b64encode(encrypted_data).decode()

    def decrypt(self, encrypted_b64: str) -> str:
        encrypted_data = base64.b64decode(encrypted_b64.encode())

        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()