from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Use a secure 16-byte or 32-byte key
SECRET_KEY = b'123456'  # You can load this from env or config

def encrypt_message(message: str) -> bytes:
    nonce = get_random_bytes(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return nonce + tag + ciphertext

def decrypt_message(encrypted_data: bytes) -> str:
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode()