from Crypto.Cipher import AES

class AESCipher:
    NONCE_SIZE = 16
    TAG_SIZE = 16

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes long")
        self.key = key

    def encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < self.NONCE_SIZE + self.TAG_SIZE:
            raise ValueError("Invalid data. Too short for nonce and tag.")
        nonce = data[:self.NONCE_SIZE]
        tag = data[self.NONCE_SIZE:self.NONCE_SIZE + self.TAG_SIZE]
        ciphertext = data[self.NONCE_SIZE + self.TAG_SIZE:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
