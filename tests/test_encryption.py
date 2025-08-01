import unittest
from encryption.aes_cipher import AESCipher

class TestAESCipher(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = "testkey123"
        cipher = AESCipher(key)
        plaintext = "Hello World"
        encrypted = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(plaintext, decrypted)

if __name__ == '__main__':
    unittest.main()