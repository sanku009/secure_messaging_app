from encryption.aes_cipher import encrypt_message, decrypt_message

msg = "Hello, Sanket!"
encrypted = encrypt_message(msg)
decrypted = decrypt_message(encrypted)

print("Original:", msg)
print("Encrypted:", encrypted)
print("Decrypted:", decrypted)