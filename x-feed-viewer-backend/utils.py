from Crypto.Cipher import AES
import base64
import json

def decrypt_token(encrypted_token, secret):
    iv = bytes.fromhex(encrypted_token['iv'])
    content = bytes.fromhex(encrypted_token['content'])
    cipher = AES.new(secret.encode(), AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(content).decode('utf-8')
    return decrypted.strip()
