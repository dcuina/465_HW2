import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json

def my_encrypt(plaintext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def my_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def relay_mod(ciphertext, o_plain, n_plain):
    delta = bytes(a ^ b for a, b in zip(o_plain, n_plain))
    return bytes(a ^ b for a, b in zip(delta, ciphertext))

plaintext = {"action":"READ","path":"notes.txt"}

plain_bytes = json.dumps(plaintext).encode('utf-8')

key = os.urandom(32)
iv = os.urandom(16)

ciphertext = my_encrypt(plain_bytes, key, iv)

new_plaintext = {"action":"LIST","path":"notes.txt"}
new_bytes = json.dumps(new_plaintext).encode('utf-8')

#=====RELAY HERE=====
changed_cipher = relay_mod(ciphertext, plain_bytes, new_bytes)

print('Output of original plaintext:', json.loads(my_decrypt(ciphertext, key, iv).decode('utf-8')))
print('Output of modified plaintext:', json.loads(my_decrypt(changed_cipher, key, iv).decode('utf-8')))

print('XOR between original and modified ciphertext:', bytes(a ^ b for a, b in zip(changed_cipher, ciphertext)))

#=====REPLAY HERE=====
print('Replay of original plaintext:', json.loads(my_decrypt(ciphertext, key, iv).decode('utf-8')))
print('Replay of modified plaintext:', json.loads(my_decrypt(changed_cipher, key, iv).decode('utf-8')))
