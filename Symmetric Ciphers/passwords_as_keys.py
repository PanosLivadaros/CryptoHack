from Crypto.Cipher import AES
import hashlib
import random


def decrypt(ciphertext_hex, key):
    try:
        return AES.new(key, AES.MODE_ECB).decrypt(bytes.fromhex(ciphertext_hex))
    except ValueError as e:
        return {"error": str(e)}


with open("words.txt") as f:
    words = [w.strip() for w in f]

random.choice(words)

CIPHERTEXT = "c92b7734070205bdf6c0087a751466ec13ae15e6f1bcdd3f3a535ec0f4bbae66"

for w in words:
    key = hashlib.md5(w.encode()).digest()
    decrypted = decrypt(CIPHERTEXT, key)
    if isinstance(decrypted, bytes) and b"crypto" in decrypted:
        print(decrypted)
