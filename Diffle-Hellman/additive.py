from pwn import *
from json import loads
from Crypto.Util.number import inverse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib


HOST = 'socket.cryptohack.org'
PORT = 13380


def cvrt(x: str) -> int:
    return int(x, 16)


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    key = hashlib.sha1(str(shared_secret).encode()).digest()[:16]

    cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
    plaintext = cipher.decrypt(bytes.fromhex(ciphertext))

    pad = plaintext[-plaintext[-1]:]
    if all(b == len(pad) for b in pad):
        plaintext = unpad(plaintext, 16)

    return plaintext.decode()


r = remote(HOST, PORT)

r.recvuntil(b'Intercepted from Alice: ')
pkt = loads(r.recvuntil(b'}'))
p, g, A = map(cvrt, (pkt['p'], pkt['g'], pkt['A']))

r.recvuntil(b'Intercepted from Bob: ')
B = cvrt(loads(r.recvuntil(b'}'))['B'])

r.recvuntil(b'Intercepted from Alice: ')
pkt = loads(r.recvuntil(b'}'))
iv, encrypted = pkt['iv'], pkt['encrypted']

a = A * inverse(g, p) % p
b = B * inverse(g, p) % p

key = g * a * b % p

print(decrypt_flag(key, iv, encrypted))
