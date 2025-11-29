import json
import hashlib
from pwn import remote, log
from sympy import discrete_log
from Crypto.Cipher import AES


def pkcs7_unpad_if_valid(pt: bytes) -> bytes:
    if not pt:
        return pt
    pad_len = pt[-1]
    if pad_len == 0 or pad_len > len(pt):
        return pt
    pad = pt[-pad_len:]
    return pt[:-pad_len] if all(b == pad_len for b in pad) else pt


def decrypt_flag(shared_secret: int, iv_hex: str, ct_hex: str) -> str:
    key = hashlib.sha1(str(shared_secret).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv_hex))
    pt = cipher.decrypt(bytes.fromhex(ct_hex))
    pt = pkcs7_unpad_if_valid(pt)
    return pt.decode("ascii")


def solve_shared_secret(p: int, g: int, A: int, B: int) -> int:
    x = discrete_log(p, A, g)
    return pow(B, x, p)


conn = remote("socket.cryptohack.org", 13379)

conn.recvuntil(b"Intercepted from Alice: ")
alice_msg = json.loads(conn.recvline())
alice_msg["supported"] = ["DH64"]
conn.recvuntil(b"Send to Bob: ")
conn.sendline(json.dumps(alice_msg).encode())

conn.recvuntil(b"Intercepted from Bob: ")
bob_msg = json.loads(conn.recvline())
conn.recvuntil(b"Send to Alice: ")
conn.sendline(json.dumps(bob_msg).encode())

conn.recvuntil(b"Intercepted from Alice: ")
alice = json.loads(conn.recvline())
p = int(alice["p"], 16)
g = int(alice["g"], 16)
A = int(alice["A"], 16)

conn.recvuntil(b"Intercepted from Bob: ")
B = int(json.loads(conn.recvline())["B"], 16)

conn.recvuntil(b"Intercepted from Alice: ")
alice_cipher = json.loads(conn.recvline())

shared = solve_shared_secret(p, g, A, B)

flag = decrypt_flag(shared, alice_cipher["iv"], alice_cipher["encrypted_flag"])
log.info(flag)

conn.close()
