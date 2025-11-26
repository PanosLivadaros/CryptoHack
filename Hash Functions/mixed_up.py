from hashlib import sha256
from pwn import *
import json
from Crypto.Util.number import long_to_bytes


io = remote("socket.cryptohack.org", 13402)
io.recvline()

FLAG_LEN = len(b"crypto{???????????????????????????????}")

REPEATED_HASHES = {sha256(bytes([i]) * FLAG_LEN).hexdigest(): i for i in range(256)}


def check_guess(h):
    return 0 if h in REPEATED_HASHES else 1


flag = 0

for i in range(8 * FLAG_LEN):
    msg = long_to_bytes(1 << i)
    msg = msg.rjust(FLAG_LEN, b"\x00")

    bit = 0
    for _ in range(5):
        io.sendline(json.dumps({"option": "mix", "data": msg.hex()}).encode())
        mixed = json.loads(io.recvline().decode())["mixed"]

        if check_guess(mixed) == 1:
            bit = 1

    flag |= (bit << i)
    print(long_to_bytes(flag))
