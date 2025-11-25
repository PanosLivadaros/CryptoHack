from pwn import remote
import json
from Crypto.Util.number import inverse


def index_of_change(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return -1


r = remote('socket.cryptohack.org', 13390)

r.sendlineafter(b'option.\n', json.dumps({"option": "get_sample"}).encode())
base = json.loads(r.recvline())
r.sendline(json.dumps({"option": "reset"}).encode())
r.recvline()

p = 127
base_a, base_b = base["a"], base["b"]
FLAG = list("crypto{????????????????????}")

while '?' in FLAG:
    r.sendline(json.dumps({"option": "get_sample"}).encode())
    s = json.loads(r.recvline())
    r.sendline(json.dumps({"option": "reset"}).encode())
    r.recvline()

    new_a, new_b = s["a"], s["b"]
    if new_a == base_a:
        continue

    idx = index_of_change(base_a, new_a)
    fi = (base_b - new_b) * inverse(base_a[idx] - new_a[idx], p) % p
    FLAG[idx] = chr(fi)

print("".join(FLAG))
