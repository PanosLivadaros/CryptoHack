from pwn import remote, xor
from json import loads, dumps
from tqdm import trange


io = remote('socket.cryptohack.org', 13421)
io.recv()


def oracle(iv, ct):
    io.sendline(dumps({"option": "unpad", "ct": (iv + ct).hex()}).encode())
    return b'true' in io.recv()


io.sendline(dumps({"option": "encrypt"}).encode())
iv, ct = (out := bytes.fromhex(loads(io.recv())["ct"]))[:16], out[16:]


def attack_block(padding_oracle, iv, c):
    r = b''
    for i in reversed(range(16)):
        pad = 16 - i
        s = bytes([pad] * pad)
        for b in trange(256):
            iv_ = b'\x00' * i + xor(s, bytes([b]) + r)
            if padding_oracle(iv_, c):
                r = bytes([b]) + r
                break
    return xor(iv, r)


def attack(padding_oracle, iv, c):
    p = attack_block(padding_oracle, iv, c[:16])
    for i in range(16, len(c), 16):
        p += attack_block(padding_oracle, c[i - 16:i], c[i:i + 16])
        print(p)
    return p


sol = attack(oracle, iv, ct)
io.sendline(dumps({"option": "check", "message": sol.decode()}).encode())
print(io.recv())
