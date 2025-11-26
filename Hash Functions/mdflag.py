import math
import json
from pwn import remote


shift = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

sine_vals = [abs(math.sin(i)) for i in range(1, 65)]
sine_randomness = [int(math.floor((2 ** 32) * v)) for v in sine_vals]

round_1_perm = list(range(16))
round_2_perm = [(5 * i + 1) % 16 for i in range(16)]
round_3_perm = [(3 * i + 5) % 16 for i in range(16)]
round_4_perm = [(7 * i) % 16 for i in range(16)]
msg_idx_for_step = round_1_perm + round_2_perm + round_3_perm + round_4_perm

MD5_BLOCK = 64
MASK32 = 0xFFFFFFFF


def left_rotate(x: int, y: int) -> int:
    y &= 31
    return ((x << y) | ((x & MASK32) >> (32 - y))) & MASK32


def bit_not(x: int) -> int:
    return MASK32 ^ x


def F(b, c, d): return d ^ (b & (c ^ d))
def G(b, c, d): return c ^ (d & (b ^ c))
def H(b, c, d): return b ^ c ^ d
def I(b, c, d): return c ^ (b | bit_not(d))


mixer_for_step = [F] * 16 + [G] * 16 + [H] * 16 + [I] * 16


class MD5:
    def __init__(self):
        self.state = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
        self.message = b""
        self.length_bits = 0

    def digest(self) -> bytes:
        return b"".join(x.to_bytes(4, "little") for x in self.state)

    def hex_digest(self) -> str:
        return self.digest().hex()

    def pad(self, message: bytes) -> bytes:
        ml_bits = (len(message) * 8) & ((1 << 64) - 1)
        padded = message + b"\x80"

        while (len(padded) % MD5_BLOCK) != 56:
            padded += b"\x00"
        padded += ml_bits.to_bytes(8, "little")
        return padded

    def compress(self, block: bytes) -> None:
        assert len(block) == MD5_BLOCK
        M = [int.from_bytes(block[i:i + 4], "little") for i in range(0, MD5_BLOCK, 4)]
        a, b, c, d = self.state

        for i in range(64):
            mixer = mixer_for_step[i]
            mi = msg_idx_for_step[i]
            a = (a + mixer(b, c, d) + M[mi] + sine_randomness[i]) & MASK32
            a = left_rotate(a, shift[i])
            a = (a + b) & MASK32
            a, b, c, d = d, a, b, c

        self.state = (
            (self.state[0] + a) & MASK32,
            (self.state[1] + b) & MASK32,
            (self.state[2] + c) & MASK32,
            (self.state[3] + d) & MASK32,
        )

    def load_state(self, hash_hex: str) -> None:
        regs = []
        for i in range(4):
            regs.append(int.from_bytes(bytes.fromhex(hash_hex[8 * i:8 * (i + 1)]), "little"))
        self.state = tuple(regs)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


FLAG_TEMPLATE = b"crypto{??????????????????????????????????????}"
FLAG_LEN = len(FLAG_TEMPLATE)

dummy = FLAG_TEMPLATE * 3 + FLAG_TEMPLATE[:-1]
payload = b"\x00" * len(dummy)

HOST = "socket.cryptohack.org"
PORT = 13407

io = remote(HOST, PORT)
io.recvline()

io.sendline(json.dumps({"option": "message", "data": payload.hex()}).encode())
secret_blk = json.loads(io.recvline().decode())["hash"]

m = MD5()

dummy_pad = m.pad(dummy)
extension_tail = dummy_pad[-9:]

payload += xor_bytes(extension_tail[:8], b"}" + FLAG_TEMPLATE[:7])

dummy_pad_extend = m.pad(dummy_pad)

extension_block_all = dummy_pad_extend[64 * 3:]

m.load_state(secret_blk)
for start in range(0, len(extension_block_all), 64):
    m.compress(extension_block_all[start:start + 64])
target = m.hex_digest()

print("Stage 1: finding first char after 'crypto{'...")
chars = [chr(i) for i in range(32, 127)]

found_flag = "crypto{"

for ch in chars:
    guess_payload = payload + ch.encode()
    io.sendline(json.dumps({"option": "message", "data": guess_payload.hex()}).encode())
    resp = json.loads(io.recvline().decode())
    if resp["hash"] == target:
        found_flag += ch
        payload = guess_payload
        print("Found initial char:", ch)
        break

print("Stage 2: recovering remaining characters...")
for _ in range(38):
    payload += b"\x00"

    io.sendline(json.dumps({"option": "message", "data": payload.hex()}).encode())
    resp = json.loads(io.recvline().decode())
    target_now = resp["hash"]

    for ch in chars:
        mtemp = MD5()
        mtemp.load_state(secret_blk)

        attack_message = dummy_pad + found_flag[8:].encode() + ch.encode()
        padded_attack = mtemp.pad(attack_message)

        for start in range(64 * 3, len(padded_attack), 64):
            mtemp.compress(padded_attack[start:start + 64])

        if mtemp.hex_digest() == target_now:
            found_flag += ch
            print("Found:", found_flag)
            break

print("Recovered flag:", found_flag)
io.close()
