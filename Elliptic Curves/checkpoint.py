from sage import *
from pwn import remote, info
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from collections import namedtuple
from tqdm import trange


Point = namedtuple("Point", "x y")
Curve = namedtuple("Curve", "p a b G")

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
P_256 = (p, a, b, G)

E256 = EllipticCurve(GF(p), [a, b])
G = E256(G)


def find_small_subgroups(p, a, stop_bound=2**256, small_group_ub=2**21, small_group_lb=2**12):
    known_mod = 1
    points = []
    bs = []
    orders = []
    F = GF(p)
    print(f"Finding small subgroups: {small_group_ub = }")
    while True:
        b = randint(1, p - 1)
        E = EllipticCurve(F, [a, b])
        curve_order = ZZ(E.order())
        order_facts = factor(curve_order, limit=ZZ(small_group_ub))
        for pi, ei in order_facts:
            if pi > 2 ** 20:
                break
            if pi < small_group_lb:
                continue
            if gcd(pi, known_mod) == 1:
                while True:
                    x = F(randint(1, p - 1))
                    try:
                        G = E.lift_x(x)
                    except:
                        continue
                    P = (curve_order // pi) * G
                    if P != E(0):
                        break
                points.append(P)
                bs.append(b)
                orders.append(ZZ(pi))
                known_mod *= pi
        print(
            f"Known mod bits: {int(known_mod).bit_length()} with points number {len(points)}")
        if known_mod > stop_bound:
            break
    return points, bs, orders


def start_key_exchange(io: remote, Q):
    payload = {"option": "start_key_exchange",
               "ciphersuite": "ECDHE_P256_WITH_AES_128",
               "Qx": hex(Q[0])[2:],
               "Qy": hex(Q[1])[2:]
               }
    io.sendline(json.dumps(payload).encode())
    response = json.loads(io.recvline().decode())
    return "successfully" in response["msg"]


def get_test_message(io:remote):
    payload = {"option": "get_test_message"}
    io.sendline(json.dumps(payload).encode())
    response = json.loads(io.recvline().decode())
    return bytes.fromhex(response["msg"])


def verify_pt(shared_key, pt, ct):
    iv = ct[:16]
    ct = ct[16:]
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    return cipher.decrypt(ct) == pad(pt, 16)


def blind_dlog(bound, base_point, ct, pt = b"SERVER_TEST_MESSAGE"):
    shared_point = 0 * base_point
    for i in range(bound):
        shared_key = sha256(str(shared_point[0]).encode()).digest()[:16]
        if verify_pt(shared_key, pt, ct):
            return i
        shared_point += base_point
    assert False, "Dlog not found"


points, bs, orders = find_small_subgroups(p, a)
io = remote("socket.cryptohack.org", 13419)

io.recvline()
io.recvline()

client_public_key = io.recvline().strip().decode().strip().split(" : ")[1]
server_public_key = io.recvline().strip().decode().strip().split(" : ")[1]
encrypted_flag = io.recvline().strip().decode().strip().split(" : ")[1]
encrypted_flag = bytes.fromhex(encrypted_flag)

cpk = eval(client_public_key)
C = E256(cpk.x, cpk.y)
spk = eval(server_public_key)
S = E256(spk.x, spk.y)
info(f"Server public key: {S = }")
info(f"Client public key: {C = }")

dlogs = []
for g, _, mod in zip(points, bs, orders):
    assert start_key_exchange(io, g)
    ct = get_test_message(io)
    dlog = blind_dlog(mod, g, ct)
    dlogs.append(dlog)
    info(f"Found dlog {dlog} mod {mod}")

l = len(dlogs)
for i in trange(2**l):
    signs = [1 if i & (1 << j) else -1 for j in range(l)]
    secret = crt([dlog * sign for dlog, sign in zip(dlogs, signs)], orders)
    if int(secret).bit_length() <= 256 and secret * G == S:
        info(f"Found server's secret {secret}, {secret.nbits() = }")
        break
assert secret * G == S, "Bad secret"
shared_point = secret * C
shared_key = sha256(str(shared_point[0]).encode()).digest()[:16]
iv = encrypted_flag[:16]
ct = encrypted_flag[16:]
cipher = AES.new(shared_key, AES.MODE_CBC, iv)
flag = cipher.decrypt(ct)
print(flag)
