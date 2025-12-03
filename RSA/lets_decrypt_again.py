import json, random
from sage.all import *
from hashlib import sha1
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import remote


try:
    from bitcoin import random_key, privtopub, pubtoaddr
except ImportError:
    random_key = lambda: "DEADBEEF"
    privtopub = pubtoaddr = lambda _: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def B_smooth(total_size, small_factors_size, big_factor_size):
    small_primes = primes_first_n(small_factors_size)
    small_part = prod(small_primes)
    while True:
        big_prime = random_prime(2**big_factor_size, lbound=2**(big_factor_size - 1))
        candidate = 2 * small_part * big_prime + 1
        if candidate.nbits() >= total_size:
            return Integer(candidate), small_primes + [big_prime]


def emsa_pkcs1_v15_encode(msg, k):
    H = sha1(msg).digest()
    if k < len(H) + 11:
        raise ValueError("Intended encoded message too long")
    return b'\x00\x01' + b'\xff' * (k - len(H) - 3) + b'\x00' + H


BIT_LENGTH = 768
alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def generate_pq(nbits):
    while True:
        p, _ = B_smooth(nbits + 32, 15, 40)
        if is_prime(p) and p > 2**nbits:
            break
    while True:
        q, _ = B_smooth(nbits + 32, 15, 40)
        if is_prime(q) and q > 2**nbits and gcd(p - 1, q - 1) == 2:
            break
    return p, q


def get_test_message(suffix):
    return "This is a test " + ''.join(random.sample(alpha, 32)) + " for a fake signature." + suffix


def get_own_message(suffix):
    return "My name is " + ''.join(random.sample(alpha, 32)) + " and I own CryptoHack.org" + suffix


def get_btc_message(suffix):
    return "Please send all my money to " + pubtoaddr(privtopub(random_key())) + suffix


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


r = remote('socket.cryptohack.org', 13394, level='debug')
r.recvline()

r.sendline(json.dumps({"option": "get_signature"}).encode())
SIG0 = Integer(int(json.loads(r.recvline().decode())["signature"], 16))
print(f"[+] Got signature s = {SIG0}")

print("[+] Generating smooth primes p, q...")
p, q = generate_pq(BIT_LENGTH)
print(f"[+] p = {p}\n[+] q = {q}")
N_ = p * q

r.sendline(json.dumps({"option": "set_pubkey", "pubkey": hex(N_)}).encode())
suffix = json.loads(r.recvline().decode())["suffix"]
print(f"[+] Got suffix: {suffix}")

messages = []
for fn in [get_test_message, get_own_message, get_btc_message]:
    while True:
        m = fn(suffix)
        try:
            EM = emsa_pkcs1_v15_encode(m.encode(), BIT_LENGTH // 8)
            h = bytes_to_long(EM)
            print(f"[+] Trying message: {m[:60]}...")

            if any(gcd(x, mod) != 1 for x in (SIG0, h) for mod in (p, q)):
                print("[!] Not invertible mod p or q — retrying")
                continue

            Fp, Fq = Zmod(p), Zmod(q)
            x = discrete_log(Fp(h), Fp(SIG0), operation='*')
            y = discrete_log(Fq(h), Fq(SIG0), operation='*')
            e = Integer(crt([x, y], [p - 1, q - 1]))
            print(f"[+] Found e = {e}")
            messages.append((m, e))
            break
        except (ValueError, RuntimeError, AttributeError) as ex:
            print(f"[!] Discrete log failed: {ex} — retrying")
            continue

shares = []
for idx, (m, e) in enumerate(messages):
    print(f"[+] Submitting message {idx}: {m[:60]}...")
    r.sendline(json.dumps({"option": "claim", "msg": m, "e": hex(e), "index": idx}).encode())
    secret = long_to_bytes(int(json.loads(r.recvline().decode())["secret"], 16))
    shares.append(secret)

if len(shares) == 3:
    flag = xor(xor(shares[0], shares[1]), shares[2])
    print("\n[+] FLAG:", flag.decode(errors='replace'))
else:
    print("[-] Failed to get 3 shares")
