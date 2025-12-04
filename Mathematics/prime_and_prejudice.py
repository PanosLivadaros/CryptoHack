from Crypto.Util.number import GCD
from pwn import *
import json


def generate_basis(n):
    basis = [True] * n
    for i in range(3, int(n**0.5) + 1, 2):
        if basis[i]:
            step = 2 * i
            start = i * i
            count = (n - start - 1) // step + 1
            basis[start::step] = [False] * count
    return [2] + [i for i in range(3, n, 2) if basis[i]]


def miller_rabin(n, b):
    if n in (2, 3): 
        return True
    if n % 2 == 0:
        return False

    basis = generate_basis(b)

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for a in basis:
        x = pow(a, s, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def xgcd(a, b):
    (r1, r), (s1, s), (t1, t) = (a, b), (1, 0), (0, 1)
    while r:
        q = r1 // r
        r1, r = r, r1 - q * r
        s1, s = s, s1 - q * s
        t1, t = t, t1 - q * t
    return r1, s1, t1


def crt1(residues, modulos):
    cur_res, cur_mod = residues[0], modulos[0]

    for r, m in list(zip(residues, modulos))[1:]:
        g = GCD(cur_mod, m)
        if cur_res % g != r % g:
            return -1, -1

        _, s, t = xgcd(m // g, cur_mod // g)
        cur_res = (cur_res * (m // g) * s + r * (cur_mod // g) * t) % (cur_mod * (m // g))
        cur_mod *= m // g

    return cur_res, cur_mod


def legendre(a, p):
    return pow(a, (p - 1) // 2, p)


primes = generate_basis(64)
print(len(primes))

fool = []

for p in primes:
    f = {i % (4 * p) for i in generate_basis(200 * p)[1:] if legendre(p, i) == i - 1}
    fool.append(list(f))

arr = [
    1030617353352977080364307518770663528633732979071959749923,
    1028807953088414986212097163368256369521677751668451001002928690467,
    240133843331243659724883651873564602171659784123766621731827
]

n = arr[0] * arr[1] * arr[2]

print(miller_rabin(n, 64))
print(n.bit_length())
print(pow(n - arr[0], n - 1, n))

payload = json.dumps({"prime": n, "base": n - arr[0]}).encode()

r = remote("socket.cryptohack.org", 13385)
print(r.recvline())
r.sendline(payload)
print(r.recvline())
