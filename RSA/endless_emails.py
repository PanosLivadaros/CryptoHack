import gmpy2
from Crypto.Util.number import long_to_bytes, inverse
from itertools import combinations


def load_output():
    ns, cs = [], []
    with open("output_0ef6d6343784e59e2f44f61d2d29896f.txt", "r") as f:
        for line in f:
            if not line.strip():
                continue
            k, v = line.strip().split("=")
            if k.strip() == "e":
                continue
            (ns if k.strip() == "n" else cs).append(int(v))
    return {"n": ns, "c": cs}


def decrypt(grps, e):
    for group in combinations(zip(grps["n"], grps["c"]), e):

        N = 1
        for n, _ in group:
            N *= n

        x = 0
        for n, c in group:
            t = N // n
            x += c * inverse(t, n) * t

        M = x % N

        m = gmpy2.iroot(M, e)[0]
        if pow(m, e, N) == M:
            print(long_to_bytes(m))


grps = load_output()
decrypt(grps, 3)
