from math import gcd


N = 95397281288258216755316271056659083720936495881607543513157781967036077217126208404659771258947379945753682123292571745366296203141706097270264349094699269750027004474368460080047355551701945683982169993697848309121093922048644700959026693232147815437610773496512273648666620162998099244184694543039944346061
E = 65537
ciphertext = 0x04fee34327a820a5fb72e71b8b1b789d22085630b1b5747f38f791c55573571d22e454bfebe0180631cbab9075efa80796edb11540404c58f481f03d12bb5f3655616df95fb7a005904785b86451d870722cc6a0ff8d622d5cb1bce15d28fee0a72ba67ba95567dc5062dfc2ac40fe76bc56c311b1c3335115e9b6ecf6282cca
MOD = 2**512
A = 2287734286973265697461282233387562018856392913150345266314910637176078653625724467256102550998312362508228015051719939419898647553300561119192412962471189
B = 4179258870716283142348328372614541634061596292364078137966699610370755625435095397634562220121158928642693078147104418972353427207082297056885055545010537

FLAG = b'crypto{???????????????????????????}'


def factor():
    def solve(f, bits):
        candidates = {b for b in (0, 1) if f(b) % 2 == 0}

        for i in range(1, bits):
            if not candidates:
                return []

            new_set = set()
            mod = 1 << (i + 1)

            for y in candidates:
                for b in (0, 1):
                    q = (b << i) | y
                    if f(q) % mod == 0:
                        new_set.add(q)

            candidates = new_set

        return list(candidates)

    a, b = A, B

    for _ in range(2000):
        for root in solve(lambda p: p * (a * p + b) - N, 512):
            g = gcd(N, root)
            if g > 1:
                return g, N // g

        b = (b + B * a) % MOD
        a = (a * A) % MOD


p, q = factor()
assert p * q == N

phi = (p - 1) * (q - 1)
d = pow(E, -1, phi)
m = pow(ciphertext, d, N)

print(m.to_bytes(len(FLAG), 'big').decode())
