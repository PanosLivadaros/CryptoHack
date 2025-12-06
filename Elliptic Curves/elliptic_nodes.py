from Crypto.Util.number import long_to_bytes
from sage.all import *


def attack(p, a2, a4, a6, Gx, Gy, Px, Py):
    x = GF(p)["x"].gen()
    f = x ** 3 + a2 * x ** 2 + a4 * x + a6
    roots = f.roots()

    if len(roots) == 1:
        alpha = roots[0][0]
        u = (Gx - alpha) / Gy
        v = (Px - alpha) / Py
        return int(v / u)

    if len(roots) == 2:
        if roots[0][1] == 2:
            alpha = roots[0][0]
            beta = roots[1][0]
        elif roots[1][1] == 2:
            alpha = roots[1][0]
            beta = roots[0][0]
        else:
            raise ValueError("Expected root with multiplicity 2.")

        t = (alpha - beta).sqrt()
        u = (Gy + t * (Gx - alpha)) / (Gy - t * (Gx - alpha))
        v = (Py + t * (Px - alpha)) / (Py - t * (Px - alpha))
        return int(v.log(u))

    raise ValueError(f"Unexpected number of roots {len(roots)}.")

p = 4368590184733545720227961182704359358435747188309319510520316493183539079703

Gxy = (8742397231329873984594235438374590234800923467289367269837473862487362482, 225987949353410341392975247044711665782695329311463646299187580326445253608)
Qxy = (2582928974243465355371953056699793745022552378548418288211138499777818633265, 2421683573446497972507172385881793260176370025964652384676141384239699096612)

a = pow(Gxy[0] - Qxy[0], -1, p) * (pow(Gxy[1], 2, p) - pow(Qxy[1], 2, p) - pow(Gxy[0], 3, p) + pow(Qxy[0], 3, p)) % p
b = pow(Gxy[1], 2, p) - pow(Gxy[0], 3, p) - (a * Gxy[0]) % p

print(f"{a=}\n{b=}")

print("Performing attack...")

l = attack(p, 0, a, b, Gxy[0], Gxy[1], Qxy[0], Qxy[1])
print("The discrete logarithm l is:", l)
print("The flag is:", long_to_bytes(l))
