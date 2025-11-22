from Crypto.Util.number import long_to_bytes, inverse
from math import floor


class Vec:
    def __init__(self, x, y):
        self.x, self.y = x, y

    def dot(self, other):
        return self.x * other.x + self.y * other.y

    def scale(self, k):
        return Vec(self.x * k, self.y * k)

    def sub(self, other):
        return Vec(self.x - other.x, self.y - other.y)


def gaussian_reduction(v, u):
    while True:
        if u.dot(u) < v.dot(v):
            v, u = u, v

        m = floor(v.dot(u) / v.dot(v))
        if m == 0:
            return v, u

        u = u.sub(v.scale(m))


def decrypt(q, f, g, e):
    a = (f * e) % q
    m = (a * inverse(f, g)) % g
    return m


q = 7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257
h = 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800
e = 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523

v, u = gaussian_reduction(Vec(1, h), Vec(0, q))
f, g = v.x, v.y

print(long_to_bytes(decrypt(q, f, g, e)).decode())
