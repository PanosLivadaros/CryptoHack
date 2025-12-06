import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sage import *


p = 1331169830894825846283645180581
E = EllipticCurve(GF(p), [-35, 98])

G = E(479691812266187139164535778017, 568535594075310466177352868412)
P1 = E(1110072782478160369250829345256, 800079550745409318906383650948)
P2 = E(1290982289093010194550717223760, 762857612860564354370535420319)

try:
    n_a = G.discrete_log(P1)
    print("n_a =", Integer(n_a))
except Exception as e:
    print("direct discrete_log failed:", e)
    raise SystemExit

S = n_a * P2
shared_x = Integer(S[0])
print("shared_x =", shared_x)

iv_hex = "eac58c26203c04f68d63dc2c58d79aca"
ct_hex = "bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d"

key = hashlib.sha1(str(shared_x).encode('ascii')).digest()[:16]
iv = bytes.fromhex(iv_hex)
ct = bytes.fromhex(ct_hex)

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), 16)
print(pt)
