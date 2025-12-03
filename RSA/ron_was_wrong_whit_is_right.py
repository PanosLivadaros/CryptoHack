from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
import gmpy2


ns, es, cs = [], [], []
for i in range(1, 51):
    key = RSA.importKey(open(f"keys_and_messages/{i}.pem").read())
    cs.append(bytes_to_long(bytes.fromhex(open(f"keys_and_messages/{i}.ciphertext").read())))
    ns.append(key.n)
    es.append(key.e)

p = q = d = N = idx = None
for i in range(50):
    for j in range(i + 1, 50):
        g = gmpy2.gcd(ns[i], ns[j])
        if g != 1:
            p, idx = int(g), i
            break
    if p:
        break

e = es[idx]
q = ns[idx] // p
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

priv = RSA.construct((ns[idx], e, d))
cipher = PKCS1_OAEP.new(priv)
print(cipher.decrypt(long_to_bytes(cs[idx])))
