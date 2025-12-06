from Crypto.Util.number import inverse
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
import hashlib


def sum(p, q, e):
    o = (0, 0)
    if p == o:
        return q
    elif q == o:
        return p
    else:
        x1, y1 = p
        x2, y2 = q
        if x1 == x2 and y1 == -y2:
            return o
        ea, ep = e['a'], e['p']
        if p != q:
            k = ((y2 - y1) * inverse(x2 - x1, ep)) % ep
        else:
            k = ((3*x1**2 + ea) * inverse(2 * y1, ep)) % ep

        x3 = (k**2 - x1 - x2) % ep
        y3 = (k*(x1 - x3) - y1) % ep
        return x3, y3


def mul(p, n, e):
    o = (0, 0)
    q = p
    r = o
    while n > 0:
        if n % 2 == 1:
            r = sum(r, q, e)
        q = sum(q, q, e)
        n //= 2
    return r


def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


g_x = 179210853392303317793440285562762725654
g_y = 105268671499942631758568591033409611165
G = (g_x, g_y)

b_x = 272640099140026426377756188075937988094
b_y = 51062462309521034358726608268084433317
B = (b_x, b_y)

q_x = 280810182131414898730378982766101210916
q_y = 291506490768054478159835604632710368904
Q = (q_x, q_y)

p = 310717010502520989590157367261876774703
E = {'a': 2, 'b': 3, 'p': p,}

iv = '07e2628b590095a5e332d397b8a59aa7'
encrypted_flag = '8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af'
n = 47836431801801373761601790722388100620

assert mul(G, n, E) == Q
ss = mul(B, n, E)[0]
flag = decrypt_flag(ss, iv, encrypted_flag)
print(flag)
