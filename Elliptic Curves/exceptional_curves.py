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


p = 310717010502520989590157367261876774703
E = {
    'a': 0x5e009506fcc7eff573bc960d88638fe25e76a9b6c7caeea072a27dcd1fa46abb15b7b6210cf90caba982893ee2779669bac06e267013486b22ff3e24abae2d42,
    'b': 0x2ce7d1ca4493b0977f088f6d30d9241f8048fdea112cc385b793bce953998caae680864a7d3aa437ea3ffd1441ca3fb352b0b710bb3f053e980e503be9a7fece,
    'p': 0xa15c4fb663a578d8b2496d3151a946119ee42695e18e13e90600192b1d0abdbb6f787f90c8d102ff88e284dd4526f5f6b6c980bf88f1d0490714b67e8a2a2b77
}

b_x = 0x7f0489e4efe6905f039476db54f9b6eac654c780342169155344abc5ac90167adc6b8dabacec643cbe420abffe9760cbc3e8a2b508d24779461c19b20e242a38
b_y = 0xdd04134e747354e5b9618d8cb3f60e03a74a709d4956641b234daa8a65d43df34e18d00a59c070801178d198e8905ef670118c15b0906d3a00a662d3a2736bf
B = (b_x, b_y)
iv = '719700b2470525781cc844db1febd994'
encrypted_flag = '335470f413c225b705db2e930b9d460d3947b3836059fb890b044e46cbb343f0'

a = 2200911270816846838022388357422161552282496835763864725672800875786994850585872907705630132325051034876291845289429009837283760741160188885749171857285407
G = (3034712809375537908102988750113382444008758539448972750581525810900634243392172703684905257490982543775233630011707375189041302436945106395617312498769005, 4986645098582616415690074082237817624424333339074969364527548107042876175480894132576399611027847402879885574130125050842710052291870268101817275410204850)
A = (4748198372895404866752111766626421927481971519483471383813044005699388317650395315193922226704604937454742608233124831870493636003725200307683939875286865, 2421873309002279841021791369884483308051497215798017509805302041102468310636822060707350789776065212606890489706597369526562336256272258544226688832663757)

assert mul(G, a, E) == A
ss = mul(B, a, E)[0]
flag = decrypt_flag(ss, iv, encrypted_flag)
print(flag)
