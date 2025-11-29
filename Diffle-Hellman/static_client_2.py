from pwn import *
from json import loads, dumps
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib


HOST = 'socket.cryptohack.org'
PORT = 13378


def is_pkcs7_padded(m):
    pad = m[-m[-1]:]
    return all(b == len(pad) for b in pad)


def decrypt_flag(shared_secret: int, iv_hex: str, ct_hex: str):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode())
    key = sha1.digest()[:16]

    cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv_hex))
    pt = cipher.decrypt(bytes.fromhex(ct_hex))
    return unpad(pt, 16).decode() if is_pkcs7_padded(pt) else pt.decode()


def send_json(r, obj):
    r.sendline(dumps(obj).encode())


r = remote(HOST, PORT)

r.recvuntil(b'Intercepted from Alice: ')
alice1 = loads(r.recvuntil(b'}'))
p_hex, g, A_hex = alice1['p'], alice1['g'], alice1['A']

r.recvuntil(b'Intercepted from Bob: ')
B_hex = loads(r.recvuntil(b'}'))['B']

r.recvuntil(b'Intercepted from Alice: ')
alice2 = loads(r.recvuntil(b'}'))
iv_A, enc_A = alice2['iv'], alice2['encrypted']

r.recvuntil(b'Bob connects to you, send him some parameters: ')

fake_p = int("21161033472192524829557170410776298658794639108376130676557783015578090330844472167861788371083170940722591241807108382859295872641348645166391260040395583908986502774347856154314632614857393087562331369896964916313777278292965202780626304839725254323083321245935920345445760469315716688808181386083935737705284353395869520861742156127496385090743602309049820934917134755461873012945704938955132724663075880436995904093654709349552656965610546540372048421026608925808493978164019986593442564905462745669412326023291812269608558332157759989142549649265359278848084868920655698461242425344000000000000000000000000000000000000000000000000000000000000000000000000000001")

send_json(r, {'g': g, 'p': hex(fake_p), 'A': A_hex})

r.recvuntil(b'Bob says to you: ')
B_from_bob = loads(r.recvuntil(b'}'))['B']

r.recvuntil(b'Bob says to you: ')
bob_cipher = loads(r.recvuntil(b'}'))
iv_B, enc_B = bob_cipher['iv'], bob_cipher['encrypted']

r.close()

b = int("1919572943691512325783103720167834163677411292709378502535498859989993544026380143919501049584589675317643993465536543895780854808442293000014297210200227069779643763121704810281976733978781152126062646602812482025293137787739116693980988513420732289020477701182639042794562638875881378349771734410919106042203493166198706573467903966100368713572415175654342828296086659529676015616513470105470901979846373335352656586302787870238998914215908919919219987614105175")

A = int(A_hex, 16)
p = int(p_hex, 16)

shared_secret = pow(A, b, p)

print(decrypt_flag(shared_secret, iv_A, enc_A))
