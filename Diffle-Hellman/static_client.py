from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import telnetlib
import hashlib
import json


HOST = "socket.cryptohack.org"
PORT = 13373

tn = telnetlib.Telnet(HOST, PORT)


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
    

def modexp(g, e, m):
    a = g % m
    b = 1
    while e > 0:
        if e % 2 == 1:
            b = b * a % m
        a = a * a % m
        e = e // 2
    return b


def recv_json():
    line = tn.read_until(b"\n").decode()
    line = line[line.find("{"):]
    return json.loads(line)


def send_json(obj):
    tn.write(json.dumps(obj).encode())


def dh_public(g, sk, p):
    return modexp(g, sk, p)


def dh_shared(pk, sk, p):
    return modexp(pk, sk, p)


def get_initial_from_alice():
    d = recv_json()
    p = int(d["p"], 16)
    g = int(d["g"], 16)
    A = int(d["A"], 16)
    return p, g, A


def get_bob_public():
    return int(recv_json()["B"], 16)


def send_to_bob(p, g, A):
    send_json({"p": p, "g": g, "A": A})


def send_to_alice(B):
    send_json({"B": B})


def get_flag_payload():
    d = recv_json()
    return d["iv"], d["encrypted"]


p, g, A = get_initial_from_alice()
B_from_bob = get_bob_public()
iv, enc_flag = get_flag_payload()

send_to_bob(hex(p), hex(A), "0x01")

shared_secret = get_bob_public()

flag = decrypt_flag(shared_secret, iv, enc_flag)
print(flag)
