import json
import hashlib
from pwn import remote
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def json_recv_line(r, chop = 0):
    return json.loads(r.recvline()[chop:].decode())


def derive_key(shared_secret: int):
    h = hashlib.sha1(str(shared_secret).encode()).digest()
    return h[:16]


def is_pkcs7_padded(msg: bytes) -> bool:
    pad_len = msg[-1]
    if pad_len == 0 or pad_len > len(msg):
        return False
    return all(b == pad_len for b in msg[-pad_len:])


def decrypt_flag(shared_secret: int, iv_hex: str, ct_hex: str) -> str:
    key = derive_key(shared_secret)
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)

    if is_pkcs7_padded(pt):
        pt = unpad(pt, 16)

    return pt.decode("ascii")


r = remote("socket.cryptohack.org", 13371, level = "debug")

data = json_recv_line(r, chop = 24)
g = int(data["g"], 16)
p = int(data["p"], 16)
A = int(data["A"], 16)

print(f"g = {g}")
print(f"p = {p}")
print(f"A = {A}")

b = 197395083814907028991785772714920885908249341925650951555219049411298436217190605190824934787336279228785809783531814507661385111220639329358048196339626065676869119737979175531770768861808581110311903548567424039264485661330995221907803300824165469977099494284722831845653985392791480264712091293580274947132480402319812110462641143884577706335859190668240694680261160210609506891842793868297672619625924001403035676872189455767944077542198064499486164431451944

B = pow(g, b, p)
print(f"B = {B}")

K = pow(A, b, p)
print(f"K = {K}")

r.sendline(json.dumps({"p": data["p"], "g": data["g"], "A": hex(B)}).encode())

bob_reply = json_recv_line(r, chop = 35)
B2 = int(bob_reply["B"], 16)
print(f"B2 = {B2}")

K2 = pow(B, b, p)
print(f"K2 = {K2}")

r.sendline(json.dumps({"B": hex(B)}).encode())

flag_msg = json_recv_line(r, chop = 39)
flag = decrypt_flag(K, flag_msg["iv"], flag_msg["encrypted_flag"])
print(flag)

r.close()
