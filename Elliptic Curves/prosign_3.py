from datetime import datetime
from Crypto.Util.number import bytes_to_long, inverse
from ecdsa.ecdsa import Private_key, Signature, generator_192
from pwn import *
import hashlib, json


g = generator_192
n = g.order()
r = remote('socket.cryptohack.org', 13381)


def sha1(data): return hashlib.sha1(data).digest()


def json_recv():
    line = r.recvline()
    return json.loads(line[line.find(b'{'):])


def json_send(x): r.sendline(json.dumps(x))


r.recvline()

print("[+] Please wait for seconds to be Second=2")
while datetime.now().second != 2: pass

k = 1
json_send({"option": "sign_time"})
data = json_recv()
msg, sig_r, sig_s = data["msg"], int(data["r"], 16), int(data["s"], 16)

h = bytes_to_long(sha1(msg.encode()))
sig = Signature(sig_r, sig_s)
pk1 = sig.recover_public_keys(h, g)[0]

secret = ((sig_s - h) * inverse(sig_r, n)) % n
priv = Private_key(pk1, secret)

hmsg = bytes_to_long(sha1(b"unlock"))
forged = priv.sign(hmsg, k)
json_send({
    "option": "verify",
    "msg": "unlock",
    "r": hex(forged.r),
    "s": hex(forged.s)
})
print(f"[+] Found flag : {json_recv()['flag']}")
