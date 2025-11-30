from Crypto.Cipher import AES
import hashlib
import json


with open('data.json') as f:
    signatures = json.load(f)['signatures']

pub_key0 = bytes.fromhex("6df32bef41a3a6242af1702da255d01baf84ebcf9a6a310d8ca90760c0579f28")


def hash(data):
    return hashlib.sha256(data).digest()


message2_hash = hash(f"{pub_key0.hex()} sent 999999 WOTScoins to me".encode())
sig2_iters = [255 - b for b in message2_hash]

bases = {i: ("", 500) for i in range(32)}

for sig_data in signatures:
    msg_hash = hash(sig_data['message'].encode())
    sig1_iters = [255 - b for b in msg_hash]
    sig1 = sig_data['signature']
    for j, count in enumerate(sig1_iters):
        if bases[j][1] > count:
            bases[j] = (sig1[j], count)

sig2 = []
for i in range(32):
    tmp = bytes.fromhex(bases[i][0])
    for _ in range(sig2_iters[i] - bases[i][1]):
        tmp = hash(tmp)
    sig2.append(tmp)

aes_key = bytes(s[0] for s in sig2)
flag = bytes.fromhex("6222d526df3e3b38b8efff531ddfc2ba370d1ed0010c98ef83c542c1f2f77d66")
aes_iv = bytes.fromhex("a73f83b7c65be39e8129125151c1fee5")

cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
print(cipher.decrypt(flag))
