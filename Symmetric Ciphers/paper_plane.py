import requests
from Crypto.Util.Padding import unpad


url = "http://aes.cryptohack.org/paper_plane/"
sess = requests.Session()
res = sess.get(url + "encrypt_flag/").json()
ct = bytes.fromhex(res["ciphertext"])
m0 = bytes.fromhex(res["m0"])
c0 = bytes.fromhex(res["c0"])


def guess_plaintext(c, m, c0_): 
    return "error" not in sess.get(
        f"{url}send_msg/{c.hex()}/{m.hex()}/{c0_.hex()}/"
    ).json()


pt = bytearray(len(ct))
keys = bytearray(len(ct))

for b in range(len(ct) // 16):
    block = ct[16*b : 16*b+16]
    for i in range(15, -1, -1):
        pad = 16 - i
        for c in range(256):
            c0_2 = bytearray(c0)
            c0_2[i] = c
            for j in range(i+1, 16):
                c0_2[j] = keys[16*b + j] ^ pad
            if guess_plaintext(block, m0, c0_2):
                k = c ^ pad
                idx = 16*b + i
                keys[idx] = k
                pt[idx] = k ^ c0[i]
                break
        print(pt)
        if pt[idx] == 0:
            break
    m0 = pt[16*b : 16*b+16]
    c0 = block

print("flag", unpad(pt, 16))
