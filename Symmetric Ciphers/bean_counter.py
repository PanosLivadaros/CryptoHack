import requests


def encrypt():
    return bytes.fromhex(requests.get(
        "http://aes.cryptohack.org/bean_counter/encrypt/"
    ).json()["encrypted"])


png_hdr = bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52])

enc = encrypt()

keystream = bytes(h ^ e for h, e in zip(png_hdr, enc))

png = bytes(enc[i] ^ keystream[i % len(keystream)] for i in range(len(enc)))

with open("bean_counter.png", "wb") as f:
    f.write(png)
