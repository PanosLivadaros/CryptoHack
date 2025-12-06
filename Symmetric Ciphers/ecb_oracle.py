import requests


ciphertext = b"177d36396d029f19708cef8d1c861bfd1f227170511203bbb211a703905f9e5128ae38bc1312435b814108836328262a"
flag = b"crypto{"


def response(b):
    url = f"http://aes.cryptohack.org/ecb_oracle/encrypt/{b.hex()}/"
    return bytes.fromhex(requests.get(url).json()["ciphertext"])


for i in range(7, 26):
    prefix = b"\x00" * (31 - i)
    print(prefix)

    target = response(prefix)[:32]

    probe = prefix + flag

    for j in range(33, 128):
        guess = probe + bytes([j])
        print(j)

        if response(guess)[:32] == target:
            flag += bytes([j])
            print(flag)
            break
