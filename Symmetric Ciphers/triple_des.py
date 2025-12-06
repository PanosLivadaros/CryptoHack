import requests


BASE = "http://aes.cryptohack.org/triple_des"


def api(path):
    return requests.get(f"{BASE}/{path}/").json()


def encrypt(key_hex, pt):
    data = api(f"encrypt/{key_hex}/{pt.hex()}")
    return bytes.fromhex(data["ciphertext"])


def encrypt_flag(key_hex):
    data = api(f"encrypt_flag/{key_hex}")
    return bytes.fromhex(data["ciphertext"])


key = (b"\x00" * 8 + b"\xff" * 8).hex()

flag_ct = encrypt_flag(key)
double_enc = encrypt(key, flag_ct)

print(double_enc)
