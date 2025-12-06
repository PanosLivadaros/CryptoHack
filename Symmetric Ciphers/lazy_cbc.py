import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long


BASE = "http://aes.cryptohack.org/lazy_cbc"


def api(path):
    return requests.get(f"{BASE}/{path}/").json()


def get_flag(key):
    data = api(f"get_flag/{key.hex()}")
    return bytes.fromhex(data["plaintext"])


def receive(ct):
    data = api(f"receive/{ct.hex()}")
    return bytes.fromhex(data["error"][19:])


def xor(a, b):
    return long_to_bytes(bytes_to_long(a) ^ bytes_to_long(b))


ct = b"\x00" * 32

CD = receive(ct)
C, D = CD[:16], CD[16:]

print(get_flag(xor(C, D)))
