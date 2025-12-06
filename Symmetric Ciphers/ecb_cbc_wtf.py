import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long


def response(block):
    url = f"http://aes.cryptohack.org/ecbcbcwtf/decrypt/{block.hex()}/"
    return bytes.fromhex(requests.get(url).json()["plaintext"])


def encrypt_flag():
    url = "http://aes.cryptohack.org/ecbcbcwtf/encrypt_flag/"
    return bytes.fromhex(requests.get(url).json()["ciphertext"])


def xor(a, b):
    return long_to_bytes(bytes_to_long(a) ^ bytes_to_long(b))


enc = encrypt_flag()

iv, block1, block2 = enc[:16], enc[16:32], enc[32:]

pt1 = xor(response(block1), iv)
pt2 = xor(response(block2), block1)

print(pt1 + pt2)
