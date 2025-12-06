import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long


xor = lambda a, b: long_to_bytes(bytes_to_long(a) ^ bytes_to_long(b))

get_cookie = lambda: bytes.fromhex(requests.get(
    "http://aes.cryptohack.org/flipping_cookie/get_cookie/"
).json()["cookie"])

response = lambda cookie, iv: print(requests.get(
    f"http://aes.cryptohack.org/flipping_cookie/check_admin/{cookie.hex()}/{iv.hex()}/"
).json())

cookie = get_cookie()
iv, block1, block2 = cookie[:16], cookie[16:32], cookie[32:]
send_iv = xor(xor(b'admin=False;expi', b'admin=True;\x05\x05\x05\x05\x05'), iv)

response(block1, send_iv)
