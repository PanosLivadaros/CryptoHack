from Crypto.Util.number import long_to_bytes, bytes_to_long
import urllib.request, json


def api(url):
    return json.loads(urllib.request.urlopen(url).read())


def encrypt(n):
    pt = long_to_bytes(n, 16).hex()
    data = api(f"http://aes.cryptohack.org/forbidden_fruit/encrypt/{pt}/")
    tag, ct, nonce, ad = (bytes.fromhex(data[k]) for k in ("tag", "ciphertext", "nonce", "associated_data"))
    return bytes_to_long(tag), bytes_to_long(ct), nonce, ad


tag0, ks, nonce, ad = encrypt(0)
tag1 = encrypt(1)[0]

msg = b"give me the flag"
pt = bytes_to_long(msg)

tag = encrypt(pt ^ 1)[0] ^ tag0 ^ tag1

cipher = long_to_bytes(ks ^ pt, 16).hex()
tag_hex = long_to_bytes(tag, 16).hex()
nonce_hex, ad_hex = nonce.hex(), ad.hex()

dec = api(f"http://aes.cryptohack.org/forbidden_fruit/decrypt/{nonce_hex}/{cipher}/{tag_hex}/{ad_hex}/")

print(bytes.fromhex(dec["plaintext"]))
