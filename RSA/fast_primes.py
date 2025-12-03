from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives import serialization


c = 0x249d72cd1d287b1a15a3881f2bff5788bc4bf62c789f2df44d88aae805b54c9a94b8944c0ba798f70062b66160fee312b98879f1dd5d17b33095feb3c5830d28

pub = serialization.load_pem_public_key(open("key_17a08b7040db46308f8b9a19894f9f95.pem","rb").read()).public_numbers()
n, e = pub.n, pub.e

print("Modulus (N):", n)
print("Public Exponent (e):", e)

p = 51894141255108267693828471848483688186015845988173648228318286999011443419469
q = 77342270837753916396402614215980760127245056504361515489809293852222206596161

d = pow(e, -1, (p - 1) * (q - 1))

cipher = PKCS1_OAEP.new(RSA.construct((n, e, d)))
plaintext = cipher.decrypt(c.to_bytes((c.bit_length() + 7) // 8, 'big'))

print(plaintext)
