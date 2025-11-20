from Crypto.PublicKey import RSA


print(RSA.importKey(open('2048b-rsa-example-cert_3220bd92e30015fe4fbeb84a755e7ca5.der', 'rb').read()).n)
