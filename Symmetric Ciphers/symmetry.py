import requests


ciphertext = requests.get('https://aes.cryptohack.org/symmetry/encrypt_flag/').json()["ciphertext"]
iv, c = ciphertext[:32], ciphertext[32:]

print(bytes.fromhex(requests.get(
    f'https://aes.cryptohack.org/symmetry/encrypt/{c}/{iv}'
).json()["ciphertext"]))
