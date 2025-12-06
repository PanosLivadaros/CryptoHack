from requests import get
from collections import Counter
from random import randbytes
from tqdm import trange


def encrypt(nonce: bytes) -> int:
    return int(get(f'http://aes.cryptohack.org/oh_snap/send_cmd/00/{nonce.hex()}/').json()['error'].split()[-1], 16)


N, FLAG_LEN = 256, 34
known = bytearray(b'crypto{')

while known[-1] != 125:
    t = (len(known) - FLAG_LEN) % N
    candidates = []

    for _ in trange(100, leave=False):
        nonce = bytes([0, t - 1]) + randbytes(N - FLAG_LEN - 2)
        z = encrypt(nonce)

        S = list(range(N))
        j = 0
        key = nonce + bytes(known)
        for i in range(len(key)):
            j = (j + S[i] + key[i]) % N
            S[i], S[j] = S[j], S[i]

        if S[1] != t:
            continue

        T = {v: i for i, v in enumerate(S)}
        k = (T[(T[z] - t) % N] - j - S[t]) % N
        candidates.append(k)

    k = Counter(candidates).most_common(1)[0][0]
    known.append(k)
    print(f'k = {chr(k)} [{k:02x}] | known = {bytes(known)}')
