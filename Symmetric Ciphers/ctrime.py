import time
import requests
import string


BASE = "http://aes.cryptohack.org/ctrime/encrypt/"


def encrypt(b):
    return requests.get(f"{BASE}{b.hex()}/").json()["ciphertext"]


alphabet = '}_!@?' + string.ascii_uppercase + string.digits + string.ascii_lowercase


def bruteforce():
    flag = b"crypto{"
    last_len = len(encrypt(flag))

    while True:
        for c in alphabet:
            trial = flag + c.encode()
            ct = encrypt(trial)
            print(c, len(ct))

            if len(ct) == last_len:
                flag = trial
                print(last_len, flag)
                break

            if c == alphabet[-1]:
                last_len += 2
                break

            time.sleep(1)

        if flag.endswith(b"}"):
            print(flag)
            break

bruteforce()
