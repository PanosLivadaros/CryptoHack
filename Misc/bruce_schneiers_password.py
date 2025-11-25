from telnetlib import Telnet
from random import choice
from string import ascii_letters, digits
from Crypto.Util.number import isPrime
import numpy as np


CHRS = [ord(c) for c in (ascii_letters + digits) if ord(c) % 2 == 1]

PREFIX = [49, 65, 97]

while True:
    pw = PREFIX + [choice(CHRS) for _ in range(20)]

    arr = np.array(pw)
    s = int(arr.sum())
    p = int(arr.prod())

    if isPrime(s) and isPrime(p):
        break

password = ''.join(map(chr, pw))

print("Password:", password)

with Telnet("socket.cryptohack.org", 13400) as tn:
    print(tn.read_until(b"\n"))
    tn.write(b'{"password":"' + password.encode() + b'"}')
    print(tn.read_until(b"\n"))
