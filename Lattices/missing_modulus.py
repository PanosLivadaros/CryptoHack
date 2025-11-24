import json
from pwn import remote
import numpy as np
from tqdm import tqdm


conn = remote("socket.cryptohack.org", 13412)
conn.recvline()


def get_sample():
    conn.sendline(b'{"option":"encrypt","message":0}')
    resp = json.loads(conn.recvline())
    return eval(resp["A"]), eval(resp["b"])


As, bs = zip(*(get_sample() for _ in tqdm(range(800))))

As = np.array(As, dtype=float)
bs = np.array(bs, dtype=float)

S = np.linalg.lstsq(As, bs, rcond=None)[0]
S = np.round(S).astype(int)

for i in range(46):
    conn.sendline(json.dumps({"option": "get_flag", "index": i}).encode())
    resp = json.loads(conn.recvline())

    A = np.array(eval(resp["A"]), dtype=int)
    b = int(eval(resp["b"]))

    val = int(b - A @ S)
    print(chr(round(val / 23)), end="")
