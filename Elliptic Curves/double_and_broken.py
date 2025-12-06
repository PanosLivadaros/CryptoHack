from Crypto.Util.number import long_to_bytes
import json, numpy as np


with open('output.txt') as f:
    readings = np.mean(json.loads(f.readline()), axis=0)

output = ''.join('0' if r < 120 else '1' for r in readings)
flag = int(output[::-1], 2)
print(long_to_bytes(flag))
