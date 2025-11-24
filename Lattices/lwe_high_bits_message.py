import math


n = 64
p = 257
q = 0x10001
error_bound = int(math.floor((q / p) / 2))
delta = int(round(q / p))

S = None
A = None
b = None
with open('output.txt', 'r') as f:
    exec(f.read())


def mod_q(x):
    return x % q


dot = 0
for i in range(len(A)):
    dot = (dot + A[i] * S[i]) % q

diff = (b - dot) % q
diff = diff % q

m = round(diff / delta)

print(m)
