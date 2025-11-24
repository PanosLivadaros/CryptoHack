def bytes_to_long(b):
    return int.from_bytes(b, 'big')


def long_to_bytes(n):
    if n == 0:
        return b'\x00'
    byte_length = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_length, 'big')


pks = []
with open("public_key.txt", "r") as f:
    for _ in range(65):
        line = f.readline().strip()
        if not line:
            continue
        row = [int(x) % 2 for x in line.split()]
        pks.append(row)

cts = []
with open("ciphertexts.txt", "r") as f:
    for _ in range(392):
        line = f.readline().strip()
        if not line:
            continue
        row = [int(x) for x in line.split()]
        cts.append(row)

known_bytes = b'crypto{}'
known_long = bytes_to_long(known_bytes)
known_bits = [(known_long >> (63 - i)) & 1 for i in range(64)]
known_cts = cts[:56] + cts[-8:]

A = []
b = []

for i in range(64):
    ct = known_cts[i]
    row = [ct[j] % 2 for j in range(64)]
    rhs = (known_bits[i] + ct[64]) % 2
    A.append(row)
    b.append(rhs)

for i in range(512):
    row = [pks[j][i] for j in range(64)]
    rhs = pks[64][i]
    A.append(row)
    b.append(rhs)

n = 64
m = len(A)

aug = [A[i] + [b[i]] for i in range(m)]

row = 0
col = 0
where = [-1] * n

while row < m and col < n:
    sel = row
    for i in range(row, m):
        if aug[i][col] == 1:
            sel = i
            break
    else:
        col += 1
        continue

    aug[row], aug[sel] = aug[sel], aug[row]

    for i in range(m):
        if i != row and aug[i][col] == 1:
            for j in range(col, n + 1):
                aug[i][j] ^= aug[row][j]

    where[col] = row
    row += 1
    col += 1

x = [0] * n
for i in range(n):
    if where[i] != -1:
        x[i] = aug[where[i]][n]
    else:
        x[i] = 0

sk = x + [1]

flag_bits = []
for ct in cts:
    total = 0
    for i in range(len(sk)):
        total += sk[i] * ct[i]
    flag_bits.append(str(total & 1))

bitstring = ''.join(flag_bits)

if bitstring == '':
    n_flag = 0
else:
    n_flag = int(bitstring, 2)

flag_bytes = long_to_bytes(n_flag)
num_bytes = (len(bitstring) + 7) // 8
flag_bytes = flag_bytes.rjust(num_bytes, b'\x00')

print(flag_bytes)
