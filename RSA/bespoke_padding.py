from pwn import *
from Crypto.Util.number import inverse, long_to_bytes
import json, sys, ast


r = remote('socket.cryptohack.org', 13386)
r.recvline()

data1, N = [], None
for i in range(1024):
    r.sendline(b'{"option":"get_flag"}')
    item = json.loads(r.recvline())
    if N is None:
        N = item['modulus']
    elif item['modulus'] != N:
        print('Failed Gather data')
    data1.append([item['padding'], item['encrypted_flag']])
    print('recv', i, file=sys.stderr)

with open('datas-1.txt', 'w') as f:
    print(data1, file=f)
with open('datas-1-N.txt', 'w') as f:
    print(N, file=f)

with open('datas-1.txt') as f1, open('datas-1-N.txt') as f1n:
    data1 = ast.literal_eval(f1.read())
    N = ast.literal_eval(f1n.read())

const_poly = [1, 11, 55, 165, 330, 462, 462, 330, 165, 55, 11]
data2 = []
for (a, b), val in data1:
    poly = [(pow(a, 11 - i, N) * pow(b, i, N) * const_poly[i]) % N for i in range(11)]
    val = (val - pow(b, 11, N)) % N
    data2.append([poly, val])

ko_list = data2
while len(ko_list) > 1:
    prev = ko_list
    ko_list = []
    for i in range(0, len(prev), 2):
        c0, c1 = prev[i][0][0], prev[i+1][0][0]
        new_val = (prev[i][1] * c1 - prev[i+1][1] * c0) % N
        new_const = [(prev[i][0][j] * c1 - prev[i+1][0][j] * c0) % N for j in range(1, len(prev[i][0]))]
        ko_list.append([new_const, new_val])

coef, val = ko_list[0][0][0], ko_list[0][1]
flag = (val * inverse(coef, N)) % N
print(long_to_bytes(flag))
