from pwn import remote
from json import loads, dumps
from sage import *


p = 2**192 - 237
a = -3
b = 1379137549983732744405137513333094987949371790433997718123
E  = EllipticCurve(GF(p), [a, b])

K2.<z> = GF(p^2)
E2 = EllipticCurve(K2, [a, b])

M = 269 * 1607 * 693493 * 2985973 * 1483406443 * 1631363213 * 40202856427 * 123462957881 
assert M > 2**192

P1 = E2.lift_x(GF(p)(826590802336585448209106331356746121539182903043624897583))
P1 *= E2.order() // M
P1_ord = P1.order()

P2 = E2.lift_x(GF(p)(1649684243721475571532789783128022845579154574715401752168))
P2 *= E2.order() // M
P2_ord = P2.order()

assert P1_ord*P2_ord == M

io = remote('socket.cryptohack.org', 13416)
print(io.recv().decode())
io.sendline(dumps({"option":"get_pubkey", "x0":int(P1[0])}).encode())
x1 = GF(p)(loads(io.readline())['pubkey'])
io.sendline(dumps({"option":"get_pubkey", "x0":int(P2[0])}).encode())
x2 = GF(p)(loads(io.readline())['pubkey'])

Q1 = E2.lift_x(x1)
Q2 = E2.lift_x(x2)
print('...')
d = int(crt([Q1.log(P1), Q2.log(P2)], [P1_ord, P2_ord]))

priv = int(d % M)
io.sendline(dumps({"option":"get_flag", "privkey":priv}).encode())
print(io.readline().decode())

priv = int(-d % M)
io.sendline(dumps({"option":"get_flag", "privkey":priv}).encode())
print(io.readline().decode())
