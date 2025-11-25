from pwn import *
import json


io = remote('socket.cryptohack.org', 13384)

hyper_share = int(json.loads(io.recvline().decode())['y'], 16)
io.recvlines(4)

prime = 2**521 - 1
friends_x = [2, 3, 4, 5]
hyper_x = 6

wallet_1k = int("8b09cfc4696b91a1cc43372ac66ca36556a41499b495f28cc7ab193e32eadd30", 16)

io.sendline(json.dumps({'sender': 'hyper', 'msg': 'lmao', 'x': hyper_x, 'y': "0x0"}).encode())

priv_fail = int(json.loads(io.recvline().decode())['privkey'], 16)

x_value = 1
for x in friends_x:
    x_value = (x_value * x * pow(x - hyper_x, -1, prime)) % prime

y = (wallet_1k - priv_fail) * pow(x_value, -1, prime) % prime

io.sendline(json.dumps({'sender': 'hyper', 'msg': 'lmao', 'x': hyper_x, 'y': hex(y)}).encode())

real_priv = (priv_fail + hyper_share * x_value) % prime
io.sendline(json.dumps({'privkey': hex(real_priv)}).encode())

io.interactive()
