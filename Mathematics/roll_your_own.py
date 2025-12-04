from pwn import *
import json


io = remote('socket.cryptohack.org', 13403)

line = io.recvline().decode()
q_str = line.split(": ")[1].strip().strip('"')
q = int(q_str, 0)

g, n = q + 1, q * q
io.recvuntil(b"Send integers (g,n) such that pow(g,q,n) = 1: ")

io.sendline(json.dumps({'g': hex(g), 'n': hex(n)}).encode())

line = io.recvline().decode()
pub_str = line.split(": ")[1].strip().strip('"')
pub = int(pub_str, 0)

x = (pub - 1) // q

io.sendline(json.dumps({'x': hex(x)}).encode())
io.interactive()
