from array import array
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import *
import json


input1 = array('I', [0x6165300e, 0x87a79a55, 0xf7c60bd0, 0x34febd0b, 0x6503cf04, 0x854f709e, 0xfb0fc034, 0x874c9c65, 0x2f94cc40, 0x15a12deb, 0x5c15f4a3, 0x490786bb, 0x6d658673, 0xa4341f7d, 0x8fd75920, 0xefd18d5a])
input2 = array('I', [x ^ y for x, y in zip(input1, [0, 0, 0, 0, 0, 1 << 10, 0, 0, 0, 0, 1 << 31, 0, 0, 0, 0, 0])])

input1 = input1.tobytes()
input2 = input2.tobytes()

prime = 9963887606631886904510816744076774312332177344481531803123536722374675497268512166355104569363455060680486552386910190260277286163274728336768970568461704559940243411194284876439012740935592693167681525648038101883475692410324531178122487559150159612652628935987989808447316201357606634199027879941123342577

input1 = long_to_bytes(prime)
input2 = input2 + long_to_bytes(prime)[64:]

a = 1083337

io = remote('socket.cryptohack.org', 13392)
io.recvline()

to_send = dict()
to_send['option'] = 'sign'
to_send['prime'] = prime
io.sendline(json.dumps(to_send).encode())
sig = json.loads(io.recvline().decode())['signature']

to_send['option'] = 'check'
to_send['prime'] = bytes_to_long(input2)
to_send['signature'] = sig
to_send['a'] = a
io.sendline(json.dumps(to_send).encode())
io.interactive()
