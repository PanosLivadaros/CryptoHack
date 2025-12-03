from pwn import remote
from json import dumps, loads
from Crypto.Util.number import bytes_to_long
from pkcs1 import emsa_pkcs1_v15


r = remote('socket.cryptohack.org', 13391)
print(r.recv())

send = lambda obj: r.sendline(dumps(obj))
hex_to_int = lambda x: int(x, 16)

send({'option': 'get_signature'})
N_hex, e_hex, s_hex = loads(r.recv()).values()
N, e, s = map(hex_to_int, (N_hex, e_hex, s_hex))

msg = 'I am Mallory, I own CryptoHack.org'
left = bytes_to_long(emsa_pkcs1_v15.encode(msg.encode(), 256))

n = s - left
assert left % n == s % n

send({
    'option': 'verify',
    'msg': msg,
    'N': hex(n),
    'e': hex(1),
})

flag = loads(r.recv())['msg'].split(':')[1]
print(flag)
