import json
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import remote


p1, p2 = 211578328037, 2173767566209

r = remote('socket.cryptohack.org', 13376)
r.recvline()


def send(option, **kwargs):
    msg = {'option': option}
    msg.update(kwargs)
    r.send(json.dumps(msg))


def get_sig(x):
    send('sign', msg=long_to_bytes(x).hex())
    return bytes_to_long(bytes.fromhex(json.loads(r.recvline())['signature'][2:]))


send('get_pubkey')
N = bytes_to_long(bytes.fromhex(json.loads(r.recvline())['N'][2:]))

signature = (get_sig(p1) * get_sig(p2)) % N

send('verify',
     msg=b'admin=True'.hex(),
     signature=long_to_bytes(signature).hex())

print(json.loads(r.recvline())['response'])
