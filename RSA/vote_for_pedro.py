from pwn import remote
from json import dumps, loads


def send(msg):
    r.sendline(dumps(msg))


r = remote('socket.cryptohack.org', 13375)
print(r.recv())

send({'option': 'vote', 'vote': hex(855520592299350692515886317752220783)})

flag = loads(r.recv())['flag']
print(flag)
