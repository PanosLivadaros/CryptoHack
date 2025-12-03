import json
from pwn import *


conn = remote('socket.cryptohack.org', 13374)
data = conn.recvline()

conn.send(json.dumps({'option': 'get_secret'}))
data = json.loads(conn.recvline())

conn.send(json.dumps({'option': 'sign', 'msg': data['secret']}))
data = json.loads(conn.recvline())

print(bytes.fromhex(data['signature'][2:]).decode())
