import telnetlib
import json


HOST = "socket.cryptohack.org"
PORT = 13393

tn = telnetlib.Telnet(HOST, PORT)


def json_recv():
    return json.loads(tn.read_until(b"\n").decode())


def json_send(payload):
    tn.write(json.dumps(payload).encode())


print(tn.read_until(b"\n").decode().strip())

json_send({
    "data": "76777776666666666666667767767676",
    "option": "hash"
})

print(json_recv())
