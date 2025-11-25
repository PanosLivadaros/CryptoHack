import telnetlib
import json


server = telnetlib.Telnet("socket.cryptohack.org", 13372)

readline = lambda: server.read_until(b"\n")
json_recv = lambda: json.loads(readline().decode())
json_send = lambda obj: server.write(json.dumps(obj).encode())

print(readline())

json_send({"option": "get_flag"})
encrypted_flag = json_recv()["encrypted_flag"]

json_send({"option": "encrypt_data", "input_data": encrypted_flag})
flag_hex = json_recv()["encrypted_data"]

flag = bytes.fromhex(flag_hex)
print(flag_hex)
print(flag)
