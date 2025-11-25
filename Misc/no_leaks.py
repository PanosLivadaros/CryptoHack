from pwn import *
import json
import base64
import string


con = remote('socket.cryptohack.org', 13370)
con.recvline()

i = 7
allowed = set(string.ascii_letters + string.digits + '_}')

while True:
    print(f"Guessing Byte {i+1}", end=" ")
    attempts = 0
    key_space = allowed.copy()

    while len(key_space) > 1:
        attempts += 1
        try:
            con.sendline(json.dumps({"msg": "request"}))
            flag_64 = json.loads(con.recvline())["ciphertext"]
            bad_char = chr(base64.b64decode(flag_64)[i])
            key_space.discard(bad_char)
        except:
            pass

    print(f"After {attempts} attempts -> {key_space}")

    if '}' in key_space:
        break

    i += 1
