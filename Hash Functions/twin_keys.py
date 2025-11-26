from pwn import remote
import json


m1 = "43727970746f4861636b2053656375726520536166656c6d522ca4e4ddf8f3410c0299c31b78267cf3dd0a8f200786f6b6aa217215d8759644c28255eafe784d54028d9321aa4fce949d8777176439a7c344b270c286c1730d36e98096cbc127e791e3d96f2c7380107c00117cf9cab68df29d2a856a082ae03df9262e07ff29"
m2 = "43727970746f4861636c2053656375726520536166656c6d522ca4e4ddf8f3410c0299c31b78267cf3dd0a8f200786f6b6aa217215d8759644c28255eafe784d54028d9321aa4fce949c8777176439a7c344b270c286c1730d36e98096cbc127e791e3d96f2c7380107c00117cf9cab68df29d2a856a082ae03df9262e07ff29"

io = remote('socket.cryptohack.org', 13397)
io.recvline()


def send_option(option, key=None):
    payload = {"option": option}
    if key is not None:
        payload["key"] = key
    io.sendline(json.dumps(payload).encode())
    return io.recvline()


print(send_option("insert_key", m1))
print(send_option("insert_key", m2))
io.sendline(b'{"option":"unlock"}')
io.interactive()
