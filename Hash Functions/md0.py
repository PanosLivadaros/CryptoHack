from Crypto.Cipher import AES
import pwn
import json


HOST = "socket.cryptohack.org"
PORT = 13388


def exploit():
    pr = pwn.connect(HOST, PORT)
    try:
        pr.readline()

        pr.sendline('{"option":"sign","message":""}')
        sig_resp = json.loads(pr.readline().decode().strip())
        c1 = bytes.fromhex(sig_resp["signature"])

        pad = b'\x06' * 6
        admin_block = b"admin=True" + pad
        forged = pwn.xor(AES.new(admin_block, AES.MODE_ECB).encrypt(c1), c1).hex()

        forged_msg = (b"\x10" * 16 + b"admin=True").hex()
        pr.sendline(
            json.dumps({
                "option": "get_flag",
                "signature": forged,
                "message": forged_msg
            }).encode()
        )

        print(pr.readline())
    finally:
        pr.close()


exploit()
