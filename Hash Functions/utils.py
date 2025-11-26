import socket as sk
from binascii import hexlify
from json import dumps as js_dumps
from json import loads as js_loads
from re import findall
from sys import stderr as sys_stderr
from typing import Union
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class PrintingSocket(sk.socket):
    def recv_print(self) -> bytes:
        msg = self.recv(4096)
        try:
            decoded = msg.decode()
            print(decoded)
        except UnicodeDecodeError:
            print("Not printable!")
        return msg

    def recv_print_dict(self) -> dict:
        msg = self.recv(4096)
        try:
            decoded = msg.decode()
            print(js_loads(decoded))
        except UnicodeDecodeError:
            print("Not printable!")
        return js_loads(msg)

    def send_print(self, data: bytes) -> int:
        try:
            msg = data.decode()
            print(msg)
        except UnicodeDecodeError:
            print("Not printable!")
        return self.send(data)

    def send_print_dict(self, data: dict) -> int:
        try:
            print(data)
        except UnicodeDecodeError:
            print("Not printable!")
        return self.send(js_dumps(data).encode())


def get_blocks(ciphertext: str, size: int = 16) -> list:
    size *= 2
    return [ciphertext[i : i + size] for i in range(0, len(ciphertext), size)]


def xor_strings(s1: str, s2: str) -> str:
    try:
        int(s1, 16)
    except ValueError:
        print(rf"ERROR: The first parameter is not an hexadecimal string", file=sys_stderr)
        exit(1)

    try:
        int(s2, 16)
    except ValueError:
        print(rf"ERROR: The second parameter is not an hexadecimal string", file=sys_stderr)
        exit(1)

    res_len = min(len(s1), len(s2)) - (min(len(s1), len(s2)) % 2)
    s1_hex_list = [s1[i : i + 2] for i in range(0, res_len, 2)]
    s2_hex_list = [s2[i : i + 2] for i in range(0, res_len, 2)]
    res_list = []

    for c1, c2 in zip(s1_hex_list, s2_hex_list):
        res_list.append(hex(int(c1, 16) ^ int(c2, 16))[2:].rjust(2, "0"))

    return "".join(res_list)


def hex_to_ascii(s: str) -> str:
    if s.startswith("0x"):
        s = s[2:]

    return bytes.fromhex(s).decode()


def num_to_hexstr(n: int) -> str:
    if len(s := hex(n)[2:]) % 2 != 0:
        s = "0" + s
    return s


def ascii_to_hex(s: str) -> str:
    return hexlify(s.encode()).decode()


def hex_to_bin(h: str) -> bytes:
    return bytes.fromhex(h)


def get_flag_in_message(m: Union[bytes, str]) -> str:
    if type(m) == str:
        m = m.encode()

    s = m.index(b"crypto{")
    e = m.index(b"}")
    return m[s : e + 1].decode()


def get_n_e_from_rsa_pubkey(pubkey: str) -> tuple[int, int]:
    public_key = serialization.load_pem_public_key(pubkey, backend=default_backend())

    n = public_key.public_numbers().n
    e = public_key.public_numbers().e

    return n, e


def parse_dicts(string):
    pattern = rb"\{[^{}]*\}"
    dicts = findall(pattern, string)
    parsed_dicts = []
    for d in dicts:
        parsed_dict = js_loads(d)
        parsed_dicts.append(parsed_dict)
    return parsed_dicts
