from json import dumps
from utils import PrintingSocket, get_flag_in_message


BLOCK_SIZE = 32


def pad(data: bytes) -> bytes:
    pad_len = (-len(data)) % BLOCK_SIZE
    return data + bytes([pad_len]) * pad_len


data = dumps({
    "m1": "01",
    "m2": "01" + "1f" * 31
}).encode()

with PrintingSocket() as s:
    s.connect(("socket.cryptohack.org", 13405))
    s.recv_print()
    s.send_print(data)
    print(get_flag_in_message(s.recv_print()))
