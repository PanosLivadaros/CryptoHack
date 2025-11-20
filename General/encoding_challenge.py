from pwn import *
import base64
import codecs
import json


class Decoder(object):
    def __init__(self, data):
        self.type = ''
        self.data = ''
        json_loads = json.loads(data)
        self.type = json_loads['type']
        self.data = json_loads['encoded']
        print("Received: ", self.data, self.type)


    def calling(self):
        if self.type == "base64":
            return base64.b64decode(self.data).decode('ISO-8859-1')
        elif self.type == "hex":
            return bytes.fromhex(self.data).decode('ISO-8859-1')
        elif self.type == "rot13":
            return codecs.decode(self.data, 'rot_13')
        elif self.type == "bigint":
            decode_length = len(self.data)
            x = int(self.data, 16).to_bytes(decode_length, 'big')
            return str(x, 'UTF-8').lstrip('\x00')
        elif self.type == "utf-8":
            return ''.join(chr(o) for o in self.data)


re = remote('socket.cryptohack.org', 13377, level='debug')
for i in range(100):
    retrieved_data = re.recv_raw(1024)
    decoder_data = Decoder(retrieved_data)
    decoded_data = decoder_data.calling()
    print("Decoded: ", i, decoded_data)
    decoded_data = {
        "decoded": decoded_data
    }
    response = json.dumps(decoded_data)
    re.send(response)
print('The flag is: ' + re.recv(1024).decode('ISO-8859-1'))
