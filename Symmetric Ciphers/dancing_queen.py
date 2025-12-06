from Crypto.Util.number import bytes_to_long


FLAG = b'crypto{?????????????????????????????}'

bytes_to_words = lambda b: [int.from_bytes(b[i:i+4], 'little') for i in range(0, len(b), 4)]
words_to_bytes = lambda w: b''.join(i.to_bytes(4, 'little') for i in w)
word = lambda x: x & 0xffffffff
xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))


def rotate(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff


def rotate_reverse(x, n): return ((x << (32 - n)) | (x >> n)) & 0xffffffff


class ChaCha20:
    def __init__(self):
        self._state = []

    def _quarter_round(self, x, a, b, c, d):
        x[a] = word(x[a] + x[b])
        x[d] = rotate(x[d] ^ x[a], 16)
        x[c] = word(x[c] + x[d])
        x[b] = rotate(x[b] ^ x[c], 12)
        x[a] = word(x[a] + x[b])
        x[d] = rotate(x[d] ^ x[a], 8)
        x[c] = word(x[c] + x[d])
        x[b] = rotate(x[b] ^ x[c], 7)

    def _quarter_round_reverse(self, x, a, b, c, d):
        x[b] = rotate_reverse(x[b], 7) ^ x[c]
        x[c] = word(x[c] - x[d])
        x[d] = rotate_reverse(x[d], 8) ^ x[a]
        x[a] = word(x[a] - x[b])
        x[b] = rotate_reverse(x[b], 12) ^ x[c]
        x[c] = word(x[c] - x[d])
        x[d] = rotate_reverse(x[d], 16) ^ x[a]
        x[a] = word(x[a] - x[b])

    def _inner_block(self, s):
        for a,b,c,d in [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),
                        (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]:
            self._quarter_round(s, a, b, c, d)

    def _inner_block_reverse(self, s):
        for a,b,c,d in reversed([(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),
                                 (0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]):
            self._quarter_round_reverse(s, a, b, c, d)

    def _setup_state(self, key, iv):
        self._state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] \
                    + bytes_to_words(key) \
                    + [self._counter] \
                    + bytes_to_words(iv)

    def encrypt(self, m, key, iv):
        c = b''
        self._counter = 1
        for i in range(0, len(m), 64):
            self._setup_state(key, iv)
            for _ in range(10):
                self._inner_block(self._state)
            c += xor(m[i:i+64], words_to_bytes(self._state))
            self._counter += 1
        return c

    decrypt = encrypt

    def state_reverse(self, msg, cipher):
        state = bytes_to_words(xor(msg[:64], cipher[:64]))
        self._state = state[:]
        for _ in range(10):
            self._inner_block_reverse(self._state)
        print(''.join(f'{x:#x} ' for x in self._state[:16]))
        print(hex(bytes_to_long(words_to_bytes(self._state[4:14]))))


msg = b'Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula.'
iv1 = bytes.fromhex('e42758d6d218013ea63e3c49')
iv2 = bytes.fromhex('a99f9a7d097daabd2aa2a235')
key = bytes.fromhex('39fd1410fef6485bf3068ea0fb3a8ff6385b4483bc1f321cea4f15cc1c43496c')
msg_enc = bytes.fromhex('f3afbada8237af6e94c7d2065ee0e221a1748b8c7b11105a8cc8a1c74253611c94fe7ea6fa8a9133505772ef619f04b05d2e2b0732cc483df72ccebb09a92c211ef5a52628094f09a30fc692cb25647f')
flag_enc = bytes.fromhex('b6327e9a2253034096344ad5694a2040b114753e24ea9c1af17c10263281fb0fe622b32732')
c = ChaCha20()
c.state_reverse(msg, msg_enc)
msg_dec = c.decrypt(msg_enc, key, iv1)
flag_dec = c.decrypt(flag_enc, key, iv2)
print(f"msg_enc = '{msg_dec}'")
print(f"flag_enc = '{flag_dec}'")
