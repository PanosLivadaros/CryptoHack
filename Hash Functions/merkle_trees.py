from hashlib import sha256


def hash256(data):
    return sha256(data).digest()


def merge_nodes(a, b):
    return hash256(a + b)


challenges = []
with open("output.txt", "r") as f:
    for line in f:
        if line.strip():
            challenge = eval(line.strip())
            challenges.append(challenge)

bits = []
for challenge in challenges:
    a_hex, b_hex, c_hex, d_hex, root_hex = challenge
    
    a = bytes.fromhex(a_hex)
    b = bytes.fromhex(b_hex)
    c = bytes.fromhex(c_hex)
    d = bytes.fromhex(d_hex)
    expected_root = bytes.fromhex(root_hex)
    
    left = merge_nodes(a, b)
    right = merge_nodes(c, d)
    computed_root = merge_nodes(left, right)
    
    if computed_root == expected_root:
        bits.append('1')
    else:
        bits.append('0')

binary_str = ''.join(bits)
while len(binary_str) % 4 != 0:
    binary_str = '0' + binary_str

hex_str = hex(int(binary_str, 2))[2:]
if len(hex_str) % 2 != 0:
    hex_str = '0' + hex_str

flag = bytes.fromhex(hex_str)
print(flag.decode())
