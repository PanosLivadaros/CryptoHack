def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if a & 0x80 else (a << 1)


def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u0, u1, u2, u3 = a
    a[0] ^= t ^ xtime(u0 ^ u1)
    a[1] ^= t ^ xtime(u1 ^ u2)
    a[2] ^= t ^ xtime(u2 ^ u3)
    a[3] ^= t ^ xtime(u3 ^ u0)


def mix_columns(s):
    for col in s:
        mix_single_column(col)


def inv_mix_columns(s):
    for col in s:
        u = xtime(xtime(col[0] ^ col[2]))
        v = xtime(xtime(col[1] ^ col[3]))
        col[0] ^= u
        col[1] ^= v
        col[2] ^= u
        col[3] ^= v
    mix_columns(s)


def matrix2bytes(matrix):
    return bytes(sum(matrix, []))


state = [
    [108, 106, 71, 86],
    [96, 62, 38, 72],
    [42, 184, 92, 209],
    [94, 79, 8, 54],
]

inv_mix_columns(state)
inv_shift_rows(state)

print(matrix2bytes(state))
