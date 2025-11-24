from pwn import remote
from json import loads, dumps
from tqdm import tqdm


q = 0x10001


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m



def mat_mult_vec_mod(A, v, mod):
    """Multiply matrix A (list of lists) by vector v (list), mod mod."""
    return [
        sum(row[j] * v[j] for j in range(len(v))) % mod
        for row in A
    ]


def mat_mult_mat_mod(A, B, mod):
    """Multiply matrices A and B modulo mod."""
    n = len(A)
    m = len(B[0])
    p = len(B)
    C = [[0] * m for _ in range(n)]
    for i in range(n):
        for k in range(p):
            if A[i][k]:
                for j in range(m):
                    C[i][j] = (C[i][j] + A[i][k] * B[k][j]) % mod
    return C


def mat_identity(n):
    return [[1 if i == j else 0 for j in range(n)] for i in range(n)]


def mat_inverse_mod(A, mod):
    """Invert matrix A modulo mod using Gauss-Jordan elimination."""
    n = len(A)

    aug = [row[:] + ident_row for row, ident_row in zip(A, mat_identity(n))]
    
    for col in range(n):

        pivot = None
        for row in range(col, n):
            if aug[row][col] % mod != 0:
                pivot = row
                break
        if pivot is None:
            raise ValueError("Matrix is singular")
        
        aug[col], aug[pivot] = aug[pivot], aug[col]
        
        inv = modinv(aug[col][col], mod)
        for j in range(2 * n):
            aug[col][j] = (aug[col][j] * inv) % mod
        
        for row in range(n):
            if row != col and aug[row][col] != 0:
                factor = aug[row][col]
                for j in range(2 * n):
                    aug[row][j] = (aug[row][j] - factor * aug[col][j]) % mod

    return [row[n:] for row in aug]


io = remote("socket.cryptohack.org", 13411)


def send(data):
    io.sendline(dumps(data).encode())
    recv = loads(io.readline())
    A = eval(recv["A"])
    b = eval(recv["b"])
    return A, b


def solve_S():
    AA = []
    bb = []
    for _ in tqdm(range(64)):
        A, b = send({"option": "encrypt", "message": "0"})
        AA.append(A)
        bb.append(b)

    AA_inv = mat_inverse_mod(AA, q)
    S = mat_mult_vec_mod(AA_inv, bb, q)
    return S


def solve_flag(S):
    flag = ""
    for i in tqdm(range(32)):
        A, b = send({"option": "get_flag", "index": i})

        dot = sum(A[j] * S[j] for j in range(len(S))) % q
        char_val = (b - dot) % q
        flag += chr(char_val)
        print(flag)


io.readline()
S = solve_S()
solve_flag(S)
