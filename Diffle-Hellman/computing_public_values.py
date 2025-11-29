p = 28151


def factor(n):
    f = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            f.add(d)
            n //= d
        d += 1
    if n > 1:
        f.add(n)
    return f


factors = factor(p - 1)


def is_primitive_element(g):
    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False
    return True


for g in range(1, p):
    if is_primitive_element(g):
        print("Smallest primitive element of finite field Fp is: ", g)
        break
