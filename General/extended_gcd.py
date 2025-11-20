def extended_gcd(p, q):
    if q == 0:
        return 1, 0, p
    u, v, gcd = extended_gcd(q, p % q)
    return v, u - v * (p // q), gcd


print(extended_gcd(26513, 32321))
