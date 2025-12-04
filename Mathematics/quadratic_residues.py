p = 29
ints = [14, 6, 11]

for i in range(1, p):
    if i ** 2 % p in ints:
        print(i, "is a quadratic residue of", i ** 2 % p, "mod", p)
