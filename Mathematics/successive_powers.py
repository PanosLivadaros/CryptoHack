from sympy import isprime


powers = [588, 665, 216, 113, 642, 4, 836, 114, 851, 492, 819, 237]
basis = [p for p in range(100, 1000) if isprime(p)]

for p in basis:
    for x in range(1, p):
        if all((x * powers[i]) % p == powers[i + 1] for i in range(len(powers) - 1)):
            print(f'crypto{{{p},{x}}}')
