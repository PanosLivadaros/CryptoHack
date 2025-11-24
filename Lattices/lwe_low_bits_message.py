S = A = b = None
with open("output.txt") as f:
    exec(f.read())

p = 257
q = 0x10001

dot_mod_q = sum(a * s for a, s in zip(A, S)) % q

val = b - dot_mod_q

if val < q / 2:
    print("positive range")
    m = val % p
else:
    print("Negative range")
    m = (val - q) % p

print(m)
