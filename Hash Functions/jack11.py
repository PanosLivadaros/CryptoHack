from math import log, sqrt, ceil


n_small = 11
lamb = 0.75
t = 2 ** ((n_small + 1) / 2) * sqrt(log(1 / (1 - lamb)))

n = 2 ** 11
p = 1.0
i = 0
ratio = (n - 1) / n

while p > 0.5:
    i += 1
    p *= ratio

print("We would expect to hash {} unique secrets to have a 50% chance of collision with Jack's secret, and we would expect to hash {} unique secrets to have a 75% chance of collision between two distinct secrets.".format(i, ceil(t)))
