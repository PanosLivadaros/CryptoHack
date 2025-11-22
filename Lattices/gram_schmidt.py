import numpy as np


v = [np.array((4, 1, 3, -1)), np.array((2, 1, -3, 4)), np.array((1, 0, -2, 7)), np.array((6, 2, 9, -5))]

u = [v[0]]

for i in range(1, 4):
    u.append(v[i] - sum((v[i] @ uj) / (uj @ uj) * uj for uj in u))

print("The result is: ", round(u[3][1], 5))
