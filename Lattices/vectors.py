v = (2, 6, 3)
w = (1, 0, 0)
u = (7, 7, 2)

result_vector = tuple(3 * (2 * v[i] - w[i]) for i in range(3))
result = sum(result_vector[i] * 2 * u[i] for i in range(3))

print("The result of the expression is: ", result)
