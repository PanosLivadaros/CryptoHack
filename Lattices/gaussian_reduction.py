import math


def gaussian_lattice_reduction(v1, v2):
    while True:
        if v2[0] ** 2 + v2[1] ** 2 < v1[0] ** 2 + v1[1] ** 2:
            v1, v2 = v2, v1

        dot12 = v1[0] * v2[0] + v1[1] * v2[1]
        dot11 = v1[0] * v1[0] + v1[1] * v1[1]
        m = math.floor(dot12 / dot11)

        if m == 0:
            return v1, v2

        v2 = (v2[0] - m * v1[0], v2[1] - m * v1[1])


v = (846835985, 9834798552)
u = (87502093, 123094980)

v1, v2 = gaussian_lattice_reduction(v, u)

inner_product = v1[0] * v2[0] + v1[1] * v2[1]
print("The inner product of the new basis vectors v1, v2 is: ", inner_product)
