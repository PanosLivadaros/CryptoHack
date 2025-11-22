import math


v = (4, 6, 2, 5)

size = math.sqrt(sum(x * x for x in v))

print("The size of the vector is: ", size)
