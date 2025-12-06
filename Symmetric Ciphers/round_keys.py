def matrix2bytes(matrix):
    return bytes([i for j in matrix for i in j])


def add_round_key(s, k):
    return [[i ^ j for i, j in zip(l1, l2)] for l1, l2 in zip(s, k)]


state = [
    [206, 243, 61, 34],
    [171, 11, 93, 31],
    [16, 200, 91, 108],
    [150, 3, 194, 51],
]

round_key = [
    [173, 129, 68, 82],
    [223, 100, 38, 109],
    [32, 189, 53, 8],
    [253, 48, 187, 78],
]

print(matrix2bytes(add_round_key(state, round_key)))
