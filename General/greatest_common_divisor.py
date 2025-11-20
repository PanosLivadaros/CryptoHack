def gcd(x, y):
    return y if not x % y else gcd(y, x % y)


a = 66528
b = 52920
print(gcd(a, b))
