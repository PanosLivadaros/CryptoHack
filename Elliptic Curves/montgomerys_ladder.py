from sage import *


F = GF(2^255 - 19)
E = EllipticCurve(F, [0, 486662, 0, 1, 0])
G = E.lift_x(F(9))
Q = 0x1337c0decafe * G
print(Q.x())
