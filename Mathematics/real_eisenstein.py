from mpmath import mp, pslq, sqrt


mp.dps = 100
ct = mp.mpf('1350995397927355657956786955603012410260017344805998076702828160316695004588429433')
nums = [sqrt(p) for p in __import__('sympy').primerange(2, 104)][:len("crypto{???????????????}")]
nums.append(-ct / mp.power(16, 64))
print(''.join(chr(c) for c in pslq(nums, maxcoeff=300, maxsteps=20000)[:-1]))
