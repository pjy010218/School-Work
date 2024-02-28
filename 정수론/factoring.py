import math

def factoring_simple(n):
    i = 2
    factor = []
    while i * i <= n:
        if n % i :
            i += 1
        else :
            n //= i
            factor.append(i)

    if n > 1 :
        factor.append(n)

    return factor

def factoring_fermat(n):
    a = math.isqrt(n) + 1
    b = a ** 2 - n
    while not math.isqrt(b) ** 2 == b:
        a += 1
        b = a ** 2 - n

    p = a + math.isqrt(b)
    q = a - math.isqrt(b)

    return int(p), int(q)
