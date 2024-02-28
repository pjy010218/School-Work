import math

def lucas_lehmer_test ( p ):
    if p == 2:
        return 1
    
    else:
        mersenne = (2 ** p) - 1
    r = 4

    for i in range(3, p + 1):
        r = (r ** 2 - 2) % mersenne

    if r == 0:
        return 1
    else :
        return 0


def is_prime(n):
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return 0

    return 1

def generate_all_primes(n):
    a = []
    for i in range(2, n + 1):
        if is_prime(i):
            a.append(i)
            
    return a


def find_mersenne_primes(p) :
    prime = generate_all_primes(p)

    flag = -1
    k = 2
    while((2 ** k - 1) <= p ): 
        num = (2 ** k) - 1

        for i in range(0, len(prime)):
            if num == prime[i]:
                flag = 1
                break
            
        if (lucas_lehmer_test(num) == 1 and flag == 1) :
            print(num, end = " " )

        k += 1

