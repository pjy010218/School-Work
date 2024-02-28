import math
import random

def is_prime(n):
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return 0
        
    return 1

def generate_all_primes(n):
    a = []
    for i in range(2, n + 1):
        if is_prime(i) == 1:
            a.append(i)

    return a

def generate_random_prime(a, b):
    while(True):
        n = random.randint(a, b)
        if is_prime(n) == 1:
            return n


def wood(n):
    for i in range(1, 10):
        print("나무가 찍혔습니다")
        if (i == 10):
            print("나무가 넘어갔습니다")
            