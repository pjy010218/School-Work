
import random
import math

def gcd(a, b):
    while(a != 0):
        b, a = a, b % a

    return b

def generate_superinc_knapsack(n) :
    super = list()
    former_sum = 0
    
    for i in range (0, n):
        list_int = random.randint(former_sum + 1, former_sum + 3)       
        former_sum += list_int
        super.append(list_int)

    mod_m = random.randint(2 * super[n - 1] + 1, 2 * super[n - 1] + 100)

    return super, mod_m

def knapsack_genkey(n):
    sk, mod_m = generate_superinc_knapsack(n)
    pk = []
    #mod_r, mod_m이 소수
    
    for i in range(2, mod_m):
        if (gcd(i, mod_m) == 1) :
            mod_r = i                   #if mod_m and i are relative prime, mod_r = i

    for i in range(0, n):
        pk.append((sk[i] * mod_r) % mod_m)   
    
    sk.append(mod_m)
    sk.append(mod_r)                  
    return sk, pk

def knapsack_encrypt(p, pk):
    enc_msg_int = format(p, "b")
    string_temp = str(enc_msg_int)                   
    
    enc_msg = []
    cipher_c = 0

    if (len(pk) > len(string_temp)):          
        contrast = len(pk) - len(string_temp)
        for i in range(0, contrast):
            enc_msg.append(0)
        
        for i in range(0, len(string_temp)):
            enc_msg.append(int(string_temp[i]))
            

    for i in range(0, len(pk)):
        cipher_c += pk[i] * enc_msg[i]

    return cipher_c

def knapsack_decrypt(c, sk):
    n = len(sk) - 2
    
    index_list = []
    p = 0

    inverse_mod_r = pow(sk[n + 1], -1, sk[n])
    subset_c = (c * inverse_mod_r) % sk[n]

    subset_c -= sk[n - 1]
    index_list.append(n)
    
    i = 0
    while (subset_c != 0):
        
        if (subset_c <= sk[i]):


            if (subset_c == sk[i]):
                index_list.append(i + 1)
                subset_c -= sk[i]
                
            elif (subset_c < sk[i]):
                index_list.append(i)
                subset_c -= sk[i - 1]
                
            i = 0

        if (i >= n):
            break

        i += 1

    for i in range(0, len(index_list)):
        p += 2**(index_list[0] - index_list[i])

    return p


    #takes an integer cipher text "c" and private key "sk" ex) [1, 2, 4, 9, 18, 37, q (mod_m), r(mod_r)]
    #outputs an integer msg "p"

#n = 10, 20, 30, 40, 50

#----------ex---------
#>> n = 10
#   sk, pk = knapsack_genkey(n) 
#>> p = 123
#>> c = knapsack_encrypt(p, pk)
#>> knapsack_decrypt(c, sk)
