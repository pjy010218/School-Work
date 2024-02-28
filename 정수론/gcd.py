def gcd(a, b):
    while(a != 0):
        b, a = a, b % a

    return b

def extended_gcd(a, b):
    if a == 0 :  
        return b, 0, 1
             
    gcd,s1,t1 = extended_gcd(b%a, a)
     
    s = t1 - (b//a) * s1 
    t = s1
     
    return gcd,s,t

#gcd = b*x1 + a*(y1 - b//a*x1)
