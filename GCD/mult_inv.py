##Name:Mooyeon Kim
#ECN Login:kim3244
#Due Date:2022-02-03
#!/usr/bin/env python3

##main function cited from GCD.py in LC5

import sys

def bit_mul(a, b): 
    x = 0
    while b > 0:
        if b & 1:
            x += a
        a = a << 1
        b = b >> 1
    return x

def bit_mod(a, b):
    if a < b:
        return a
    m = bit_mod(a, b << 2)
    if m >= b:
        m -= b
    return m

def b_gcdExtended(a, b): 
    u = 1
    v = 0
    x = 0
    y = 1
    z = 0

    while (a & -a == 0) and (b & -b == 0):
        a = a >> 1
        b = b >> 1
        z = z  + 1

    m = a
    n = b

    while (a & -a == 0):
        a = a >> 1
        if (u & -u == 0) and (v & -v == 0):
            u = u >> 1
            v = v >> 1
        else:
            u = (u + n) >> 1
            v = (v - m) >> 1
            
    while a != b:
        if (b & -b == 0):
            b = b >> 1
            
            if (x & -x == 0) and (y & -y == 0):
                x = x >> 1
                y = y >> 1
            else:
                x = (x + n) >> 1
                y = (y - m) >> 1

        elif b < a:
            ta = a
            tb = b
            tu = u 
            tv = v
            tx = x
            ty = y
            a = tb
            b = ta 
            u = tx
            v = ty 
            x = tu
            y = tv

        else:
            b = b - a
            x = x - u
            y = y - v

    return bit_mul((1 << z), a), x, y
    
def mult_inv(a,m):
    g, x, y = b_gcdExtended(a, m);
    if g != 1:
        print("\nNO MI. However, the GCD of %d and %d is %u\n" % (a, m, g))
    else:
        inv = bit_mod((bit_mod(x, m) + m), m)
        print("\nMI of %d modulo %d is: %d\n" % (a, m, inv))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("\nUsage:   %s  <integer>  <integer>\n" % sys.argv[0])
    a, m = int(sys.argv[1]), int(sys.argv[2])
    mult_inv(a, m)