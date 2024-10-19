##Name:Mooyeon Kim
#ECN Login:kim3244
#Due Date:2022-03-03
#!/usr/bin/env python3

from BitVector import *
from PrimeGenerator import *
from rsa import *
from solve_pRoot_BST import *
import sys
import numpy as np

BLOCKSIZE = 256
KEYSIZE = 128
e = 3

#cited from LC12
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def generation():

    generator = PrimeGenerator(bits = KEYSIZE)

    while True:

        p = BitVector(intVal = generator.findPrime(), size = KEYSIZE)
        q = BitVector(intVal = generator.findPrime(), size = KEYSIZE)
        #p and q should not be equal
        if p != q:
            #The two leftmost bits of both p and q must be set
            if p[0] == 1 and p[1] == 1  and q[1] == 1  and q[0] == 1 :
                #(p −1) and (q −1) should be co-prime to e. Hence, gcd(p −1, e) and gcd(q −1, e) should be 1.
                if gcd((p.int_val() - 1), e) == 1 and gcd(q.int_val() - 1, e) == 1:
                    return p.int_val(), q.int_val()

def encryption(plain, enc1, enc2, enc3, n123):
    enc = [enc1, enc2, enc3]
    public_key = []   
   
    for i in range(3):
        p, q = generation()
        while (p * q) in public_key:
            p, q = generation()

        n = p * q
        public_key.append(n)
        
        bv = BitVector(filename = plain)
        
        with open(enc[i], 'w') as FILEOUT:
            while bv.more_to_read:
                bitvec = bv.read_bits_from_file(KEYSIZE)
                if bitvec.length() > 0:
                    if bitvec.length() < KEYSIZE:
                        bitvec.pad_from_right(KEYSIZE - bitvec.length())
                    bitvec.pad_from_left(KEYSIZE)

                    output = BitVector(intVal = pow(bitvec.int_val(), e, n), size=BLOCKSIZE)
                    FILEOUT.write(output.get_bitvector_in_hex())       
    FILEOUT.close()       

    with open(n123, "w") as FILEOUT2:
        for i in range(3):
            FILEOUT2.write(str(public_key[i]) + '\n')
    FILEOUT2.close()
    return

def crack(enc1, enc2, enc3, n123, out):

    N = 1
    enc = [enc1, enc2, enc3]
    keys = []

    with open(n123, "r") as FILEIN:
        for i in range(3):
            k = int(FILEIN.readline().strip("\n"))
            N = N * k
            keys.append(k)
    FILEIN.close()

    N_inv = []
    bv = []

    with open(out, "wb") as FILEOUT:
    
        FILEIN2 = open(enc1)
        bv_i = BitVector(hexstring=FILEIN2.read())

        for i in range(0, bv_i.length() // BLOCKSIZE):
            M = 0
            for j in range(3):
                N_i_bv = BitVector(intVal=N // keys[j])
                N_inv.append(N // keys[j] * N_i_bv.multiplicative_inverse(BitVector(intVal=keys[j])).int_val())

                FILEIN2 = open(enc[j])
                bv.append(BitVector(hexstring = FILEIN2.read()))

                if len(bv[j]) % BLOCKSIZE:
                    bv[j].pad_from_right(BLOCKSIZE - len(bv[j]) % BLOCKSIZE)

                M = M + bv[j][i*BLOCKSIZE : (i+1)*BLOCKSIZE].int_val() * N_inv[j]

            M = M % N
            M_bv = BitVector(intVal = solve_pRoot(3, M), size = BLOCKSIZE)[KEYSIZE : BLOCKSIZE]

            if i == (bv_i.length() // BLOCKSIZE - 1):
                for k in range(0, len(M_bv) // 8):
                    output = M_bv[8*k : 8*(k+1)]
                    if output.int_val() != 0:
                        output.write_to_file(FILEOUT)
            else:
                M_bv.write_to_file(FILEOUT)

    FILEIN2.close()
    FILEOUT.close()
    
    return

if __name__ == '__main__':
    if len(sys.argv) != 7:
        sys.exit("Invalid command")
    if sys.argv[1] == '-e':
        encryption(sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5],sys.argv[6])
    elif sys.argv[1] == '-c':
        crack(sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5],sys.argv[6])
    else:
        sys.exit("Invalid command")        