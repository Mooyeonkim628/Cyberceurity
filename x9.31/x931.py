##Name:Mooyeon Kim
#ECN Login:kim3244
#Due Date:2022-02-22
#!/usr/bin/env python3

import sys
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []                                                  # for encryption
invSubBytesTable = []                                               # for decryption

BLOCKSIZE = 128

mix_column = {i: None for i in range(4)}
mix_column[0] = [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")]
mix_column[1] = [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")]
mix_column[2] = [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")]
mix_column[3] = [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]

inverse_mix_column = {i: None for i in range(4)}
inverse_mix_column[0] = [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")]
inverse_mix_column[1] = [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")]
inverse_mix_column[2] = [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")]
inverse_mix_column[3] = [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]

#Cited from Lecture 8
def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    return subBytesTable, invSubBytesTable

#Cited from Lecture 8
def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

# generate the keywords used in each round of AES
def gen_key_schedule_256(key_bv):
    byte_sub_table, _ = genTables()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal=0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32:i*32+32]
    for i in range(8, 60):
        if i % 8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size=0)
            for j in range(4):
                key_words[i] += BitVector(intVal=byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size=8)
            key_words[i] ^= key_words[i-8]
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words


def gen_round_keys(key_words, key_schedule):
    for x, y in enumerate(key_words):
        a = []

        for i in range(4):
            a.append(y[(i*8) : (i*8) + 8].intValue())

        key_schedule.append(a)

    round_keys = [None for i in range(15)]
    
    for i in range(15):
        round_keys[i] = (key_words[(i*4)] + key_words[(i*4) + 1] + key_words[(i*4) + 2] + key_words[(i*4) + 3])
        
    return round_keys

def mix_Column(state):
    res = [[0 for i in range(4)] for i in range(4)]
    
    for j in range(4):
    
        for row in range(4):
        
            bv = BitVector( size=8 )
            
            for column in range(4):
                bv ^= state[column][j].gf_multiply_modular(mix_column[row][column], AES_modulus, 8)
                
            res[row][j] = bv
            
    return res

def inverse_mix_Column(state):
    res = [[0 for i in range(4)] for i in range(4)]
    for j in range(4):

        for row in range(4):
            
            bv = BitVector( size=8 )
            
            for column in range(4):
                bv ^= state[column][j].gf_multiply_modular(inverse_mix_column[row][column], AES_modulus, 8)
            
            res[row][j] = bv
    
    return res

def get_key_from_user():
    with open(sys.argv[3], 'r') as FILEIN:
        key = FILEIN.read()
    key = key.strip()
    key_bv = BitVector(textstring=key)
    key_words = gen_key_schedule_256(key_bv)
    return key_bv

def encrypt(bitvec, round_keys):

    bitvec = bitvec ^ round_keys[0]

    state = [[0 for x in range(4)] for x in range(4)]
    
    for i in range(1, 15):
        for row in range(4):
            for column in range(4):
                    state[column][row] = bitvec[32*row + 8*column : 32*row + 8*(column+1)]
        for row in range(4):
            for column in range(4):
                    state[row][column] = BitVector(intVal=subBytesTable[int(state[row][column])], size=8)
                        
        for row in range(1, 4):
            state[row] = state[row][row:] + state[row][:row]

        if i != 14:
            state = mix_Column(state)

        bitvec = BitVector( size=0 )

        for row in range(4):
            for column in range(4):
                bitvec += state[column][row]

        bitvec ^= round_keys[i]

    return bitvec

def x931(v0, dt, totalNum, key_file):
    with open(key_file, 'r') as FILEIN:
        key = FILEIN.read()
    key = key.strip()
    
    key_bv = BitVector( textstring=key )
    key_schedule = []
    key_words = gen_key_schedule_256(key_bv)

    round_keys = gen_round_keys(key_words, key_schedule)
    e_dt = encrypt(dt, round_keys)

    output = []
    tmp = v0 
    
    for i in range(totalNum):
        output.append(encrypt(tmp ^ e_dt, round_keys))
        tmp = encrypt(e_dt ^ encrypt(tmp ^ e_dt, round_keys), round_keys)
        
    return output


if __name__ == "__main__":
    v0 = BitVector(textstring="computersecurity") #v0 will be  128 bits
    #As mentioned before, for testing purposes dt is set to a predetermined value
    dt = BitVector(intVal = 501, size=128)
    listX931 = x931(v0,dt,3,"keyX931.txt")
    #Check if list is correct
    print("{}\n{}\n{}".format(int(listX931[0]),int(listX931[1]),int(listX931[2])))