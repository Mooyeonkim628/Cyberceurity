#!/usr/bin/env python

###  Based on differential XORing of bit blocks.  Differential XORing
###  destroys any repetitive patterns in the messages to be encrypted and
###  makes it more difficult to break encryption by statistical
###  analysis. Differential XORing needs an Initialization Vector that is
###  derived from a pass phrase in the script shown below.  The security
###  level of this script can be taken to full strength by using 3DES or
###  AES for encrypting the bit blocks produced by differential XORing.

###  Call syntax:
###
###       EncryptForFun.py  message_file.txt  output.txt
###
###  The encrypted output is deposited in the file `output.txt'

import sys
from BitVector import *                                                       #(A)

#arg 3개 아니면 리턴
if len(sys.argv) is not 3:                                                    #(B)
    sys.exit('''Needs two command-line arguments, one for '''
             '''the message file and the other for the '''
             '''encrypted output file''')

PassPhrase = "Hopes and dreams of a million years"                            #(C)

BLOCKSIZE = 64                                                                #(D)
numbytes = BLOCKSIZE // 8                                                     #(E)

# Reduce the passphrase to a bit array of size BLOCKSIZE:
#bv_iv = [00000...0000] (64개)
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                    #(F)

for i in range(0,len(PassPhrase) // numbytes):                                #(G)
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                           #(H)
    bv_iv ^= BitVector( textstring = textstr )                                #(I)
#passphrase를 8개(1byte)씩 끊어서 비트 벡터로 bv_iv에 저장

# Get key from user:
key = None
if sys.version_info[0] == 3:                                                  #(J)
    key = input("\nEnter key: ")                                              #(K)
else:                                                                         
    key = raw_input("\nEnter key: ")                                          #(L)
key = key.strip()                                                             #(M)

# Reduce the key to a bit array of size BLOCKSIZE:
key_bv = BitVector(bitlist = [0]*BLOCKSIZE)                                   #(N)
for i in range(0,len(key) // numbytes):                                       #(O)
    keyblock = key[i*numbytes:(i+1)*numbytes]                                 #(P)
    key_bv ^= BitVector( textstring = keyblock )                              #(Q)

#key를 8개씩 끊어서 key_bv에 저장

# Create a bitvector for storing the ciphertext bit array:
msg_encrypted_bv = BitVector( size = 0 )                                      #(R)

# Carry out differential XORing of bit blocks and encryption:
previous_block = bv_iv                                                        #(S)
bv = BitVector( filename = sys.argv[1] )                                      #(T)
#bv는 인풋의 비트벡터
#첫 preivous_block=bv_iv
while (bv.more_to_read):                                                      #(U)
    bv_read = bv.read_bits_from_file(BLOCKSIZE)                               #(V)
    print(bv_read)
    #bv를 빗트로 읽음
    if len(bv_read) < BLOCKSIZE:                                              #(W)
        bv_read += BitVector(size = (BLOCKSIZE - len(bv_read)))               #(X)
        #블락사이즈보다 bv_read가 짧으면 블락사이즈와 같게만듬
        
    bv_read ^= key_bv                                                         #(Y)
    bv_read ^= previous_block                                                 #(Z)
    #key랑 passphrase xor
    previous_block = bv_read.deep_copy()                                      #(a)
    #preivous_block=bv_read
    msg_encrypted_bv += bv_read                                               #(b)
#bv.more_to_read:bv가 false일떄까지


# Convert the encrypted bitvector into a hex string:    
outputhex = msg_encrypted_bv.get_hex_string_from_bitvector()                  #(c)
#비트벡터를 헥스 '스트링'으로 변환

# Write ciphertext bitvector to the output file:
FILEOUT = open(sys.argv[2], 'w')                                              #(d)
FILEOUT.write(outputhex)                                                      #(e)
FILEOUT.close()                                                               #(f)
#아웃풋 파일에 작성 