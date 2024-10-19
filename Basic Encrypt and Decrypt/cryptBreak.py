#Homework Number:1
#Name:Mooyeon Kim
#ECN Login:kim3244
#Due Date:2022-01-20
#!/usr/bin/env python3

import sys
from BitVector import *

def cryptBreak(ciphertextFile, key_bv):
    BLOCKSIZE = 16 
    numbytes = BLOCKSIZE // 8
    PassPhrase = "Hopes and dreams of a million years" 
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)     
    for i in range(0,len(PassPhrase) // numbytes):                              
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                         
        bv_iv ^= BitVector( textstring = textstr ) 
      
    FILEIN = open(ciphertextFile, 'r')                                                 
    encrypted_bv = BitVector( hexstring = FILEIN.read())         
    msg_decrypted_bv = BitVector( size = 0 )                                    

    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):                       
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]                          
        temp = bv.deep_copy()                                                  
        bv ^=  previous_decrypted_block                                         
        previous_decrypted_block = temp                                        
        bv ^=  key_bv                                                          
        msg_decrypted_bv += bv                                                 
  
    outputtext = msg_decrypted_bv.get_text_from_bitvector()                    
    FILEIN.close()
    return outputtext      
        
if __name__ == "__main__":    
    someRandomInteger = 0
    while someRandomInteger < 65535:
        key_bv = BitVector(intVal=someRandomInteger, size=16)
        decryptedMessage = cryptBreak('ciphertext.txt', key_bv)
        if 'Douglas Adams' in decryptedMessage:
            print("Encryption Broken!")
            print("message:",decryptedMessage)
            print("key:",someRandomInteger)
            break
        else:
            pass  
        someRandomInteger+=1