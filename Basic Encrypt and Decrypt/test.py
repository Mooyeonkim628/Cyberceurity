import cryptBreak
from BitVector import *
someRandomInteger = 29556 #Arbitrary integer for creating a BitVector
key_bv = BitVector(intVal=someRandomInteger, size=16)
decryptedMessage = cryptBreak.cryptBreak('ciphertext.txt', key_bv)
if "Douglas Adams" in decryptedMessage:
    print("Encryption Broken!")
else:
    print("Not decrypted yet")