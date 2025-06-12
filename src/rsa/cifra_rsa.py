import hashlib
import os
import math

def gerar_mascara( seed , tamanho, hash_func=hashlib.sha256):
   
   hash_length = hash_func().digest_size
   num_blocks = math.ceil(tamanho / hash_length)  # garante blocos suficientes
   output = b'' 

   for i in range(num_blocks):  #cONCATENA SEED COM O CONTADOR
      c = i.to_bytes(4, 'big')
      output += hash_func(seed + c).digest()

   return output[:tamanho]