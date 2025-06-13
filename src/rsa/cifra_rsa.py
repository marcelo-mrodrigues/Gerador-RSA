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

def oeap_cifrar(message , tamanho_chave , label=b'' , hash_func=hashlib.sha256):
   tamanho_mensagem = len(message)
   hash_tamanho = hash_func().digest_size

   if tamanho_mensagem > tamanho_chave - 2 * hash_tamanho - 2:
      raise ValueError("Mensagem muito grande")
   
   hash = hash_func(label).digest()
   l_len = tamanho_chave - tamanho_mensagem - 2 * hash_tamanho - 2
   l = b'\x00' * l_len  # preenchimento

   dados = hash_tamanho + l + b'\x01' + message

   seed = os.urandom(hash_tamanho)

   dados_mask = gerar_mascara( seed, len(dados) , hash_func)
   masked_dados = bytes(a ^ b for a, b in zip(dados, dados_mask))

   seed_mask = gerar_mascara(masked_dados, hash_tamanho, hash_func)
   masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

   mensagem_cifrada = b'\x00' + masked_seed + masked_dados
   return mensagem_cifrada

def oeap_decifrar(mensagem_cifrada, tamanho_chave, label=b'', hash_func=hashlib.sha256):

   
#comentar codigo!!!!