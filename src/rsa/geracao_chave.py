import random
from teste_primalidade import talvez_primo
from sympy import mod_inverse 

def gerar_primo(bits):
      # Primo aleatório com a quantidade de bits especificada.
    while True:
        p = random.getrandbits(bits)

          # Garante exatamente 'bits' de comprimento,
          # MSB como 1.
        p |= (1 << bits - 1)

          # -> ímpar
        p |= 1

        if talvez_primo(p, k=40):
            return p


print(gerar_primo(512))
print(gerar_primo(1024))
print(gerar_primo(3))
print(gerar_primo(5))
print(gerar_primo(8))
print(gerar_primo(10))