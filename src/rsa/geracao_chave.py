import random
from .teste_primalidade import talvez_primo
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

def chave_rsa(bits=1024):
    p = gerar_primo(bits)
    q = gerar_primo(bits)
    while p == q:
        q = gerar_primo(bits)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    chave_publica = (n, e)
    chave_privada = (n, d)

    return (chave_publica, chave_privada)


  # testes das funções !apagr!

"""
print(chave_rsa(bits=1024))
"""

"""
print(gerar_primo(512))
print(gerar_primo(1024))
print(gerar_primo(3))
print(gerar_primo(5))
print(gerar_primo(8))
print(gerar_primo(10))"""