import random
# from .teste_primalidade import talvez_primo
from teste_primalidade import talvez_primo
from sympy import mod_inverse


def gerar_primo(bits):
    # Loop até encontrar primo
    while True:
        # Número aleatório com a quantidade de bits
        p = random.getrandbits(bits)

        # Garante exatamente 'bits' de comprimento, MSB = 1
        p |= 1 << bits - 1

        # Garente ímpar, para otimização
        p |= 1

        if talvez_primo(p, k=40):
            # Se passar, retorna o primo
            return p


def chave_rsa(bits=1024):
    # Gerar 2 primos distintos p e q
    p = gerar_primo(bits)
    q = gerar_primo(bits)

    while p == q:
        q = gerar_primo(bits)
    # Dfine n, phi, e, d
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537 # Comum valor de e, primo de Fermat, e é coprimo com phi
    d = mod_inverse(e, phi) # (e*d) mod phi(n) = 1

    chave_publica = (n, e)
    chave_privada = (n, d)

    # Retorna par de chaves
    return (chave_publica, chave_privada)


