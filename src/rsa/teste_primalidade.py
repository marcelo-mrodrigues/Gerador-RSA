import random

def talvez_primo(n ,  k = 40):
      # Objetivo de testar Miller-Rabin
      # True para Provavél primo, False Caso contrário
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
