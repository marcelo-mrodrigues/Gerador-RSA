import random


def talvez_primo(n, k=100):
    # Objetivo de testar Miller-Rabin
    # True para Provavél primo, False Caso contrário
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # n - 1 = 2^s*d
    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    # Testes k

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)  # x = a^d mod n , obs: mais eficiente

        if x == n - 1 or x == 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break

        else:
            return False
    # Se passou até aqui, provavelmente é primo
    return True

print(talvez_primo(12367))
print(talvez_primo(12347))
# https://www.walter-fendt.de/html5/mpt/primenumbers_pt.htm
