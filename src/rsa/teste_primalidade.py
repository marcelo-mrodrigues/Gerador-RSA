import random


def talvez_primo(n, k=1000):
    # Miller-Rabin
    # Triviais
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Decompor n-1 na forma 2^s * d, onde d é ímpar.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Testes k vezes com difetenres valores de a
    for _ in range(k):
        # Escolhe um a aleatório entre 2 e n-2
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)  # x = a^d mod n

        # Se x for 1 ou n-1, 'a' não é uma testemunha
        # O número pode ser primo -> passa
        if x == n - 1 or x == 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)

            # Se em algum momento x se tornar n-1, 'a' também não é uma testemunha tam,bém
            # e o número ainda pode ser primo, saí do loop
            if x == n - 1:
                break

        else:
            # Se não saiu do loop, significa que 'a' é uma testemunha
            return False
        
    # Se passou até aqui, provavelmente é primo
    return True

    # https://www.walter-fendt.de/html5/mpt/primenumbers_pt.htm
