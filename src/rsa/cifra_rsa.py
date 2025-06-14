import hashlib
import os
import math


def gerar_mascara(seed, tamanho, hash_func=hashlib.sha256):

    hash_length = hash_func().digest_size
    num_blocks = math.ceil(tamanho / hash_length)  # garante blocos suficientes
    output = b""

    for i in range(num_blocks):  # cONCATENA SEED COM O CONTADOR
        c = i.to_bytes(4, "big")
        output += hash_func(seed + c).digest()

    return output[:tamanho]


def oeap_cifrar(message, tamanho_chave, label=b"", hash_func=hashlib.sha256):
    tamanho_mensagem = len(message)
    hash_tamanho = hash_func().digest_size

    if tamanho_mensagem > tamanho_chave - 2 * hash_tamanho - 2:
        raise ValueError("Mensagem muito grande")

    hash = hash_func(label).digest()
    l_len = tamanho_chave - tamanho_mensagem - 2 * hash_tamanho - 2
    l = b"\x00" * l_len  # preenchimento

    dados = hash + l + b"\x01" + message

    seed = os.urandom(hash_tamanho)

    dados_mask = gerar_mascara(seed, len(dados), hash_func)
    masked_dados = bytes(a ^ b for a, b in zip(dados, dados_mask))

    seed_mask = gerar_mascara(masked_dados, hash_tamanho, hash_func)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    mensagem_cifrada = b"\x00" + masked_seed + masked_dados
    return mensagem_cifrada


def oeap_decifrar(mensagem_cifrada, tamanho_chave, label=b"", hash_func=hashlib.sha256):
    tamanho_mensagem = len(mensagem_cifrada)
    hash_tamanho = hash_func().digest_size

    if tamanho_mensagem != tamanho_chave:
        raise ValueError("Tamanho invalido")

    y = mensagem_cifrada[0]
    masked_seed = mensagem_cifrada[1: hash_tamanho + 1]
    masked_dados = mensagem_cifrada[1 + hash_tamanho:]

    # tira o masking do seed
    seed_mask = gerar_mascara(masked_dados, hash_tamanho, hash_func)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    # tirra o masking do bloco de dados
    dados_mask = gerar_mascara(seed, len(masked_dados), hash_func)
    dados = bytes(x ^ y for x, y in zip(masked_dados, dados_mask))

    l_hash_bloco = dados[
        :hash_tamanho
    ]  # separa o blodco de dados pra encontrar mensagem
    l_hash = hash_func(label).digest()

    if l_hash_bloco != l_hash or y != 0:
        raise ValueError("erro na decodificacao")

    # encontra o separador 0x01
    separador_index = -1
    for i in range(hash_tamanho, len(dados)):
        if dados[i] == 1:
            separador_index = i

            break
    if separador_index == -1:
        raise ValueError("separador nao encontrado")

    return dados[separador_index + 1:]  # retorna a mensagem decifrada


def cifrar(bytes, chave_publicas):

    n, e = chave_publicas
    # calcula o tamanho da chave em bytes
    tamanho_chave = (n.bit_length() + 7) // 8
    # aplica padding OEAP
    mensagem_cifrada = oeap_cifrar(bytes, tamanho_chave)

    m = int.from_bytes(mensagem_cifrada, "big")  # converte bytes para inteiro
    c = pow(m, e, n)  # cifra a mensagem usando a chave pública

    return c


# comentar codigo!!!!


def decifrar(cifrado_inteiro, chave_privada):
    n, d = chave_privada
    # Calcula o tamanho da chave em bytes
    tamanho_chave = (n.bit_length() + 7) // 8

    # Decifragem RSA
    m = pow(cifrado_inteiro, d, n)  # Decifra a mensagem usando a chave privada
    mensagem_cifrada = m.to_bytes(
        tamanho_chave, "big"
    )  # converte inteiro de volta para bytes

    mensagem_original = oeap_decifrar(
        mensagem_cifrada, tamanho_chave
    )  # remove o padding OEAP

    return mensagem_original


if __name__ == "__main__":
    from geracao_chave import chave_rsa

    # Gera um par de chaves
    publica, privada = chave_rsa(1024)

    mensagem_original = (
        b"Teste secreto para testar a completude das funcoes lerolerolero"  # TESTE
    )
    print(f"\nmensagem original: {mensagem_original.decode()}")

    texto_cifrado = cifrar(mensagem_original, publica)
    print(f"texto cifrado como inteiro: {texto_cifrado}")

    # Decifrando
    texto_decifrado = decifrar(texto_cifrado, privada)
    print(f"texto decifrado: {texto_decifrado.decode()}")

    # Verificação
    assert mensagem_original == texto_decifrado
    print("Asserticva bem sucedida")
