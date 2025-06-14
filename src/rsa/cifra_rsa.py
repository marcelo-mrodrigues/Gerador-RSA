import hashlib
import os
import math
from unidecode import unidecode

# MGF1 , bloco de bytes de tamanho fixo pseudoaleatório
def gerar_mascara(seed, tamanho, hash_func=hashlib.sha3_256):
    # 32 bytes para SHA-256
    hash_length = hash_func().digest_size
    num_blocks = math.ceil(tamanho / hash_length)  # Garante blocos suficientes
    output = b""

    # Gera blocos de hash concatenando seed com contador
    for i in range(num_blocks):  
        c = i.to_bytes(4, "big")
        output += hash_func(seed + c).digest()

    return output[:tamanho]

# Prepara a mensagem para cifrar usando OAEP
def oeap_cifrar(message, tamanho_chave, label=b"", hash_func=hashlib.sha3_256):
    tamanho_mensagem = len(message)
    hash_tamanho = hash_func().digest_size

    # A mensagem não pode ser longa pro bloco RSA
    if tamanho_mensagem > tamanho_chave - 2 * hash_tamanho - 2:
        raise ValueError("Mensagem muito grande")

    # Hash da label
    hash = hash_func(label).digest()

    # Calcula o tamanho do padding com bytes nulos
    pd_len = tamanho_chave - tamanho_mensagem - 2 * hash_tamanho - 2
    pd = b"\x00" * pd_len

    dados = hash + pd + b"\x01" + message # H(label) + Padding + 0x01 + Mensagem

    # seed aleatório 
    seed = os.urandom(hash_tamanho)

    # Mascara o Bloco de Dados aplicando XOR de gerar_mascara
    dados_mask = gerar_mascara(seed, len(dados), hash_func)
    masked_dados = bytes(a ^ b for a, b in zip(dados, dados_mask))

    # Mascara o seed
    seed_mask = gerar_mascara(masked_dados, hash_tamanho, hash_func)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    mensagem_cifrada = b"\x00" + masked_seed + masked_dados

    return mensagem_cifrada

# Recupera a mensagem original após decifrar o RSA
# Desfaz o mascaramento e valida a integridade do bloco de dados
def oeap_decifrar(mensagem_cifrada, tamanho_chave, label=b"", hash_func=hashlib.sha3_256):
    tamanho_mensagem = len(mensagem_cifrada)
    hash_tamanho = hash_func().digest_size

    if tamanho_mensagem != tamanho_chave:
        raise ValueError("Tamanho invalido")

    # Separa a mensagem em suas partes
    y = mensagem_cifrada[0]
    masked_seed = mensagem_cifrada[1: hash_tamanho + 1]
    masked_dados = mensagem_cifrada[1 + hash_tamanho:]

    # Tira o masking do seed
    seed_mask = gerar_mascara(masked_dados, hash_tamanho, hash_func)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))

    # Tira o masking do bloco de dados
    dados_mask = gerar_mascara(seed, len(masked_dados), hash_func)
    dados = bytes(x ^ y for x, y in zip(masked_dados, dados_mask))

    l_hash_bloco = dados[
        :hash_tamanho
    ]  # Separa o hash do rotulo do resto do bloco de dados
    l_hash = hash_func(label).digest()

    # Verifica se o hash do rótulo e o byte Y estão corretos
    if l_hash_bloco != l_hash or y != 0:
        raise ValueError("erro na decodificacao")

    # Encontra b'\x01' que marca o início da mensagem original
    separador_index = -1
    for i in range(hash_tamanho, len(dados)):
        if dados[i] == 1:
            separador_index = i

            break
    if separador_index == -1:
        raise ValueError("separador nao encontrado")

    return dados[separador_index + 1:]  # Retorna a parte que contém a mensagem original


def cifrar(bytes, chave_publicas):

    n, e = chave_publicas
    # Calcula o tamanho da chave em bytes
    tamanho_chave = (n.bit_length() + 7) // 8
    # Aplica padding OEAP para preparar a mensagem
    mensagem_cifrada = oeap_cifrar(bytes, tamanho_chave)

    m = int.from_bytes(mensagem_cifrada, "big")  # Converte bytes para inteiro
    c = pow(m, e, n)  # C = M^e mod n
   
    return c


def decifrar(cifrado_inteiro, chave_privada):
    
    n, d = chave_privada
    # Calcula o tamanho da chave em bytes
    tamanho_chave = (n.bit_length() + 7) // 8

    # Decifragem RSA: M = C^d mod n
    m = pow(cifrado_inteiro, d, n)
    # Inteiro de volta para Bytes
    mensagem_cifrada = m.to_bytes(
        tamanho_chave, "big"
    )
    # Remove o padding OEAP e recupera a mensagem original
    mensagem_original = oeap_decifrar(
        mensagem_cifrada, tamanho_chave
    )

    return mensagem_original

# Bloco de teste que tem que tirar depois da interface pronta

if __name__ == "__main__":
    from geracao_chave import chave_rsa

    # Gera um par de chaves
    publica, privada = chave_rsa(1024)
    texto_original = unidecode("Teste ç é ó ídsadasd")
    mensagem_original = texto_original.encode('utf-8')

    print(f"\nmensagem original: {mensagem_original.decode()}")

    texto_cifrado = cifrar(mensagem_original, publica)
    print(f"texto cifrado como inteiro: {texto_cifrado}")

    # Decifrando
    texto_decifrado = decifrar(texto_cifrado, privada)
    print(f"texto decifrado: {texto_decifrado.decode()}")

    # Verificação
    assert mensagem_original == texto_decifrado
    print("Assertiva bem sucedida")
