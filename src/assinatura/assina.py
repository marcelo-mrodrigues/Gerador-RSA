import hashlib

# ´´´python -m src.assinatura.assina

def aplicar_hash(bytes: bytes) -> bytes:
    """
    Aplica a função de hash SHA-3 na mensagem.

    Parâmetros:
        bytes (bytes): Mensagem a ser hasheada
    
    Retorna:
        bytes: Mensagem hasheada (32 bytes -> tamanho fixo)
    """
    return hashlib.sha3_256(bytes).digest()


def assinar(hash_bytes: bytes, chave_privada: tuple) -> bytes:
    """
    Assina valor de hash ao criptografá-lo com a chave privada.
    
    Parâmetros:
        hash_bytes (bytes): Valor de hash em bytes
        chave_privada (tuple): Chave privada (n,d) 

    Retorna:
        bytes: Assinatura em bytes
    """
    n, d = chave_privada
    tamanho_chave = (chave_privada[0].bit_length() + 7) // 8
    m = int.from_bytes(hash_bytes, 'big') # Mensagem vira inteiro
    assinatura = pow(m, d, n) # c = m^d mod n
    return assinatura.to_bytes(tamanho_chave, 'big')


def formatar_base64(data: bytes) -> str:
    """
    Primitiva da formatação em BASE64.

    Parâmetros:
        data (bytes): Mensagem a ser formatada 

    Retorna:
        str: Mensagem formatada na BASE64
    """
    BASE64_TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    result = []

    # Percorre os dados em blocos de 3 bytes em 3 bytes (24 bits)
    for i in range(0, len(data), 3):
        bloco = data[i:i + 3]
        bloco_len = len(bloco) # Verifica se o bloco tem 1, 2 ou 3 bytes

        # Converte o bloco de bytes em um inteiro
        value = int.from_bytes(bloco, 'big')

        # Calcula bits que faltam pra completar 3 bytes
        missing_bits = (3 - bloco_len) * 8
        
        # Preenche com zeros no final pra completar 3 bytes
        value <<= missing_bits

        # Reparte inteiro de 3 bytes (24 bits) em 4 grupos de 6 bits
        for j in range(4):
            # Shift pra direita e máscara pra pegar os 6 bits
            index = (value >> (18 - 6 * j)) & 0x3F
            # Pega caractere correspondente na tabela da BASE64
            result.append(BASE64_TABLE[index])

    # Se o comprimento dos dados não for múltiplo de 3, precisa adicionar padding
    # Sabendo que o último bloco deve ter 3 bytes:
    #   - Se sobrar 1 byte: padding = 2 '=='
    #   - Se sobrar 2 bytes: padding = 1 '='
    padding = (3 - len(data) % 3) % 3

    # Substitui últimos caracteres pelo padding se for preciso
    if padding:
        result[-padding:] = '=' * padding

    return ''.join(result)


if __name__ == '__main__':
    from ..rsa.cifra_rsa import cifrar, decifrar
    from ..rsa.geracao_chave import chave_rsa

    publica, privada = chave_rsa(1024)
    mensagem = b"Teste secreto para testar a completude das funcoes lerolerolero"

    # 1°) Hasheando a mensagem
    hash_mensagem = aplicar_hash(mensagem)

    # 2°) Assinando o hash
    assinatura = assinar(hash_mensagem, privada)
    print("Assinatura (bytes):", assinatura.hex())

    # 3°) Convertendo assinatura para Base64
    assinatura_base64 = formatar_base64(assinatura)
    print("Assinatura (Base64):", assinatura_base64)
