import hashlib

# ´´´python -m src.assinatura.verifica


def parse_base64(base64_string: str) -> bytes:
    """
    Primitiva do parsing de dados na BASE64.

    Parâmetros:
        dados_b64 (string): dados formatados na Base64 (Parte II)

    Retorna:
        bytes: Dados parseados
    """
    BASE64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    # Remove o padding '=' do final
    base64_string = base64_string.rstrip("=")

    # Armazena os bytes resultantes do parsing
    result = bytearray()

    value = 0  # Acumulador de bits
    bits = 0  # Contador dos bits acumulados

    for char in base64_string:
        # Ignora caracteres inválidos
        if char not in BASE64_TABLE:
            continue

        # Converte o caractere Base64 pro seu valor numérico (6 bits)
        value = (value << 6) | BASE64_TABLE.index(char)
        bits += 6  # Avança caractere

        # Caso acumule pelo menos 1 byte (8 bits), extrai
        if bits >= 8:
            bits -= 8
            result.append((value >> bits) & 0xFF)  # Pega os 8 MSB
            value &= (1 << bits) - 1  # Mantém os demais bits

    return bytes(result)


def decifrar_assinatura(assinatura:bytes, chave_publica:tuple)->bytes:
    """
    Decifra assinatura e obtém valor de hash.

    Parâmetros:
        assinatura (int): Assinatura como inteiro grande
        chave_publica (tuple): Chave pública (n, e) pra decifrar assinatura

    Retorna:
        bytes: Hash original (32 bytes do SHA-3)
    """
    n, e = chave_publica
    assinatura_int = int.from_bytes(assinatura, "big")

    # Decifra hash assinado com RSA
    hash_decifrado_int = pow(assinatura_int, e, n)
    return hash_decifrado_int.to_bytes(32, "big")


def verificar(
    hash_decifrado: bytes, mensagem: bytes, hash_func=hashlib.sha3_256
) -> bool:
    """
    Compara hash decifrado com hash esperado, após aplicar SHA-3 na mensagem original.

    Parâmetros:
        hash_decifrado (bytes): Hash obtido após decifrar assinatura
        mensagem (bytes): Mensagem original
        hash_func: Função de hash (default: SHA-3)

    Retorna:
        bool: True casos valores de hash forem iguais, False caso contrário
    """
    hash_esperado = hash_func(mensagem).digest()  # Aplica SHA-3 na mensagem
    return hash_decifrado == hash_esperado


if __name__ == "__main__":
    from .assina import aplicar_hash, assinar, formatar_base64
    from ..rsa.geracao_chave import chave_rsa

    # 1°) Gera chaves e assina o hash de uma mensagem (Parte II)
    publica, privada = chave_rsa(1024)
    mensagem = b"Teste secreto para testar a completude das funcoes lerolerolero"
    hash_msg = aplicar_hash(mensagem)
    assinatura_int = assinar(hash_msg, privada)
    assinatura_b64 = formatar_base64(assinatura_int)

    # 2°) Parsing da assinatura (Base64 -> inteiro)
    assinatura_formatada = parse_base64(assinatura_b64)

    # 3°) Decifração (RSA com chave pública)
    hash_recuperado = decifrar_assinatura(assinatura_formatada, publica)

    # 4°) Verificação dos valores de hash
    if verificar(hash_recuperado, mensagem):
        print("Assinatura válida e integridade comprovada.")
    else:
        print("Assinatura inválida e/ou integridade comprometida.")
