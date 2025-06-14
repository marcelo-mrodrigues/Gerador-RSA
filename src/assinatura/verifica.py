import hashlib
import base64

# ´´´python -m src.assinatura.verifica

def parse(assinatura_b64:str) -> int:
    """
    Converte a assinatura da Base64 pra inteiro.

    Parâmetros: 
        assinatura_b64 (str): Assinatura formatada em Base64 (Parte II)

    Retorna:
        int: Assinatura como inteiro grande
    """
    try:
        assinatura_bytes = base64.b64decode(assinatura_b64)
        return int.from_bytes(assinatura_bytes, 'big')
    except ValueError as e:
        raise ValueError(f'Erro na formatação da assinatura: {e}')


def decifrar_assinatura(assinatura: int, chave_publica: tuple) -> bytes:
    """
    Decifra assinatura e obtém valor de hash.

    Parâmetros:
        assinatura (int): Assinatura como inteiro grande
        chave_publica (tuple): Chave pública (n, e) pra decifrar assinatura
    
    Retorna:
        bytes: Hash original (32 bytes do SHA-3)
    """
    n, e = chave_publica
    hash_decifrado = pow(assinatura, e, n) # m = c^e mod n
    return hash_decifrado.to_bytes(32, 'big')


def verificar(hash_decifrado: bytes, mensagem: bytes, hash_func=hashlib.sha3_256) -> bool:
    """
    Compara hash decifrado com hash esperado, após aplicar SHA-3 na mensagem original.

    Parâmetros:
        hash_decifrado (bytes): Hash obtido após decifrar assinatura
        mensagem (bytes): Mensagem original
        hash_func: Função de hash (default: SHA-3)

    Retorna:
        bool: True casos valores de hash forem iguais, False caso contrário
    """
    hash_esperado = hash_func(mensagem).digest() # Aplica SHA-3 na mensagem
    return hash_decifrado == hash_esperado


if __name__ == '__main__':
    from .assina import aplicar_hash, assinar, formatar_assinatura
    from ..rsa.geracao_chave import chave_rsa

    # 1°) Gera chaves e assina o hash de uma mensagem (Parte II)
    publica, privada = chave_rsa(1024)
    mensagem = b"Teste secreto para testar a completude das funcoes lerolerolero"
    hash_msg = aplicar_hash(mensagem)
    assinatura_int = assinar(hash_msg, privada)
    assinatura_b64 = formatar_assinatura(assinatura_int, (publica[0].bit_length() + 7) // 8)

    # 2°) Parsing da assinatura (Base64 -> inteiro)
    assinatura_int = parse(assinatura_b64)
    
    # 3°) Decifração (RSA com chave pública)
    hash_recuperado = decifrar_assinatura(assinatura_int, publica)
    
    # 4°) Verificação dos valores de hash
    if verificar(hash_recuperado, mensagem):
        print("Assinatura válida e integridade comprovada.")
    else:
        print("Assinatura inválida e/ou integridade comprometida.")