import hashlib
import base64

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


def assinar(hash_bytes: bytes, chave_privada: tuple) -> int:
    """
    Assina valor de hash ao criptografá-lo com a chave privada.
    
    Parâmetros:
        hash_bytes (bytes): Valor de hash em bytes
        chave_privada (tuple): Chave privada (n,d) 

    Retorna:
        int: Assinatura como inteiro
    """
    n, d = chave_privada
    m = int.from_bytes(hash_bytes, 'big') # Mensagem vira inteiro
    assinatura = pow(m, d, n) # c = m^d mod n
    return assinatura


def formatar_assinatura(assinatura: int, tamanho_chave: int) -> str:
    """
    Formata a assinatura como string base64.

    Parâmetros:
        assinatura (int): Assinatura como inteiro
        tamanho_chave (int): Tamanho da chave em bytes

    Retorna:
        str: Assinatura formatada na base64
    """
    # Converte a assinatura de inteiro para bytes no tamanho de n
    assinatura_bytes = assinatura.to_bytes(tamanho_chave, 'big')
    # Codifica os bytes em string BASE64
    assinatura_formatada = base64.b64encode(assinatura_bytes).decode()
    return assinatura_formatada


if __name__ == '__main__':
    from ..rsa.cifra_rsa import cifrar, decifrar
    from ..rsa.geracao_chave import chave_rsa

    publica, privada = chave_rsa(1024)
    tamanho_chave = (publica[0].bit_length() + 7) // 8  # Tamanho da chave em bytes
    mensagem = b"Teste secreto para testar a completude das funcoes lerolerolero"

    # 1°) Hasheando a mensagem
    hash_mensagem = aplicar_hash(mensagem)

    # 2°) Assinando o hash
    assinatura = assinar(hash_mensagem, privada)
    print("Assinatura (inteiro gigante):", assinatura) # Sem formatação

    # 3°) Formatando a assinatura para base64
    assinatura_base64 = formatar_assinatura(assinatura, tamanho_chave)
    print("Assinatura (base64):", assinatura_base64) # Com formatação
