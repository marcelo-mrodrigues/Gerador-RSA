import os
import random
import time
import sys

# Garante que a aleatoriedade seja imprevisível a cada execução
random.seed(os.urandom(128))

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from rsa.geracao_chave import chave_rsa, salvar_chave, carregar_chave
from rsa.cifra_rsa import cifrar, decifrar
from assinatura.assina import aplicar_hash, assinar as assinar_hash, formatar_base64
from assinatura.verifica import parse_base64, decifrar_assinatura, verificar

def header(titulo: str):
    print("\n" + "-" * 60)
    print(f" {titulo.upper()}")
    print("-" * 60)
    time.sleep(1)

def pause():
    input("...")

def execucao():
    header("Geração de Chaves RSA")
    print("Gerando par de chaves...")
    publica, privada = chave_rsa(1024)
    salvar_chave(publica, 'chave_publica.pub')
    salvar_chave(privada, 'chave_privada.key')
    print("Chaves salvas")
    pause()
#----------
    header("Cifragem de Mensagem com OAEP")
    print("Cifragem da mensagem secreta.")
    mensagem_secreta_bytes = b"Esta e uma mensagem secreta para a disciplina de SegComp, por favor nao espalhar"
    print(f"Mensagem original: '{mensagem_secreta_bytes.decode()}'")
    pause()

    print("Cifrando a mensagem com a chave pública...")
    chave_publica_tupla = carregar_chave('chave_publica.pub')
    texto_cifrado_int = cifrar(mensagem_secreta_bytes, chave_publica_tupla)
    print("\nMensagem Cifrada (como um número inteiro):")
    print(texto_cifrado_int)
    pause()

    print("\nDecifrando com a chave privada...")
    print("Decifra o número, desfaz o padding e recupera a mensagem original.")
    chave_privada_tupla = carregar_chave('chave_privada.key')
    texto_decifrado_bytes = decifrar(texto_cifrado_int, chave_privada_tupla)

    assert mensagem_secreta_bytes == texto_decifrado_bytes
    print(f"\nSucesso na recuperação da mensagem orgiginal: '{texto_decifrado_bytes.decode()}'")
    pause()
#------------
    header("Assinatura de Arquivo")
    
    conteudo_original_bytes = b"O rato roeu a roupa do rei de Roma e a rainha de raia ficou muito brava."
    print(f"Conteúdo a ser assinado: '{conteudo_original_bytes.decode()}'")
    pause()

    print("Assinando o arquivo...")
    hash_original = aplicar_hash(conteudo_original_bytes)
    assinatura_bytes = assinar_hash(hash_original, chave_privada_tupla)
    conteudo_b64_str = formatar_base64(conteudo_original_bytes)
    assinatura_b64_str = formatar_base64(assinatura_bytes)
    conteudo_final_str = f"{conteudo_b64_str}.{assinatura_b64_str}"

    caminho_saida = 'documento.txt.sig'
    with open(caminho_saida, 'w') as f: f.write(conteudo_final_str)
    print(f"\nArquivo assinado e salvo em '{caminho_saida}'.")
    pause()

    header("Parte 4: Verificação da Assinatura")
    with open(caminho_saida, 'r') as f: conteudo_lido_str = f.read()
    
    conteudo_b64, assinatura_b64 = conteudo_lido_str.split('.')
    mensagem_bytes = parse_base64(conteudo_b64)
    assinatura_bytes_decodificada = parse_base64(assinatura_b64)
    hash_recuperado = decifrar_assinatura(assinatura_bytes_decodificada, chave_publica_tupla)
    eh_valido = verificar(hash_recuperado, mensagem_bytes)
    
    if eh_valido:
        print("\n    >>> RESULTADO: Assinatura VÁLIDA. Integridade confirmada.")
    else:
        print("\n    >>> RESULTADO: FALHA INESPERADA.")
    pause()

    header("FIM")

    pause()
    print("Limpando os arquivos de demonstração...")
    if os.path.exists('chave_publica.pub'): os.remove('chave_publica.pub')
    if os.path.exists('chave_privada.key'): os.remove('chave_privada.key')
    if os.path.exists('documento.txt.sig'): os.remove('documento.txt.sig')


if __name__ == '__main__':
    execucao()

