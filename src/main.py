import os
from rsa.geracao_chave import chave_rsa, salvar_chave, carregar_chave
from assinatura.assina import aplicar_hash, assinar as assinar_hash, formatar_base64
from assinatura.verifica import parse_base64, decifrar_assinatura, verificar


def header(titulo):
    print("-" * 60)
    print(f" {titulo.upper()}")
    print("-" * 60)


def pause():
    print("...")
    input()


def execucao():
    header("Parte 1: Geração de Chaves RSA")
    print("Iniciando a geração de um par de chaves (pública e privada)...")
    publica, privada = chave_rsa(1024)
    salvar_chave(publica, "chave_publica.pub")
    salvar_chave(privada, "chave_privada.key")
    print("Chaves geradas e salvas com sucesso!")
    pause()

    header("Parte 2: Assinatura de Arquivo")
    print("Criando um arquivo de exemplo ('documento.txt')...")
    conteudo_original_bytes = b"O rato roeu a roupa do rei de Roma em 3 anos, incrivel!"

    print(f"Conteúdo: '{conteudo_original_bytes.decode()}'")
    pause()

    print("Assinando o arquivo...")
    print("1. Calculando o hash SHA-3 do conteúdo.")
    hash_original = aplicar_hash(conteudo_original_bytes)

    print("2. 'Cifrando' o hash com a chave privada.")
    chave_privada_tupla = carregar_chave("chave_privada.key")

    assinatura_bytes = assinar_hash(hash_original, chave_privada_tupla)

    print("3. Formatando o conteúdo original e a assinatura em Base64.")
    conteudo_b64_str = formatar_base64(conteudo_original_bytes)
    assinatura_b64_str = formatar_base64(assinatura_bytes)

    conteudo_final_str = f"{conteudo_b64_str}.{assinatura_b64_str}"

    caminho_saida = "documento.txt.sig"
    with open(caminho_saida, "w") as f:
        f.write(conteudo_final_str)
    print(f"Arquivo assinado e salvo em '{caminho_saida}'.")
    pause()

    header("Parte 3.1: Verificacao de Assinatura (Caso de Sucesso)")
    print("Verificando o arquivo assinado...")
    chave_publica_tupla = carregar_chave("chave_publica.pub")
    with open(caminho_saida, "r") as f:
        conteudo_lido_str = f.read()

    print("1. Separando o conteúdo da assinatura.")
    conteudo_b64, assinatura_b64 = conteudo_lido_str.split(".")

    print("2. Decodificando ambos de Base64 para bytes.")
    mensagem_bytes = parse_base64(conteudo_b64)
    assinatura_bytes_decodificada = parse_base64(assinatura_b64)

    print("3. 'Decifrando' a assinatura com a chave pública para recuperar o hash.")
    hash_recuperado = decifrar_assinatura(
        assinatura_bytes_decodificada, chave_publica_tupla
    )

    print("4. Comparando o hash recuperado com um novo hash do conteúdo.")
    eh_valido = verificar(hash_recuperado, mensagem_bytes)

    if eh_valido:
        print(
            "\n    RESULTADO: Assinatura VÁLIDA. A integridade e autenticidade foram confirmadas."
        )
    else:
        print("\n    RESULTADO: FALHA INESPERADA. A assinatura deveria ser válida.")
    pause()

    header("Parte 3.2: Verificacao de Falha (Arquivo Adulterado)")
    print("Simulando um ataque, modificando o conteúdo do arquivo assinado...")

    conteudo_b64_adulterado, assinatura_b64 = conteudo_lido_str.split(".")
    conteudo_adulterado_str = (
        "O rato roeu a roupa do rei" + conteudo_b64_adulterado + "." + assinatura_b64
    )
    print("Tentando verificar o arquivo adulterado...")
    pause()

    try:
        conteudo_b64_ad, assinatura_b64_ad = conteudo_adulterado_str.split(".")
        mensagem_bytes_ad = parse_base64(conteudo_b64_ad)
        assinatura_bytes_ad = parse_base64(assinatura_b64_ad)
        hash_recuperado_ad = decifrar_assinatura(
            assinatura_bytes_ad, chave_publica_tupla
        )

        eh_valido_adulterado = verificar(hash_recuperado_ad, mensagem_bytes_ad)

        if not eh_valido_adulterado:
            print(
                "\n    RESULTADO: Assinatura INVÁLIDA. O sistema detectou corretamente a adulteração!"
            )
        else:
            print(
                "\n    RESULTADO: FALHA INESPERADA. O sistema não detectou a adulteração."
            )

    except Exception as e:
        print(
            f"\n    RESULTADO: Ocorreu um erro esperado durante a verificação do arquivo adulterado ({e}), provando que o formato é inválido."
        )

    pause()

    header("Demonstracao Finalizada")
    print("Limpando os arquivos de demonstração...")
    os.remove("chave_publica.pub")
    os.remove("chave_privada.key")
    os.remove("documento.txt.sig")
    print("Apresentação concluída.")


if __name__ == "__main__":
    execucao()
