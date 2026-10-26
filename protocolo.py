# -*- coding: utf-8 -*-
"""Protocolo de comunicação compartilhado entre o Servidor Central e o Agente Cliente.

Cada mensagem é enviada como um cabeçalho de 4 bytes (tamanho, big-endian) seguido do
JSON em UTF-8. Isso evita que mensagens grandes (como imagens em base64) sejam
truncadas ou misturadas com a próxima mensagem, o que acontecia no protocolo antigo
baseado em `sock.recv(1024)` sem delimitação.

Toda a conexão roda dentro de TLS (criptografada). O Servidor Central usa um
certificado autoassinado gerado na primeira execução, e cada agente só aceita o
servidor cujo certificado tenha a impressão digital (SHA-256) configurada em
"cert_sha256" no config.json — assim um computador que assuma o IP do servidor
não consegue nem ler o token dos agentes nem disparar popups falsos.
"""
import base64
import hashlib
import hmac
import io
import json
import logging
import logging.handlers
import os
import secrets
import socket
import ssl
import struct
import time

from PIL import Image

TAMANHO_CABECALHO = 4

# Nenhuma mensagem legítima deste app (nem imagem redimensionada em base64)
# chega perto disso; qualquer cabeçalho declarando mais que isso é tratado como
# conexão maliciosa/corrompida e descartado, evitando alocação/travamento por
# um tamanho declarado absurdo (proteção contra esgotamento de memória).
TAMANHO_MAXIMO_MENSAGEM = 15 * 1024 * 1024  # 15 MB

# Tempo máximo (segundos) que qualquer envio ou recebimento "em andamento" pode
# demorar antes de ser considerado uma conexão travada/morta. Não se aplica à
# espera ociosa pelo próximo alerta (isso pode legitimamente durar horas) — ver
# receber_json().
TIMEOUT_SOCKET = 20

# Devolvido por receber_json(..., espera_ociosa=N) quando nenhuma mensagem nova
# começou a chegar dentro de N segundos (diferente de None, que significa
# conexão encerrada ou mensagem recusada).
SEM_MENSAGEM = object()

# Arquivos do certificado TLS do Servidor Central (ficam ao lado do .exe).
ARQUIVO_CERTIFICADO = "servidor_cert.pem"
ARQUIVO_CHAVE_PRIVADA = "servidor_chave.pem"

# Os logs contêm nomes de pessoas; com rotação eles não crescem para sempre.
TAMANHO_MAXIMO_LOG = 2 * 1024 * 1024  # 2 MB por arquivo
QUANTIDADE_LOGS_ANTIGOS = 3

CONFIG_PADRAO = {
    "servidor_ip": "192.168.70.198",
    "porta": 5000,
    # Segredo compartilhado entre o Servidor Central e os Agentes: sem ele
    # (ou com um valor diferente), a conexão é recusada. Evita que qualquer
    # dispositivo na rede se conecte na porta aberta e finja ser um agente
    # legítimo (ex.: forjar uma "assinatura" de leitura em nome de outra
    # pessoa). O Servidor Central gera um token automaticamente na primeira
    # vez que roda, se o config.json dele não tiver um definido — copie esse
    # mesmo valor para o config.json de cada agente.
    "token": "",
    # Só nos agentes: impressão digital SHA-256 do certificado do Servidor
    # Central. O servidor grava o valor certo em config_agente.json.
    "cert_sha256": "",
    # Só no servidor: assinaturas (CSV) e alertas registrados com mais de N
    # dias são apagados automaticamente. 0 = guardar para sempre.
    "retencao_dias": 0,
}

# Chaves cujo valor nunca deve aparecer em log.
_CHAVES_SECRETAS = ("token",)


def _config_para_log(config: dict) -> dict:
    return {k: ("***" if k in _CHAVES_SECRETAS and v else v) for k, v in config.items()}


def carregar_config(base_dir: str) -> dict:
    """Lê config.json ao lado do executável; chaves ausentes usam CONFIG_PADRAO."""
    config = dict(CONFIG_PADRAO)
    caminho = os.path.join(base_dir, "config.json")
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            dados = json.load(f)
        if isinstance(dados, dict):
            for chave in CONFIG_PADRAO:
                if chave in dados:
                    config[chave] = dados[chave]
        logging.info("Configuração carregada de %s: %s", caminho, _config_para_log(config))
    except FileNotFoundError:
        logging.info("config.json não encontrado, usando padrão: %s", _config_para_log(config))
    except Exception as e:
        logging.warning("config.json inválido (%s), usando padrão: %s", e, _config_para_log(config))
    config["porta"] = int(config["porta"])
    try:
        config["retencao_dias"] = max(0, int(config["retencao_dias"]))
    except (TypeError, ValueError):
        config["retencao_dias"] = 0
    return config


def garantir_token_servidor(base_dir: str, config: dict) -> str:
    """Garante que o Servidor Central tenha um token de autenticação definido.

    Se config.json não tiver um "token" (instalação nova ou arquivo antigo sem
    essa chave), gera um valor aleatório, grava de volta no config.json (sem
    apagar as outras chaves) e avisa no log para ser copiado aos agentes.
    """
    if config.get("token"):
        return config["token"]

    token_novo = secrets.token_hex(16)
    config["token"] = token_novo
    caminho = os.path.join(base_dir, "config.json")
    try:
        dados_existentes = {}
        if os.path.isfile(caminho):
            with open(caminho, "r", encoding="utf-8") as f:
                dados_existentes = json.load(f) or {}
        dados_existentes["token"] = token_novo
        dados_existentes.setdefault("porta", config["porta"])
        dados_existentes.setdefault("servidor_ip", config.get("servidor_ip", CONFIG_PADRAO["servidor_ip"]))
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(dados_existentes, f, indent=2, ensure_ascii=False)
        # O valor do token não vai para o log: quem lesse o log poderia se
        # passar por um agente. Ele fica só em config.json/config_agente.json.
        logging.warning("Nenhum token de autenticação configurado: um novo foi gerado e salvo em config.json. "
                        "Copie o config_agente.json gerado pelo servidor para a pasta de CADA agente.")
    except Exception as e:
        logging.error("Não foi possível salvar o token gerado em config.json (%s). "
                       "Defina um manualmente em ambos os lados.", e)
    return token_novo


def sanitizar_campo_csv(valor) -> str:
    """Neutraliza injeção de fórmula em CSV/Excel (CSV Injection).

    Se um campo vindo de uma fonte não confiável (ex.: nome digitado por um
    agente na rede) começar com um caractere que o Excel/LibreOffice interpreta
    como início de fórmula (=, +, -, @) ou como tabulação/retorno de carro,
    prefixa com um apóstrofo para que seja tratado como texto puro em vez de
    ser executado como fórmula ao abrir a planilha.
    """
    texto = "" if valor is None else str(valor)
    if texto[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + texto
    return texto


def configurar_log(base_dir: str, nome_arquivo: str) -> None:
    """Grava log em arquivo ao lado do executável (o .exe roda sem console).
    O arquivo é rotacionado (TAMANHO_MAXIMO_LOG x QUANTIDADE_LOGS_ANTIGOS) para
    não acumular indefinidamente os nomes de quem assinou."""
    handlers = [logging.StreamHandler()]
    try:
        handlers.append(logging.handlers.RotatingFileHandler(
            os.path.join(base_dir, nome_arquivo), maxBytes=TAMANHO_MAXIMO_LOG,
            backupCount=QUANTIDADE_LOGS_ANTIGOS, encoding="utf-8",
        ))
    except Exception:
        pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )


def ativar_keepalive(sock) -> None:
    """Faz o SO detectar conexões mortas (cabo desconectado, máquina desligada)."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "SIO_KEEPALIVE_VALS"):
            # (ativo, tempo ocioso até 1º probe em ms, intervalo entre probes em ms)
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 5000))
    except Exception as e:
        logging.warning("Não foi possível ativar keepalive: %s", e)


def enviar_json(sock, payload: dict) -> None:
    """Envia uma mensagem JSON. Se o destinatário não estiver consumindo a
    rede (ex.: popup travado, máquina travada), `sendall` levanta
    socket.timeout após TIMEOUT_SOCKET em vez de bloquear para sempre — quem
    chamar deve tratar essa exceção como "destinatário indisponível", igual a
    qualquer outra falha de rede."""
    dados = json.dumps(payload).encode("utf-8")
    cabecalho = struct.pack(">I", len(dados))
    # receber_json ajusta o timeout a cada leitura; garante o valor certo aqui.
    sock.settimeout(TIMEOUT_SOCKET)
    sock.sendall(cabecalho + dados)


def receber_json(sock, tamanho_max=TAMANHO_MAXIMO_MENSAGEM, espera_ociosa=None, prazo=None):
    """Lê uma mensagem completa do socket. Retorna None se a conexão foi encerrada
    ou se a mensagem foi recusada (tamanho inválido, corpo incompleto ou prazo
    estourado).

    A espera pelo *início* de uma mensagem nova (os 4 bytes do cabeçalho) tolera
    timeouts indefinidamente — é normal um agente ficar horas sem receber nada
    entre um alerta e outro. Mas uma vez que o cabeçalho começou a chegar, ou
    quando já se sabe o tamanho do corpo, um timeout passa a significar conexão
    travada/instável e a mensagem é descartada.

    - tamanho_max: mensagens maiores que isso são recusadas.
    - espera_ociosa: se informado (segundos), devolve SEM_MENSAGEM quando nada
      começa a chegar nesse intervalo, em vez de continuar esperando.
    - prazo: instante (time.monotonic()) até o qual a mensagem inteira precisa
      ter chegado; usado para a identificação, para que uma conexão ainda não
      autenticada não consiga ocupar o servidor indefinidamente.
    """
    cabecalho = _receber_exato(sock, TAMANHO_CABECALHO, prazo, espera_ociosa, inicio_de_mensagem=True)
    if cabecalho is None or cabecalho is SEM_MENSAGEM:
        return cabecalho
    (tamanho,) = struct.unpack(">I", cabecalho)
    if tamanho > tamanho_max:
        logging.warning(
            "Mensagem recusada: tamanho declarado (%d bytes) excede o máximo permitido (%d bytes).",
            tamanho, tamanho_max,
        )
        return None
    dados = _receber_exato(sock, tamanho, prazo)
    if dados is None:
        logging.warning("Conexão descartada: corpo da mensagem não chegou a tempo.")
        return None
    return json.loads(dados.decode("utf-8"))


def _receber_exato(sock, quantidade: int, prazo=None, espera_ociosa=None, inicio_de_mensagem=False):
    """Lê exatamente `quantidade` bytes. Com `inicio_de_mensagem`, um timeout
    antes de qualquer byte chegar significa "ainda não há mensagem nova" (continua
    esperando, ou devolve SEM_MENSAGEM se houver `espera_ociosa`); um timeout
    depois que a mensagem já começou a chegar é tratado como falha."""
    buffer = b""
    while len(buffer) < quantidade:
        ocioso = inicio_de_mensagem and not buffer
        timeout = espera_ociosa if (ocioso and espera_ociosa is not None) else TIMEOUT_SOCKET
        if prazo is not None:
            restante = prazo - time.monotonic()
            if restante <= 0:
                return None
            timeout = min(timeout, restante)
        sock.settimeout(timeout)
        try:
            pedaco = sock.recv(quantidade - len(buffer))
        except socket.timeout:
            if prazo is not None and time.monotonic() >= prazo:
                return None
            if not ocioso:
                return None
            if espera_ociosa is not None:
                return SEM_MENSAGEM
            continue
        if not pedaco:
            return None
        buffer += pedaco
    return buffer


# --- TLS -----------------------------------------------------------------------

def impressao_digital_certificado(cert_der: bytes) -> str:
    """SHA-256 (hex, minúsculo) de um certificado em formato DER."""
    return hashlib.sha256(cert_der).hexdigest()


def _normalizar_impressao_digital(valor) -> str:
    # Aceita o valor com ou sem ":"/espaços e em qualquer caixa (ex.: copiado do Windows).
    return "".join(ch for ch in str(valor or "").lower() if ch in "0123456789abcdef")


def garantir_certificado_servidor(base_dir: str):
    """Gera, na primeira execução do Servidor Central, um certificado TLS
    autoassinado e sua chave privada (servidor_cert.pem / servidor_chave.pem,
    ao lado do .exe). Devolve (caminho_certificado, caminho_chave).

    Apagar os dois arquivos gera um par novo — e aí todos os agentes precisam
    receber o novo "cert_sha256".
    """
    caminho_cert = os.path.join(base_dir, ARQUIVO_CERTIFICADO)
    caminho_chave = os.path.join(base_dir, ARQUIVO_CHAVE_PRIVADA)
    if os.path.isfile(caminho_cert) and os.path.isfile(caminho_chave):
        return caminho_cert, caminho_chave

    # Importado só aqui: apenas o servidor precisa dessa biblioteca (o .exe do
    # agente nem a inclui).
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    chave_privada = ec.generate_private_key(ec.SECP256R1())
    nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Servidor Central de Alertas")])
    agora = datetime.datetime.now(datetime.timezone.utc)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(nome)
        .issuer_name(nome)
        .public_key(chave_privada.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora - datetime.timedelta(days=1))
        .not_valid_after(agora + datetime.timedelta(days=365 * 20))
        .sign(chave_privada, hashes.SHA256())
    )
    with open(caminho_chave, "wb") as f:
        f.write(chave_privada.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
    with open(caminho_cert, "wb") as f:
        f.write(certificado.public_bytes(serialization.Encoding.PEM))
    logging.warning("Certificado TLS novo gerado em %s. Distribua o config_agente.json atualizado "
                    "para todos os agentes.", caminho_cert)
    return caminho_cert, caminho_chave


def criar_contexto_tls_servidor(base_dir: str):
    """Devolve (contexto SSL do servidor, impressão digital SHA-256 do certificado)."""
    caminho_cert, caminho_chave = garantir_certificado_servidor(base_dir)
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    contexto.load_cert_chain(caminho_cert, caminho_chave)
    with open(caminho_cert, "r", encoding="ascii") as f:
        cert_der = ssl.PEM_cert_to_DER_cert(f.read())
    return contexto, impressao_digital_certificado(cert_der)


def criar_contexto_tls_agente():
    """Contexto TLS do agente. Como o certificado do servidor é autoassinado, a
    validação por autoridade certificadora é desligada e substituída pela
    conferência da impressão digital (certificado_servidor_confere), feita
    antes de qualquer dado — inclusive o token — ser enviado."""
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    contexto.check_hostname = False
    contexto.verify_mode = ssl.CERT_NONE
    return contexto


def certificado_servidor_confere(sock_tls, impressao_esperada) -> bool:
    esperado = _normalizar_impressao_digital(impressao_esperada)
    cert_der = sock_tls.getpeercert(binary_form=True)
    if not esperado or not cert_der:
        return False
    return hmac.compare_digest(impressao_digital_certificado(cert_der), esperado)


def imagem_para_base64(caminho: str, tamanho_max=(900, 650), qualidade=85) -> str:
    """Abre uma imagem do disco, redimensiona para caber no popup e comprime em JPEG.

    Isso mantém o payload enviado pela rede pequeno mesmo quando o usuário anexa
    fotos grandes (ex: foto tirada de celular com vários MB).
    """
    with Image.open(caminho) as img:
        img = img.convert("RGB")
        img.thumbnail(tamanho_max, Image.LANCZOS)
        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=qualidade)
        return base64.b64encode(buffer.getvalue()).decode("ascii")


def base64_para_photoimage(b64_str: str, tamanho_max=(380, 220)):
    """Decodifica uma imagem em base64 e retorna um ImageTk.PhotoImage pronto para uso."""
    from PIL import ImageTk

    dados = base64.b64decode(b64_str)
    img = Image.open(io.BytesIO(dados))
    img.thumbnail(tamanho_max, Image.LANCZOS)
    return ImageTk.PhotoImage(img)


# --- Logomarca institucional (Instituto Acqua) ---------------------------------
# Embutida em base64 (em vez de exigir um arquivo logo.png ao lado do .exe) para
# que a marca do Instituto Acqua apareça sempre fixa nos dois programas, mesmo
# quando o executável é copiado isoladamente para outro computador.
_LOGO_INSTITUTO_ACQUA_B64 = (
    "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"
    "7l12SznNLHJ0nHZ8ml3CfGLFs8z2P2Q43LkuobVWhcOKrftBAJycKp8Rg/J9fWbWpk0RYn6vrdZGJ2tWOI7QhdJjctjkfCP6yRvW"
    "4GYRCOBwGv8xUSAdB9Z1v8uWSyTE2KXLK1WA7ZWX7NgRbc3BTQRINtWn+mQkPMMcuqe9UBNVerj41d1LV31m1po1zt7zz3cxjmda"
    "vq/PpJmFeqL4HlMuf1+GQnLM637ks8zIaMSxEld6QRlrFZFEwL3Micde4uXsIBNZ4Sjh1so3DF1+5U8bTJeMHu97pqWzUP31U7e4"
    "hdLDKhJWXq5Jg85v/wgAZvhCfcelmMzsbDZMwLW2Whu7mAwRwKibWv3bJAQwxvo3A1YoCRZ8U6dYTz4gPE6iNRs4tCT5T+6Bwhec"
    "rrjDlvVzKo2lslaRyJtNXH695Qd1othRjJjN33HHafN2bOiXseif6VLZwNoJMZuXwaAgKStupXTN7sUr08lsVoKZjne/yNFdws7P"
    "EpZYKHXFRdvuekUulbLgyV8A6R0ckCDioKquUPHYWaZeH0nWmNnKcJhA9N/5VKroG9FPTjGZnv7sdCKxwpTLYxeTIWKSEiT4j0H8"
    "XREMgnlMtCNhGuIyLy3pwpKJFJdhi+uEktwefeowanggIHS59AurnfelmcXe97xHT0Sh69FcjvLXX181Wl/H1rokJXuYuAlbd8GM"
    "lY3Zv/aKQK3ZKLa4nq1lr/wxmdk48Zg0pfJ/P7j0qg0TapPUPBf33nKLS1y/1mpdEkrCi7um6fMJIeXbLtq89pwMkT3RiusngpiM"
    "jMkFMho9a8xiMs1uOTP/ilndyMwGYy3sNej/TBBL5u7c+NIWZd0HhH68oPLo0MM/fK9bKPY70+KKrT1MeZSUO1zQKh5b1NO/9ou5"
    "VMo0kwM6Eczm52y88y2R02NDMhxa4D473PBbGu95QctaxaKK2f7KlCtv27ModUcLrJ4QyT0R9w6ulvnEimdh+T87N0tI1Kish8PK"
    "qPcD4N4Jossds5k5QGTwfjZmdLLGJIQ0pVLFWP7SqK/1Y5KJyTCLd6p4dJo1Ro/xfLHCUcJWKk/umr/qAQC7SalGCt+GuAyxvfkQ"
    "sYTxVFzdsOEkgBeaSpU8Ey8hYnIUWW0/sGf58sLg4GoxUWdoa3xjz5LUd2299h8qGvGsS9gwqK4xSXFe9+zzzgURj7m41ZyN6tmy"
    "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"
)


def carregar_logo_instituto_acqua(altura_max: int = 60):
    """Decodifica e redimensiona a logo institucional do Instituto Acqua.

    A logo fica embutida em base64 no próprio código (constante acima) em vez de
    depender de um arquivo externo, para garantir que apareça sempre, fixa e bem
    visível, tanto no popup de alerta quanto no painel do servidor, mesmo quando
    o .exe é copiado sozinho para outra máquina.
    """
    from PIL import ImageTk

    dados = base64.b64decode(_LOGO_INSTITUTO_ACQUA_B64)
    img = Image.open(io.BytesIO(dados))
    proporcao = altura_max / img.height
    novo_tamanho = (max(1, round(img.width * proporcao)), altura_max)
    img = img.resize(novo_tamanho, Image.LANCZOS)
    return ImageTk.PhotoImage(img)
