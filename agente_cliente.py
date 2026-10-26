# -*- coding: utf-8 -*-
import ctypes
import getpass
import logging
import os
import socket
import sys
import time
from datetime import datetime

import tkinter as tk
from tkinter import ttk

from protocolo import (
    enviar_json, receber_json, base64_para_photoimage,
    carregar_config, configurar_log, ativar_keepalive,
    carregar_logo_instituto_acqua, criar_contexto_tls_agente,
    certificado_servidor_confere, TIMEOUT_SOCKET,
)
from ui_widgets import BotaoArredondado, CartaoArredondado

# Trata o caminho absoluto se estiver rodando como script .py ou como .exe compilado
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

configurar_log(BASE_DIR, "agente.log")

# IP e porta do Servidor Central vêm de config.json (ao lado do .exe).
# Sem o arquivo, usa o padrão definido em protocolo.CONFIG_PADRAO.
CONFIG = carregar_config(BASE_DIR)
SERVIDOR_IP = CONFIG["servidor_ip"]
PORT = CONFIG["porta"]

# Logomarca fixa e opcional: coloque um arquivo "logo.png" na mesma pasta do
# executável para exibi-la no cabeçalho de todo popup. Se não existir, é ignorada.
LOGO_PATH = os.path.join(BASE_DIR, "logo.png")

COMPUTADOR = os.environ.get('COMPUTERNAME', socket.gethostname())
USUARIO = getpass.getuser()

# Assinaturas que não puderam ser enviadas (rede caiu na hora de assinar);
# são reenviadas assim que a conexão com o servidor volta.
confirmacoes_pendentes = []

# Alertas já assinados nesta sessão: se o mesmo alerta chegar de novo (ex.:
# "Reenviar aos pendentes" enquanto o popup ainda estava aberto), não reabre.
alertas_assinados = set()

CONTEXTO_TLS = criar_contexto_tls_agente()

# --- Paleta visual --- (acento em verde-azulado, ecoando a logo do Instituto Acqua)
COR_HEADER = "#0f172a"
COR_HEADER_SUB = "#cbd5e1"
COR_FUNDO = "#f1f5f4"
COR_CARTAO = "#ffffff"
COR_TEXTO = "#0f172a"
COR_TEXTO_SEC = "#475569"
COR_ACCENT = "#0d9488"
COR_ACCENT_HOVER = "#0f766e"
COR_ATENCAO = "#f59e0b"
COR_SUCESSO = "#16a34a"
COR_DESABILITADO = "#94a3b8"
COR_DIVISOR = "#e2e8f0"
RAIO_CARTAO = 16
RAIO_BOTAO = 14


def _garantir_instancia_unica() -> bool:
    """Evita dois agentes rodando ao mesmo tempo (ex.: atalho de inicialização duplicado)."""
    if sys.platform != "win32":
        return True
    try:
        ERROR_ALREADY_EXISTS = 183
        handle = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\AgenteAlertaReuniao")
        if ctypes.windll.kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
            return False
        globals()["_mutex_handle"] = handle  # mantém o handle vivo
    except Exception as e:
        logging.warning("Falha ao verificar instância única: %s", e)
    return True


def _piscar_barra_tarefas(root):
    """Faz o ícone da janela piscar na barra de tarefas do Windows para chamar atenção."""
    if sys.platform != "win32":
        return
    try:
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())

        class FLASHWINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_uint),
                ("hwnd", ctypes.c_void_p),
                ("dwFlags", ctypes.c_uint),
                ("uCount", ctypes.c_uint),
                ("dwTimeout", ctypes.c_uint),
            ]

        FLASHW_ALL = 3
        info = FLASHWINFO(ctypes.sizeof(FLASHWINFO), hwnd, FLASHW_ALL, 6, 0)
        ctypes.windll.user32.FlashWindowEx(ctypes.byref(info))
    except Exception:
        pass


def _carregar_logo():
    """Carrega a logomarca do cabeçalho: usa um "logo.png" ao lado do executável se
    existir (permite trocar a marca sem recompilar), senão usa a logo do Instituto
    Acqua embutida no código, garantindo que ela apareça sempre, fixa."""
    if os.path.isfile(LOGO_PATH):
        try:
            from PIL import Image, ImageTk
            img = Image.open(LOGO_PATH)
            img.thumbnail((64, 64), Image.LANCZOS)
            return ImageTk.PhotoImage(img)
        except Exception:
            pass
    try:
        return carregar_logo_instituto_acqua(64)
    except Exception:
        return None


def exibir_popup(payload, sock):
    mensagem = payload.get("mensagem", "")
    alerta_id = payload.get("alerta_id")
    imagem_b64 = payload.get("imagem_b64")

    root = tk.Tk()
    root.title("Alerta de Reunião")
    root.resizable(False, False)
    root.configure(bg=COR_FUNDO)
    root.attributes("-topmost", True)
    root.protocol("WM_DELETE_WINDOW", lambda: None)  # Impede fechar pelo "X"

    def _impedir_minimizar(event=None):
        # Restaura instantaneamente se alguém minimizar pelo botão, pela barra de
        # tarefas ou por atalhos do Windows (Win+D, Win+M). Testado: usar o atributo
        # "-toolwindow" para remover o botão de minimizar chegou a fechar a janela
        # por completo em vez de só bloquear o minimizar — por isso a abordagem
        # aqui é sempre restaurar o estado normal, em vez de tentar remover o botão.
        if root.state() == "iconic":
            root.deiconify()
            root.lift()
            root.attributes("-topmost", True)

    root.bind("<Unmap>", _impedir_minimizar)

    # --- Cabeçalho ---
    header = tk.Frame(root, bg=COR_HEADER, height=84)
    header.pack(fill="x")
    header.pack_propagate(False)

    logo_img = _carregar_logo()
    if logo_img is not None:
        lbl_logo = tk.Label(header, image=logo_img, bg=COR_HEADER)
        lbl_logo.image = logo_img  # evita coleta de lixo
        lbl_logo.pack(side="left", padx=(20, 10))

    frame_titulo = tk.Frame(header, bg=COR_HEADER)
    frame_titulo.pack(side="left", pady=10, padx=(10, 0))
    tk.Label(
        frame_titulo, text="🔔 ALERTA DE REUNIÃO", font=("Segoe UI", 17, "bold"),
        fg="white", bg=COR_HEADER,
    ).pack(anchor="w")
    tk.Label(
        frame_titulo, text=datetime.now().strftime("Recebido em %d/%m/%Y às %H:%M"),
        font=("Segoe UI", 10), fg=COR_HEADER_SUB, bg=COR_HEADER,
    ).pack(anchor="w")

    # Faixa pulsante logo abaixo do cabeçalho para chamar atenção
    faixa = tk.Frame(root, bg=COR_ACCENT, height=5)
    faixa.pack(fill="x")

    def _pulsar(ciclos_restantes=40):
        if not root.winfo_exists():
            return
        cor_atual = faixa.cget("bg")
        faixa.config(bg=COR_ATENCAO if cor_atual == COR_ACCENT else COR_ACCENT)
        if ciclos_restantes > 0:
            root.after(500, _pulsar, ciclos_restantes - 1)
        else:
            faixa.config(bg=COR_ACCENT)

    # --- Corpo ---
    corpo = tk.Frame(root, bg=COR_FUNDO, padx=28, pady=20)
    corpo.pack(fill="both", expand=True)

    cartao_msg = CartaoArredondado(corpo, cor_cartao=COR_CARTAO, cor_fundo=COR_FUNDO,
                                    raio=RAIO_CARTAO, padx=20, pady=16)
    cartao_msg.pack(fill="x")

    tk.Label(
        cartao_msg.interior, text=mensagem, wraplength=520, justify="left", font=("Segoe UI", 13),
        bg=COR_CARTAO, fg=COR_TEXTO,
    ).pack(anchor="w", fill="x")

    if imagem_b64:
        try:
            foto = base64_para_photoimage(imagem_b64, tamanho_max=(500, 300))
            frame_img = tk.Frame(cartao_msg.interior, bg="white", highlightbackground=COR_DIVISOR,
                                  highlightthickness=1)
            frame_img.pack(pady=(14, 0))
            lbl_img = tk.Label(frame_img, image=foto, bg="white")
            lbl_img.image = foto  # evita coleta de lixo
            lbl_img.pack()
        except Exception as e:
            logging.error("Falha ao carregar imagem do alerta: %s", e)

    cartao_msg.ajustar_altura_ao_conteudo()

    cartao_confirmar = CartaoArredondado(corpo, cor_cartao=COR_CARTAO, cor_fundo=COR_FUNDO,
                                          raio=RAIO_CARTAO, padx=20, pady=16)
    cartao_confirmar.pack(fill="x", pady=(14, 0))
    interior_conf = cartao_confirmar.interior

    tk.Label(
        interior_conf, text="Digite seu nome completo para confirmar a leitura:",
        font=("Segoe UI", 11, "italic"), bg=COR_CARTAO, fg=COR_TEXTO_SEC,
    ).pack(anchor="w")

    entry_nome = ttk.Entry(interior_conf, font=("Segoe UI", 13))
    entry_nome.pack(fill="x", pady=(8, 4), ipady=6)
    entry_nome.focus_set()

    lbl_dica = tk.Label(
        interior_conf, text="Informe nome e sobrenome", font=("Segoe UI", 9),
        bg=COR_CARTAO, fg=COR_TEXTO_SEC,
    )
    lbl_dica.pack(anchor="w", pady=(0, 12))

    btn_confirmar = BotaoArredondado(
        interior_conf, "✔   Assinar e Fechar",
        cor=COR_ACCENT, cor_hover=COR_ACCENT_HOVER, cor_desabilitado=COR_DESABILITADO,
        cor_texto="white", fonte=("Segoe UI", 12, "bold"), raio=RAIO_BOTAO,
        padx=12, pady=12, cor_fundo=COR_CARTAO,
    )
    btn_confirmar.set_estado(tk.DISABLED)
    btn_confirmar.pack(fill="x")

    tk.Label(
        interior_conf, text=f"Assinando como {USUARIO} · {COMPUTADOR}", font=("Segoe UI", 8),
        bg=COR_CARTAO, fg=COR_DESABILITADO,
    ).pack(anchor="e", pady=(10, 0))
    cartao_confirmar.ajustar_altura_ao_conteudo()

    def confirmar():
        nome_digitado = entry_nome.get().strip()
        relatorio = {
            "tipo": "CONFIRMACAO",
            "alerta_id": alerta_id,
            "computador": COMPUTADOR,
            "usuario": USUARIO,
            "nome_assinado": nome_digitado,
            "mensagem": mensagem,
            "data_hora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        alertas_assinados.add(alerta_id)
        try:
            enviar_json(sock, relatorio)
            logging.info("Assinatura enviada: %s", nome_digitado)
        except Exception as e:
            logging.error("Erro ao enviar confirmação (%s); guardando para reenviar.", e)
            confirmacoes_pendentes.append(relatorio)
        root.destroy()

    def validar_texto(event=None):
        texto = entry_nome.get().strip()
        # Valida se possui pelo menos 2 palavras e 5 caracteres
        if len(texto.split()) >= 2 and len(texto) >= 5:
            btn_confirmar.set_estado(tk.NORMAL)
            lbl_dica.config(text="✔ Pronto para assinar", fg=COR_SUCESSO)
        else:
            btn_confirmar.set_estado(tk.DISABLED)
            lbl_dica.config(text="Informe nome e sobrenome", fg=COR_TEXTO_SEC)

    def _ao_pressionar_enter(event=None):
        if btn_confirmar["state"] == tk.NORMAL:
            confirmar()

    entry_nome.bind("<KeyRelease>", validar_texto)
    entry_nome.bind("<Return>", _ao_pressionar_enter)
    btn_confirmar.set_comando(confirmar)

    # Garante um tamanho mínimo confortável e centraliza a janela na tela
    root.update_idletasks()
    largura = max(root.winfo_reqwidth(), 620)
    altura = max(root.winfo_reqheight(), 380)
    x = (root.winfo_screenwidth() // 2) - (largura // 2)
    y = (root.winfo_screenheight() // 2) - (altura // 2)
    root.geometry(f"{largura}x{altura}+{x}+{y}")

    root.bell()
    root.after(200, lambda: _piscar_barra_tarefas(root))
    root.after(500, _pulsar)

    root.mainloop()


def _enviar_identificacao(sock):
    enviar_json(sock, {
        "tipo": "IDENTIFICACAO",
        "computador": COMPUTADOR,
        "usuario": USUARIO,
        "token": CONFIG.get("token", ""),
    })


def _reenviar_confirmacoes_pendentes(sock):
    while confirmacoes_pendentes:
        relatorio = confirmacoes_pendentes[0]
        enviar_json(sock, relatorio)
        confirmacoes_pendentes.pop(0)
        logging.info("Assinatura pendente reenviada: %s", relatorio.get("nome_assinado"))


class CertificadoNaoConfere(Exception):
    pass


def _conectar():
    """Abre a conexão TLS e confere a impressão digital do certificado do
    servidor ANTES de enviar qualquer dado (inclusive o token). Se não conferir,
    quem está naquele IP não é o Servidor Central legítimo."""
    sock_bruto = socket.create_connection((SERVIDOR_IP, PORT), timeout=TIMEOUT_SOCKET)
    ativar_keepalive(sock_bruto)
    try:
        sock = CONTEXTO_TLS.wrap_socket(sock_bruto)
    except Exception:
        sock_bruto.close()
        raise
    if not certificado_servidor_confere(sock, CONFIG.get("cert_sha256")):
        sock.close()
        raise CertificadoNaoConfere()
    return sock


def _configuracao_completa() -> bool:
    faltando = [chave for chave in ("token", "cert_sha256") if not CONFIG.get(chave)]
    if not faltando:
        return True
    logging.error("config.json sem %s: o agente não pode se conectar com segurança. Copie para esta "
                  "pasta o config_agente.json gerado pelo Servidor Central (renomeado para config.json).",
                  " e ".join(faltando))
    try:
        from tkinter import messagebox
        janela = tk.Tk()
        janela.withdraw()
        messagebox.showerror(
            "Agente de Alertas",
            "Configuração incompleta: falta " + " e ".join(f'"{c}"' for c in faltando) + " no config.json.\n\n"
            "Copie para a pasta do agente o config_agente.json gerado pelo Servidor Central "
            "e renomeie-o para config.json.",
        )
        janela.destroy()
    except Exception:
        pass
    return False


def escutar_servidor():
    ultimo_erro = None
    while True:
        try:
            sock = _conectar()
            ultimo_erro = None
            logging.info("Conectado ao Servidor Central em %s:%s (TLS)", SERVIDOR_IP, PORT)
            _enviar_identificacao(sock)
            _reenviar_confirmacoes_pendentes(sock)

            while True:
                payload = receber_json(sock)
                if payload is None:
                    break

                if payload.get("tipo") == "ERRO":
                    logging.error(
                        "Servidor recusou a conexão (%s). Verifique se o \"token\" no config.json "
                        "deste agente é igual ao do Servidor Central.", payload.get("motivo"))
                    break

                if payload.get("comando") == "EXIBIR_POPUP":
                    if payload.get("alerta_id") in alertas_assinados:
                        logging.info("Alerta %s já assinado; ignorando reenvio.", payload.get("alerta_id"))
                        continue
                    logging.info("Alerta recebido: %s", payload.get("mensagem", "")[:80])
                    try:
                        exibir_popup(payload, sock)
                    except Exception as e:
                        logging.exception("Erro ao exibir popup: %s", e)

            logging.warning("Conexão com o servidor encerrada; tentando reconectar.")
        except CertificadoNaoConfere:
            # Registrado só uma vez por sequência de falhas para não lotar o log
            # (a tentativa se repete a cada 5 segundos).
            if ultimo_erro != "certificado":
                logging.error(
                    "O certificado de %s:%s NÃO confere com \"cert_sha256\" do config.json. Conexão recusada "
                    "(nenhum dado foi enviado). Se o servidor foi reinstalado, copie o config_agente.json "
                    "novo; caso contrário, outra máquina pode estar se passando pelo servidor.",
                    SERVIDOR_IP, PORT)
                ultimo_erro = "certificado"
        except Exception as e:
            # Em caso de queda de conexão, tenta reconectar a cada 5 segundos
            logging.debug("Sem conexão com %s:%s (%s)", SERVIDOR_IP, PORT, e)
        time.sleep(5)


if __name__ == "__main__":
    if not _garantir_instancia_unica():
        logging.info("Agente já está em execução nesta sessão; encerrando duplicata.")
        sys.exit(0)
    if not _configuracao_completa():
        sys.exit(1)
    escutar_servidor()
