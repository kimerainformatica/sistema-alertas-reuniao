# -*- coding: utf-8 -*-
import csv
import hmac
import json
import logging
import os
import queue
import shutil
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from protocolo import (
    enviar_json, receber_json, imagem_para_base64,
    carregar_config, configurar_log, ativar_keepalive,
    carregar_logo_instituto_acqua, garantir_token_servidor,
    sanitizar_campo_csv, criar_contexto_tls_servidor,
    SEM_MENSAGEM, TIMEOUT_SOCKET,
)
from ui_widgets import BotaoArredondado, CartaoArredondado

# Trata o caminho absoluto se estiver rodando como script .py ou como .exe compilado
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

configurar_log(BASE_DIR, "servidor.log")

# Configurações Globais (porta pode ser alterada em config.json ao lado do .exe)
_CONFIG = carregar_config(BASE_DIR)
HOST = '0.0.0.0'
PORT = _CONFIG["porta"]
# Segredo compartilhado que os agentes precisam enviar para serem aceitos (ver
# protocolo.garantir_token_servidor). Sem isso, qualquer dispositivo na rede
# que conectasse na porta aberta seria tratado como um agente legítimo.
TOKEN = garantir_token_servidor(BASE_DIR, _CONFIG)
RETENCAO_DIAS = _CONFIG["retencao_dias"]

CSV_PATH = os.path.join(BASE_DIR, "relatorios_assinados.csv")
REGISTRO_ALERTAS_PATH = os.path.join(BASE_DIR, "alertas_emitidos.jsonl")
# config.json pronto para copiar (renomeado) para a pasta de cada agente.
CONFIG_AGENTE_PATH = os.path.join(BASE_DIR, "config_agente.json")
CSV_CABECALHOS = ["Data", "Hora", "Computador", "Usuário", "Nome Assinado", "Mensagem do Alerta"]
CSV_CABECALHOS_ANTIGOS = ["data_hora", "computador", "usuario", "nome_assinado", "mensagem_alerta"]

# Limites para o histórico/lista de alertas mantidos em memória: o CSV em disco
# guarda tudo, mas manter tudo também na RAM por tempo indefinido faria o
# processo crescer sem parar num servidor que fica no ar por meses.
LIMITE_HISTORICO_MEMORIA = 5000
LIMITE_ALERTAS_MEMORIA = 300
# Alertas guardados em alertas_emitidos.jsonl para validar assinaturas
# (inclusive as que chegam atrasadas, depois de o servidor ser reiniciado).
LIMITE_ALERTAS_REGISTRO = 1000

# Proteções contra conexões abusivas (ver _loop_servidor/_gerenciar_cliente).
LIMITE_CONEXOES = 500
PRAZO_IDENTIFICACAO = 10  # segundos para concluir o TLS e se identificar
TAMANHO_MAXIMO_IDENTIFICACAO = 4 * 1024
TAMANHO_MAXIMO_MENSAGEM_AGENTE = 256 * 1024
# De quanto em quanto tempo a thread de cada agente para de esperar mensagens
# para enviar o que estiver na fila (ver ConexaoAgente).
INTERVALO_LEITURA = 0.25

LIMITE_NOME_ASSINADO = 120
LIMITE_IDENTIFICACAO = 64
INTERVALO_RETENCAO_MS = 24 * 60 * 60 * 1000


def _texto_limpo(valor, limite):
    """Converte um campo vindo da rede em texto de uma linha, sem caracteres de
    controle e com tamanho limitado."""
    texto = "" if valor is None else str(valor)
    texto = "".join(ch if ch.isprintable() else " " for ch in texto)
    return " ".join(texto.split())[:limite]


def _data_hora_assinatura(valor_agente, disparo_iso):
    """Horário que vai para o CSV. Usa o informado pelo agente (preserva o
    momento real de uma assinatura feita com a rede fora e enviada depois) só
    se for plausível: não antes do disparo do alerta e não no futuro, com 5
    minutos de folga para relógios dessincronizados. Senão, usa o do servidor."""
    agora = datetime.now()
    folga = timedelta(minutes=5)
    try:
        dt = datetime.strptime(str(valor_agente), "%Y-%m-%d %H:%M:%S")
        inicio = datetime.strptime(disparo_iso, "%Y-%m-%d %H:%M:%S") - folga
        if not (inicio <= dt <= agora + folga):
            dt = agora
    except (ValueError, TypeError):
        dt = agora
    return dt.strftime("%d/%m/%Y"), dt.strftime("%H:%M:%S")


class RegistroAlertas:
    """Registro persistente (alertas_emitidos.jsonl) de cada alerta disparado:
    texto, horário e para quem (computador/usuário) foi enviado, mais quem já
    assinou.

    É a referência usada para validar uma assinatura: o agente só informa QUAL
    alerta está assinando; o texto e o horário vêm daqui e o computador/usuário
    vêm da conexão autenticada. Assim uma assinatura não pode ser atribuída a
    outro texto, a um alerta que a máquina não recebeu, nem ser repetida.

    O arquivo é só de acréscimo (uma linha JSON por evento) e é compactado na
    inicialização e a cada aplicação da retenção.
    """

    def __init__(self, caminho, limite, retencao_dias):
        self._caminho = caminho
        self._limite = limite
        self._retencao_dias = retencao_dias
        self._lock = threading.Lock()
        # {alerta_id: {"mensagem", "disparo", "destinatarios": set, "confirmados": set}}
        self._alertas = {}
        self._carregar()
        self.aplicar_retencao()

    def _carregar(self):
        if not os.path.isfile(self._caminho):
            return
        try:
            with open(self._caminho, "r", encoding="utf-8") as f:
                for linha in f:
                    try:
                        self._aplicar_evento(json.loads(linha))
                    except (ValueError, KeyError, TypeError):
                        continue
        except Exception as e:
            logging.error("Erro ao ler %s: %s", self._caminho, e)

    def _aplicar_evento(self, ev):
        if ev["evento"] == "disparo":
            self._alertas[ev["id"]] = {
                "mensagem": ev["mensagem"],
                "disparo": ev["disparo"],
                "destinatarios": {tuple(p) for p in ev["destinatarios"]},
                "confirmados": set(),
            }
        elif ev["evento"] == "confirmacao":
            alerta = self._alertas.get(ev["id"])
            if alerta is not None:
                alerta["confirmados"].add((ev["computador"], ev["usuario"]))

    def _anexar(self, ev):
        try:
            with open(self._caminho, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        except Exception as e:
            logging.error("Erro ao gravar em %s: %s", self._caminho, e)

    def _podar(self):
        if self._retencao_dias > 0:
            limite = (datetime.now() - timedelta(days=self._retencao_dias)).strftime("%Y-%m-%d %H:%M:%S")
            for alerta_id in [i for i, a in self._alertas.items() if a["disparo"] < limite]:
                del self._alertas[alerta_id]
        excedente = len(self._alertas) - self._limite
        for alerta_id in list(self._alertas)[:max(excedente, 0)]:
            del self._alertas[alerta_id]

    def aplicar_retencao(self):
        """Descarta alertas antigos (por idade e por quantidade) e reescreve o arquivo só com o que restou."""
        with self._lock:
            self._podar()
            temporario = self._caminho + ".tmp"
            try:
                with open(temporario, "w", encoding="utf-8") as f:
                    for alerta_id, a in self._alertas.items():
                        f.write(json.dumps({
                            "evento": "disparo", "id": alerta_id, "mensagem": a["mensagem"],
                            "disparo": a["disparo"], "destinatarios": sorted(a["destinatarios"]),
                        }, ensure_ascii=False) + "\n")
                        for computador, usuario in sorted(a["confirmados"]):
                            f.write(json.dumps({
                                "evento": "confirmacao", "id": alerta_id,
                                "computador": computador, "usuario": usuario,
                            }, ensure_ascii=False) + "\n")
                os.replace(temporario, self._caminho)
            except Exception as e:
                logging.error("Erro ao compactar %s: %s", self._caminho, e)

    def registrar_disparo(self, alerta_id, mensagem, disparo_iso, pares):
        ev = {"evento": "disparo", "id": alerta_id, "mensagem": mensagem,
              "disparo": disparo_iso, "destinatarios": sorted(pares)}
        with self._lock:
            self._aplicar_evento(ev)
            self._anexar(ev)
            self._podar()

    def registrar_confirmacao(self, alerta_id, par, gravar):
        """Valida a assinatura de `par` (computador, usuário) para o alerta e,
        se válida, chama gravar(alerta). Só marca como assinado se gravar()
        devolver True. Devolve (ok, motivo_da_recusa, alerta)."""
        with self._lock:
            alerta = self._alertas.get(alerta_id)
            if alerta is None:
                return False, "alerta desconhecido ou já expirado", None
            if par not in alerta["destinatarios"]:
                return False, "o alerta não foi enviado para este computador/usuário", None
            if par in alerta["confirmados"]:
                return False, "assinatura repetida", None
            if not gravar(alerta):
                return False, "não foi possível gravar no CSV", None
            alerta["confirmados"].add(par)
            self._anexar({"evento": "confirmacao", "id": alerta_id, "computador": par[0], "usuario": par[1]})
            return True, "", alerta


class ConexaoAgente:
    """Conexão TLS com um agente.

    Só a thread de _gerenciar_cliente lê ou escreve no socket: um objeto TLS
    não pode ser usado por duas threads ao mesmo tempo. As threads de disparo
    apenas colocam a mensagem na fila e esperam o resultado; a thread dona do
    socket alterna entre esperar mensagens do agente (INTERVALO_LEITURA) e
    enviar o que estiver na fila.
    """

    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self._fila = queue.Queue()
        self._encerrada = False

    def enviar(self, payload) -> bool:
        """Pode ser chamado de qualquer thread. Devolve True se a mensagem foi enviada."""
        if self._encerrada:
            return False
        pedido = {"payload": payload, "feito": threading.Event(), "ok": False}
        self._fila.put(pedido)
        # Folga para a thread dona terminar uma leitura em andamento e o envio.
        if not pedido["feito"].wait(TIMEOUT_SOCKET * 3):
            return False
        return pedido["ok"]

    def processar_envios(self):
        """Chamado só pela thread dona do socket. Uma falha de envio derruba a conexão."""
        while True:
            try:
                pedido = self._fila.get_nowait()
            except queue.Empty:
                return
            try:
                enviar_json(self.sock, pedido["payload"])
                pedido["ok"] = True
            finally:
                pedido["feito"].set()

    def encerrar(self):
        self._encerrada = True
        while True:
            try:
                self._fila.get_nowait()["feito"].set()
            except queue.Empty:
                return


def _formatar_data_hora(valor):
    """Recebe uma data/hora vinda do agente (formato ISO "%Y-%m-%d %H:%M:%S")
    e devolve (data_dd_mm_aaaa, hora_hh_mm_ss), legíveis em português. Se não
    conseguir interpretar o valor, devolve-o como está na coluna de data."""
    for formato in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            dt = datetime.strptime(valor, formato)
            return dt.strftime("%d/%m/%Y"), dt.strftime("%H:%M:%S")
        except (ValueError, TypeError):
            continue
    return valor, ""


def _migrar_csv_se_necessario(caminho):
    """Converte um relatorios_assinados.csv do formato antigo (uma única coluna
    de data/hora combinada, sem cabeçalho legível) para o novo formato, com
    Data e Hora em colunas separadas e cabeçalhos em português. Roda uma única
    vez por arquivo: se ele já estiver no formato novo, não faz nada. Antes de
    sobrescrever, guarda uma cópia do arquivo original em ".bak"."""
    if not os.path.isfile(caminho) or os.path.getsize(caminho) == 0:
        return
    try:
        with open(caminho, "r", newline="", encoding="utf-8-sig") as f:
            linhas = list(csv.reader(f, delimiter=";"))
    except Exception as e:
        logging.error("Não foi possível ler '%s' para migração: %s", caminho, e)
        return

    if linhas and linhas[0] == CSV_CABECALHOS:
        return  # já está no formato novo

    linhas_convertidas = []
    for row in linhas:
        if not row or row == CSV_CABECALHOS_ANTIGOS:
            continue
        if len(row) < 3:
            continue
        data_legivel, hora_legivel = _formatar_data_hora(row[0])
        computador = row[1] if len(row) > 1 else ""
        usuario = row[2] if len(row) > 2 else ""
        nome_assinado = row[3] if len(row) > 3 else ""
        mensagem = row[4] if len(row) > 4 else ""
        linhas_convertidas.append([
            sanitizar_campo_csv(data_legivel), sanitizar_campo_csv(hora_legivel),
            sanitizar_campo_csv(computador), sanitizar_campo_csv(usuario),
            sanitizar_campo_csv(nome_assinado), sanitizar_campo_csv(mensagem),
        ])

    try:
        backup = caminho + ".bak"
        if not os.path.isfile(backup):
            shutil.copyfile(caminho, backup)
        with open(caminho, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow(CSV_CABECALHOS)
            writer.writerows(linhas_convertidas)
        logging.info(
            "relatorios_assinados.csv convertido para o formato legível: %d registro(s) migrado(s) "
            "(cópia do arquivo original salva em %s).", len(linhas_convertidas), backup,
        )
    except Exception as e:
        logging.error("Falha ao gravar CSV convertido para o formato legível: %s", e)

# --- Paleta visual --- (acento em verde-azulado, ecoando a logo do Instituto Acqua)
COR_HEADER = "#1e293b"
COR_HEADER_SUB = "#cbd5e1"
COR_FUNDO = "#eef2f6"
COR_ACCENT = "#0d9488"
COR_ACCENT_HOVER = "#0f766e"
COR_ACCENT_CLARO = "#f0fdfa"
COR_SUCESSO = "#16a34a"
COR_ALERTA = "#dc2626"
COR_ALERTA_CLARO = "#fef2f2"
COR_TEXTO_SEC = "#64748b"
COR_DIVISOR = "#e2e8f0"
COR_CARTAO = "#ffffff"
RAIO_CARTAO = 16
RAIO_BOTAO = 12


def _ip_local() -> str:
    """Descobre o IP desta máquina na rede local (sem enviar tráfego de fato)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def _gravar_config_agente(cert_sha256):
    """Gera config_agente.json com tudo o que um agente precisa (IP, porta,
    token e impressão digital do certificado). Contém o token: trate o arquivo
    como uma senha."""
    dados = {"servidor_ip": _ip_local(), "porta": PORT, "token": TOKEN, "cert_sha256": cert_sha256}
    try:
        with open(CONFIG_AGENTE_PATH, "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.error("Não foi possível gravar %s: %s", CONFIG_AGENTE_PATH, e)


class ServidorCentralGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Painel de Controle - Servidor Central de Alertas")
        largura = min(1140, self.root.winfo_screenwidth() - 80)
        altura = min(800, self.root.winfo_screenheight() - 120)
        self.root.geometry(f"{largura}x{altura}+40+40")
        self.root.minsize(980, 700)
        self.root.configure(bg=COR_FUNDO)

        # Guarda as conexões ativas {socket: {"addr", "computador", "usuario"}}
        self.clientes = {}
        # Mapeia o iid de cada linha da árvore "Agentes Conectados" de volta para
        # o socket correspondente, para saber quem foi selecionado ao clicar em
        # "Enviar para Selecionados". Recriado a cada _atualizar_lista_clientes.
        self._mapa_iid_conn = {}
        # Guarda os alertas disparados {alerta_id: {...}}
        self.alertas = {}
        self.alerta_selecionado = None
        # Histórico completo de confirmações (mais recente primeiro)
        self.historico = []
        # Caminho da imagem anexada ao próximo disparo
        self.imagem_selecionada = None
        self._thumb_preview_img = None
        self._csv_lock = threading.Lock()
        # Protege self.clientes e self.alertas, que são lidos/alterados tanto
        # pela thread da interface quanto por uma thread por agente conectado.
        # RLock porque alguns métodos que já seguram o lock chamam outros que
        # também o adquirem (ex.: _atualizar_lista_clientes -> _atualizar_kpis).
        self._lock = threading.RLock()
        self._conexoes_abertas = 0
        self._lock_conexoes = threading.Lock()

        self._construir_interface()
        _migrar_csv_se_necessario(CSV_PATH)
        self._registro = RegistroAlertas(REGISTRO_ALERTAS_PATH, LIMITE_ALERTAS_REGISTRO, RETENCAO_DIAS)
        self._apagar_assinaturas_antigas()
        self._carregar_historico_csv()
        if RETENCAO_DIAS > 0:
            self.root.after(INTERVALO_RETENCAO_MS, self._aplicar_retencao_periodica)
        self._iniciar_servidor_socket()

    # ------------------------------------------------------------------ #
    # Construção da interface
    # ------------------------------------------------------------------ #

    def _construir_interface(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", rowheight=26, font=("Segoe UI", 9),
                         background="white", fieldbackground="white", borderwidth=0)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"),
                         background="#e2e8f0", foreground="#1e293b", relief="flat")
        style.map("Treeview", background=[("selected", COR_ACCENT)], foreground=[("selected", "white")])
        style.configure("TNotebook", background=COR_FUNDO, borderwidth=0)
        style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=(16, 9))
        style.map("TNotebook.Tab", background=[("selected", "white")], foreground=[("selected", COR_ACCENT)])
        style.configure("TLabelframe", background=COR_FUNDO, bordercolor=COR_DIVISOR)
        style.configure("TLabelframe.Label", background=COR_FUNDO, font=("Segoe UI", 9, "bold"), foreground="#334155")
        style.configure("TFrame", background=COR_FUNDO)
        style.configure("TLabel", background=COR_FUNDO, font=("Segoe UI", 9))
        style.configure("TEntry", font=("Segoe UI", 10))

        # --- Cabeçalho do app ---
        header = tk.Frame(self.root, bg=COR_HEADER, height=68)
        header.pack(fill="x")
        header.pack_propagate(False)
        try:
            self._logo_img = carregar_logo_instituto_acqua(48)
            tk.Label(header, image=self._logo_img, bg=COR_HEADER).pack(side="left", padx=(16, 12))
        except Exception:
            self._logo_img = None
        tk.Label(header, text="🖥️  Painel de Controle — Alertas de Reunião", font=("Segoe UI", 13, "bold"),
                 fg="white", bg=COR_HEADER).pack(side="left", padx=(0, 16))
        self.lbl_status_clientes = tk.Label(header, text="🟢 Máquinas online: 0", font=("Segoe UI", 10, "bold"),
                                             fg=COR_HEADER_SUB, bg=COR_HEADER)
        self.lbl_status_clientes.pack(side="right", padx=16)

        # --- Painel de disparo ---
        cartao_disparo = CartaoArredondado(self.root, cor_cartao=COR_CARTAO, cor_fundo=COR_FUNDO,
                                            raio=RAIO_CARTAO, padx=18, pady=14)
        cartao_disparo.pack(fill="x", padx=12, pady=10)
        frame_top = cartao_disparo.interior

        tk.Label(frame_top, text="📢  Disparar Novo Alerta", font=("Segoe UI", 11, "bold"),
                 bg=COR_CARTAO, fg="#1e293b").pack(anchor="w", pady=(0, 8))

        tk.Label(frame_top, text="Mensagem do alerta:", bg=COR_CARTAO, fg=COR_TEXTO_SEC,
                 font=("Segoe UI", 9)).pack(anchor="w")
        self.txt_mensagem = tk.Text(frame_top, height=3, font=("Segoe UI", 10), wrap="word",
                                     relief="solid", bd=1, highlightthickness=1,
                                     highlightbackground=COR_DIVISOR, highlightcolor=COR_ACCENT)
        self.txt_mensagem.pack(fill="x", pady=(4, 8))
        self.txt_mensagem.bind("<Control-Return>", lambda e: self.disparar_alerta())

        frame_acoes = tk.Frame(frame_top, bg=COR_CARTAO)
        frame_acoes.pack(fill="x")

        frame_imagem = tk.Frame(frame_acoes, bg=COR_CARTAO)
        frame_imagem.pack(side="left", fill="x", expand=True)

        btn_anexar = BotaoArredondado(
            frame_imagem, "🖼  Anexar Imagem", comando=self._anexar_imagem,
            cor="white", cor_hover="#f8fafc", cor_texto="#334155", cor_borda=COR_DIVISOR, borda=1,
            fonte=("Segoe UI", 9), raio=RAIO_BOTAO, padx=12, pady=7, cor_fundo=COR_CARTAO,
        )
        btn_anexar.pack(side="left")

        self.lbl_thumb = tk.Label(frame_imagem, bg=COR_CARTAO)
        self.lbl_thumb.pack(side="left", padx=(8, 4))

        self.lbl_nome_imagem = tk.Label(frame_imagem, text="Nenhuma imagem anexada",
                                         fg=COR_TEXTO_SEC, bg=COR_CARTAO, font=("Segoe UI", 9))
        self.lbl_nome_imagem.pack(side="left", padx=(0, 4))

        self.btn_remover_imagem = BotaoArredondado(
            frame_imagem, "✖", comando=self._remover_imagem_selecionada,
            cor=COR_CARTAO, cor_hover=COR_ALERTA_CLARO, cor_texto=COR_ALERTA,
            fonte=("Segoe UI", 9, "bold"), raio=12, padx=8, pady=6, cor_fundo=COR_CARTAO,
        )

        frame_botoes_disparo = tk.Frame(frame_acoes, bg=COR_CARTAO)
        frame_botoes_disparo.pack(side="right")

        self.btn_disparar = BotaoArredondado(
            frame_botoes_disparo, "📢  Disparar para Todos", comando=self.disparar_alerta,
            cor=COR_ACCENT, cor_hover=COR_ACCENT_HOVER, cor_texto="white",
            fonte=("Segoe UI", 10, "bold"), raio=RAIO_BOTAO, padx=18, pady=9, cor_fundo=COR_CARTAO,
        )
        self.btn_disparar.pack(fill="x")

        self.btn_disparar_selecionados = BotaoArredondado(
            frame_botoes_disparo, "📤  Enviar para Selecionados", comando=self.disparar_selecionados,
            cor="white", cor_hover=COR_ACCENT_CLARO, cor_texto=COR_ACCENT, cor_borda=COR_ACCENT, borda=1,
            fonte=("Segoe UI", 9, "bold"), raio=RAIO_BOTAO, padx=18, pady=7, cor_fundo=COR_CARTAO,
        )
        self.btn_disparar_selecionados.pack(fill="x", pady=(6, 0))
        cartao_disparo.ajustar_altura_ao_conteudo()

        # --- Barra de status (rodapé) ---
        barra_status = tk.Frame(self.root, bg="#dde3ea", height=26)
        barra_status.pack(side="bottom", fill="x")
        barra_status.pack_propagate(False)
        tk.Label(
            barra_status,
            text=f"  Servidor ouvindo em {_ip_local()}:{PORT} (TLS)   ·   "
                 f"copie {os.path.basename(CONFIG_AGENTE_PATH)} para os agentes como config.json",
            font=("Segoe UI", 8), fg="#334155", bg="#dde3ea",
        ).pack(side="left")
        tk.Label(
            barra_status, text=f"Registros: {os.path.basename(CSV_PATH)}  ", font=("Segoe UI", 8),
            fg=COR_TEXTO_SEC, bg="#dde3ea",
        ).pack(side="right")

        # --- Abas principais ---
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        aba_pendencias = ttk.Frame(notebook, padding=8)
        aba_historico = ttk.Frame(notebook, padding=8)
        notebook.add(aba_pendencias, text="👥  Agentes & Pendências")
        notebook.add(aba_historico, text="🧾  Histórico de Assinaturas")

        self._construir_aba_pendencias(aba_pendencias)
        self._construir_aba_historico(aba_historico)

    def _criar_kpi(self, pai, coluna, titulo, cor):
        card = CartaoArredondado(pai, cor_cartao="white", cor_fundo=COR_FUNDO, raio=12, padx=0, pady=0)
        card.grid(row=0, column=coluna, sticky="nsew", padx=(0 if coluna == 0 else 6, 0))
        pai.columnconfigure(coluna, weight=1)
        interior = card.interior
        tk.Frame(interior, bg=cor, width=5).pack(side="left", fill="y")
        interno = tk.Frame(interior, bg="white", padx=12, pady=8)
        interno.pack(side="left", fill="both", expand=True)
        valor = tk.Label(interno, text="0", font=("Segoe UI", 18, "bold"), fg=cor, bg="white")
        valor.pack(anchor="w")
        tk.Label(interno, text=titulo, font=("Segoe UI", 8), fg=COR_TEXTO_SEC, bg="white").pack(anchor="w")
        card.ajustar_altura_ao_conteudo()
        return valor

    def _construir_aba_pendencias(self, container):
        container.columnconfigure(0, weight=1)
        container.columnconfigure(1, weight=2)
        container.rowconfigure(1, weight=1)

        # Linha de indicadores
        frame_kpis = ttk.Frame(container)
        frame_kpis.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        self.kpi_online = self._criar_kpi(frame_kpis, 0, "MÁQUINAS ONLINE", COR_ACCENT)
        self.kpi_alertas = self._criar_kpi(frame_kpis, 1, "ALERTAS DISPARADOS", "#7c3aed")
        self.kpi_confirmados = self._criar_kpi(frame_kpis, 2, "ASSINATURAS RECEBIDAS", COR_SUCESSO)
        self.kpi_pendentes = self._criar_kpi(frame_kpis, 3, "AINDA PENDENTES", COR_ALERTA)

        # Esquerda: agentes conectados
        cartao_left = CartaoArredondado(container, cor_cartao="white", cor_fundo=COR_FUNDO,
                                         raio=RAIO_CARTAO, padx=14, pady=12)
        cartao_left.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        frame_left = cartao_left.interior

        tk.Label(frame_left, text="Agentes Conectados", font=("Segoe UI", 10, "bold"),
                 bg="white", fg="#1e293b").pack(anchor="w")
        tk.Label(
            frame_left, text="Ctrl+clique ou Shift+clique para selecionar vários",
            font=("Segoe UI", 8, "italic"), fg=COR_TEXTO_SEC, bg="white",
        ).pack(anchor="w", pady=(0, 6))

        self.tree_clientes = ttk.Treeview(
            frame_left, columns=("computador", "usuario", "ip"), show="headings", selectmode="extended",
        )
        self.tree_clientes.heading("computador", text="Computador")
        self.tree_clientes.heading("usuario", text="Usuário")
        self.tree_clientes.heading("ip", text="IP")
        self.tree_clientes.column("computador", width=120, anchor="center")
        self.tree_clientes.column("usuario", width=100, anchor="center")
        self.tree_clientes.column("ip", width=110, anchor="center")
        self.tree_clientes.pack(fill="both", expand=True)
        self._configurar_zebra(self.tree_clientes)

        # Direita: alertas disparados + detalhe de pendências
        cartao_right = CartaoArredondado(container, cor_cartao="white", cor_fundo=COR_FUNDO,
                                          raio=RAIO_CARTAO, padx=14, pady=12)
        cartao_right.grid(row=1, column=1, sticky="nsew", padx=(6, 0))
        frame_right = cartao_right.interior
        tk.Label(frame_right, text="Alertas Disparados", font=("Segoe UI", 10, "bold"),
                 bg="white", fg="#1e293b").pack(anchor="w", pady=(0, 6))
        frame_right_corpo = tk.Frame(frame_right, bg="white")
        frame_right_corpo.pack(fill="both", expand=True)
        frame_right_corpo.rowconfigure(0, weight=1)
        frame_right_corpo.rowconfigure(1, weight=1)
        frame_right_corpo.columnconfigure(0, weight=1)
        frame_right = frame_right_corpo

        self.tree_alertas = ttk.Treeview(
            frame_right, columns=("hora", "mensagem", "total", "confirmados", "pendentes", "pct"),
            show="headings", height=6,
        )
        self.tree_alertas.heading("hora", text="Horário")
        self.tree_alertas.heading("mensagem", text="Mensagem")
        self.tree_alertas.heading("total", text="Enviado p/")
        self.tree_alertas.heading("confirmados", text="✅ Confirmados")
        self.tree_alertas.heading("pendentes", text="⏳ Pendentes")
        self.tree_alertas.heading("pct", text="% Lido")
        self.tree_alertas.column("hora", width=110, anchor="center")
        self.tree_alertas.column("mensagem", width=230, anchor="w")
        self.tree_alertas.column("total", width=75, anchor="center")
        self.tree_alertas.column("confirmados", width=95, anchor="center")
        self.tree_alertas.column("pendentes", width=85, anchor="center")
        self.tree_alertas.column("pct", width=65, anchor="center")
        self.tree_alertas.grid(row=0, column=0, sticky="nsew")
        self.tree_alertas.bind("<<TreeviewSelect>>", self._ao_selecionar_alerta)
        self._configurar_zebra(self.tree_alertas)
        self.tree_alertas.tag_configure("completo", foreground=COR_SUCESSO)

        frame_detalhe = tk.Frame(frame_right, bg="white")
        frame_detalhe.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        frame_detalhe.columnconfigure(0, weight=1)
        frame_detalhe.columnconfigure(1, weight=1)
        frame_detalhe.rowconfigure(1, minsize=22)

        self.lbl_detalhe_titulo = tk.Label(frame_detalhe, text="Selecione um alerta acima para ver os detalhes",
                                            font=("Segoe UI", 9, "italic"), fg=COR_TEXTO_SEC, bg="white")
        self.lbl_detalhe_titulo.grid(row=0, column=0, sticky="w", pady=(0, 4))

        self.btn_reenviar = BotaoArredondado(
            frame_detalhe, "🔁  Reenviar aos pendentes", comando=self._reenviar_pendentes,
            cor="white", cor_hover=COR_ALERTA_CLARO, cor_texto=COR_ALERTA, cor_borda=COR_ALERTA, borda=1,
            fonte=("Segoe UI", 9, "bold"), raio=RAIO_BOTAO, padx=10, pady=5, cor_fundo="white",
        )
        self.btn_reenviar.set_estado("disabled")
        self.btn_reenviar.grid(row=0, column=1, sticky="e", pady=(0, 4))

        tk.Label(frame_detalhe, text="✅ Confirmaram", font=("Segoe UI", 9, "bold"),
                 bg="white").grid(row=1, column=0, sticky="nw")
        self.lista_confirmados = tk.Listbox(frame_detalhe, font=("Segoe UI", 9), relief="solid", bd=1,
                                             fg=COR_SUCESSO, height=5)
        self.lista_confirmados.grid(row=2, column=0, sticky="nsew", padx=(0, 4))

        tk.Label(frame_detalhe, text="⏳ Pendentes", font=("Segoe UI", 9, "bold"),
                 bg="white").grid(row=1, column=1, sticky="nw")
        self.lista_pendentes = tk.Listbox(frame_detalhe, font=("Segoe UI", 9), relief="solid", bd=1,
                                           fg=COR_ALERTA, height=5)
        self.lista_pendentes.grid(row=2, column=1, sticky="nsew", padx=(4, 0))
        frame_detalhe.rowconfigure(2, weight=1)

    def _construir_aba_historico(self, container):
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)

        cartao = CartaoArredondado(container, cor_cartao="white", cor_fundo=COR_FUNDO,
                                    raio=RAIO_CARTAO, padx=14, pady=12)
        cartao.grid(row=0, column=0, sticky="nsew")
        corpo = cartao.interior
        corpo.columnconfigure(0, weight=1)
        corpo.rowconfigure(1, weight=1)

        frame_busca = tk.Frame(corpo, bg="white")
        frame_busca.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        tk.Label(frame_busca, text="🔎 Buscar:", bg="white", fg="#1e293b").pack(side="left")
        self.entry_busca = ttk.Entry(frame_busca)
        self.entry_busca.pack(side="left", fill="x", expand=True, padx=6)
        self.entry_busca.bind("<KeyRelease>", lambda e: self._renderizar_historico())

        self.lbl_total_historico = tk.Label(frame_busca, text="0 registro(s)", fg=COR_TEXTO_SEC, bg="white")
        self.lbl_total_historico.pack(side="left", padx=(0, 10))

        btn_exportar = BotaoArredondado(
            frame_busca, "📊  Exportar Excel", comando=self._exportar_excel,
            cor=COR_SUCESSO, cor_hover="#15803d", cor_texto="white",
            fonte=("Segoe UI", 9, "bold"), raio=RAIO_BOTAO, padx=12, pady=6, cor_fundo="white",
        )
        btn_exportar.pack(side="right")

        frame_tree = tk.Frame(corpo, bg="white")
        frame_tree.grid(row=1, column=0, sticky="nsew")
        frame_tree.rowconfigure(0, weight=1)
        frame_tree.columnconfigure(0, weight=1)

        self.tree_relatorios = ttk.Treeview(
            frame_tree, columns=("data", "hora", "comp", "user", "nome", "mensagem"), show="headings"
        )
        self.tree_relatorios.heading("data", text="Data")
        self.tree_relatorios.heading("hora", text="Hora")
        self.tree_relatorios.heading("comp", text="Computador")
        self.tree_relatorios.heading("user", text="Usuário Logado")
        self.tree_relatorios.heading("nome", text="Assinado Por")
        self.tree_relatorios.heading("mensagem", text="Mensagem do Alerta")

        self.tree_relatorios.column("data", width=90, anchor="center")
        self.tree_relatorios.column("hora", width=80, anchor="center")
        self.tree_relatorios.column("comp", width=110, anchor="center")
        self.tree_relatorios.column("user", width=100, anchor="center")
        self.tree_relatorios.column("nome", width=170, anchor="w")
        self.tree_relatorios.column("mensagem", width=250, anchor="w")

        scroll_y = ttk.Scrollbar(frame_tree, orient="vertical", command=self.tree_relatorios.yview)
        self.tree_relatorios.configure(yscrollcommand=scroll_y.set)
        self._configurar_zebra(self.tree_relatorios)

        self.tree_relatorios.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")

    # ------------------------------------------------------------------ #
    # Rede e threads
    # ------------------------------------------------------------------ #

    def _iniciar_servidor_socket(self):
        threading.Thread(target=self._loop_servidor, daemon=True).start()

    def _loop_servidor(self):
        try:
            contexto_tls, cert_sha256 = criar_contexto_tls_servidor(BASE_DIR)
            _gravar_config_agente(cert_sha256)
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, PORT))
            server.listen()
        except Exception as e:
            mensagem_erro = str(e)
            logging.error("Não foi possível iniciar o servidor na porta %s: %s", PORT, mensagem_erro)
            self.root.after(0, lambda: messagebox.showerror(
                "Erro ao iniciar servidor", f"Não foi possível iniciar o servidor na porta {PORT}:\n{mensagem_erro}"))
            return

        logging.info("Servidor ouvindo em %s:%s (TLS)", HOST, PORT)
        while True:
            conn, addr = server.accept()
            # Cada conexão ocupa uma thread; sem limite, alguém abrindo milhares
            # de conexões esgotaria o servidor.
            with self._lock_conexoes:
                lotado = self._conexoes_abertas >= LIMITE_CONEXOES
                if not lotado:
                    self._conexoes_abertas += 1
            if lotado:
                logging.warning("Conexão de %s recusada: limite de %d conexões simultâneas atingido.",
                                addr[0], LIMITE_CONEXOES)
                conn.close()
                continue
            threading.Thread(target=self._gerenciar_cliente, args=(conn, addr, contexto_tls), daemon=True).start()

    def _gerenciar_cliente(self, conn_bruta, addr, contexto_tls):
        conexao = None
        info = None
        sock = None
        # O handshake TLS e a identificação precisam terminar dentro deste
        # prazo: uma conexão não autenticada não pode ocupar o servidor à toa.
        prazo = time.monotonic() + PRAZO_IDENTIFICACAO
        try:
            ativar_keepalive(conn_bruta)
            conn_bruta.settimeout(PRAZO_IDENTIFICACAO)
            try:
                sock = contexto_tls.wrap_socket(conn_bruta, server_side=True)
            except Exception as e:
                logging.warning("Conexão de %s recusada: falha no TLS (%s). Agente desatualizado?", addr[0], e)
                return

            ident = receber_json(sock, tamanho_max=TAMANHO_MAXIMO_IDENTIFICACAO, prazo=prazo)
            if not isinstance(ident, dict) or ident.get("tipo") != "IDENTIFICACAO":
                logging.warning("Conexão de %s recusada: identificação ausente, inválida ou fora do prazo.", addr[0])
                return

            token_recebido = str(ident.get("token", "")).encode("utf-8")
            if not hmac.compare_digest(token_recebido, str(TOKEN).encode("utf-8")):
                logging.warning(
                    "Conexão de %s recusada: token de autenticação ausente ou incorreto "
                    "(computador informado: %s).", addr[0], _texto_limpo(ident.get("computador"), LIMITE_IDENTIFICACAO),
                )
                try:
                    enviar_json(sock, {"tipo": "ERRO", "motivo": "token_invalido"})
                except Exception:
                    pass
                return

            conexao = ConexaoAgente(sock, addr)
            info = {
                "addr": addr,
                "computador": _texto_limpo(ident.get("computador"), LIMITE_IDENTIFICACAO) or "?",
                "usuario": _texto_limpo(ident.get("usuario"), LIMITE_IDENTIFICACAO) or "?",
            }
            with self._lock:
                self.clientes[conexao] = info
            logging.info("Agente conectado: %s (%s) de %s", info["computador"], info["usuario"], addr[0])
            self.root.after(0, self._atualizar_lista_clientes)

            while True:
                conexao.processar_envios()
                msg = receber_json(sock, tamanho_max=TAMANHO_MAXIMO_MENSAGEM_AGENTE, espera_ociosa=INTERVALO_LEITURA)
                if msg is SEM_MENSAGEM:
                    continue
                if msg is None:
                    break
                if isinstance(msg, dict) and msg.get("tipo") == "CONFIRMACAO":
                    self._processar_confirmacao(conexao, msg)
        except Exception as e:
            logging.debug("Conexão com %s encerrada: %s", addr, e)
        finally:
            if conexao is not None:
                conexao.encerrar()
                with self._lock:
                    self.clientes.pop(conexao, None)
            if info:
                logging.info("Agente desconectado: %s (%s)", info["computador"], info["usuario"])
            for s in (sock, conn_bruta):
                try:
                    if s is not None:
                        s.close()
                except Exception:
                    pass
            with self._lock_conexoes:
                self._conexoes_abertas -= 1
            if info:
                self.root.after(0, self._atualizar_lista_clientes)

    # ------------------------------------------------------------------ #
    # Disparo de alertas
    # ------------------------------------------------------------------ #

    def disparar_alerta(self):
        """Dispara o alerta para todos os agentes conectados no momento."""
        with self._lock:
            destinatarios_snapshot = dict(self.clientes)
        if not destinatarios_snapshot:
            messagebox.showwarning("Aviso", "Nenhum agente conectado no momento.")
            return
        self._iniciar_disparo(destinatarios_snapshot)

    def disparar_selecionados(self):
        """Dispara o alerta somente para os agentes marcados na lista 'Agentes
        Conectados' (Ctrl/Shift+clique para marcar vários)."""
        selecao = self.tree_clientes.selection()
        if not selecao:
            messagebox.showwarning(
                "Aviso", "Selecione ao menos um agente na lista 'Agentes Conectados' antes de enviar.")
            return

        with self._lock:
            destinatarios_snapshot = {}
            for iid in selecao:
                conn = self._mapa_iid_conn.get(iid)
                if conn is not None and conn in self.clientes:
                    destinatarios_snapshot[conn] = self.clientes[conn]

        if not destinatarios_snapshot:
            messagebox.showwarning("Aviso", "O(s) agente(s) selecionado(s) não está(ão) mais conectado(s).")
            return

        self._iniciar_disparo(destinatarios_snapshot)

    def _iniciar_disparo(self, destinatarios_snapshot):
        mensagem = self.txt_mensagem.get("1.0", "end").strip()
        if not mensagem:
            messagebox.showwarning("Aviso", "Digite uma mensagem antes de disparar.")
            return

        imagem_b64 = None
        imagem_nome = None
        if self.imagem_selecionada:
            try:
                imagem_b64 = imagem_para_base64(self.imagem_selecionada)
                imagem_nome = os.path.basename(self.imagem_selecionada)
            except Exception as e:
                messagebox.showerror("Erro na imagem", f"Não foi possível processar a imagem:\n{e}")
                return

        alerta_id = uuid.uuid4().hex[:10]
        payload = {
            "comando": "EXIBIR_POPUP",
            "alerta_id": alerta_id,
            "mensagem": mensagem,
            "imagem_b64": imagem_b64,
            "imagem_nome": imagem_nome,
        }

        # O envio roda numa thread separada, em paralelo por destinatário: com
        # dezenas de agentes, bastaria 1 estar lento/travado (ex.: popup de um
        # alerta anterior ainda aberto) para congelar a janela inteira caso o
        # envio fosse feito aqui, síncrono, um de cada vez.
        self.btn_disparar.config(state=tk.DISABLED, text="Enviando...")
        self.btn_disparar_selecionados.config(state=tk.DISABLED)
        threading.Thread(
            target=self._disparar_em_thread, args=(alerta_id, payload, destinatarios_snapshot), daemon=True,
        ).start()

        self.txt_mensagem.delete("1.0", "end")
        self._remover_imagem_selecionada()

    def _disparar_em_thread(self, alerta_id, payload, destinatarios):
        # O alerta é registrado ANTES do envio: um usuário rápido pode assinar
        # antes de o envio para as outras máquinas terminar, e a assinatura só
        # é aceita para alertas registrados.
        agora = datetime.now()
        with self._lock:
            self.alertas[alerta_id] = {
                "mensagem": payload["mensagem"],
                "hora_disparo": agora.strftime("%d/%m/%Y %H:%M:%S"),
                "tem_imagem": payload["imagem_b64"] is not None,
                "payload": payload,
                "destinatarios": dict(destinatarios),
                "pendentes": dict(destinatarios),
                "confirmados": {},
            }
        self._registro.registrar_disparo(
            alerta_id, payload["mensagem"], agora.strftime("%Y-%m-%d %H:%M:%S"),
            [(info["computador"], info["usuario"]) for info in destinatarios.values()],
        )

        falhas = []
        lock_local = threading.Lock()

        def _enviar_para(conn, info):
            if not conn.enviar(payload):
                with lock_local:
                    falhas.append(conn)
                with self._lock:
                    self.clientes.pop(conn, None)

        threads = [threading.Thread(target=_enviar_para, args=(conn, info))
                   for conn, info in destinatarios.items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with self._lock:
            alerta = self.alertas.get(alerta_id)
            if alerta is not None:
                for conn in falhas:
                    alerta["destinatarios"].pop(conn, None)
                    alerta["pendentes"].pop(conn, None)
        enviados = len(destinatarios) - len(falhas)
        logging.info("Alerta %s disparado para %d de %d máquina(s): %s",
                     alerta_id, enviados, len(destinatarios), payload["mensagem"][:80])
        self.root.after(0, self._apos_disparo, alerta_id, enviados)

    def _apos_disparo(self, alerta_id, total_enviados):
        self.btn_disparar.config(state=tk.NORMAL, text="📢  Disparar para Todos")
        self.btn_disparar_selecionados.config(state=tk.NORMAL)
        self._atualizar_lista_clientes()
        self._inserir_linha_alerta(alerta_id)
        self._podar_alertas_antigos()
        messagebox.showinfo("Sucesso", f"Alerta enviado para {total_enviados} máquina(s).")

    def _podar_alertas_antigos(self):
        """Evita que self.alertas cresça sem limite num servidor que fica no
        ar por muito tempo, disparando muitos alertas."""
        with self._lock:
            excedente = len(self.alertas) - LIMITE_ALERTAS_MEMORIA
            antigos = list(self.alertas.keys())[:excedente] if excedente > 0 else []
            for alerta_id_antigo in antigos:
                self.alertas.pop(alerta_id_antigo, None)
        for alerta_id_antigo in antigos:
            if self.tree_alertas.exists(alerta_id_antigo):
                self.tree_alertas.delete(alerta_id_antigo)

    def _reenviar_pendentes(self):
        alerta_id = self.alerta_selecionado
        with self._lock:
            if not alerta_id or alerta_id not in self.alertas:
                return
            a = self.alertas[alerta_id]
            pendentes_snapshot = dict(a["pendentes"])
            payload = a["payload"]
            clientes_snapshot = dict(self.clientes)

        if not pendentes_snapshot:
            messagebox.showinfo("Reenviar", "Todos já confirmaram este alerta.")
            return

        self.btn_reenviar.config(state=tk.DISABLED, text="Reenviando...")
        threading.Thread(
            target=self._reenviar_em_thread,
            args=(alerta_id, payload, pendentes_snapshot, clientes_snapshot),
            daemon=True,
        ).start()

    def _reenviar_em_thread(self, alerta_id, payload, pendentes_antigos, clientes_atuais):
        # Localiza a conexão atual de cada pendente pelo par computador/usuário,
        # pois o agente pode ter reconectado com um socket novo desde o disparo.
        conexoes_atuais = {
            (info["computador"], info["usuario"]): conn for conn, info in clientes_atuais.items()
        }
        novos_pendentes = {}
        lock_local = threading.Lock()
        contador = {"reenviados": 0}

        def _reenviar_para(conn_antiga, info):
            conn_atual = conexoes_atuais.get((info["computador"], info["usuario"]))
            if conn_atual is None:
                with lock_local:
                    novos_pendentes[conn_antiga] = info
                return
            if conn_atual.enviar(payload):
                with lock_local:
                    contador["reenviados"] += 1
                    novos_pendentes[conn_atual] = info
            else:
                with lock_local:
                    novos_pendentes[conn_antiga] = info

        threads = [threading.Thread(target=_reenviar_para, args=(conn_antiga, info))
                   for conn_antiga, info in pendentes_antigos.items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with self._lock:
            if alerta_id in self.alertas:
                self.alertas[alerta_id]["pendentes"] = novos_pendentes

        reenviados = contador["reenviados"]
        offline = len(novos_pendentes) - reenviados
        logging.info("Alerta %s reenviado para %d pendente(s); %d offline", alerta_id, reenviados, offline)
        self.root.after(0, self._apos_reenvio, alerta_id, reenviados, offline)

    def _apos_reenvio(self, alerta_id, reenviados, offline):
        self.btn_reenviar.config(text="🔁  Reenviar aos pendentes")
        self._atualizar_linha_alerta(alerta_id)
        self._atualizar_painel_detalhe(alerta_id)
        messagebox.showinfo(
            "Reenviar",
            f"Alerta reenviado para {reenviados} máquina(s) pendente(s)."
            + (f"\n{offline} pendente(s) estão offline no momento." if offline else ""),
        )

    def _anexar_imagem(self):
        caminho = filedialog.askopenfilename(
            title="Selecionar imagem para o alerta",
            filetypes=[("Imagens", "*.png *.jpg *.jpeg *.bmp *.gif"), ("Todos os arquivos", "*.*")],
        )
        if not caminho:
            return
        try:
            from PIL import Image, ImageTk
            img = Image.open(caminho)
            img.thumbnail((56, 56), Image.LANCZOS)
            thumb = ImageTk.PhotoImage(img)
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível abrir a imagem:\n{e}")
            return

        self.imagem_selecionada = caminho
        self._thumb_preview_img = thumb
        self.lbl_thumb.config(image=thumb)
        self.lbl_nome_imagem.config(text=os.path.basename(caminho))
        self.btn_remover_imagem.pack(side="left", padx=(2, 4))

    def _remover_imagem_selecionada(self):
        self.imagem_selecionada = None
        self._thumb_preview_img = None
        self.lbl_thumb.config(image="")
        self.lbl_nome_imagem.config(text="Nenhuma imagem anexada")
        self.btn_remover_imagem.pack_forget()

    # ------------------------------------------------------------------ #
    # Atualizações de UI
    # ------------------------------------------------------------------ #

    @staticmethod
    def _configurar_zebra(tree):
        tree.tag_configure("par", background="white")
        tree.tag_configure("impar", background="#f1f5f9")

    @staticmethod
    def _aplicar_zebra(tree):
        for indice, item in enumerate(tree.get_children()):
            tags = [t for t in tree.item(item, "tags") if t not in ("par", "impar")]
            tags.append("par" if indice % 2 == 0 else "impar")
            tree.item(item, tags=tuple(tags))

    def _atualizar_kpis(self):
        with self._lock:
            total_confirmados = sum(len(a["confirmados"]) for a in self.alertas.values())
            total_pendentes = sum(len(a["pendentes"]) for a in self.alertas.values())
            total_online = len(self.clientes)
            total_alertas = len(self.alertas)
        self.kpi_online.config(text=str(total_online))
        self.kpi_alertas.config(text=str(total_alertas))
        self.kpi_confirmados.config(text=str(total_confirmados))
        self.kpi_pendentes.config(text=str(total_pendentes))

    def _atualizar_lista_clientes(self):
        # Preserva a seleção do operador entre atualizações (a lista é
        # reconstruída toda vez que um agente conecta/desconecta), senão
        # marcar agentes para "Enviar para Selecionados" ficaria impossível
        # assim que qualquer outro agente entrasse ou saísse da rede.
        selecionados_antes = set(self.tree_clientes.selection())

        for item in self.tree_clientes.get_children():
            self.tree_clientes.delete(item)

        with self._lock:
            clientes_snapshot = list(self.clientes.items())

        self._mapa_iid_conn = {}
        for conn, info in clientes_snapshot:
            iid = str(id(conn))
            self._mapa_iid_conn[iid] = conn
            self.tree_clientes.insert("", "end", iid=iid, values=(info["computador"], info["usuario"], info["addr"][0]))

        ainda_conectados = [iid for iid in selecionados_antes if self.tree_clientes.exists(iid)]
        if ainda_conectados:
            self.tree_clientes.selection_set(ainda_conectados)

        self._aplicar_zebra(self.tree_clientes)
        self.lbl_status_clientes.config(text=f"🟢 Máquinas online: {len(clientes_snapshot)}")
        self._atualizar_kpis()

    def _inserir_linha_alerta(self, alerta_id):
        with self._lock:
            a = self.alertas[alerta_id]
            total = len(a["destinatarios"])
            mensagem = a["mensagem"]
            hora_disparo = a["hora_disparo"]
            tem_imagem = a["tem_imagem"]
        msg_curta = (mensagem[:45] + "…") if len(mensagem) > 45 else mensagem
        prefixo = "🖼 " if tem_imagem else ""
        self.tree_alertas.insert("", 0, iid=alerta_id, values=(
            hora_disparo, f"{prefixo}{msg_curta}", total, 0, total, "0%",
        ))
        self._aplicar_zebra(self.tree_alertas)
        # Assinaturas podem ter chegado enquanto o envio ainda estava em andamento.
        self._atualizar_linha_alerta(alerta_id)

    def _atualizar_linha_alerta(self, alerta_id):
        with self._lock:
            if not alerta_id or alerta_id not in self.alertas:
                return
            a = self.alertas[alerta_id]
            total = len(a["destinatarios"])
            confirmados = len(a["confirmados"])
            pendentes = len(a["pendentes"])

        if not self.tree_alertas.exists(alerta_id):
            return
        pct = round(100 * confirmados / total) if total else 0
        valores = list(self.tree_alertas.item(alerta_id, "values"))
        valores[2] = total
        valores[3] = confirmados
        valores[4] = pendentes
        valores[5] = f"{pct}%"
        self.tree_alertas.item(alerta_id, values=valores)

        tags = [t for t in self.tree_alertas.item(alerta_id, "tags") if t != "completo"]
        if total and pendentes == 0:
            tags.append("completo")
        self.tree_alertas.item(alerta_id, tags=tuple(tags))
        self._atualizar_kpis()

    def _ao_selecionar_alerta(self, event=None):
        selecao = self.tree_alertas.selection()
        if not selecao:
            return
        self.alerta_selecionado = selecao[0]
        self._atualizar_painel_detalhe(self.alerta_selecionado)

    def _atualizar_painel_detalhe(self, alerta_id):
        with self._lock:
            if alerta_id is None or alerta_id != self.alerta_selecionado or alerta_id not in self.alertas:
                return
            a = self.alertas[alerta_id]
            confirmados_snapshot = list(a["confirmados"].values())
            pendentes_snapshot = list(a["pendentes"].values())
            mensagem = a["mensagem"]
            hora_disparo = a["hora_disparo"]
            tem_pendentes = bool(a["pendentes"])

        self.lista_confirmados.delete(0, "end")
        self.lista_pendentes.delete(0, "end")

        for info in confirmados_snapshot:
            nome = info.get("nome_assinado", "?")
            self.lista_confirmados.insert("end", f"{nome}  ({info.get('computador', '?')})")

        for info in pendentes_snapshot:
            self.lista_pendentes.insert("end", f"{info.get('computador', '?')} — {info.get('usuario', '?')}")

        titulo = mensagem[:70] + ("…" if len(mensagem) > 70 else "")
        self.lbl_detalhe_titulo.config(text=f"Alerta: “{titulo}” — disparado às {hora_disparo}")
        self.btn_reenviar.config(state=tk.NORMAL if tem_pendentes else tk.DISABLED)

    # ------------------------------------------------------------------ #
    # Confirmações e persistência (CSV)
    # ------------------------------------------------------------------ #

    def _processar_confirmacao(self, conexao, relatorio):
        """Do que o agente envia, só são usados o ID do alerta, o nome digitado
        e (se plausível) o horário. Computador e usuário vêm da conexão
        autenticada e o texto do alerta vem do registro do servidor, então uma
        máquina não consegue assinar em nome de outra, por um texto diferente,
        por um alerta que não recebeu nem duas vezes."""
        with self._lock:
            info = self.clientes.get(conexao)
        if info is None:
            return
        computador, usuario = info["computador"], info["usuario"]
        alerta_id = str(relatorio.get("alerta_id") or "")
        nome_assinado = _texto_limpo(relatorio.get("nome_assinado"), LIMITE_NOME_ASSINADO)
        if len(nome_assinado.split()) < 2 or len(nome_assinado) < 5:
            logging.warning("Assinatura recusada de %s (%s) para o alerta %s: nome inválido.",
                            computador, usuario, alerta_id)
            return

        registro = {}

        def _gravar(alerta):
            data, hora = _data_hora_assinatura(relatorio.get("data_hora"), alerta["disparo"])
            registro.update({
                "data": data, "hora": hora, "computador": computador, "usuario": usuario,
                "nome_assinado": nome_assinado, "mensagem": alerta["mensagem"],
            })
            return self._salvar_csv(registro)

        ok, motivo, _ = self._registro.registrar_confirmacao(alerta_id, (computador, usuario), _gravar)
        if not ok:
            logging.warning("Assinatura recusada de %s (%s) para o alerta %s: %s.",
                            computador, usuario, alerta_id, motivo)
            return
        logging.info("Assinatura recebida: %s (%s) para alerta %s", nome_assinado, computador, alerta_id)

        with self._lock:
            a = self.alertas.get(alerta_id)
            if a is not None:
                # Localiza a pendência pelo par computador/usuário: o agente pode
                # ter reconectado com outra conexão desde o disparo.
                for conn_pendente, info_pendente in list(a["pendentes"].items()):
                    if (info_pendente["computador"], info_pendente["usuario"]) == (computador, usuario):
                        a["pendentes"].pop(conn_pendente)
                        break
                a["confirmados"][conexao] = {"nome_assinado": nome_assinado, "computador": computador}

            self.historico.insert(0, registro)
            if len(self.historico) > LIMITE_HISTORICO_MEMORIA:
                del self.historico[LIMITE_HISTORICO_MEMORIA:]

        self.root.after(0, self._renderizar_historico)
        self.root.after(0, self._atualizar_linha_alerta, alerta_id)
        self.root.after(0, self._atualizar_painel_detalhe, alerta_id)

    def _salvar_csv(self, registro) -> bool:
        linha = [sanitizar_campo_csv(registro.get(campo, "")) for campo in
                 ("data", "hora", "computador", "usuario", "nome_assinado", "mensagem")]
        with self._csv_lock:
            try:
                arquivo_novo = not os.path.isfile(CSV_PATH) or os.path.getsize(CSV_PATH) == 0
                with open(CSV_PATH, "a", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f, delimiter=";")
                    if arquivo_novo:
                        writer.writerow(CSV_CABECALHOS)
                    writer.writerow(linha)
                return True
            except PermissionError:
                logging.error("O arquivo '%s' está aberto no Excel ou travado; assinatura não gravada!", CSV_PATH)
                self.root.after(0, lambda: messagebox.showwarning(
                    "CSV travado",
                    "O arquivo relatorios_assinados.csv está aberto em outro programa (Excel?).\n"
                    "Feche-o para que as assinaturas voltem a ser gravadas."))
            except Exception as e:
                logging.error("Erro ao salvar CSV: %s", e)
            return False

    def _apagar_assinaturas_antigas(self) -> int:
        """Retenção (LGPD): remove do CSV as assinaturas com mais de
        "retencao_dias" dias. Não faz nada se a retenção estiver desligada (0)."""
        if RETENCAO_DIAS <= 0 or not os.path.isfile(CSV_PATH):
            return 0
        limite = (datetime.now() - timedelta(days=RETENCAO_DIAS)).date()
        with self._csv_lock:
            try:
                with open(CSV_PATH, "r", newline="", encoding="utf-8-sig") as f:
                    linhas = list(csv.reader(f, delimiter=";"))
                mantidas = []
                for row in linhas:
                    try:
                        if row and row != CSV_CABECALHOS and datetime.strptime(row[0], "%d/%m/%Y").date() < limite:
                            continue
                    except ValueError:
                        pass
                    mantidas.append(row)
                removidas = len(linhas) - len(mantidas)
                if removidas:
                    temporario = CSV_PATH + ".tmp"
                    with open(temporario, "w", newline="", encoding="utf-8-sig") as f:
                        csv.writer(f, delimiter=";").writerows(mantidas)
                    os.replace(temporario, CSV_PATH)
                    logging.info("Retenção: %d assinatura(s) com mais de %d dias removida(s) do CSV.",
                                 removidas, RETENCAO_DIAS)
                return removidas
            except Exception as e:
                logging.error("Não foi possível aplicar a retenção ao CSV (aberto no Excel?): %s", e)
                return 0

    def _aplicar_retencao_periodica(self):
        # O servidor costuma ficar no ar por meses: a retenção roda uma vez por dia.
        self._registro.aplicar_retencao()
        if self._apagar_assinaturas_antigas():
            self._carregar_historico_csv()
        self.root.after(INTERVALO_RETENCAO_MS, self._aplicar_retencao_periodica)

    def _carregar_historico_csv(self):
        if not os.path.isfile(CSV_PATH):
            return
        try:
            with open(CSV_PATH, "r", newline="", encoding="utf-8-sig") as f:
                linhas = list(csv.reader(f, delimiter=";"))
        except Exception as e:
            logging.error("Erro ao carregar histórico: %s", e)
            return

        registros = []
        for row in linhas:
            if not row or row == CSV_CABECALHOS:
                continue
            if len(row) < 4:
                continue
            data, hora = row[0], row[1]
            computador = row[2] if len(row) > 2 else ""
            usuario = row[3] if len(row) > 3 else ""
            nome_assinado = row[4] if len(row) > 4 else ""
            mensagem = row[5] if len(row) > 5 else ""
            registros.append({
                "data": data, "hora": hora, "computador": computador, "usuario": usuario,
                "nome_assinado": nome_assinado, "mensagem": mensagem,
            })

        registros.reverse()  # mais recentes primeiro
        with self._lock:
            self.historico = registros[:LIMITE_HISTORICO_MEMORIA]
        self._renderizar_historico()

    def _renderizar_historico(self):
        termo = self.entry_busca.get().strip().lower() if hasattr(self, "entry_busca") else ""

        for item in self.tree_relatorios.get_children():
            self.tree_relatorios.delete(item)

        with self._lock:
            historico_snapshot = list(self.historico)

        total_exibidos = 0
        for r in historico_snapshot:
            if termo:
                alvo = " ".join([
                    r.get("computador", ""), r.get("usuario", ""),
                    r.get("nome_assinado", ""), r.get("mensagem", ""),
                ]).lower()
                if termo not in alvo:
                    continue
            self.tree_relatorios.insert("", "end", values=(
                r.get("data"), r.get("hora"), r.get("computador"), r.get("usuario"),
                r.get("nome_assinado"), r.get("mensagem"),
            ), tags=("par" if total_exibidos % 2 == 0 else "impar",))
            total_exibidos += 1

        self.lbl_total_historico.config(text=f"{total_exibidos} registro(s)")

    # ------------------------------------------------------------------ #
    # Exportação
    # ------------------------------------------------------------------ #

    def _exportar_excel(self):
        if not self.tree_relatorios.get_children():
            messagebox.showinfo("Exportar", "Não há registros para exportar.")
            return

        caminho = filedialog.asksaveasfilename(
            title="Exportar relatório de assinaturas",
            defaultextension=".xlsx",
            filetypes=[("Planilha Excel", "*.xlsx")],
            initialfile=f"relatorio_assinaturas_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx",
        )
        if not caminho:
            return

        try:
            from openpyxl import Workbook
            from openpyxl.styles import Font, PatternFill, Alignment

            wb = Workbook()
            ws = wb.active
            ws.title = "Assinaturas"

            cabecalhos = ["Data", "Hora", "Computador", "Usuário", "Assinado Por", "Mensagem do Alerta"]
            ws.append(cabecalhos)
            for cel in ws[1]:
                cel.font = Font(bold=True, color="FFFFFF")
                cel.fill = PatternFill("solid", fgColor="1E293B")
                cel.alignment = Alignment(horizontal="center")

            for item in self.tree_relatorios.get_children():
                valores = self.tree_relatorios.item(item, "values")
                # Sanitiza de novo aqui (mesmo já sanitizado no CSV) porque o
                # Excel também interpretaria fórmulas em qualquer célula.
                ws.append([sanitizar_campo_csv(v) for v in valores])

            larguras = [12, 10, 20, 18, 30, 50]
            for i, largura in enumerate(larguras, start=1):
                ws.column_dimensions[chr(64 + i)].width = largura

            ws.freeze_panes = "A2"
            wb.save(caminho)
            messagebox.showinfo("Exportar", f"Relatório exportado com sucesso:\n{caminho}")
        except ImportError:
            messagebox.showerror(
                "Exportar", "A biblioteca 'openpyxl' não está instalada.\nInstale com: pip install openpyxl")
        except Exception as e:
            messagebox.showerror("Exportar", f"Erro ao exportar:\n{e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ServidorCentralGUI(root)
    root.mainloop()
