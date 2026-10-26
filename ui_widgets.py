# -*- coding: utf-8 -*-
"""Widgets com cantos arredondados usando só Tkinter puro (sem dependências
externas). tk.Button, tk.Frame e ttk não têm suporte nativo a border-radius;
aqui isso é obtido desenhando um polígono com `smooth=True` num Canvas — os
pontos ficam em pares próximos a cada canto, e o Tk arredonda a curva entre
eles automaticamente (a mesma técnica usada por vários projetos Tkinter para
simular cantos arredondados sem bibliotecas de terceiros).
"""
import tkinter as tk
from tkinter import font as tkfont


def retangulo_arredondado(canvas, x1, y1, x2, y2, raio=14, cantos=("tl", "tr", "br", "bl"), **kwargs):
    """Desenha um retângulo de cantos arredondados no `canvas` e devolve o id
    do polígono criado. `cantos` escolhe quais dos 4 cantos ficam arredondados
    (os demais ficam retos) — útil para, por exemplo, arredondar só a parte de
    baixo de um cabeçalho."""
    r = max(0, min(raio, (x2 - x1) / 2, (y2 - y1) / 2))
    pontos = []
    pontos += [x1, y1 + r, x1, y1, x1 + r, y1] if "tl" in cantos else [x1, y1, x1, y1]
    pontos += [x2 - r, y1, x2, y1, x2, y1 + r] if "tr" in cantos else [x2, y1, x2, y1]
    pontos += [x2, y2 - r, x2, y2, x2 - r, y2] if "br" in cantos else [x2, y2, x2, y2]
    pontos += [x1 + r, y2, x1, y2, x1, y2 - r] if "bl" in cantos else [x1, y2, x1, y2]
    return canvas.create_polygon(pontos, smooth=True, **kwargs)


class BotaoArredondado(tk.Canvas):
    """Um botão clicável com cantos arredondados, com a mesma ideia de uso de
    um tk.Button comum (texto, comando, e os métodos .config(state=...,
    text=...) mais usados no resto do app)."""

    def __init__(self, mestre, texto, comando=None, *, cor="#14b8a6", cor_hover=None,
                 cor_pressionado=None, cor_texto="white", cor_desabilitado="#cbd5e1",
                 cor_texto_desabilitado="#94a3b8", fonte=("Segoe UI", 10, "bold"),
                 raio=14, padx=18, pady=10, cor_fundo=None, borda=0, cor_borda="",
                 largura_min=0, **kwargs):
        try:
            cor_fundo = cor_fundo or mestre.cget("bg")
        except tk.TclError:
            cor_fundo = cor_fundo or "#f8fafc"
        super().__init__(mestre, highlightthickness=0, bg=cor_fundo, bd=0, **kwargs)

        self._comando = comando
        self._cor = cor
        self._cor_hover = cor_hover or cor
        self._cor_pressionado = cor_pressionado or cor
        self._cor_texto = cor_texto
        self._cor_desabilitado = cor_desabilitado
        self._cor_texto_desabilitado = cor_texto_desabilitado
        self._fonte = tkfont.Font(font=fonte)
        self._raio = raio
        self._padx = padx
        self._pady = pady
        self._borda = borda
        self._cor_borda = cor_borda
        self._texto = texto
        self._estado = "normal"
        self._sob_mouse = False
        self._pressionado = False

        largura = max(largura_min, self._fonte.measure(texto) + padx * 2)
        altura = self._fonte.metrics("linespace") + pady * 2
        self.configure(width=largura, height=altura)

        self.bind("<Configure>", lambda e: self._redesenhar())
        self.bind("<Enter>", self._ao_entrar)
        self.bind("<Leave>", self._ao_sair)
        self.bind("<ButtonPress-1>", self._ao_pressionar)
        self.bind("<ButtonRelease-1>", self._ao_soltar)
        self._redesenhar()

    def _cor_atual(self):
        if self._estado == "disabled":
            return self._cor_desabilitado
        if self._pressionado:
            return self._cor_pressionado
        if self._sob_mouse:
            return self._cor_hover
        return self._cor

    def _redesenhar(self):
        self.delete("all")
        w = self.winfo_width() or int(self._fonte.measure(self._texto) + self._padx * 2)
        h = self.winfo_height() or int(self._fonte.metrics("linespace") + self._pady * 2)
        cor = self._cor_atual()
        kwargs = {"fill": cor, "outline": self._cor_borda or cor}
        if self._borda and self._cor_borda:
            kwargs["width"] = self._borda
        retangulo_arredondado(self, 1, 1, max(w - 1, 2), max(h - 1, 2), self._raio, **kwargs)
        cor_texto = self._cor_texto_desabilitado if self._estado == "disabled" else self._cor_texto
        self.create_text(w / 2, h / 2, text=self._texto, fill=cor_texto, font=self._fonte)
        self.configure(cursor="hand2" if self._estado == "normal" else "arrow")

    def _ao_entrar(self, _e=None):
        self._sob_mouse = True
        self._redesenhar()

    def _ao_sair(self, _e=None):
        self._sob_mouse = False
        self._pressionado = False
        self._redesenhar()

    def _ao_pressionar(self, _e=None):
        if self._estado == "normal":
            self._pressionado = True
            self._redesenhar()

    def _ao_soltar(self, _e=None):
        disparar = self._estado == "normal" and self._pressionado
        self._pressionado = False
        self._redesenhar()
        if disparar and self._comando:
            self._comando()

    def configurar_texto(self, texto):
        self._texto = texto
        largura = self._fonte.measure(texto) + self._padx * 2
        self.configure(width=largura)
        self._redesenhar()

    def set_estado(self, estado):
        self._estado = estado
        self._redesenhar()

    def set_comando(self, comando):
        self._comando = comando

    def config(self, **kwargs):
        atualizar = False
        if "state" in kwargs:
            self._estado = kwargs.pop("state")
            atualizar = True
        if "text" in kwargs:
            self._texto = kwargs.pop("text")
            largura = self._fonte.measure(self._texto) + self._padx * 2
            super().config(width=largura)
            atualizar = True
        if "bg" in kwargs and "cor" not in kwargs:
            self._cor = kwargs.pop("bg")
            atualizar = True
        if "cor" in kwargs:
            self._cor = kwargs.pop("cor")
            atualizar = True
        if kwargs:
            super().config(**kwargs)
        if atualizar:
            self._redesenhar()

    configure = config

    def cget(self, key):
        # Permite o uso comum `botao["state"]`/`botao["text"]` (como em um
        # tk.Button), embora Canvas não tenha essas opções nativamente.
        if key == "state":
            return self._estado
        if key == "text":
            return self._texto
        return super().cget(key)

    __getitem__ = cget


class CartaoArredondado(tk.Frame):
    """'Card' com fundo e cantos arredondados; qualquer widget colocado dentro
    de `.interior` aparece por cima do fundo arredondado, preenchendo o cartão
    (menos a margem `padx`/`pady`)."""

    def __init__(self, mestre, cor_cartao="white", cor_fundo=None, raio=16,
                 padx=16, pady=14, cor_borda="", largura_borda=0, **kwargs):
        try:
            cor_fundo = cor_fundo or mestre.cget("bg")
        except tk.TclError:
            cor_fundo = cor_fundo or "#f1f5f9"
        super().__init__(mestre, bg=cor_fundo, **kwargs)

        self._cor_cartao = cor_cartao
        self._raio = raio
        self._padx = padx
        self._pady = pady
        self._cor_borda = cor_borda
        self._largura_borda = largura_borda

        self._canvas = tk.Canvas(self, highlightthickness=0, bg=cor_fundo, bd=0)
        self._canvas.pack(fill="both", expand=True)

        self.interior = tk.Frame(self._canvas, bg=cor_cartao)
        self._id_janela = self._canvas.create_window(padx, pady, anchor="nw", window=self.interior)

        self._canvas.bind("<Configure>", self._ao_redimensionar)

    def ajustar_altura_ao_conteudo(self):
        """Para cartões usados com pack(fill="x") (largura segue o pai, mas a
        altura precisa acompanhar o conteúdo): como o conteúdo real fica
        dentro de uma janela de Canvas, o Canvas não cresce sozinho para
        caber o conteúdo como um Frame normal faria. Chame isso depois de
        montar todos os widgets internos."""
        self.interior.update_idletasks()
        altura = self.interior.winfo_reqheight() + 2 * self._pady
        self._canvas.config(height=altura)

    def _ao_redimensionar(self, event):
        w, h = event.width, event.height
        self._canvas.delete("fundo")
        kwargs = {"fill": self._cor_cartao, "outline": self._cor_borda or self._cor_cartao}
        if self._cor_borda:
            kwargs["width"] = self._largura_borda or 1
        retangulo_arredondado(self._canvas, 1, 1, max(w - 1, 2), max(h - 1, 2), self._raio, tags="fundo", **kwargs)
        self._canvas.tag_lower("fundo")
        largura_interna = max(w - 2 * self._padx, 1)
        altura_interna = max(h - 2 * self._pady, 1)
        self._canvas.coords(self._id_janela, self._padx, self._pady)
        self._canvas.itemconfig(self._id_janela, width=largura_interna, height=altura_interna)
