# Sistema de Alertas de Reunião

Sistema cliente-servidor para rede local (Windows) que dispara **alertas em popup** para os computadores da organização e coleta uma **assinatura de leitura** de cada usuário. Cada confirmação fica registrada em CSV e pode ser exportada para Excel.

O sistema tem dois programas:

| Programa | Arquivo | Onde roda | Função |
|---|---|---|---|
| **Servidor Central** | `servidor_central.py` → `ServidorCentral.exe` | Computador de quem envia os alertas | Painel de controle: dispara alertas, acompanha quem leu, guarda o histórico |
| **Agente** | `agente_cliente.py` → `AgenteAlerta.exe` | Cada computador que vai receber alertas | Fica em segundo plano, conectado ao servidor, e exibe o popup quando chega um alerta |

---

## Sumário

1. [Como funciona](#como-funciona)
2. [Estrutura do projeto](#estrutura-do-projeto)
3. [Instalação e build](#instalação-e-build)
4. [Configuração (`config.json`)](#configuração-configjson)
5. [Implantação passo a passo](#implantação-passo-a-passo)
6. [Usando o Servidor Central](#usando-o-servidor-central)
7. [O popup no Agente](#o-popup-no-agente)
8. [Arquivos gerados](#arquivos-gerados)
9. [Protocolo de comunicação](#protocolo-de-comunicação)
10. [Segurança](#segurança)
11. [Solução de problemas](#solução-de-problemas)
12. [Limitações conhecidas](#limitações-conhecidas)

---

## Como funciona

```
 ┌──────────────────────┐       TLS sobre TCP (porta 5000)    ┌──────────────────┐
 │   Servidor Central   │ ◄───────────────────────────────── │  Agente (PC 1)   │
 │  (painel + CSV)      │ ◄───────────────────────────────── │  Agente (PC 2)   │
 │                      │ ◄───────────────────────────────── │  Agente (PC N)   │
 └──────────────────────┘                                    └──────────────────┘
```

1. O **Servidor Central** abre a porta TCP configurada (padrão `5000`) e fica aguardando conexões. Toda a comunicação é **criptografada com TLS**.
2. Cada **Agente**, ao iniciar, conecta-se ao IP do servidor e **confere o certificado do servidor** (impressão digital `cert_sha256`). Se não conferir, desconecta sem enviar nada.
3. Com o servidor confirmado, o agente envia uma mensagem de **identificação** com nome do computador, usuário do Windows e o **token** de autenticação.
4. O servidor valida o token. Se for válido, o agente aparece na lista **Agentes Conectados**; caso contrário, a conexão é recusada.
5. O operador escreve uma mensagem (e, se quiser, anexa uma imagem) e dispara para **todos** ou só para os **selecionados**. O alerta é registrado em `alertas_emitidos.jsonl`.
6. Cada agente exibe um **popup em primeiro plano** que não pode ser fechado nem minimizado. O usuário precisa digitar **nome e sobrenome** e clicar em **Assinar e Fechar**.
7. A assinatura volta ao servidor, que a **valida** (ver [Segurança](#segurança)), grava em `relatorios_assinados.csv` e atualiza os contadores de confirmados e pendentes.
8. Se a conexão cair, o agente tenta reconectar a cada **5 segundos**. Assinaturas feitas enquanto a rede estava fora ficam guardadas em memória e são reenviadas assim que a conexão volta, mesmo que o servidor tenha sido reiniciado nesse meio-tempo.

---

## Estrutura do projeto

```
POPUP REUNIAO BUILD/
├── servidor_central.py       # Painel do Servidor Central (Tkinter)
├── agente_cliente.py         # Agente que roda nas máquinas e exibe o popup
├── protocolo.py              # Código compartilhado: protocolo de rede, config, log, imagens, logo
├── ui_widgets.py             # Botões e cartões com cantos arredondados (Tkinter puro)
├── ServidorCentral.spec      # Receita do PyInstaller para gerar ServidorCentral.exe
├── AgenteAlerta.spec         # Receita do PyInstaller para gerar AgenteAlerta.exe
├── requirements.txt          # Dependências Python
└── logo.png                  # (opcional) logo alternativa para o popup do agente
```

### Módulos

- **`protocolo.py`**: base usada pelos dois programas.
  - `enviar_json` / `receber_json`: troca de mensagens com cabeçalho de tamanho, com limite de tamanho e prazo (ver [Protocolo](#protocolo-de-comunicação)).
  - `carregar_config`: lê o `config.json` (sem nunca registrar o token no log).
  - `garantir_token_servidor`: gera e salva o token na primeira execução do servidor.
  - `criar_contexto_tls_servidor` / `garantir_certificado_servidor`: geram o certificado TLS do servidor na primeira execução.
  - `criar_contexto_tls_agente` / `certificado_servidor_confere`: TLS do agente e conferência da impressão digital do servidor.
  - `configurar_log`: grava log em arquivo ao lado do executável, com rotação.
  - `ativar_keepalive`: faz o Windows detectar conexões mortas (cabo desconectado, PC desligado).
  - `imagem_para_base64` / `base64_para_photoimage`: compactam e decodificam as imagens anexadas.
  - `sanitizar_campo_csv`: protege o CSV/Excel contra injeção de fórmulas.
  - `carregar_logo_instituto_acqua`: logo institucional embutida no código em base64.
- **`servidor_central.py`**, além do painel:
  - `RegistroAlertas`: registro persistente dos alertas disparados, usado para validar assinaturas.
  - `ConexaoAgente`: conexão com um agente. Uma única thread lê e escreve no socket TLS; os disparos entram numa fila.
- **`ui_widgets.py`**: `BotaoArredondado` e `CartaoArredondado`, widgets com cantos arredondados desenhados em `Canvas`, sem bibliotecas externas.

---

## Instalação e build

### Requisitos

- Windows 10/11
- Python 3.10+ com Tkinter (já incluso no instalador oficial do Python para Windows)

### Dependências

```bash
pip install -r requirements.txt
```

| Pacote | Uso |
|---|---|
| `Pillow` | Redimensionar e exibir imagens e a logo |
| `openpyxl` | Exportar o histórico para Excel (só o servidor usa) |
| `cryptography` | Gerar o certificado TLS na primeira execução (só o servidor usa) |
| `pyinstaller` | Gerar os `.exe` (só necessário para o build) |

### Executar a partir do código-fonte

```bash
python servidor_central.py
python agente_cliente.py
```

### Gerar os executáveis

```bash
python -m PyInstaller --clean --noconfirm ServidorCentral.spec
python -m PyInstaller --clean --noconfirm AgenteAlerta.spec
```

Os executáveis são gerados em `dist/` como **arquivo único e sem janela de console**:

- `dist/ServidorCentral.exe`
- `dist/AgenteAlerta.exe`

> Como os `.exe` não têm console, todas as mensagens vão para o arquivo de log (`servidor.log` / `agente.log`) na mesma pasta do executável.

---

## Configuração (`config.json`)

Os dois programas leem um `config.json` **na mesma pasta do executável** (ou do `.py`). Chaves ausentes usam o valor padrão.

**Agente:**
```json
{
  "servidor_ip": "192.168.70.198",
  "porta": 5000,
  "token": "…",
  "cert_sha256": "…"
}
```

**Servidor:**
```json
{
  "porta": 5000,
  "token": "…",
  "retencao_dias": 365
}
```

| Chave | Padrão | Usado por | Descrição |
|---|---|---|---|
| `servidor_ip` | `192.168.70.198` | Agente | IP da máquina onde roda o Servidor Central |
| `porta` | `5000` | Ambos | Porta TCP de comunicação |
| `token` | *(vazio)* | Ambos | Segredo compartilhado. Precisa ser **idêntico** no servidor e em todos os agentes. **Obrigatório no agente** |
| `cert_sha256` | *(vazio)* | Agente | Impressão digital SHA-256 do certificado do servidor. **Obrigatório**: sem ele, o agente se recusa a iniciar |
| `retencao_dias` | `0` | Servidor | Assinaturas e alertas registrados com mais de N dias são apagados automaticamente (na inicialização e uma vez por dia). `0` = guardar para sempre |

### `config_agente.json`: o jeito fácil de configurar os agentes

O servidor gera, toda vez que inicia, um arquivo **`config_agente.json`** na pasta dele, com `servidor_ip`, `porta`, `token` e `cert_sha256` já preenchidos. Basta copiá-lo para a pasta de cada agente e **renomeá-lo para `config.json`**.

> ⚠️ O `config_agente.json` contém o token: trate-o como uma senha. Não envie por e-mail nem deixe em pasta compartilhada aberta.
>
> O `servidor_ip` é detectado automaticamente. Se o servidor tiver mais de uma placa de rede (Wi-Fi + cabo, VPN), confira se é o IP certo.

### Token e certificado

- Na **primeira execução**, o servidor **gera um token aleatório** (gravado no próprio `config.json`) e um **certificado TLS autoassinado** (`servidor_cert.pem` + `servidor_chave.pem`).
- O valor do token **não aparece em nenhum log**.
- **Trocar o token** (ex.: se vazou): apague a linha `token` do `config.json` do servidor, reinicie-o e distribua o novo `config_agente.json`.
- **Trocar o certificado**: apague `servidor_cert.pem` e `servidor_chave.pem`, reinicie o servidor e distribua o novo `config_agente.json`. Agentes com o `cert_sha256` antigo deixam de conectar.
- Guarde uma **cópia de segurança** de `config.json`, `servidor_cert.pem` e `servidor_chave.pem`. Se forem perdidos (ex.: formatação da máquina), todos os agentes precisam ser reconfigurados.

---

## Implantação passo a passo

### 1. Servidor Central

1. Copie `ServidorCentral.exe` para uma pasta fixa no computador do operador (ex.: `C:\AlertasReuniao\`).
2. Execute-o uma vez. Isso cria o `config.json` (com o token), o certificado TLS e o `config_agente.json`.
3. Confira o **IP e a porta** no rodapé do painel: *"Servidor ouvindo em X.X.X.X:5000 (TLS)"*.
4. Libere a porta no **Firewall do Windows** (entrada TCP 5000), se necessário.
5. Se possível, reserve um **IP fixo** para essa máquina no roteador/DHCP. Se o IP mudar, todos os agentes deixam de encontrar o servidor.
6. **Restrinja o acesso à pasta** (botão direito → Propriedades → Segurança): só o usuário que roda o servidor e os administradores devem ter acesso. Ela contém o token, a chave privada do certificado e os dados pessoais das assinaturas.
7. Proteja a **sessão do Windows** do servidor com senha e bloqueio automático de tela: o painel não tem login próprio, e quem usa a sessão pode disparar alertas e exportar o histórico.

### 2. Agentes

Em cada computador que vai receber alertas:

1. Copie `AgenteAlerta.exe` para uma pasta fixa.
2. Copie para a mesma pasta o **`config_agente.json`** gerado pelo servidor e **renomeie-o para `config.json`**.
3. (Opcional) Coloque um `logo.png` na mesma pasta para trocar a logo exibida no popup.
4. Configure para iniciar com o Windows: pressione `Win + R`, digite `shell:startup` e crie ali um **atalho** para o `AgenteAlerta.exe`.
5. Execute o agente. Ele roda em segundo plano, sem janela, e deve aparecer em **Agentes Conectados** no servidor.

> O agente permite **uma única instância por sessão de usuário**: se for aberto de novo (ex.: atalho duplicado), a segunda cópia se encerra sozinha.
>
> Se o `config.json` do agente não tiver `token` ou `cert_sha256`, o agente mostra uma mensagem de erro e não inicia.

### Atualizando uma instalação anterior (sem TLS)

A versão com TLS **não conversa com agentes antigos**. Ao atualizar, substitua **os dois programas** e distribua o novo `config_agente.json` para todos os agentes. Os agentes antigos aparecem no `servidor.log` como *"falha no TLS… Agente desatualizado?"*.

Aproveite a atualização para **trocar o token**: as versões anteriores gravavam o token nos arquivos `servidor.log` e `agente.log`. Apague a linha `token` do `config.json` do servidor antes de reiniciá-lo e apague os logs antigos das máquinas.

---

## Usando o Servidor Central

### Disparar um alerta

1. Digite a mensagem no campo **Mensagem do alerta**.
2. (Opcional) Clique em **🖼 Anexar Imagem** (PNG, JPG, BMP, GIF). A imagem é redimensionada e comprimida antes do envio. Use **✖** para remover.
3. Envie:
   - **📢 Disparar para Todos**: envia para todos os agentes conectados. Atalho: `Ctrl + Enter` no campo de mensagem.
   - **📤 Enviar para Selecionados**: envia só para os agentes marcados na lista (`Ctrl+clique` ou `Shift+clique` para marcar vários).

O envio é feito em segundo plano e em paralelo, então um agente lento não trava o painel. Ao final, aparece quantas máquinas receberam o alerta.

### Aba "👥 Agentes & Pendências"

- **Indicadores**: máquinas online, alertas disparados, assinaturas recebidas e pendências.
- **Agentes Conectados**: computador, usuário e IP de cada agente online.
- **Alertas Disparados**: horário, mensagem (🖼 indica imagem), total enviado, confirmados, pendentes e % de leitura. A linha fica verde quando todos confirmam.
- **Detalhe do alerta**: clique em um alerta para ver as listas **✅ Confirmaram** e **⏳ Pendentes**.
- **🔁 Reenviar aos pendentes**: reenvia o alerta só para quem ainda não assinou. O servidor encontra o agente pelo par *computador + usuário*, mesmo que ele tenha reconectado desde o disparo. Quem estiver offline continua como pendente.

### Aba "🧾 Histórico de Assinaturas"

- Lista todas as assinaturas, das mais recentes para as mais antigas, carregadas do `relatorios_assinados.csv`.
- **🔎 Buscar**: filtra por computador, usuário, nome assinado ou mensagem.
- **📊 Exportar Excel**: gera um `.xlsx` com os registros **visíveis** (respeita o filtro de busca).

> A aba de pendências mostra só os alertas disparados **desde que o servidor foi aberto**. O histórico de assinaturas fica salvo no CSV, e os alertas continuam registrados em `alertas_emitidos.jsonl`: uma assinatura atrasada de um alerta anterior ao reinício ainda é aceita e gravada.

---

## O popup no Agente

Quando um alerta chega, o agente:

- Abre uma janela **sempre em primeiro plano**, centralizada, com som de aviso, ícone piscando na barra de tarefas e uma faixa colorida pulsante.
- **Impede o fechamento** pelo "X" e **restaura a janela** se alguém tentar minimizá-la (inclusive com `Win+D` / `Win+M`).
- Mostra a mensagem, a imagem anexada (se houver) e um campo para o nome.
- Só libera o botão **✔ Assinar e Fechar** quando o nome tem **pelo menos 2 palavras e 5 caracteres**. `Enter` também confirma.
- Envia ao servidor: ID do alerta, computador, usuário do Windows, nome digitado, mensagem e data/hora.
- Se o mesmo alerta chegar de novo depois de assinado (ex.: **Reenviar aos pendentes** enquanto o popup ainda estava aberto), não abre outro popup.

**Logo do popup:** se existir um `logo.png` ao lado do `AgenteAlerta.exe`, ele é usado. Caso contrário, aparece a logo do Instituto Acqua embutida no código.

---

## Arquivos gerados

Todos ficam na mesma pasta do executável:

| Arquivo | Programa | Conteúdo |
|---|---|---|
| `config.json` | Ambos | Configuração (o servidor cria/atualiza com o token). **Sensível** |
| `config_agente.json` | Servidor | `config.json` pronto para os agentes, recriado a cada início. **Sensível** |
| `servidor_cert.pem` | Servidor | Certificado TLS (público) |
| `servidor_chave.pem` | Servidor | Chave privada do certificado. **Sensível**: nunca copie para os agentes |
| `alertas_emitidos.jsonl` | Servidor | Registro dos alertas disparados (texto, horário, destinatários e quem assinou), usado para validar assinaturas. Guarda os últimos 1.000 alertas |
| `servidor.log` (+ `.1` a `.3`) | Servidor | Conexões, disparos, assinaturas, recusas e erros. Rotacionado a cada 2 MB |
| `agente.log` (+ `.1` a `.3`) | Agente | Conexão, alertas recebidos e erros. Rotacionado a cada 2 MB |
| `relatorios_assinados.csv` | Servidor | Histórico de assinaturas (sujeito a `retencao_dias`) |
| `relatorios_assinados.csv.bak` | Servidor | Cópia do CSV no formato antigo, criada uma única vez durante a migração. Não é afetado pela retenção: apague-o manualmente quando não for mais necessário |

### Formato do CSV

- Separador `;`, codificação UTF-8 com BOM (abre corretamente no Excel em português).
- Colunas: `Data;Hora;Computador;Usuário;Nome Assinado;Mensagem do Alerta`

```
Data;Hora;Computador;Usuário;Nome Assinado;Mensagem do Alerta
26/10/2026;14:32:10;PC-FINANCEIRO;maria.souza;Maria Souza;Reunião geral às 15h na sala 2
```

- **Migração automática:** se o servidor encontrar um CSV no formato antigo (data e hora na mesma coluna, cabeçalhos técnicos), ele converte para o formato novo na inicialização e guarda o original em `.bak`.
- ⚠️ **Não deixe o CSV aberto no Excel** enquanto o servidor estiver rodando: o Windows bloqueia o arquivo e as novas assinaturas **não são gravadas**. O servidor exibe um aviso quando isso acontece. Para consultar os dados, use **Exportar Excel**.

---

## Protocolo de comunicação

Comunicação via **TLS 1.2+ sobre TCP**. Cada mensagem é um **JSON em UTF-8** precedido de um **cabeçalho de 4 bytes** (big-endian) com o tamanho do corpo:

```
[ 4 bytes: tamanho N ][ N bytes: JSON UTF-8 ]
```

Isso garante que mensagens grandes (como imagens em base64) cheguem inteiras e não se misturem com a próxima mensagem.

### Mensagens

**Agente → Servidor: identificação** (primeira mensagem da conexão)
```json
{ "tipo": "IDENTIFICACAO", "computador": "PC-01", "usuario": "joao", "token": "..." }
```

**Servidor → Agente: recusa** (token inválido)
```json
{ "tipo": "ERRO", "motivo": "token_invalido" }
```

**Servidor → Agente: alerta**
```json
{
  "comando": "EXIBIR_POPUP",
  "alerta_id": "a1b2c3d4e5",
  "mensagem": "Reunião geral às 15h",
  "imagem_b64": "<JPEG em base64 ou null>",
  "imagem_nome": "pauta.png"
}
```

**Agente → Servidor: confirmação**
```json
{
  "tipo": "CONFIRMACAO",
  "alerta_id": "a1b2c3d4e5",
  "computador": "PC-01",
  "usuario": "joao",
  "nome_assinado": "João da Silva",
  "mensagem": "Reunião geral às 15h",
  "data_hora": "2026-10-26 14:32:10"
}
```

Da confirmação, o servidor só aproveita `alerta_id`, `nome_assinado` e, se for plausível, `data_hora`. Os campos `computador`, `usuario` e `mensagem` são **ignorados**: o servidor usa os da conexão autenticada e os do alerta registrado.

### Parâmetros de rede

| Parâmetro | Valor | Onde |
|---|---|---|
| Tamanho máximo de mensagem (servidor → agente) | 15 MB | `TAMANHO_MAXIMO_MENSAGEM` em `protocolo.py` |
| Tamanho máximo da identificação | 4 KB | `TAMANHO_MAXIMO_IDENTIFICACAO` em `servidor_central.py` |
| Tamanho máximo de outras mensagens do agente | 256 KB | `TAMANHO_MAXIMO_MENSAGEM_AGENTE` em `servidor_central.py` |
| Prazo para handshake TLS + identificação | 10 s | `PRAZO_IDENTIFICACAO` em `servidor_central.py` |
| Conexões simultâneas no servidor | 500 | `LIMITE_CONEXOES` em `servidor_central.py` |
| Timeout de envio/recebimento em andamento | 20 s | `TIMEOUT_SOCKET` em `protocolo.py` |
| Keepalive TCP | 1º teste após 30 s ocioso, depois a cada 5 s | `ativar_keepalive` |
| Intervalo de reconexão do agente | 5 s | `escutar_servidor` em `agente_cliente.py` |
| Imagem enviada | redimensionada para no máx. 900×650, JPEG qualidade 85 | `imagem_para_base64` |

A espera **ociosa** por um novo alerta não tem limite de tempo; o timeout de 20 s só vale quando uma mensagem já começou a chegar.

---

## Segurança

### Na rede

- **Criptografia TLS 1.2+**: token, mensagens, imagens e nomes trafegam criptografados.
- **Autenticação do servidor**: o agente confere a impressão digital do certificado (`cert_sha256`) **antes** de enviar qualquer dado. Uma máquina que assuma o IP do servidor não recebe o token e não consegue abrir popups falsos (phishing).
- **Autenticação dos agentes**: só agentes com o token correto são aceitos. A comparação usa `hmac.compare_digest`, que não vaza informação pelo tempo de resposta.

### Integridade das assinaturas

O agente informa apenas **qual alerta** está assinando e o **nome digitado**. O servidor:

- usa o **computador e o usuário da conexão autenticada**, e não os enviados na confirmação. Uma máquina não assina em nome de outra;
- usa o **texto do alerta que ele mesmo registrou**. Não dá para registrar a leitura de um texto diferente;
- só aceita assinaturas de alertas que **foram enviados para aquele computador/usuário**;
- recusa **assinaturas repetidas** e nomes inválidos (mínimo de 2 palavras e 5 caracteres; máximo de 120);
- só aceita o horário informado pelo agente se estiver entre o disparo do alerta e o momento atual (com 5 min de folga). Caso contrário, usa o horário do servidor.

Toda recusa fica registrada no `servidor.log` com o motivo.

### Contra abusos e travamentos

- **Prazo de 10 s** para concluir o TLS e se identificar. Conexões que ficam paradas são derrubadas.
- **Limite de 500 conexões simultâneas**.
- **Limites de tamanho**: 4 KB para a identificação e 256 KB para as demais mensagens dos agentes.
- **Limites de memória**: o servidor mantém no máximo 5.000 registros de histórico e 300 alertas em memória.

### Dados armazenados

- **O token nunca é gravado em log.**
- **Proteção contra injeção de fórmula (CSV Injection)**: campos que começam com `=`, `+`, `-`, `@`, tabulação ou retorno de carro recebem um apóstrofo na frente, tanto no CSV quanto na exportação para Excel.
- **Retenção (LGPD)**: com `retencao_dias` configurado, assinaturas e alertas mais antigos são apagados automaticamente.
- **Logs com rotação**: no máximo ~8 MB por programa (4 arquivos de 2 MB).

### Riscos que continuam (e como reduzir)

- **Token único compartilhado**: quem tiver acesso ao `config.json` de qualquer agente consegue se conectar e se identificar com qualquer nome de computador/usuário. Proteja as pastas e troque o token se houver suspeita de vazamento.
- **Arquivos sem criptografia em disco**: CSV, registro de alertas, logs e chave privada ficam em texto puro. Restrinja as permissões da pasta do servidor (ver [Implantação](#1-servidor-central)).
- **Painel sem login**: depende do bloqueio da sessão do Windows.
- **Planilhas exportadas** ficam fora do controle do sistema e da retenção.
- O "nome assinado" é texto digitado pelo usuário, não uma assinatura digital com validade jurídica.

> Mesmo com TLS, o sistema foi feito para **rede local**. Não exponha a porta para a internet.

---

## Solução de problemas

| Sintoma | Causa provável | Solução |
|---|---|---|
| Agente não aparece no painel | IP/porta errados no `config.json` do agente | Confira o IP no rodapé do servidor e ajuste `servidor_ip` |
| Agente mostra *"Configuração incompleta"* ao iniciar | Falta `token` ou `cert_sha256` | Copie o `config_agente.json` do servidor como `config.json` |
| Agente não aparece e o `agente.log` diz *"Servidor recusou a conexão (token_invalido)"* | Token diferente | Copie o `config_agente.json` atualizado do servidor |
| `agente.log` diz *"certificado … NÃO confere"* | O certificado do servidor foi recriado, **ou outra máquina está se passando pelo servidor** | Se o servidor foi reinstalado, distribua o novo `config_agente.json`. Se não foi, investigue: pode ser um ataque |
| `servidor.log` diz *"falha no TLS… Agente desatualizado?"* | Agente de versão antiga (sem TLS) | Atualize o `AgenteAlerta.exe` dessa máquina |
| `servidor.log` diz *"Assinatura recusada…"* | Assinatura repetida, de alerta expirado ou de quem não recebeu o alerta | Normal em reenvios. Se for frequente para a mesma máquina, investigue |
| Agente não conecta de jeito nenhum | Firewall bloqueando | Libere a porta TCP (padrão 5000) na máquina do servidor |
| *"Não foi possível iniciar o servidor na porta 5000"* | Porta em uso (outro servidor já aberto?) | Feche a outra instância ou mude a `porta` em todos os `config.json` |
| Aviso *"CSV travado"* | `relatorios_assinados.csv` aberto no Excel | Feche o arquivo. Use **Exportar Excel** para consultar |
| Todos os agentes caíram de uma vez | IP do servidor mudou | Fixe o IP da máquina do servidor e atualize os agentes |
| Popup sem imagem | Falha ao decodificar a imagem | Veja o `agente.log`. Tente outro formato (PNG/JPG) |

Para diagnosticar qualquer problema, consulte primeiro **`servidor.log`** e **`agente.log`**.

---

## Limitações conhecidas

- **Um popup por vez no agente**: enquanto um popup está aberto, o agente não processa novos alertas. Eles são exibidos depois que o atual for assinado. Se o operador disparar vários alertas seguidos (principalmente com imagem), o envio para uma máquina com popup aberto pode exceder o timeout de 20 s e essa máquina não entra na contagem daquele alerta.
- **Painel recomeça vazio**: a aba de pendências mostra só os alertas da sessão atual do servidor. As assinaturas atrasadas de alertas anteriores continuam sendo aceitas e gravadas no CSV.
- **Assinaturas offline em memória**: assinaturas feitas sem conexão ficam em memória no agente. Se o agente for encerrado antes de reconectar, elas se perdem.
- **Somente Windows**: recursos como instância única, piscar na barra de tarefas e keepalive ajustado usam APIs do Windows.
