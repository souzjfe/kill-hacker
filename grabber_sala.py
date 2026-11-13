#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
grabber_sala.py — "IP grabber" didático para aula de Segurança da Computação
===========================================================================

O QUE ESTE ARQUIVO FAZ (de verdade):
  - Sobe um servidor HTTP na rede local.
  - Serve uma página de isca ("Quiz da turma").
  - Registra o que QUALQUER site do mundo vê quando você visita ele:
        IP de origem, User-Agent, Referer, Accept-Language, Host, data/hora.
  - Recebe, via JavaScript, um punhado de dados que o navegador entrega de graça
    (idioma, fuso, tamanho de tela, núcleos da CPU...).
  - Mostra tudo isso num painel em /painel.

O QUE ESTE ARQUIVO NÃO FAZ (de propósito):
  - Não usa nada de terceiros, não chama API de geolocalização, não usa
    fingerprinting, não persiste cookie, não tenta furar VPN.
  - Todo o resto que um "grabber" real faz está apenas COMENTADO, como material
    de aula. Nada ali é executável.

USO:
    python3 grabber_sala.py                 # porta 8000, escuta na rede local
    python3 grabber_sala.py --porta 8080
    python3 grabber_sala.py --destino https://youtube.com   # isca com redirect

AVISO LEGAL / ÉTICO (leia em voz alta para a turma):
  Coletar IP de quem NÃO consentiu é tratamento de dado pessoal sem base legal
  (LGPD, art. 5º, I + art. 7º). Este programa só deve rodar em ambiente de aula,
  com participantes avisados, e os logs devem ser apagados no fim da aula.
  Use em rede de terceiros sem autorização = problema sério, inclusive criminal.
"""

import argparse
import json
import os
import re
import secrets
import socket
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
ARQ_LOG_PADRAO = BASE_DIR / "capturas.jsonl"

# Lock porque ThreadingHTTPServer atende várias conexões ao mesmo tempo.
# Sem isso, dois alunos clicando juntos corrompem o arquivo de log.
_TRAVA = threading.Lock()

# Preenchidas no main() a partir dos argumentos de linha de comando
# ou das variáveis de ambiente (usadas no Docker).
CONFIG = {
    "destino": None,                 # URL para onde /r redireciona (isca)
    "token": None,                   # senha simples do painel
    "mascara": BASE_DIR / "mascara.html",   # a fachada servida em /
    "divulgar": True,                # mantém o selo "demonstração de aula"
    "log": ARQ_LOG_PADRAO,           # onde as capturas são gravadas
}

# Remove o selinho de transparência quando se roda com --sem-divulgar.
_SELO_AULA = re.compile(r'<span class="selo-aula".*?</span>', re.S)


# ---------------------------------------------------------------------------
# 1. Descoberta do IP do visitante
# ---------------------------------------------------------------------------
def descobrir_ip(handler):
    """
    Retorna (ip, confiavel, xff_bruto).

    Existe uma pegadinha enorme aqui, e é a primeira lição da aula:

    - `handler.client_address[0]` é o IP da conexão TCP. É o único dado que o
      seu kernel conhece. É confiável *para aquela conexão*.
    - `X-Forwarded-For` (XFF) é um CABEÇALHO que o cliente escreve. Qualquer um
      pode mandar `X-Forwarded-For: 8.8.8.8` com um `curl` e o servidor burro
      acredita. É por isso que "IP grabber" caseiro é tão fácil de enganar.
    - Só se confia em XFF quando existe um proxy conhecido na frente (nginx,
      Cloudflare, ngrok), e aí se confia na ÚLTIMA entrada, que foi escrita pelo
      proxy mais próximo — não na primeira, que o atacante controla.

    >>> O QUE UM ATACANTE REAL FAZ AQUI <<<
    - Escolhe a linha de XFF que mais lhe convém para forjar um "alvo".
    - Usa `CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP` e `Forwarded` e testa
      qual o alvo respeita (header smuggling de IP).
    - Faz o mesmo com o IP do log do servidor web, do WAF e do SIEM, e depois
      compara os três para descobrir qual camada está sendo enganada.
    """
    peer = handler.client_address[0]
    xff = handler.headers.get("X-Forwarded-For", "").strip()

    if xff:
        ultimo = xff.split(",")[-1].strip()
        if ultimo:
            # Só aceitamos porque o professor sabe que pode haver proxy na frente.
            # Em produção você teria uma lista de proxies confiáveis.
            return ultimo, False, xff
    return peer, True, ""


# ---------------------------------------------------------------------------
# 2. Montagem do registro
# ---------------------------------------------------------------------------
CABECALHOS_INTERESSANTES = (
    "User-Agent",
    "Referer",
    "Accept-Language",
    "Accept",
    "Host",
    "Connection",
    "Sec-CH-UA-Platform",
    "Sec-CH-UA-Mobile",
)

# >>> O QUE UM ATACANTE REAL FAZ AQUI <<<
# - GeoIP: pega o IP e consulta MaxMind/IPinfo/DB-IP -> cidade, CEP, ASN,
#   provedor. Com ASN ele separa "residencial" de "datacenter/VPN/Tor".
# - Reverse DNS + whois do bloco -> nome da empresa/universidade do alvo.
# - rDNS também revela hostname de máquina corporativa (ex.: NOTE-FIN-042).
# - Correlaciona o IP com hora do dia para inferir fuso real e rotina.
# - Se o IP é de VPN, ele NÃO desiste: salva o IP e espera o vazamento
#   (WebRTC, DNS, e-mail com tracking pixel) para casar as duas sessões.
# - Reputação do IP: AbuseIPDB, listas de bot, histórico de scam.
# Nada disso está implementado aqui: são chamadas de API externas, e o objetivo
# da aula é entender a coleta, não construir o produto.


def montar_registro(handler, tipo):
    ip, confiavel, xff = descobrir_ip(handler)
    agora = datetime.now(timezone.utc)

    registro = {
        "quando_utc": agora.isoformat(timespec="seconds"),
        "quando_local": agora.astimezone().isoformat(timespec="seconds"),
        "tipo": tipo,                 # "pagina", "redirect" ou "beacon"
        "ip": ip,
        "ip_confiavel": confiavel,    # False = veio de X-Forwarded-For
        "x_forwarded_for": xff,
        "metodo": handler.command,
        "caminho": handler.path,
        "cabecalhos": {
            h: handler.headers.get(h)
            for h in CABECALHOS_INTERESSANTES
            if handler.headers.get(h)
        },
        # Tudo abaixo vem do JS e é 100% FALSIFICÁVEL pelo cliente.
        # O atacante sabe disso e usa para cruzar com outros dados, não como prova.
        "navegador": None,
    }
    return registro


def gravar(registro):
    linha = json.dumps(registro, ensure_ascii=False)
    with _TRAVA:
        with CONFIG["log"].open("a", encoding="utf-8") as f:
            f.write(linha + "\n")
    return linha


def imprimir(registro):
    """Mostra no terminal, porque na aula o telão é o terminal."""
    ip = registro["ip"]
    marca = "confiável" if registro.get("ip_confiavel") else "XFF (FALSIFICÁVEL)"
    print(f"[{registro['quando_local']}] {registro['tipo']:<8} {ip:<15} ({marca})")
    ua = registro.get("cabecalhos", {}).get("User-Agent", "-")
    print(f"    UA: {ua[:110]}")
    nav = registro.get("navegador")
    if nav:
        print(f"    fuso: {nav.get('fuso')} | idioma: {nav.get('idioma')} | "
              f"tela: {nav.get('tela')} | cores: {nav.get('nucleos')}")


# ---------------------------------------------------------------------------
# 3. Páginas
# ---------------------------------------------------------------------------
PAGINA_ISCA = """<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quiz rápido da turma</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         max-width: 40rem; margin: 3rem auto; padding: 0 1.25rem; line-height: 1.55; }
  .aviso { border-left: 4px solid #d97706; background: #d9770615;
           padding: .75rem 1rem; border-radius: .25rem; font-size: .9rem; }
  h1 { margin-bottom: .25rem; }
  .sub { color: #6b7280; margin-top: 0; }
  ul { padding-left: 1.2rem; }
  code { background: #8882; padding: .1rem .3rem; border-radius: .2rem; font-size: .9em; }
  .rodape { margin-top: 2.5rem; font-size: .8rem; color: #6b7280; }
</style>
</head>
<body>
  <h1>Quiz rápido da turma</h1>
  <p class="sub">Segurança da Computação — atividade em sala</p>

  <!--
    ============================================================
    AULA: repare que NADA aqui é malware. Não há exploit, não há
    download, não há falha sendo explorada. É só uma página comum
    que registra o que todo servidor web do planeta já registra.
    O "golpe" é social: a pessoa clica no link.
    ============================================================
    >>> O QUE UM ATACANTE REAL FARIA NESTA PÁGINA <<<
    - Não avisaria nada. O aviso laranja abaixo é a nossa escolha ética
      (e a diferença jurídica entre aula e crime).
    - Colocaria um redirect imediato para um site real (YouTube, grupo do
      WhatsApp) para a vítima nem ver a página e não desconfiar.
    - Serviria conteúdo diferente para robôs: se User-Agent é Googlebot,
      scanner de URL ou ASN de datacenter, mostra página inofensiva; se é
      humano em rede residencial, mostra a versão "armada". Isso se chama
      cloaking e derrota a análise automática de links.
    - Ofuscaria o JS (packer/base64/eval) para atrapalhar leitura.
    - Passaria por 2-3 domínios diferentes (cadeia de redirects) para
      quebrar o rastro no Referer.
    - Coletaria TAMBÉM: canvas/WebGL/áudio fingerprint, fontes instaladas,
      extensões, bateria, aceleração de GPU — que sobrevivem à troca de IP.
    - Mediria tempo de permanência com visibilitychange + beacon, para
      saber se a pessoa realmente olhou a tela.
    - Exfiltraria via webhook de Discord/Telegram em vez de log local,
      para não precisar de servidor próprio.
  -->

  <p class="aviso">
    <strong>Transparência:</strong> esta página registra seu IP, seu navegador
    e alguns dados do dispositivo para a demonstração da aula.
    Um site malicioso faria o mesmo <em>sem</em> lhe avisar.
  </p>

  <p>Responda mentalmente enquanto a página carrega:</p>
  <ul>
    <li>Seu IP aparece em algum lugar do seu corpo?</li>
    <li>O Wi-Fi da universidade te identifica pelo nome?</li>
    <li>Se você ligar a VPN agora, o servidor vê o quê?</li>
    <li>O que o administrador da rede da universidade já sabe sobre você?</li>
  </ul>

  <p>Abra o painel da aula para ver o que chegou: <code>/painel</code></p>

  <p class="rodape">
    Demonstração acadêmica. Nenhum dado sai desta máquina.
  </p>

<!-- A coleta vive em /beacon.js, arquivo separado, igual a um analytics. -->
<script src="/beacon.js" defer></script>
</body>
</html>
"""

PAGINA_PAINEL = """<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Painel da aula — capturas</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
         margin: 2rem; line-height: 1.45; font-size: .88rem; }
  h1 { font-family: system-ui, sans-serif; font-size: 1.3rem; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  th, td { text-align: left; padding: .4rem .55rem; border-bottom: 1px solid #8883;
           vertical-align: top; }
  th { font-family: system-ui, sans-serif; font-size: .78rem;
       text-transform: uppercase; letter-spacing: .04em; color: #6b7280; }
  td.ip { white-space: nowrap; font-weight: 600; }
  .suspeito { color: #d97706; font-weight: 600; }
  .cards { display: flex; gap: .75rem; flex-wrap: wrap; font-family: system-ui, sans-serif; }
  .card { border: 1px solid #8883; border-radius: .4rem; padding: .6rem .9rem; }
  .card b { display: block; font-size: 1.4rem; }
  .vazio { color: #6b7280; font-family: system-ui, sans-serif; }
  .nota { font-family: system-ui, sans-serif; color: #6b7280; font-size: .82rem;
          margin-top: 1.5rem; max-width: 55rem; }
</style>
</head>
<body>
  <h1>Painel da aula — o que o servidor viu</h1>
  <div class="cards" id="cards"></div>
  <table>
    <thead>
      <tr>
        <th>hora local</th><th>IP</th><th>tipo</th><th>UA</th>
        <th>fuso / idioma</th><th>tela</th><th>ref.</th>
      </tr>
    </thead>
    <tbody id="corpo"></tbody>
  </table>
  <p class="vazio" id="vazio">Nenhuma captura ainda. Peça para a turma abrir o link.</p>

  <p class="nota">
    <b>Leitura crítica em sala:</b> a coluna IP mostra o resultado de
    <code>X-Forwarded-For</code> quando esse cabeçalho existe — e ele é
    escrito pelo cliente, logo é falsificável. Compare com o IP real do
    terminal. Os dados de fuso/idioma/tela vêm do JavaScript e também são
    falsificáveis. Um "grabber" comercial vende esses dados como se fossem
    prova: não são.
  </p>

<script>
const esc = (s) => String(s ?? "-").replace(/[&<>"]/g, c => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]
));

async function atualizar() {
  // location.search carrega o ?t=TOKEN da própria página do painel.
  // Sem repassar o token, /api/capturas responde 401 e a tabela fica vazia.
  const r = await fetch("/api/capturas" + location.search);
  if (!r.ok) return;
  const { capturas, resumo } = await r.json();

  document.getElementById("cards").innerHTML = `
    <div class="card">capturas<b>${resumo.total}</b></div>
    <div class="card">IPs únicos<b>${resumo.ips_unicos}</b></div>
    <div class="card">IPs via XFF (falsificável)<b>${resumo.via_xff}</b></div>
  `;

  const corpo = document.getElementById("corpo");
  corpo.innerHTML = capturas.map(c => {
    const nav = c.navegador || {};
    const ipCell = c.ip_confiavel
      ? esc(c.ip)
      : `<span class="suspeito" title="veio de X-Forwarded-For">${esc(c.ip)} ⚠</span>`;
    return `<tr>
      <td>${esc(c.quando_local?.replace("T", " ").slice(0, 19))}</td>
      <td class="ip">${ipCell}</td>
      <td>${esc(c.tipo)}</td>
      <td>${esc((c.cabecalhos?.["User-Agent"] || "-").slice(0, 70))}</td>
      <td>${esc(nav.fuso)} / ${esc(nav.idioma)}</td>
      <td>${esc(nav.tela)}</td>
      <td>${esc((c.cabecalhos?.Referer || "-").slice(0, 40))}</td>
    </tr>`;
  }).join("");

  document.getElementById("vazio").style.display = capturas.length ? "none" : "block";
}

atualizar();
setInterval(atualizar, 2000);   // polling simples, sem websocket, de propósito
</script>
</body>
</html>
"""

PAGINA_403 = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<title>401</title></head><body style="font-family:system-ui;margin:3rem">
<h1>401 — token inválido</h1>
<p>Use a URL completa que apareceu no terminal, algo como
<code>/painel?t=SEU_TOKEN</code>.</p>
<p>Isto existe para o painel não ficar aberto para a rede inteira da
universidade durante a aula. Um "grabber" real deixa o painel aberto e
vaza a base inteira depois.</p>
</body></html>
"""


# ---------------------------------------------------------------------------
# 4. Handler HTTP
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "AulaSeguranca/1.0"

    # Silencia o log padrão (que já imprime IP e caminho) e usa o nosso.
    def log_message(self, formato, *args):
        pass

    # -- utilidades ---------------------------------------------------------
    def _responder(self, corpo, status=200, tipo="text/html; charset=utf-8"):
        dados = corpo.encode("utf-8") if isinstance(corpo, str) else corpo
        self.send_response(status)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(dados)))
        # Sem cache: o atacante real também quer que cada refresh conte.
        self.send_header("Cache-Control", "no-store")
        # Cabeçalhos de privacidade que o atacante real NÃO manda:
        # >>> ele manda zero deles, e é assim que o Referer viaja completo. <<<
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(dados)

    def _json(self, obj, status=200):
        self._responder(json.dumps(obj, ensure_ascii=False), status,
                        "application/json; charset=utf-8")

    # -- rotas --------------------------------------------------------------
    def do_GET(self):
        rota = urlparse(self.path).path

        if rota in ("/", "/index.html"):
            # A ISCA: máscara de contatos da empresa fictícia (mascara.html).
            self._capturar("pagina")
            self._responder(self._mascara())

        elif rota in ("/quiz", "/quiz.html"):
            # Página alternativa, mais "honesta", para comparar as duas.
            self._capturar("quiz")
            self._responder(PAGINA_ISCA)

        elif rota == "/beacon.js":
            # Não é captura: é o script que a isca carrega.
            # Igual a um analytics: pedido separado, com cache longo.
            self._responder(self._ler_beacon_js(), 200,
                            "application/javascript; charset=utf-8")

        elif rota == "/painel":
            if not self._autorizado():
                self._responder(PAGINA_403, 401)
                return
            self._responder(PAGINA_PAINEL)

        elif rota == "/api/capturas":
            # O painel em si não é captura: não registramos o professor.
            if not self._autorizado():
                self._json({"erro": "token inválido"}, 401)
                return
            self._json(self._ler_capturas())

        elif rota == "/r":
            # Rota "isca clássica": captura e joga o visitante num site real.
            # >>> Um atacante real faz exatamente isso, e o alvo nunca vê
            #     que passou por um servidor de coleta. <<<
            self._capturar("redirect")
            destino = CONFIG["destino"] or "https://example.com"
            self.send_response(302)
            self.send_header("Location", destino)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        elif rota == "/health":
            self._json({"ok": True})

        else:
            self._capturar("404")
            self._responder("<h1>404</h1>", 404)

    def do_POST(self):
        rota = urlparse(self.path).path
        if rota != "/api/beacon":
            self._responder("<h1>404</h1>", 404)
            return

        # Não grava ainda: o beacon chega com dados do navegador no corpo,
        # então montamos o registro primeiro e gravamos uma única vez.
        registro = montar_registro(self, "beacon")
        tamanho = int(self.headers.get("Content-Length") or 0)
        corpo = self.rfile.read(tamanho) if 0 < tamanho <= 20_000 else b""
        try:
            payload = json.loads(corpo or b"{}")
            if isinstance(payload, dict):
                # Só aceita chaves conhecidas: um atacante real aceitaria tudo
                # e depois usaria isso como vetor de injeção no painel.
                permitidas = {
                    "idioma", "idiomas", "fuso", "deslocamento_min", "tela",
                    "janela", "densidade", "nucleos", "memoria_gb", "toque",
                    "plataforma", "conexao", "ua_completo", "referencia",
                    "segundos_na_pagina",
                }
                registro["navegador"] = {
                    k: (v[:200] if isinstance(v, str) else v)
                    for k, v in payload.items() if k in permitidas
                }
        except (ValueError, UnicodeDecodeError):
            pass

        gravar(registro)
        imprimir(registro)
        self._json({"ok": True})

    # -- apoio --------------------------------------------------------------
    def _autorizado(self):
        token = CONFIG["token"]
        if not token:
            return True
        from urllib.parse import parse_qs
        q = parse_qs(urlparse(self.path).query)
        enviado = (q.get("t", [""])[0] or
                   self.headers.get("X-Token", ""))
        return secrets.compare_digest(enviado, token)

    def _capturar(self, tipo):
        registro = montar_registro(self, tipo)
        gravar(registro)
        imprimir(registro)
        return registro

    def _mascara(self):
        """
        Lê mascara.html do disco a cada request.

        Isso é de propósito: o professor edita o nome da empresa, salva e a
        turma só dá F5 — sem reiniciar o servidor. Custa nada (arquivo pequeno).
        """
        try:
            html = CONFIG["mascara"].read_text(encoding="utf-8")
        except OSError:
            return PAGINA_ISCA     # sem máscara? cai na página de quiz

        if not CONFIG["divulgar"]:
            # Remove o selinho "demonstração de aula" da máscara.
            # >>> É o único elemento da página que denuncia o exercício.
            #     Um golpe real nunca teria esse selo — e é justamente essa
            #     ausência que faz a vítima confiar. <<<
            html = _SELO_AULA.sub("", html)
        return html

    def _ler_beacon_js(self):
        try:
            return (BASE_DIR / "beacon.js").read_text(encoding="utf-8")
        except OSError:
            # Sem o arquivo, a captura de headers ainda funciona; só os dados
            # de navegador deixam de chegar. Avisa no console do visitante
            # (num ataque real: falha silenciosa).
            return ("console.warn('beacon.js nao encontrado ao lado do "
                    "grabber_sala.py');")

    def _ler_capturas(self, limite=200):
        log = CONFIG["log"]
        if not log.exists():
            return {"capturas": [], "resumo": {"total": 0, "ips_unicos": 0, "via_xff": 0}}
        linhas = log.read_text(encoding="utf-8").splitlines()
        registros = []
        for linha in reversed(linhas):           # mais recente primeiro
            try:
                registros.append(json.loads(linha))
            except ValueError:
                continue
            if len(registros) >= limite:
                break
        todos = set()
        xff = 0
        for linha in linhas:
            try:
                r = json.loads(linha)
            except ValueError:
                continue
            todos.add(r.get("ip"))
            if not r.get("ip_confiavel", True):
                xff += 1
        return {
            "capturas": registros,
            "resumo": {"total": len(linhas), "ips_unicos": len(todos), "via_xff": xff},
        }


# ---------------------------------------------------------------------------
# 5. main
# ---------------------------------------------------------------------------
def ip_da_maquina():
    """
    Descobre o IP da própria máquina na LAN, para montar a URL que a turma
    vai digitar. Truque: não envia pacote nenhum, só faz o kernel escolher
    a rota de saída (UDP connect em socket não geram tráfego).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def main():
    env = os.environ.get

    def env_bool(nome, padrao):
        """Lê variável de ambiente como booleano (1/sim/true)."""
        valor = env(nome)
        if valor is None:
            return padrao
        return valor.strip().lower() in ("1", "sim", "true", "yes", "on")

    p = argparse.ArgumentParser(description="IP grabber didático (aula).")
    p.add_argument("--porta", type=int, default=int(env("PORTA", "8000")))
    p.add_argument("--host", default=env("HOST", "0.0.0.0"),
                   help="0.0.0.0 = visível na rede local; 127.0.0.1 = só local")
    p.add_argument("--destino", default=env("DESTINO") or None,
                   help="URL para a rota /r redirecionar depois de capturar")
    p.add_argument("--sem-senha", action="store_true",
                   default=env_bool("SEM_SENHA", False),
                   help="não protege o /painel com token")
    p.add_argument("--mascara", default=env("MASCARA") or None,
                   help="HTML da fachada servida em / (padrão: mascara.html)")
    p.add_argument("--sem-divulgar", action="store_true",
                   default=not env_bool("DIVULGAR", True),
                   help="remove o selo 'demonstração de aula' da fachada")
    p.add_argument("--log", default=env("ARQ_LOG") or None,
                   help="caminho do arquivo de log (padrão: ./capturas.jsonl)")
    args = p.parse_args()

    # Mostra as capturas no terminal na hora, mesmo com a saída redirecionada
    # para arquivo (ex.: `python3 grabber_sala.py | tee aula.log`).
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)

    CONFIG["destino"] = args.destino
    CONFIG["divulgar"] = not args.sem_divulgar

    # Token fixo vem do ambiente (obrigatório no Docker: se fosse aleatório a
    # cada boot, o container reiniciaria e o link do painel mudaria sozinho).
    token_env = env("TOKEN_PAINEL", "").strip()
    CONFIG["token"] = None if args.sem_senha else (token_env or secrets.token_urlsafe(6))

    if args.mascara:
        CONFIG["mascara"] = Path(args.mascara).expanduser().resolve()

    if args.log:
        CONFIG["log"] = Path(args.log).expanduser().resolve()
        # No Docker o volume pode montar uma pasta ainda sem permissão de
        # escrita; falhar cedo com mensagem clara é melhor que estourar no
        # primeiro visitante.
        CONFIG["log"].parent.mkdir(parents=True, exist_ok=True)

    # No Dokploy quem fala com o público é o domínio, não o IP do container.
    base = env("URL_PUBLICA", "").strip().rstrip("/") or f"http://{ip_da_maquina()}:{args.porta}"
    token_q = f"?t={CONFIG['token']}" if CONFIG["token"] else ""

    print("=" * 66)
    print("  GRABBER DIDÁTICO — Segurança da Computação")
    print("=" * 66)
    print(f"  Isca para a turma  :  {base}/        <- mascara.html")
    print(f"  Quiz alternativo   :  {base}/quiz")
    print(f"  Isca com redirect  :  {base}/r" + ("  (destino: " + args.destino + ")" if args.destino else ""))
    print(f"  Painel do professor:  {base}/painel{token_q}")
    print(f"  Fachada em uso     :  {CONFIG['mascara']}")
    print(f"  Selo de aula       :  {'visível' if CONFIG['divulgar'] else 'REMOVIDO (--sem-divulgar)'}")
    print(f"  Log                :  {CONFIG['log']}")
    print("-" * 66)
    print("  Os dados NÃO saem da sua rede. Apague no fim da aula:")
    print(f"      rm {CONFIG['log']}")
    print("  Ctrl+C para parar.")
    print("=" * 66)

    servidor = ThreadingHTTPServer((args.host, args.porta), Handler)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")
    finally:
        servidor.server_close()


if __name__ == "__main__":
    main()
