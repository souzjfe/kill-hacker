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
from html import escape as escapar_html
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
    "divulgar": False,                # mantém o selo "demonstração de aula"
    "log": ARQ_LOG_PADRAO,           # onde as capturas são gravadas
    "info": None,                    # textos da fachada (env > padrão)
}

# Remove o selinho de transparência quando se roda com --sem-divulgar.
_SELO_AULA = re.compile(r'<span class="selo-aula".*?</span>', re.S)

# Evita repetir o aviso de placeholder sem valor a cada request.
_avisou_placeholder = False

# ---------------------------------------------------------------------------
# Textos da fachada (mascara.html). Tudo pode ser trocado por variável de
# ambiente, para o professor não precisar editar arquivo — no Dokploy é só
# preencher no Environment do compose.
#
# Os números abaixo são INEXISTENTES de propósito: fixo brasileiro começa com
# 2, 3, 4 ou 5, então 0000-xxxx não existe. (O CNPJ também tem dígito
# verificador inválido.) É a pista falsa nº 1 da aula: ninguém confere.
# ---------------------------------------------------------------------------
INFO_PADRAO = {
    "EMPRESA_NOME": "PsiWare",
    "EMPRESA_RAMO": "Software de segurança e monitoramento",
    "EMPRESA_BIO": "Canais oficiais de atendimento da matriz.",
    "EMPRESA_CNPJ": "58.761.840/0001-00",
    "EMPRESA_ENDERECO": "Av. Antonio Sílvio Barbierri, 2346 Francisco Beltrão - PR, 85503-000",
    "EMPRESA_HORARIO": "Segunda a sexta, das 8h às 17h",
    "CONTATO1_NOME": "Kelly Moreira",
    "CONTATO1_CARGO": "Secretaria",
    "CONTATO1_NUMERO": "(11) 0000-0000",
    "CONTATO2_NOME": "Recursos Humanos",
    "CONTATO2_CARGO": "RH",
    "CONTATO2_NUMERO": "(11) 0000-0001",
    "CONTATO3_NOME": "Contábil",
    "CONTATO3_CARGO": "Financeiro",
    "CONTATO3_NUMERO": "(11) 0000-0002",
}


def so_digitos(texto):
    return re.sub(r"\D", "", texto or "")


def tel_href(numero, ddi="55"):
    """
    Converte "(11) 0000-0000" no href "tel:+551100000000".

    Se o professor digitar o número já com DDI, não duplica. Número vazio
    vira href vazio (o link não disca nada) em vez de "tel:" quebrado.
    """
    digitos = so_digitos(numero)
    if not digitos:
        return ""
    if len(digitos) > 11 or digitos.startswith(ddi):
        return "+" + digitos
    return f"+{ddi}{digitos}"


def montar_info():
    """
    Monta o dicionário de substituição da fachada: env > padrão.

    O valor é escapado depois, na hora de injetar no HTML — sem isso, uma
    variável de ambiente com "<script>" viraria execução de código na página.
    (Sim: isso já aconteceu em produto de verdade.)
    """
    info = {chave: os.environ.get(chave, padrao) for chave, padrao in INFO_PADRAO.items()}
    info["EMPRESA_INICIAL"] = (info["EMPRESA_NOME"].strip()[:1] or "A").upper()
    for i in (1, 2, 3):
        info[f"CONTATO{i}_TEL"] = tel_href(info[f"CONTATO{i}_NUMERO"])
    return info


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


def ler_cookie(handler, nome):
    """Lê um cookie do cabeçalho Cookie (formato: 'a=1; b=2')."""
    bruto = handler.headers.get("Cookie", "")
    for pedaco in bruto.split(";"):
        chave, _, valor = pedaco.strip().partition("=")
        if chave == nome:
            return valor.strip()
    return ""


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
        # Identificador de sessão (cookie first-party, 2 h). Não é "login":
        # é o mínimo para juntar o GET / com o POST do beacon e não misturar
        # dois alunos que compartilham o mesmo IP (NAT) e o mesmo aparelho.
        # >>> É exatamente o que Google Analytics/Facebook Pixel fazem com
        #     _ga/_fbp — e o que o modo anônimo ainda guarda durante a aba. <<<
        "sessao": getattr(handler, "_sid", None),
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
# 2b. Agregação para a página de aula (/aula)
# ---------------------------------------------------------------------------
def mascarar_ip(ip):
    """
    Esconde a última parte do IP para a tela pública da sala.

    O objetivo da aula é o aluno se reconhecer (fuso, tela, horário), não
    expor o IP de colega no telão — e, se a aplicação estiver publicada, não
    expor IP de ninguém para quem abrir a página. IP completo só no /painel.

    >>> Um atacante real faz o contrário: junta o IP completo com nome,
    matrícula e foto, e publica. É assim que "doxxing" começa. <<<
    """
    if not ip:
        return "-"
    if ":" in ip:                      # IPv6
        partes = ip.split(":")
        return ":".join(partes[:4]) + ":••••"
    partes = ip.split(".")
    if len(partes) == 4:               # IPv4
        return ".".join(partes[:3] + ["•••"])
    return ip


def dispositivo(user_agent):
    """Rótulo curto de dispositivo a partir do User-Agent (para a tabela)."""
    ua = (user_agent or "").lower()
    if not ua:
        return "—"
    if "iphone" in ua:
        return "iPhone"
    if "ipad" in ua:
        return "iPad"
    if "android" in ua:
        return "Android"
    if "windows" in ua:
        return "Windows"
    if "macintosh" in ua or "mac os" in ua:
        return "Mac"
    if "linux" in ua:
        return "Linux"
    if any(x in ua for x in ("curl", "wget", "python", "go-http", "bot", "spider")):
        return "script/bot"
    return "outro"


def agrupar_visitas(registros):
    """
    Junta os vários registros de um mesmo visitante em UMA linha.

    Cada visita gera 2–3 registros (GET /, POST do beacon, beacon de saída).
    Na tabela da aula isso vira uma linha só: primeira e última vez, se
    clicou de fato ou só carregou preview, e tempo de permanência.

    >>> Um atacante real agrupa por muito mais que IP + UA: cookie, id de
    sessão, fingerprint de canvas, horário. Aqui é o mínimo para a tabela
    não ficar repetida. <<<
    """
    visitas = {}
    for r in registros:
        cab = r.get("cabecalhos") or {}
        ua = cab.get("User-Agent") or ""
        # IP + UA + sessão: sem a sessão, 30 alunos no Wi-Fi da faculdade
        # (mesmo IP público) com o mesmo iPhone virariam 1 linha só.
        chave = (r.get("ip") or "-", ua, r.get("sessao") or "")
        quando = r.get("quando_local") or ""

        v = visitas.get(chave)
        if v is None:
            v = visitas[chave] = {
                "ip": r.get("ip") or "-",
                "dispositivo": dispositivo(ua),
                "primeiro": quando,
                "ultimo": quando,
                "clicou": False,
                "segundos": None,
                "navegador": None,
                "ip_confiavel": bool(r.get("ip_confiavel", True)),
            }
        v["primeiro"] = min(v["primeiro"], quando) if v["primeiro"] else quando
        v["ultimo"] = max(v["ultimo"], quando) if v["ultimo"] else quando

        if r.get("tipo") in ("beacon", "redirect"):
            v["clicou"] = True
        nav = r.get("navegador") or {}
        if nav:
            v["navegador"] = nav
            seg = nav.get("segundos_na_pagina")
            if isinstance(seg, (int, float)):
                v["segundos"] = max(v["segundos"] or 0, seg)

    # Mais recente primeiro.
    return sorted(visitas.values(), key=lambda x: x["ultimo"], reverse=True)


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

PAGINA_AULA = """<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ao vivo — o que o servidor viu</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 28px 22px 48px;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #f5f7fa; color: #111827;
    font-size: 17px;
  }
  .topo {
    display: flex; align-items: baseline; gap: 14px;
    flex-wrap: wrap; margin-bottom: 4px;
  }
  a.baixar {
    margin-left: auto; background: #111827; color: #fff;
    text-decoration: none; font-size: .85rem; font-weight: 650;
    padding: 8px 14px; border-radius: 999px;
  }
  a.baixar[hidden] { display: none; }
  h1 { font-size: 1.65rem; margin: 0; letter-spacing: -.02em; }
  .ao-vivo {
    display: inline-flex; align-items: center; gap: 7px;
    font-size: .78rem; font-weight: 700; letter-spacing: .08em;
    text-transform: uppercase; color: #b91c1c;
  }
  .ponto {
    width: 9px; height: 9px; border-radius: 50%; background: #dc2626;
    animation: pulso 1.4s ease-in-out infinite;
  }
  @keyframes pulso { 0%,100% { opacity: 1; } 50% { opacity: .25; } }
  .sub { color: #6b7280; font-size: .95rem; margin: 2px 0 22px; }

  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
           gap: 14px; margin-bottom: 22px; }
  .card {
    background: #fff; border: 1px solid #e5e7eb; border-radius: 14px;
    padding: 16px 18px; box-shadow: 0 1px 2px rgba(16,24,40,.04);
  }
  .card .rotulo { font-size: .76rem; text-transform: uppercase; letter-spacing: .06em;
                  color: #6b7280; font-weight: 600; }
  .card .valor { font-size: 2.15rem; font-weight: 700; line-height: 1.15; margin-top: 4px;
                 font-variant-numeric: tabular-nums; }
  .card .detalhe { font-size: .8rem; color: #6b7280; margin-top: 2px; }

  .tabela-wrap {
    background: #fff; border: 1px solid #e5e7eb; border-radius: 14px;
    overflow: hidden; box-shadow: 0 1px 2px rgba(16,24,40,.04);
  }
  table { width: 100%; border-collapse: collapse; }
  thead th {
    position: sticky; top: 0; background: #eef2f7;
    font-size: .74rem; text-transform: uppercase; letter-spacing: .06em;
    color: #4b5563; text-align: left; padding: 12px 16px; white-space: nowrap;
  }
  tbody td { padding: 14px 16px; border-top: 1px solid #f0f2f5; vertical-align: middle; }
  tbody tr:nth-child(even) { background: #fbfcfe; }
  td.num { color: #9ca3af; font-variant-numeric: tabular-nums; width: 46px; }
  td.ip { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          font-weight: 600; white-space: nowrap; }
  td.hora { font-variant-numeric: tabular-nums; white-space: nowrap; color: #374151; }
  .pilula {
    display: inline-block; padding: 3px 10px; border-radius: 999px;
    font-size: .76rem; font-weight: 600; white-space: nowrap;
  }
  .clicou { background: #dcfce7; color: #166534; }
  .preview { background: #fef3c7; color: #92400e; }
  .fraco { color: #6b7280; }
  .vazio { padding: 56px 20px; text-align: center; color: #6b7280; }
  .vazio strong { display: block; font-size: 1.1rem; color: #374151; margin-bottom: 6px; }

  .nota { margin-top: 18px; color: #6b7280; font-size: .85rem; max-width: 70ch; }
  .nota code { background: #e8edf5; padding: 1px 6px; border-radius: 4px; }

  @media (max-width: 720px) {
    body { padding: 18px 12px 32px; font-size: 15px; }
    th:nth-child(5), td:nth-child(5),
    th:nth-child(6), td:nth-child(6) { display: none; }
  }
</style>
</head>
<body>

<div class="topo">
  <h1>O que o servidor viu</h1>
  <span class="ao-vivo"><span class="ponto"></span> ao vivo</span>
  <a class="baixar" id="baixar" hidden>Baixar tudo</a>
</div>
<p class="sub">
  Atualiza sozinho a cada 2 segundos. Uma linha por visita.
</p>

<div class="cards" id="cards"></div>

<div class="tabela-wrap">
  <table>
    <thead>
      <tr>
        <th>#</th><th>Hora</th><th>IP</th><th>Dispositivo</th>
        <th>Fuso</th><th>Tela</th><th>Tempo</th><th>Como chegou</th>
      </tr>
    </thead>
    <tbody id="corpo"></tbody>
  </table>
  <div class="vazio" id="vazio">
    <strong>Aguardando a primeira visita…</strong>
    Peça para a turma abrir o link da secretaria.
  </div>
</div>

<p class="nota" id="nota"></p>

<script>
const esc = (s) => String(s ?? "—").replace(/[&<>"]/g, c => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]
));

function segundos(v) {
  if (v === null || v === undefined) return "—";
  if (v < 60) return v + "s";
  return Math.floor(v / 60) + "min " + (v % 60) + "s";
}

async function atualizar() {
  // location.search leva o ?t=TOKEN quando o professor abre com token.
  const r = await fetch("/api/aula" + location.search);
  if (!r.ok) return;
  const { visitas, resumo } = await r.json();

  document.getElementById("cards").innerHTML = `
    <div class="card"><div class="rotulo">Visitas</div>
      <div class="valor">${resumo.visitas}</div></div>
    <div class="card"><div class="rotulo">Clicaram no link</div>
      <div class="valor">${resumo.clicaram}</div>
      <div class="detalhe">${resumo.so_preview} só por preview</div></div>
    <div class="card"><div class="rotulo">Dispositivos</div>
      <div class="valor">${resumo.dispositivos.length}</div>
      <div class="detalhe">${resumo.dispositivos.map(d => d.nome + " " + d.qtd).join(" · ") || "—"}</div></div>
    <div class="card"><div class="rotulo">Tempo médio na página</div>
      <div class="valor">${segundos(resumo.media_segundos)}</div></div>
  `;

  const corpo = document.getElementById("corpo");
  corpo.innerHTML = visitas.map((v, i) => {
    const nav = v.navegador || {};
    const origem = v.clicou
      ? '<span class="pilula clicou">clique</span>'
      : '<span class="pilula preview">preview</span>';
    return `<tr>
      <td class="num">${i + 1}</td>
      <td class="hora">${esc((v.ultimo || "").slice(11, 19))}</td>
      <td class="ip">${esc(v.ip)}</td>
      <td>${esc(v.dispositivo)}</td>
      <td class="fraco">${esc(nav.fuso)}</td>
      <td class="fraco">${esc(nav.tela)}</td>
      <td class="fraco">${segundos(v.segundos)}</td>
      <td>${origem}</td>
    </tr>`;
  }).join("");

  document.getElementById("vazio").style.display = visitas.length ? "none" : "block";

  const baixar = document.getElementById("baixar");
  baixar.hidden = !resumo.revelado;
  if (resumo.revelado) baixar.href = "/api/export" + location.search;

  const nota = document.getElementById("nota");
  nota.innerHTML = resumo.revelado
    ? "IPs completos. <b>Baixar tudo</b> entrega o log inteiro: sessão, "
      + "cabeçalhos e o que o navegador enviou — não só as colunas desta tela."
    : "IPs mascarados (o último bloco fica oculto). Para revelar e baixar "
      + "o log inteiro, abra esta página com <code>?t=SEU_TOKEN</code>.";
}

atualizar();
setInterval(atualizar, 2000);
</script>
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
        if getattr(self, "_cookie_novo", False):
            # Cookie de sessão: 2 h, sem HttpOnly (o JS da isca pode ler —
            # um analytics real também lê o próprio _ga).
            self.send_header(
                "Set-Cookie",
                f"sid={self._sid}; Path=/; SameSite=Lax; Max-Age=7200",
            )
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

        elif rota in ("/aula", "/telao"):
            # Tela para projetar na sala. Abre sem token, mas com IP mascarado.
            # >>> Aqui não registramos visita: se registrasse, o professor
            #     apareceria na própria tabela e a turma se perdia. <<<
            self._responder(PAGINA_AULA)

        elif rota == "/api/aula":
            self._json(self._dados_aula())

        elif rota == "/api/export":
            # Log inteiro, só com o token. A tela pública fica no resumo.
            if not self._autorizado():
                self._json({"erro": "token inválido"}, 401)
                return
            self._baixar_tudo()

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
        self._garantir_sessao()
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
                    "online", "cookieEnabled", "plataforma", "conexao", "ua_completo",
                    "referencia", "segundos_na_pagina", "storage",
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

    def _garantir_sessao(self):
        """
        Dá a cada visitante um id de sessão (cookie), para a tabela da aula
        ter UMA linha por pessoa mesmo quando todos saem pelo mesmo IP (NAT
        da universidade) e usam o mesmo modelo de celular.

        >>> Um atacante real não para no cookie: casa sessão com fingerprint
        (canvas, fontes, WebGL), e-mail e conta social. Aqui é só a sessão. <<<
        """
        if getattr(self, "_sid", None):
            return self._sid

        atual = ler_cookie(self, "sid")
        if atual and len(atual) <= 64:
            self._sid = atual
        else:
            self._sid = secrets.token_hex(8)
            self._cookie_novo = True
        return self._sid

    def _capturar(self, tipo):
        self._garantir_sessao()
        registro = montar_registro(self, tipo)
        gravar(registro)
        imprimir(registro)
        return registro

    def _mascara(self):
        """
        Lê mascara.html do disco a cada request e troca os {{PLACEHOLDERS}}
        pelos valores de ambiente (empresa, contatos, endereço).

        Ler do disco a cada visita custa nada (arquivo pequeno) e permite
        editar o HTML e só dar F5, sem reiniciar o servidor.
        """
        try:
            pagina = CONFIG["mascara"].read_text(encoding="utf-8")
        except OSError:
            return PAGINA_ISCA     # sem máscara? cai na página de quiz

        info = CONFIG.get("info") or montar_info()
        for chave, valor in info.items():
            pagina = pagina.replace("{{" + chave + "}}",
                                    escapar_html(str(valor), quote=True))

        # Placeholder que sobrou = nome de variável errado. Avisa uma vez no
        # terminal em vez de servir "{{CONTATO4_NOME}}" na cara da turma.
        global _avisou_placeholder
        if "{{" in pagina and not _avisou_placeholder:
            _avisou_placeholder = True
            sobrou = re.findall(r"\{\{[A-Z0-9_]+\}\}", pagina)[:5]
            print(f"  [aviso] placeholders sem valor: {', '.join(sobrou)}")

        if not CONFIG["divulgar"]:
            # Remove o selinho "demonstração de aula" da máscara.
            # >>> É o único elemento da página que denuncia o exercício.
            #     Um golpe real nunca teria esse selo — e é justamente essa
            #     ausência que faz a vítima confiar. <<<
            pagina = _SELO_AULA.sub("", pagina)
        return pagina

    def _ler_beacon_js(self):
        try:
            return (BASE_DIR / "beacon.js").read_text(encoding="utf-8")
        except OSError:
            # Sem o arquivo, a captura de headers ainda funciona; só os dados
            # de navegador deixam de chegar. Avisa no console do visitante
            # (num ataque real: falha silenciosa).
            return ("console.warn('beacon.js nao encontrado ao lado do "
                    "grabber_sala.py');")

    def _dados_aula(self):
        """
        Dados da tela /aula: uma linha por visitante (não por registro).

        Quem abre com o token do professor vê o IP completo; quem abre só a
        /aula vê o IP mascarado. A decisão é do servidor: a página recebe o
        dado já mascarado, não "esconde no CSS" — esconder no cliente não
        esconde nada de quem abre o DevTools.

        >>> Dá para mascarar só na tela, mas o atacante real não mascara nada:
        ele publica o IP completo com print do perfil. <<<
        """
        registros = self._ler_capturas(limite=5000)["capturas"]
        visitas = agrupar_visitas(registros)

        revelar = self._autorizado()
        if not revelar:
            for v in visitas:
                v["ip"] = mascarar_ip(v["ip"])

        clicaram = sum(1 for v in visitas if v["clicou"])
        tempos = [v["segundos"] for v in visitas
                  if isinstance(v["segundos"], (int, float))]

        contagem = {}
        for v in visitas:
            contagem[v["dispositivo"]] = contagem.get(v["dispositivo"], 0) + 1
        dispositivos = [{"nome": nome, "qtd": qtd}
                        for nome, qtd in sorted(contagem.items(),
                                                key=lambda x: -x[1])]

        return {
            "visitas": visitas,
            "resumo": {
                "visitas": len(visitas),
                "clicaram": clicaram,
                "so_preview": len(visitas) - clicaram,
                "media_segundos": round(sum(tempos) / len(tempos)) if tempos else None,
                "dispositivos": dispositivos,
                "revelado": revelar,
            },
        }

    def _baixar_tudo(self):
        """
        Arquivo com cada linha do log, sem o limite da tela.

        A /aula agrega e esconde sessão, cabeçalhos e o resto do beacon.
        Quem tem o token leva o registro completo, na ordem em que chegou.
        """
        log = CONFIG["log"]
        capturas = []
        if log.exists():
            for linha in log.read_text(encoding="utf-8").splitlines():
                linha = linha.strip()
                if not linha:
                    continue
                try:
                    capturas.append(json.loads(linha))
                except ValueError:
                    continue
        corpo = json.dumps(
            {"total": len(capturas), "capturas": capturas},
            ensure_ascii=False,
            indent=2,
        )
        dados = corpo.encode("utf-8")
        nome = "capturas-" + datetime.now().astimezone().strftime("%Y-%m-%d") + ".json"
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(dados)))
        self.send_header("Content-Disposition", f'attachment; filename="{nome}"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(dados)

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
    CONFIG["info"] = montar_info()

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
    print(f"  Empresa (fachada)  :  {CONFIG['info']['EMPRESA_NOME']}  |  "
          f"{CONFIG['info']['CONTATO1_NOME']} / {CONFIG['info']['CONTATO2_NOME']} / "
          f"{CONFIG['info']['CONTATO3_NOME']}")
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
