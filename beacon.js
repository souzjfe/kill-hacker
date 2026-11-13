/* ============================================================================
   beacon.js — o "cavalo de troia" da demonstração
   ============================================================================
   Servido em /beacon.js e incluído pela máscara (mascara.html) e pela página
   de quiz. O nome e o formato imitam um script de analytics qualquer — porque,
   tecnicamente, é isso que ele é.

   Todo dado aqui é obtido com APIs públicas do navegador, SEM pedir permissão
   ao usuário. É a primeira constatação da aula: "aceitar cookies" não protege
   nada, porque a coleta acontece antes e independente do consentimento.

   >>> O QUE UM ATACANTE REAL ACRESCENTARIA NESTE ARQUIVO <<<
   (nada disso está implementado abaixo, de propósito)

   1. WebRTC / STUN
      new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]})
      Descobre o IP LOCAL (192.168.x.x / 10.x.x.x) e, em muitos casos, o IP
      PÚBLICO REAL mesmo com VPN ligada. É o vazamento clássico de "VPN não me
      protege". Também revela topologia interna e faixa da rede da empresa.

   2. Fingerprint estável (o que substitui o IP quando o alvo usa VPN)
      - canvas: desenha texto/gradiente e faz hash do resultado (difere por
        GPU, driver, fontes e antialiasing).
      - WebGL: gl.getParameter(gl.RENDERER) entrega o modelo da placa.
      - Áudio: OfflineAudioContext gera um sinal e compara a saída.
      - Fontes instaladas: mede largura de spans com fontes candidatas.
      - navigator.plugins, screen.colorDepth, devicePixelRatio, hardwareConcurrency.
      Combinado dá ~1 em milhões de identificação, e SOBREVIVE a trocar de IP,
      limpar cookie, usar anônimo. É o que permite "seguir a mesma pessoa"
      através de várias sessões.

   3. ID persistente
      localStorage / IndexedDB / cache / ETag / favicon cache. O clássico
      "evercookie": se apagar o cookie, ele se recria a partir do storage.

   4. Tempo e comportamento
      visibilitychange, mousemove, scroll, tempo de permanência, primeiro
      clique. Serve para separar "pessoa real" de "preview de link" e para
      saber se a isca foi realmente vista.

   5. Exfiltração resiliente
      navigator.sendBeacon -> fetch(keepalive) -> <img src="pixel.gif"> ->
      WebSocket. Sempre com fallback, para não perder o dado se a aba fechar
      em 200ms.

   6. Domínio de coleta disfarçado
      Enviar para /analytics, /cdn-cgi/rum, /_vercel/insights ou um host que
      imita o legítimo. Passa batido em revisão manual de código.

   7. Ofuscação
      String array + base64 + eval, nomes de variável de uma letra, código
      dividido em vários arquivos. Dificulta leitura, não impede análise.

   8. Cloaking
      Se o IP for de datacenter/VPN (MaxMind), ou o UA for de scanner
      (Googlebot, URLScan, VirusTotal), o script simplesmente NÃO roda —
      e quem for analisar o link vê uma página limpa.
   ============================================================================ */

(function () {
  "use strict";

  // --- 1. Coleta -----------------------------------------------------------
  function coletar() {
    const nav = navigator;
    return {
      idioma: nav.language,
      idiomas: nav.languages,
      fuso: Intl.DateTimeFormat().resolvedOptions().timeZone,
      deslocamento_min: new Date().getTimezoneOffset(),
      tela: screen.width + "x" + screen.height,
      janela: innerWidth + "x" + innerHeight,
      densidade: window.devicePixelRatio,
      nucleos: nav.hardwareConcurrency || null,
      memoria_gb: nav.deviceMemory || null,
      toque: nav.maxTouchPoints > 0,
      // navigator.userAgentData é a API nova; navigator.platform é a antiga.
      plataforma: (nav.userAgentData && nav.userAgentData.platform) || nav.platform,
      conexao: nav.connection && nav.connection.effectiveType,
      ua_completo: nav.userAgent,
      referencia: document.referrer || null,
    };
  }

  // --- 2. Envio ------------------------------------------------------------
  const dados = coletar();

  function enviar(extra) {
    const corpo = JSON.stringify(Object.assign({}, dados, extra || {}));
    // `keepalive` deixa o pedido terminar mesmo se a aba fechar agora.
    fetch("/api/beacon", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: corpo,
      keepalive: true,
    }).catch(function () {
      // Fallback silencioso. Um atacante real tentaria mais 3 caminhos aqui
      // (sendBeacon -> <img> -> WebSocket), justamente para não perder o dado.
    });
  }

  if (document.readyState === "complete") {
    enviar();
  } else {
    addEventListener("load", enviar, { once: true });
  }

  // --- 3. Tempo de permanência --------------------------------------------
  // Um "grabber" real usa isso para distinguir clique humano de preview de
  // link (WhatsApp/Discord/Slack carregam a página sem ninguém abrir).
  const inicio = Date.now();
  let enviado = false;

  addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden" && !enviado) {
      enviado = true;
      enviar({ segundos_na_pagina: Math.round((Date.now() - inicio) / 1000) });
    }
  });
})();
