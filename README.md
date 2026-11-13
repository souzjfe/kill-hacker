# kill-hacker — o que um site sabe sobre você

> **Experimento social de sala de aula.** Um "IP grabber" mínimo, escrito do
> zero, para mostrar a alunos de Segurança da Computação o quanto de
> informação sai do navegador deles ao abrir um link — **sem exploit, sem
> malware e sem página de login**. Roda na rede da universidade (ou num
> container), com a turma avisada de que é uma atividade de aula.

```
Python puro · zero dependências · zero requisições para a internet
```

---

## ⚠️ Uso responsável — leia antes de rodar

Este projeto coleta **IP e dados do navegador de quem visita a página**.
Isso é dado pessoal (LGPD, art. 5º, I) e, no Brasil, tratar dado pessoal sem
base legal é infração — não é "só um experimento".

Regras que o repositório assume como parte do experimento:

1. **Só rode com participantes informados** de que há uma atividade de coleta
   em andamento. O selo "demonstração de aula" na página existe para isso e
   vem **ligado por padrão**.
2. **Nunca compartilhe o link com quem não está na atividade.** Um link de
   coleta mandado para fora da turma é phishing, independentemente da intenção.
3. **Não publique IPs.** Divulgue apenas números agregados (ver seção
   *Resultados*), e nunca junto com nome, matrícula ou foto.
4. **Apague os dados no fim**: `docker compose down -v` ou `rm capturas.jsonl`.
5. **Não rode em rede de terceiros sem autorização por escrito.**

O que este projeto **não é**: não é kit de phishing. Não tem tela de login,
não captura senha, não instala nada, não explora falha, não ofusca código e
não exfiltra para servidor de terceiros. Ele registra exatamente o que
qualquer `python3 -m http.server` com log já registraria — a diferença é que
aqui isso é explicado linha por linha.

---

## O experimento social (descrição completa)

**Pergunta.** Quanto uma pessoa entrega de si ao clicar num link que parece
institucional — e o que ela *acha* que entregou?

**Hipótese.** A maioria dos participantes abre o link sem verificar domínio,
telefone ou CNPJ, e subestima o que o servidor registrou: acredita que "só
apareceu meu IP", quando o conjunto (IP + fuso + idioma + tela + horário)
descreve um dispositivo e uma rotina com bastante precisão.

**Desenho.** Antes da atividade, o professor avisa a turma que haverá uma
demonstração de coleta de dados naquela aula e que a participação é
voluntária (quem não quiser participar simplesmente não abre o link). O link
é apresentado como "o contato da secretaria" e **nada mais é explicado**. A
página é uma tela de contatos de uma empresa fictícia (Aurora Serviços), com
três contatos de fachada — **Kelly (secretaria)**, **RH** e **Contábil** —
todos com nome, cargo e telefone inventados (e números inválidos).

Depois de ~10 minutos, a tela `/aula` é aberta no telão e cada aluno se
reconhece nos próprios dados. Só então a coleta é explicada.

**O que é medido (agregado, em sala):**

| Métrica | Como sai do log |
|---|---|
| Quantos abriram o link | nº de IPs únicos em `capturas.jsonl` |
| Quantos abriram por preview de app (sem clique) | registros `tipo: pagina` sem `beacon` correspondente |
| Tempo até o primeiro clique | delta entre a hora do convite e o 1º registro |
| Quantos notaram o telefone falso | pergunta em voz alta, mão levantada |
| Quantos leram o selo de demonstração | pergunta em voz alta, mão levantada |
| Dispositivos e fusos horários | campos `navegador.tela`, `navegador.fuso` |
| Quantos usavam VPN/proxy | comparação entre IP do log e o IP mostrado no `meuip` |

**O que não é medido, por decisão de projeto:** nome, e-mail, matrícula,
localização por GPS, geolocalização por API, fingerprint de canvas/WebGL,
histórico de navegação, cookie persistente. Nada disso é coletado — em vez
disso, o código **comenta** como um atacante real faria cada um.

**Anonimização.** Antes de qualquer divulgação, descarte o `.jsonl` e publique
apenas contagens. Se precisar citar um IP no material, use a faixa de
documentação (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

**Limitações (honestidade metodológica).** A amostra é uma turma, não uma
população; há efeito de plateia (o professor está olhando); e o resultado não
se generaliza. O valor do experimento é didático: fazer o aluno *sentir* o
que ele já sabia em teoria.

**Resultados.** Sem resultados publicados neste repositório, de propósito:
cada turma gera os seus. Se quiser registrar, crie `RESULTADOS.md` com
números agregados e **nenhum dado pessoal**.

---

## Rodando localmente (rede da universidade)

```bash
python3 grabber_sala.py                        # porta 8000
python3 grabber_sala.py --porta 8080
python3 grabber_sala.py --sem-divulgar         # tira o selo "aula" da fachada
python3 grabber_sala.py --destino https://example.com   # /r redireciona
```

O terminal imprime a URL para projetar na sala:

```
  Isca para a turma  :  http://192.168.0.42:8000/
  Painel do professor:  http://192.168.0.42:8000/painel?t=AbC123
```

Não precisa `pip install`. Os dados não saem da sua rede.

## Deploy no Dokploy

O repositório já vem com `Dockerfile` e `docker-compose.yml`.

1. Dokploy → **Create Application** → provider **Docker Compose**.
2. Aponte para este repositório, branch `main`, arquivo `docker-compose.yml`.
3. Em **Environment**, preencha as variáveis (todas já estão declaradas no
   `docker-compose.yml`, com padrão — você só sobrescreve o que quiser):

   | Variável | Padrão | Para que serve |
   |---|---|---|
   | `PORTA` | `8000` | porta do container, do mapeamento e do healthcheck |
   | `TOKEN_PAINEL` | *(sorteado)* | senha do `/painel` — **defina** |
   | `URL_PUBLICA` | — | domínio, só para o log de inicialização |
   | `DIVULGAR` | `1` | `0` remove o selo "demonstração de aula" |
   | `DESTINO` | — | URL para onde `/r` redireciona |
   | `EMPRESA_NOME` | `Aurora Serviços` | nome da empresa fictícia |
   | `EMPRESA_RAMO` | `Assessoria contábil...` | linha abaixo do nome |
   | `EMPRESA_BIO` | `Canais oficiais...` | texto de apoio |
   | `EMPRESA_CNPJ` | `00.000.000/0001-00` | rodapé (dígito inválido de propósito) |
   | `EMPRESA_ENDERECO` | `Av. das Acácias, 1200` | endereço no rodapé |
   | `EMPRESA_HORARIO` | `Segunda a sexta...` | horário de atendimento |
   | `CONTATO1_*` | Kelly Moreira / Secretaria | botão em destaque |
   | `CONTATO2_*` | Recursos Humanos / RH | segundo contato |
   | `CONTATO3_*` | Contábil / Financeiro | terceiro contato |

   Cada contato tem `_NOME`, `_CARGO` e `_NUMERO`. O link `tel:` é gerado
   sozinho a partir do número (aceita `(11) 99999-9999`, `11 99999-9999` ou
   `+55 11 99999-9999`).

   Sem `TOKEN_PAINEL`, o app sorteia um token novo a cada boot e o link do
   painel muda a cada deploy (o valor aparece no log do container).

4. Em **Domains**, aponte o domínio para a porta `8000` (ou a que você pôs
   em `PORTA`).
5. Deploy. O healthcheck bate em `/health`.

Para ler o log (o volume `dados` guarda as capturas):

```bash
docker compose exec grabber sh -c 'wc -l /dados/capturas.jsonl'
docker compose exec grabber sh -c 'tail -n 5 /dados/capturas.jsonl'
```

Para zerar os dados depois da aula:

```bash
docker compose down -v      # remove o volume junto
```

> **Atenção no deploy público:** atrás do Traefik/Dokploy o IP real chega em
> `X-Forwarded-For`. O código usa a **última** entrada desse cabeçalho (escrita
> pelo proxy mais próximo) e marca no painel quando o IP não é o da conexão
> TCP. Se você expuser o container sem proxy, `X-Forwarded-For` passa a ser
> 100% controlado pelo visitante — e o "IP" do painel, falsificável. Isso é
> intencional: é uma das lições da aula.

---

## Rotas

| Rota | O que é |
|---|---|
| `/` | a isca: contatos da empresa fictícia + captura |
| `/quiz` | página alternativa, mais "honesta", para comparar |
| `/r` | captura e redireciona na hora para `--destino` (isca clássica) |
| `/painel` | painel do professor, detalhado (token no boot, ou `TOKEN_PAINEL`) |
| `/aula` (e `/telao`) | tela grande para projetar: 1 linha por aluno, atualiza a cada 2 s, IP mascarado |
| `/api/aula` | os dados da tela da aula em JSON (IP completo só com `?t=TOKEN`) |
| `/beacon.js` | o script de coleta que a isca carrega |
| `/health` | healthcheck do container |

**`/painel` × `/aula`:** o painel é o seu caderno (tudo, IP completo, token). A
`/aula` é o telão: números grandes, uma linha por visitante, auto-refresh e
**IP mascarado** (`203.0.113.•••`) — o aluno se reconhece pelo horário, pelo
fuso e pelo aparelho, sem expor o IP do colega. Abra `/aula?t=SEU_TOKEN` na
hora de revelar os IPs.

## O que é capturado de verdade

- IP de origem, `User-Agent`, `Referer`, `Accept-Language`, `Host`, data/hora;
- `X-Forwarded-For`, quando existe — **marcado no painel como falsificável**;
- idioma, fuso, tamanho de tela, núcleos de CPU, tipo de conexão (via JS);
- segundos de permanência na página;
- um **cookie de sessão** (`sid`, 2 h) só para juntar "abriu a página" +
  "mandou o beacon" na mesma linha. Sem ele, 30 alunos no Wi-Fi da faculdade
  (mesmo IP público) com o mesmo celular virariam uma linha só.

O resto — geolocalização por API, fingerprint de canvas/WebGL, WebRTC,
cookie persistente, ofuscação, cloaking, exfiltração por webhook — está
**comentado** em `grabber_sala.py`, `beacon.js` e `mascara.html`, explicando
como um atacante real faria. É o material da aula, não o programa.

## Roteiro sugerido (50 min)

1. **10 min — a isca.** Projete o link/QR de `/` no telão. Diga só: "preciso
   que vocês acessem esse contato da secretaria". Não explique nada ainda.
2. **10 min — a tela da aula.** Abra `/aula` (ou `/telao`) no telão, com fonte
   grande e auto-refresh. Cada aluno se reconhece pelo horário, pelo fuso, pela
   tela e pelo aparelho. Pergunte: *"quem aqui foi avisado?"* Ninguém foi.
   Não houve senha, pop-up de cookie ou pedido de permissão. Se quiser mostrar
   o IP completo, abra `/aula?t=SEU_TOKEN` (ou use o `/painel`).
3. **10 min — os telefones falsos.** `(11) 0000-0000/0001/0002` não existem
   (fixo brasileiro começa com 2–5) e o CNPJ tem dígito inválido. Ninguém
   conferiu. Pergunte quem tentaria ligar para o RH antes de mandar currículo.
   O ataque é **social**, não técnico.
4. **10 min — IP não é identidade.** Mesmo aluno em: Wi-Fi da universidade
   (NAT compartilhado), dados móveis (IP da operadora), VPN (IP do provedor).
   O IP muda; fuso, idioma e fingerprint, não.
5. **10 min — defesa.** Bloqueador de script de terceiros, DNS filtrado,
   desconfiar de domínio parecido (o cadeado HTTPS não prova nada), não abrir
   "contato" que chegou sem contexto, e o fato de que a rede da universidade
   registra quem acessou o quê.

## Detalhes que rendem discussão

- **`X-Forwarded-For` é cabeçalho, não fato.**
  `curl -H "X-Forwarded-For: 8.8.8.8"` faz o painel acreditar em qualquer IP.
  Por isso o painel mostra ⚠.
- **Nada nesta pasta vem da internet.** Sem Google Fonts, sem CDN, sem
  analytics — cada recurso externo entregaria o IP dos alunos a um terceiro.
  `mascara.html` não tem nenhuma URL absoluta (verificável: `grep -c "https\?://"`).
- **O `beacon.js` não pede permissão** porque só usa o que o navegador entrega
  de graça. "Aceitar cookies" não protege contra isso.
- **Preview de link já é captura.** WhatsApp/Discord/Slack carregam a página
  para gerar o cartão de prévia — e isso entrega IP e User-Agent **sem**
  ninguém clicar. O log mostra `tipo: "pagina"` antes de qualquer `beacon`.
- **`tel:` pode virar `wa.me`**, link encurtado ou portal que pede CPF. Trocar
  o `href` da máscara e discutir o efeito é um exercício de 5 minutos.
- **Cookie de sessão sem pedir licença.** A primeira visita a `/` recebe um
  `sid` (2 h) — o mesmo que `_ga` (Analytics) e `_fbp` (Meta) fazem. É o que
  separa dois alunos atrás do mesmo NAT, e o que o "modo anônimo" apaga quando
  você fecha a janela (mas não entre abas).
- **O único JavaScript da fachada é o de coleta.** Não há script de interface,
  nem framework, nem biblioteca: `grep -n "<script src" mascara.html` retorna
  uma única linha (o `beacon.js`). Isso mostra que "site bonito" não exige
  dependência nenhuma — e que dá para rastrear alguém com 60 linhas.

## Estrutura

```
grabber_sala.py      servidor + rotas + log + textos da fachada (Python puro)
mascara.html         fachada: contatos da empresa fictícia (com {{placeholders}})
beacon.js            coleta no navegador (o "analytics" da isca)
Dockerfile           imagem python:slim, usuário não-root, healthcheck
docker-compose.yml   stack para o Dokploy (env, volume do log, limites)
.env.example         todas as variáveis, prontas para copiar
```

## Licença

MIT (veja `LICENSE`). A licença cobre o código; **não** cobre uso para
coletar dados de pessoas sem consentimento — isso não é autorizado pelo
autor, nem pela lei.
