# syntax=docker/dockerfile:1
#
# Imagem mínima, sem dependências externas: o servidor usa só a biblioteca
# padrão do Python. Não há `pip install`, então não há supply chain para
# auditar — o que também é um bom argumento em aula.
FROM python:3.12-slim

# Sem buffer no stdout (para ver as capturas no log do Dokploy em tempo real)
# e sem .pyc dentro do container.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORTA=8000 \
    ARQ_LOG=/dados/capturas.jsonl

WORKDIR /app

# Usuário sem privilégio: o processo que recebe requisições da internet
# não precisa ser root. Regra básica de container que muita gente esquece.
RUN useradd --system --uid 10001 --create-home aula

COPY grabber_sala.py mascara.html beacon.js ./

# /dados é o volume onde o log vive; precisa existir e ser gravável pelo usuário.
RUN mkdir -p /dados && chown -R aula:aula /app /dados

USER aula

EXPOSE 8000

# O Docker marca o container como unhealthy se /health parar de responder.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+__import__('os').environ.get('PORTA','8000')+'/health', timeout=2).status==200 else 1)"

CMD ["python3", "grabber_sala.py"]
