FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10001 appuser && mkdir -p /run/kube-api
COPY app.py .
COPY templates templates
USER 10001
EXPOSE 8443
CMD ["gunicorn", "--bind=0.0.0.0:8443", "--workers=1", "--threads=4", "--timeout=60", "--certfile=/run/tls/tls.crt", "--keyfile=/run/tls/tls.key", "app:APP"]
