FROM python:3.12-slim

RUN useradd --create-home --uid 1000 cyberlab

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY challenges /app/challenges

RUN mkdir -p /data && chown -R cyberlab:cyberlab /app /data

USER 1000:1000
ENV CYBERLAB_DATA_DIR=/data
EXPOSE 8443

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8443", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
