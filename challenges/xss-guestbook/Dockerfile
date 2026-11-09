FROM python:3.12-slim

RUN useradd --create-home --uid 1000 lab

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY app.py /app/app.py

USER 1000:1000
EXPOSE 8000

CMD ["python", "/app/app.py"]
