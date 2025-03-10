# syntax=docker/dockerfile:1
FROM docker.io/library/python:alpine
WORKDIR /app
COPY requirements.txt .

RUN \
    pip install --no-cache-dir -r requirements.txt && \
    pip cache purge

COPY --chmod=755 update_cookie.py .

CMD ["python", "/app/update_cookie.py"]