# syntax=docker/dockerfile:1
FROM docker.io/library/alpine:edge
WORKDIR /app
COPY requirements.txt .

RUN \
    sed -i 's/dl-cdn.alpinelinux.org/mirrors.bfsu.edu.cn/g' /etc/apk/repositories && \
    apk update --no-cache && \
    apk add --no-cache python pip && \
    pip config set global.extra-index-url "https://mirrors.bfsu.edu.cn/pypi/web/simple" && \
    pip install --no-cache-dir -r requirements.txt && \
    pip cache purge

COPY --chmod=755 update_cookie.py .

CMD ["python", "/app/update_cookie.py"]