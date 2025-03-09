# syntax=docker/dockerfile:1
FROM alpine:edge

RUN \
    sed -i 's/dl-cdn.alpinelinux.org/mirrors.zju.edu.cn/g' /etc/apk/repositories && \
    apk update --no-cache && \
    apk add wget --no-cache && \
    apk add --no-cache curl jq

COPY update_cookie.sh /app/update_cookie.sh

RUN chmod +x /app/update_cookie.sh

CMD ["/app/update_cookie.sh"]