FROM metacubex/mihomo:v1.19.12 AS core
FROM python:3.13-alpine
RUN apk add --no-cache ca-certificates openssl && pip install --no-cache-dir PyYAML==6.0.3 && mkdir /data && chown 10001:10001 /data && chmod 700 /data
COPY --from=core /mihomo /usr/local/bin/mihomo
WORKDIR /opt/console
COPY app/subscription.py app/resolve_host.py standalone/runtime.py standalone/ui.py standalone/index.html standalone/ui.js ./
USER 10001:10001
VOLUME ["/data"]
EXPOSE 17680/tcp 17890/tcp
CMD ["python","-B","ui.py"]
