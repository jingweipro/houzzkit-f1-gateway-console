FROM metacubex/mihomo:v1.19.12@sha256:faa7f8ef37573f59430024c6a0278627f50ddec48a25a2ad60e04f0d851636c8 AS core
FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e
RUN apk add --no-cache ca-certificates openssl && pip install --no-cache-dir PyYAML==6.0.3 && mkdir /data && chown 10001:10001 /data && chmod 700 /data
COPY --from=core /mihomo /usr/local/bin/mihomo
WORKDIR /opt/console
COPY app/subscription.py app/resolve_host.py standalone/runtime.py standalone/ui.py standalone/index.html standalone/ui.js ./
USER 10001:10001
VOLUME ["/data"]
EXPOSE 17680/tcp 17890/tcp
CMD ["python","-B","ui.py"]
