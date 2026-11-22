# HOS source preview. Host control agent deliberately not bundled.
# Standalone UI container is not a functioning gateway without reviewed agent integration.
FROM python:3.12-alpine
ENV PYTHONUNBUFFERED=1 F1_CONSOLE_BIND=0.0.0.0 F1_CONSOLE_PORT=17680 F1_CONSOLE_UI_STATE=/data
COPY app/server.py app/index.html app/app.js app/style.css app/favicon.svg /opt/f1-console/
RUN mkdir -p /data && chown 10001:10001 /data && chmod 0700 /data
USER 10001:10001
WORKDIR /opt/f1-console
EXPOSE 17680
VOLUME ["/data"]
CMD ["python3","-B","server.py"]
