import hashlib
import hmac
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import threading
import time

from runtime import Runtime, parse_snapshot, subscription


class UI(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def setup(self):
        self.request.settimeout(8)
        self.request = self.server.tls.wrap_socket(self.request, server_side=True)
        super().setup()

    def finish(self):
        try:
            super().finish()
        finally:
            self.request.close()

    def reply(self, code, data, mime="application/json", cookie=None):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def authenticated(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie.get("sid")
        return token and time.monotonic() < self.server.expiry and hmac.compare_digest(
            token.value.encode(), self.server.sid.encode())

    def do_GET(self):
        assets = {"/": ("index.html", "text/html; charset=utf-8"), "/ui.js": ("ui.js", "text/javascript")}
        if self.path in assets:
            name, mime = assets[self.path]
            return self.reply(200, Path(__file__).with_name(name).read_bytes(), mime)
        with self.server.lock:
            if self.path != "/status" or not self.authenticated():
                return self.reply(403, {})
            r = self.server.runtime
            self.reply(200, dict(csrf=self.server.csrf, saved=len(r.state["saved"]),
                                 active=len(r.state["active"]), listening=r.healthy(), password=r.state["proxy"]))

    def do_POST(self):
        s = self.server
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if self.headers.get("Content-Type") != "application/json" or not 1 <= length <= 8192:
                return self.reply(400, {})
            data = json.loads(self.rfile.read(length))
            with s.lock:
                r = s.runtime
                if self.path == "/login":
                    if time.monotonic() < s.retry:
                        return self.reply(429, {})
                    if not hmac.compare_digest(data["password"].encode(), r.state["admin"].encode()):
                        s.retry = time.monotonic()+1
                        return self.reply(403, {})
                    s.sid, s.csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                    s.expiry = time.monotonic()+1800
                    return self.reply(200, {}, cookie=f"sid={s.sid}; Secure; HttpOnly; SameSite=Strict; Path=/")
                if not self.authenticated() or data.get("csrf") != s.csrf:
                    return self.reply(403, {})
                if self.path == "/save":
                    nodes = subscription.fetch(data["url"], parse=parse_snapshot)
                    r.check(nodes)
                    r.commit(saved=nodes)
                elif self.path == "/enable" and r.state["saved"]:
                    r.switch(r.state["saved"])
                elif self.path == "/disable":
                    r.switch([])
                elif self.path == "/logout":
                    s.expiry = 0
                else:
                    return self.reply(400, {})
                self.reply(200, {})
        except Exception:
            self.reply(400, {"error": "操作失败，请核对订阅格式、核心和当前状态。"})


def pairing_context(directory, password):
    cert, key = directory/"ui.crt", directory/"ui.key"
    if not cert.exists() or not key.exists():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "365",
                        "-subj", "/CN=F1 Standalone", "-keyout", str(key), "-out", str(cert)],
                       check=True, stderr=subprocess.DEVNULL)
    pairing = directory/"pairing.txt"
    pairing.write_text("证书 SHA256 "+hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
                       +"\n管理密码 "+password+"\n")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    return tls


def main():
    os.umask(0o077)
    directory = Path(os.environ.get("F1_STANDALONE_DATA", "/data")).resolve()
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.stat().st_mode & 0o077 or directory.stat().st_uid != os.getuid():
        raise SystemExit("数据目录必须由当前服务账户持有，权限为 0700")
    r = Runtime(directory)
    tls = pairing_context(directory, r.state["admin"])
    s = ThreadingHTTPServer((os.environ.get("F1_STANDALONE_BIND", "0.0.0.0"), int(os.environ.get("F1_STANDALONE_PORT", "17680"))), UI)
    s.runtime, s.lock, s.expiry, s.retry = r, threading.Lock(), 0, 0
    s.tls = tls
    try:
        s.serve_forever()
    finally:
        r.stop()


if __name__ == "__main__":
    main()
