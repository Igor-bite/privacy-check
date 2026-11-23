#!/usr/bin/env python3
"""
«Что видит сайт» — локальный сервер для проверки данных, доступных сайту.

Запуск:   python3 server.py
Порты:    HTTPS 8443 (камера работает с любого устройства в сети),
          HTTP  8080 (камера работает только на localhost; с других адресов — редирект на HTTPS)
Переопределить: HTTP_PORT=8000 HTTPS_PORT=8444 python3 server.py

Только стандартная библиотека Python 3.7+. Для HTTPS нужен openssl (есть в macOS).
"""
import datetime
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import uuid
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
HTTP_PORT = int(os.environ.get("HTTP_PORT", 8080))
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", 8443))
CERT_DIR = os.path.join(ROOT, "cert")
CERT = os.path.join(CERT_DIR, "cert.pem")
KEY = os.path.join(CERT_DIR, "key.pem")
IPS_FILE = os.path.join(CERT_DIR, "ips.txt")

HTTPONLY_COOKIES = {"server_session"}

# Client Hints: браузер (Chromium) пришлёт их в следующих запросах без вопросов пользователю
ACCEPT_CH = ", ".join([
    "Sec-CH-UA", "Sec-CH-UA-Arch", "Sec-CH-UA-Bitness", "Sec-CH-UA-Full-Version-List",
    "Sec-CH-UA-Mobile", "Sec-CH-UA-Model", "Sec-CH-UA-Platform", "Sec-CH-UA-Platform-Version",
    "Sec-CH-UA-WoW64", "Sec-CH-UA-Form-Factors", "Sec-CH-Prefers-Color-Scheme",
    "Sec-CH-Prefers-Reduced-Motion", "Device-Memory", "Sec-CH-Device-Memory", "DPR", "Sec-CH-DPR",
    "Viewport-Width", "Sec-CH-Viewport-Width", "Downlink", "ECT", "RTT", "Save-Data",
])


def lan_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))


def ensure_cert(ips):
    """Создаёт самоподписанный сертификат с текущими IP в SAN (пересоздаёт, если IP сменился)."""
    key = ",".join(ips)
    if os.path.exists(CERT) and os.path.exists(KEY) and os.path.exists(IPS_FILE):
        with open(IPS_FILE) as f:
            if f.read().strip() == key:
                return True
    os.makedirs(CERT_DIR, exist_ok=True)
    host = socket.gethostname().split(".")[0]
    alt = ["DNS.1 = localhost", f"DNS.2 = {host}.local", "IP.1 = 127.0.0.1"]
    alt += [f"IP.{i + 2} = {ip}" for i, ip in enumerate(ips)]
    cnf = os.path.join(CERT_DIR, "openssl.cnf")
    with open(cnf, "w") as f:
        f.write(
            "[req]\ndistinguished_name = dn\nx509_extensions = v3\nprompt = no\n"
            "[dn]\nCN = privacy-check.local\nO = Privacy Check (local)\n"
            "[v3]\nsubjectAltName = @alt\nbasicConstraints = CA:FALSE\n"
            "keyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\n"
            "[alt]\n" + "\n".join(alt) + "\n"
        )
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
             "-days", "825", "-keyout", KEY, "-out", CERT, "-config", cnf],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as e:
        err = getattr(e, "stderr", b"") or b""
        print("! Не удалось создать сертификат через openssl:", e, err.decode(errors="ignore")[:300])
        return False
    with open(IPS_FILE, "w") as f:
        f.write(key)
    return True


def is_local_host(host):
    h = (host or "").rsplit(":", 1)[0].strip("[]").lower()
    return h in ("localhost", "127.0.0.1", "::1") or h.endswith(".localhost")


class Handler(BaseHTTPRequestHandler):
    server_version = "PrivacyCheck/1.0"
    protocol_version = "HTTP/1.1"
    timeout = 30

    def setup(self):
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(10)
            self.request.do_handshake()
        super().setup()

    @property
    def is_tls(self):
        return isinstance(self.connection, ssl.SSLSocket)

    def log_message(self, fmt, *args):
        sys.stdout.write("%s  %s  %s\n" % (
            datetime.datetime.now().strftime("%H:%M:%S"), self.client_address[0], fmt % args))

    def send_body(self, code, body, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlparse(self.path).path
        host = self.headers.get("Host", "")

        # С других устройств по HTTP камера недоступна — отправляем на HTTPS
        if not self.is_tls and not is_local_host(host) and self.server.https_ok:
            h = host.rsplit(":", 1)[0] if (":" in host and not host.endswith("]")) else host
            self.send_response(302)
            self.send_header("Location", f"https://{h}:{HTTPS_PORT}{self.path}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path in ("/", "/index.html"):
            return self.serve_index()
        if path == "/api/request":
            return self.serve_request_info()
        if path == "/favicon.ico":
            return self.send_body(204, b"", "image/x-icon")
        self.send_body(404, "Не найдено".encode(), "text/plain; charset=utf-8")

    def serve_index(self):
        try:
            with open(os.path.join(ROOT, "index.html"), "rb") as f:
                body = f.read()
        except OSError:
            return self.send_body(500, b"index.html not found", "text/plain")

        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except Exception:
            pass
        secure = "; Secure" if self.is_tls else ""
        year = 60 * 60 * 24 * 365
        cookies = []
        visitor = jar["visitor_id"].value if "visitor_id" in jar else uuid.uuid4().hex[:16]
        cookies.append(f"visitor_id={visitor}; Path=/; Max-Age={year}; SameSite=Lax{secure}")
        try:
            count = int(jar["visit_count"].value) + 1 if "visit_count" in jar else 1
        except ValueError:
            count = 1
        cookies.append(f"visit_count={count}; Path=/; Max-Age={year}; SameSite=Lax{secure}")
        if "first_visit" not in jar:
            first = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            cookies.append(f"first_visit={first}; Path=/; Max-Age={year}; SameSite=Lax{secure}")
        if "server_session" not in jar:
            cookies.append(f"server_session={uuid.uuid4().hex}; Path=/; HttpOnly; SameSite=Strict{secure}")

        extra = [("Set-Cookie", c) for c in cookies]
        extra += [("Accept-CH", ACCEPT_CH), ("Vary", "Cookie")]
        self.send_body(200, body, "text/html; charset=utf-8", extra)

    def serve_request_info(self):
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except Exception:
            pass
        ip = self.client_address[0]
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        try:
            ipobj = ipaddress.ip_address(ip)
            kind = "loopback (этот же компьютер)" if ipobj.is_loopback else (
                "частный (локальная сеть)" if ipobj.is_private else "публичный")
        except ValueError:
            kind = None
        tls = None
        if self.is_tls:
            c = self.connection.cipher()
            tls = {"version": self.connection.version(), "cipher": c[0] if c else None,
                   "bits": c[2] if c else None}
        local = self.connection.getsockname()
        data = {
            "client_ip": ip,
            "client_ip_kind": kind,
            "client_port": self.client_address[1],
            "server_ip": local[0],
            "server_port": local[1],
            "server_hostname": socket.gethostname(),
            "scheme": "https" if self.is_tls else "http",
            "tls": tls,
            "method": self.command,
            "path": self.path,
            "http_version": self.request_version,
            "headers": [[k, v] for k, v in self.headers.items()],
            "cookies": [{"name": k, "value": m.value, "httponly": k in HTTPONLY_COOKIES}
                        for k, m in jar.items()],
            "server_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        body = json.dumps(data, ensure_ascii=False, indent=1).encode()
        self.send_body(200, body, "application/json; charset=utf-8", [("Accept-CH", ACCEPT_CH)])


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    https_ok = False

    def handle_error(self, request, client_address):
        # Тихо игнорируем обрывы и отказ браузера от самоподписанного сертификата
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError, OSError)):
            return
        super().handle_error(request, client_address)


def main():
    ips = lan_ips()
    https_ok = ensure_cert(ips)

    http = Server(("0.0.0.0", HTTP_PORT), Handler)
    http.https_ok = https_ok
    servers = [http]

    if https_ok:
        https = Server(("0.0.0.0", HTTPS_PORT), Handler)
        https.https_ok = True
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        # Рукопожатие — в потоке обработчика, чтобы один зависший клиент не блокировал сервер
        https.socket = ctx.wrap_socket(https.socket, server_side=True, do_handshake_on_connect=False)
        servers.append(https)

    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()

    print("\n  «Что видит сайт» запущен\n")
    print(f"  На этом компьютере:   http://localhost:{HTTP_PORT}")
    if https_ok:
        for ip in ips:
            print(f"  В локальной сети:     https://{ip}:{HTTPS_PORT}")
        print("\n  Сертификат самоподписанный: браузер покажет предупреждение —")
        print("  нажмите «Подробнее» → «Перейти на сайт» (Safari: «Посетить этот веб-сайт»).")
    else:
        print("  HTTPS не поднят (нет openssl) — камера будет работать только на localhost.")
    print("\n  Остановить: Ctrl+C\n")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n  Остановлено.")
        for s in servers:
            s.shutdown()


if __name__ == "__main__":
    main()
