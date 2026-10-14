#!/usr/bin/env python3
"""painel-servicos: painel web minimo que descobre portas TCP escutando no host.

Somente biblioteca padrao do Python 3.9+. Roda nativo no host (ou em container
com network_mode: host e pid: host), portanto /proc/net/tcp e /proc/<pid> sao os
do host. Le o socket do Docker via AF_UNIX para descobrir containers.

Configuracao por variavel de ambiente (todas com default tolerante):
  PANEL_PORT          porta do servidor HTTP (default 8090)
  PANEL_BIND          endereco de bind do servidor HTTP (default 0.0.0.0)
  DOCKER_SOCKET       socket unix do Docker (default /var/run/docker.sock)
  PANEL_USER          usuario do Basic auth (default admin)
  PANEL_PASSWORD      senha do Basic auth (default vazio = sem auth)
  PANEL_HTTPS_PORTS   portas que recebem scheme https, separadas por virgula
                      (default 443,8443,9443)
"""

import base64
import glob
import hmac
import http.client
import json
import os
import re
import signal
import socket
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

APP_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE = os.path.join(APP_DIR, "index.html")

LISTEN_STATE = "0A"
LOOPBACK_ADDRS = {"127.0.0.1", "::1"}


def _env_int(name, default, minimum=None):
    """Le inteiro de env; ausente/invalido cai no default, nunca ValueError."""
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        number = int(value.strip())
    except ValueError:
        return default
    if minimum is not None and number < minimum:
        return default
    return number


def _env_str(name, default):
    """Le string de env; ausente/vazia cai no default."""
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else default


def _env_ports(name, default):
    """Le lista de portas de env (separada por virgula); default se ausente/vazia."""
    value = os.environ.get(name)
    if value is not None and value.strip():
        ports = set()
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                ports.add(int(item))
            except ValueError:
                continue
        return ports
    ports = set()
    for item in default.split(","):
        item = item.strip()
        if item:
            try:
                ports.add(int(item))
            except ValueError:
                continue
    return ports


PANEL_PORT = _env_int("PANEL_PORT", 8090, minimum=1)
PANEL_BIND = _env_str("PANEL_BIND", "0.0.0.0")
DOCKER_SOCKET = _env_str("DOCKER_SOCKET", "/var/run/docker.sock")
PANEL_USER = _env_str("PANEL_USER", "admin")
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "")
if PANEL_PASSWORD is None:
    PANEL_PASSWORD = ""
HTTPS_PORTS = _env_ports("PANEL_HTTPS_PORTS", "443,8443,9443")


def _parse_v4(hex_ip):
    return socket.inet_ntoa(bytes.fromhex(hex_ip)[::-1])


def _parse_v6(hex_ip):
    raw = bytes.fromhex(hex_ip)
    words = [raw[i:i + 4][::-1] for i in range(0, 16, 4)]
    return socket.inet_ntop(socket.AF_INET6, b"".join(words))


def _family_for(hex_ip):
    return "ipv4" if len(hex_ip) == 8 else "ipv6"


def _format_addr(family, hex_ip):
    return _parse_v4(hex_ip) if family == "ipv4" else _parse_v6(hex_ip)


def _read_ids(path):
    try:
        with open(path, "r", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return None


def _read_cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    text = data.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    return text or None


def socket_inode_pids():
    """Mapa inode -> lista de PIDs donos do socket, via /proc/<pid>/fd."""
    mapping = {}
    for path in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            target = os.readlink(path)
        except OSError:
            continue
        if not target.startswith("socket:["):
            continue
        inode = target[8:-1]
        if not inode:
            continue
        try:
            pid = int(path.split("/")[2])
        except (IndexError, ValueError):
            continue
        mapping.setdefault(inode, set()).add(pid)
    return mapping


def listening_tcp():
    """Le /proc/net/tcp e /proc/net/tcp6 e devolve sockets em LISTEN relevantes."""
    records = []
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(proc_file, "r", errors="replace") as handle:
                lines = handle.readlines()
        except OSError:
            continue
        for line in lines[1:]:
            try:
                fields = line.split()
                if len(fields) < 10 or fields[3] != LISTEN_STATE:
                    continue
                hex_ip, hex_port = fields[1].rsplit(":", 1)
                family = _family_for(hex_ip)
                address = _format_addr(family, hex_ip)
                records.append({
                    "port": int(hex_port, 16),
                    "family": family,
                    "address": address,
                    "inode": fields[9],
                })
            except (ValueError, IndexError):
                continue
    return records


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection que fala com o socket unix do Docker."""

    def __init__(self, socket_path):
        super().__init__("localhost")
        self._socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(self._socket_path)


_DOCKER_API_VERSION = None
_DOCKER_API_LOCK = threading.Lock()


def _docker_api_version():
    """GET /version no socket unix e cacheia ApiVersion (module-level)."""
    global _DOCKER_API_VERSION
    if _DOCKER_API_VERSION is not None:
        return _DOCKER_API_VERSION
    with _DOCKER_API_LOCK:
        if _DOCKER_API_VERSION is not None:
            return _DOCKER_API_VERSION
        version = ""
        try:
            conn = UnixHTTPConnection(DOCKER_SOCKET)
            conn.request("GET", "/version", headers={"Host": "localhost"})
            response = conn.getresponse()
            raw = response.read()
            conn.close()
            if response.status == 200:
                version = (json.loads(raw.decode("utf-8", "replace")).get("ApiVersion") or "").strip()
        except Exception:
            version = ""
        _DOCKER_API_VERSION = version
        return version


def docker_containers():
    """GET /containers/json?all=1 no socket unix. Nunca levanta excecao."""
    try:
        version = _docker_api_version()
        path = ("/v%s/containers/json?all=1" % version) if version else "/containers/json?all=1"
        conn = UnixHTTPConnection(DOCKER_SOCKET)
        conn.request("GET", path, headers={"Host": "localhost"})
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        if response.status != 200:
            return []
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return []

    containers = []
    for item in data:
        try:
            names = item.get("Names") or []
            name = names[0].lstrip("/") if names else item.get("Id", "")[:12]
            ports = []
            for port in item.get("Ports") or []:
                if port.get("PrivatePort") is None:
                    continue
                ports.append({
                    "private": port.get("PrivatePort"),
                    "public": port.get("PublicPort"),
                    "type": port.get("Type") or "tcp",
                })
            containers.append({
                "name": name,
                "image": item.get("Image", ""),
                "state": item.get("State", ""),
                "status": item.get("Status", ""),
                "ports": ports,
                "id": item.get("Id", "") or "",
            })
        except Exception:
            continue
    return containers


_CGROUP_ID_RE = re.compile(
    r"(?:docker/|docker-|cri-containerd-|libpod-)([0-9a-fA-F]{12,})"
)


def _cgroup_container_id(pid):
    """Extrai o id (12 hex) do container a partir do cgroup do PID, ou None."""
    data = _read_ids("/proc/%d/cgroup" % pid)
    if not data:
        return None
    for line in data.splitlines():
        match = _CGROUP_ID_RE.search(line)
        if match:
            return match.group(1)[:12].lower()
    return None


def build_payload():
    inode_pids = socket_inode_pids()
    containers = docker_containers()

    public_owner = {}
    container_id_names = {}
    for container in containers:
        cid = (container.get("id") or "").lower()
        if len(cid) >= 12:
            container_id_names.setdefault(cid[:12], container["name"])
        for port in container["ports"]:
            public = port.get("public")
            if public is not None and port.get("type") == "tcp":
                public_owner.setdefault(public, container["name"])

    def _cgroup_owner(pids):
        for pid in pids:
            cid = _cgroup_container_id(pid)
            if cid:
                owner = container_id_names.get(cid[:12])
                if owner:
                    return owner
        return None

    items = []
    for record in listening_tcp():
        pids = sorted(inode_pids.get(record["inode"], ()))
        main_pid = pids[0] if pids else None
        process = _read_ids("/proc/%d/comm" % main_pid) if main_pid else None
        cmdline = _read_cmdline(main_pid) if main_pid else None
        port = record["port"]
        container = public_owner.get(port)
        if container is None and pids:
            container = _cgroup_owner(pids)
        items.append({
            "port": port,
            "proto": "tcp",
            "family": record["family"],
            "address": record["address"],
            "exposed": record["address"] not in LOOPBACK_ADDRS,
            "scheme": "https" if port in HTTPS_PORTS else "http",
            "process": process,
            "pids": pids,
            "cmdline": cmdline,
            "container": container,
        })

    items.sort(key=lambda entry: entry["port"])
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": socket.gethostname(),
        "items": items,
        "containers": containers,
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "painel-servicos/1.0"

    def _respond(self, status, content_type, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, obj):
        self._respond(status, "application/json", json.dumps(obj))

    def _unauthorized(self):
        body = json.dumps({"error": "unauthorized"}).encode("utf-8")
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="painel-servicos"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        if not PANEL_PASSWORD:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            token = base64.b64decode(header[6:]).decode("utf-8", "replace")
        except Exception:
            return False
        if ":" not in token:
            return False
        user, password = token.split(":", 1)
        return (hmac.compare_digest(user, PANEL_USER)
                and hmac.compare_digest(password, PANEL_PASSWORD))

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            self._json(200, {"status": "ok", "host": socket.gethostname()})
            return
        if not self._authorized():
            self._unauthorized()
            return
        if path == "/":
            try:
                with open(INDEX_FILE, "rb") as handle:
                    body = handle.read()
            except OSError:
                self._json(500, {"error": "index.html indisponivel"})
                return
            self._respond(200, "text/html; charset=utf-8", body)
            return
        if path == "/api/ports":
            try:
                self._json(200, build_payload())
            except Exception as exc:  # nunca derruba o servidor
                self._json(500, {"error": str(exc)})
            return
        self._json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        return


def main():
    server = ThreadingHTTPServer((PANEL_BIND, PANEL_PORT), Handler)
    server.daemon_threads = True

    def _shutdown(_signum, _frame):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    print("painel-servicos: ouvindo em %s:%d (auth=%s)" % (
        PANEL_BIND, PANEL_PORT, "on" if PANEL_PASSWORD else "off"),
        file=sys.stderr, flush=True)
    if not PANEL_PASSWORD:
        print("AVISO: servidor sem autenticacao (defina PANEL_PASSWORD)",
              file=sys.stderr, flush=True)
    main()
