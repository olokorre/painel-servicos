#!/usr/bin/env python3
"""vm-panel: painel web minimo que descobre portas TCP escutando na VM.

Somente biblioteca padrao do Python 3.12. Roda dentro de um container com
network_mode: host e pid: host, portanto /proc/net/tcp e /proc/<pid> sao os
do host. Le o socket do Docker via AF_UNIX para descobrir containers.
"""

import glob
import http.client
import json
import os
import signal
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

APP_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE = os.path.join(APP_DIR, "index.html")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "8090"))
DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")

LISTEN_STATE = "0A"
LOOPBACK_ADDRS = {"127.0.0.1", "::1"}
HTTPS_PORTS = {443, 8443}


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


def docker_containers():
    """GET /containers/json?all=1 no socket unix. Nunca levanta excecao."""
    try:
        conn = UnixHTTPConnection(DOCKER_SOCKET)
        conn.request("GET", "/v1.41/containers/json?all=1",
                     headers={"Host": "localhost"})
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
            })
        except Exception:
            continue
    return containers


def build_payload():
    inode_pids = socket_inode_pids()
    containers = docker_containers()

    public_owner = {}
    for container in containers:
        for port in container["ports"]:
            public = port.get("public")
            if public is not None and port.get("type") == "tcp":
                public_owner.setdefault(public, container["name"])

    items = []
    for record in listening_tcp():
        pids = sorted(inode_pids.get(record["inode"], ()))
        main_pid = pids[0] if pids else None
        process = _read_ids("/proc/%d/comm" % main_pid) if main_pid else None
        cmdline = _read_cmdline(main_pid) if main_pid else None
        port = record["port"]
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
            "container": public_owner.get(port),
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
    server_version = "vm-panel/1.0"

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

    def do_GET(self):
        path = urlparse(self.path).path
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
    server = ThreadingHTTPServer(("0.0.0.0", PANEL_PORT), Handler)
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
    main()
