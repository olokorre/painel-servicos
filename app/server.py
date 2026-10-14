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
  PANEL_PROBE_INTERVAL      segundos entre ciclos de sondagem HTTP (default 60)
  PANEL_PROBE_TTL           idade maxima de um resultado para ser fresco (default 300)
  PANEL_PROBE_TIMEOUT       timeout (float) por requisicao de sondagem (default 2.0)
  PANEL_CACHE_FILE          arquivo de cache em disco (default vazio = so memoria)
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
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urljoin, urlparse

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


def _env_float(name, default):
    """Le float de env; ausente/invalido cai no default, nunca ValueError."""
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        return float(value.strip())
    except ValueError:
        return default


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
PANEL_PROBE_INTERVAL = _env_int("PANEL_PROBE_INTERVAL", 60, minimum=1)
PANEL_PROBE_TTL = _env_int("PANEL_PROBE_TTL", 300, minimum=1)
PANEL_PROBE_TIMEOUT = _env_float("PANEL_PROBE_TIMEOUT", 2.0)
PANEL_CACHE_FILE = _env_str("PANEL_CACHE_FILE", "")

PAINEL_VERSION = "1.0"
_USER_AGENT = "painel-servicos/%s" % PAINEL_VERSION
MAX_BODY = 512 * 1024
MAX_ICON = 256 * 1024
MAX_CACHE_ENTRIES = 512

_SSL_NO_VERIFY = ssl.create_default_context()
_SSL_NO_VERIFY.check_hostname = False
_SSL_NO_VERIFY.verify_mode = ssl.CERT_NONE


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


_PROBE_CACHE = {}
_PROBE_LOCK = threading.Lock()
_CURRENT_PORTS = set()
_CURRENT_PORTS_LOCK = threading.Lock()
_CACHE_DISK_OK = True
_LAST_PROBE_LOG = None


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _checked_age_seconds(checked_at):
    if not checked_at:
        return None
    try:
        naive = datetime.strptime(checked_at, "%Y-%m-%dT%H:%M:%SZ")
        naive = naive.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - naive).total_seconds()
    except ValueError:
        return None


class _DocParser(HTMLParser):
    """Extrai titulo (title/og:title/og:site_name) e o melhor link de icone."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = None
        self.og_title = None
        self.og_site = None
        self._in_title = False
        self._title_buf = []
        self.icon_link = None
        self._icon_prio = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
            self._title_buf = []
            return
        if tag == "meta":
            d = dict(attrs)
            prop = (d.get("property") or d.get("name") or "").lower()
            content = d.get("content")
            if prop == "og:title" and not self.og_title and content:
                self.og_title = content
            elif prop == "og:site_name" and not self.og_site and content:
                self.og_site = content
            return
        if tag == "link":
            d = dict(attrs)
            rels = (d.get("rel") or "").lower().split()
            href = d.get("href")
            if not href:
                return
            relset = set(rels)
            priority = None
            if relset == {"icon"}:
                priority = 0
            elif relset == {"icon", "shortcut"}:
                priority = 1
            elif relset == {"apple-touch-icon"}:
                priority = 2
            if priority is not None and (self._icon_prio is None
                                         or priority < self._icon_prio):
                self.icon_link = href
                self._icon_prio = priority

    def handle_data(self, data):
        if self._in_title:
            self._title_buf.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "title" and self._in_title:
            self._in_title = False
            text = "".join(self._title_buf).strip()
            if text:
                self.title = text

    def result(self):
        if self.title:
            return self.title
        if self.og_title:
            return self.og_title
        if self.og_site:
            return self.og_site
        return None


def _body_charset(content_type):
    if not content_type:
        return "utf-8"
    for part in content_type.split(";"):
        part = part.strip()
        low = part.lower()
        if low.startswith("charset="):
            charset = part.split("=", 1)[1].strip().strip("\"'")
            if charset:
                return charset
    return "utf-8"


def _normalize_title(title):
    title = " ".join(title.split())
    if len(title) > 120:
        title = title[:120].rstrip()
    return title


def _parse_doc(content_type, body):
    """Devolve (titulo, icon_href) a partir do corpo HTML, ou (None, None)."""
    charset = _body_charset(content_type)
    try:
        text = body.decode(charset, errors="replace")
    except (LookupError, ValueError):
        text = body.decode("utf-8", errors="replace")
    parser = _DocParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        return None, None
    title = parser.result()
    if title:
        title = _normalize_title(title)
    return title, parser.icon_link


def _looks_like_html(content_type, body):
    if not body:
        return False
    ctype = (content_type or "").split(";")[0].strip().lower()
    low = body[:8192].lower()
    markers = (b"<html" in low or b"<!doctype html" in low or b"<title" in low)
    if ctype == "text/html":
        return True
    return markers


def _resolve_icon_path(port, href):
    """Resolve href relativo ao host 127.0.0.1:<port> e devolve so o path + query."""
    scheme = "https" if port in HTTPS_PORTS else "http"
    joined = urljoin("%s://127.0.0.1:%d/" % (scheme, port), href)
    parsed = urlparse(joined)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return path


def _valid_icon_bytes(data, url):
    if data.startswith(b"\x00\x00\x01\x00"):
        return True
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    if data.startswith(b"GIF8"):
        return True
    if b"<svg" in data[:2048]:
        return True
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return True
    return False


def _pick_icon_type(ctype, url):
    base = (ctype or "").split(";")[0].strip().lower()
    if base.startswith("image/"):
        return base
    low = url.lower()
    if low.endswith(".png"):
        return "image/png"
    if low.endswith(".ico"):
        return "image/x-icon"
    if low.endswith(".svg"):
        return "image/svg+xml"
    if low.endswith(".webp"):
        return "image/webp"
    if low.endswith(".gif"):
        return "image/gif"
    return base or "image/x-icon"


def _fetch_icon(port, href):
    """Busca o icone no mesmo host/porta. Devolve dict ou None se invalido."""
    url_path = _resolve_icon_path(port, href)
    scheme = "https" if port in HTTPS_PORTS else "http"
    conn = None
    ctype = None
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(
                "127.0.0.1", port, timeout=PANEL_PROBE_TIMEOUT,
                context=_SSL_NO_VERIFY)
        else:
            conn = http.client.HTTPConnection(
                "127.0.0.1", port, timeout=PANEL_PROBE_TIMEOUT)
        conn.request("GET", url_path, headers={
            "Host": "127.0.0.1:%d" % port,
            "User-Agent": _USER_AGENT,
            "Accept": "image/*,*/*;q=0.1",
            "Connection": "close",
        })
        response = conn.getresponse()
        ctype = response.getheader("Content-Type")
        data = response.read(MAX_ICON + 1)
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    if len(data) > MAX_ICON:
        return None
    is_image = ctype and ctype.split(";")[0].strip().lower().startswith("image/")
    ends_image = url_path.lower().endswith((".ico", ".png", ".svg", ".webp"))
    if not (is_image or ends_image):
        return None
    if not _valid_icon_bytes(data, url_path):
        return None
    return {"bytes": data, "type": _pick_icon_type(ctype, url_path)}


def _probe_port(port):
    """Sonda uma porta e devolve a entrada de cache. Nunca levanta excecao."""
    entry = {"ok": False, "status": None, "title": None, "server": None,
             "has_icon": False, "icon_type": None, "icon_bytes": None,
             "checked_at": _now_iso()}
    scheme = "https" if port in HTTPS_PORTS else "http"
    conn = None
    status = None
    server = None
    content_type = None
    body = b""
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(
                "127.0.0.1", port, timeout=PANEL_PROBE_TIMEOUT,
                context=_SSL_NO_VERIFY)
        else:
            conn = http.client.HTTPConnection(
                "127.0.0.1", port, timeout=PANEL_PROBE_TIMEOUT)
        conn.request("GET", "/", headers={
            "Host": "127.0.0.1:%d" % port,
            "User-Agent": _USER_AGENT,
            "Accept": "text/html,*/*",
            "Connection": "close",
        })
        response = conn.getresponse()
        status = response.status
        server = response.getheader("Server")
        content_type = response.getheader("Content-Type")
        body = response.read(MAX_BODY + 1)
    except Exception:
        return entry
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    entry["status"] = status
    entry["server"] = server
    if _looks_like_html(content_type, body):
        title, icon_href = _parse_doc(content_type, body)
        entry["ok"] = True
        entry["title"] = title
        if icon_href:
            icon = _fetch_icon(port, icon_href)
            if icon:
                entry["has_icon"] = True
                entry["icon_type"] = icon["type"]
                entry["icon_bytes"] = icon["bytes"]
    return entry


def _store_entry(port, entry):
    if port not in _PROBE_CACHE and len(_PROBE_CACHE) >= MAX_CACHE_ENTRIES:
        oldest = min(_PROBE_CACHE,
                     key=lambda key: (_PROBE_CACHE[key].get("checked_at") or ""))
        del _PROBE_CACHE[oldest]
    _PROBE_CACHE[port] = entry


def _probe_cycle():
    global _CURRENT_PORTS, _LAST_PROBE_LOG
    start = time.time()
    current_ports = {record["port"] for record in listening_tcp()}
    with _CURRENT_PORTS_LOCK:
        _CURRENT_PORTS = current_ports

    to_probe = []
    with _PROBE_LOCK:
        for port in list(_PROBE_CACHE):
            if port not in current_ports:
                del _PROBE_CACHE[port]
        for port in current_ports:
            entry = _PROBE_CACHE.get(port)
            if entry is None:
                to_probe.append(port)
            else:
                age = _checked_age_seconds(entry.get("checked_at"))
                if age is None or age > PANEL_PROBE_TTL:
                    to_probe.append(port)

    for port in to_probe:
        entry = _probe_port(port)
        with _PROBE_LOCK:
            _store_entry(port, entry)

    _cache_save()

    total = len(_PROBE_CACHE)
    http_ok = sum(1 for entry in _PROBE_CACHE.values() if entry.get("ok"))
    icons = sum(1 for entry in _PROBE_CACHE.values() if entry.get("has_icon"))
    log = (total, http_ok, icons)
    if log != _LAST_PROBE_LOG:
        _LAST_PROBE_LOG = log
        elapsed = time.time() - start
        print("probe: %d portas, %d http ok, %d com icone (ciclo em %.2fs)" % (
            total, http_ok, icons, elapsed), file=sys.stderr, flush=True)


def _probe_loop():
    _probe_cycle()
    while True:
        time.sleep(PANEL_PROBE_INTERVAL)
        _probe_cycle()


def _entry_to_disk(entry):
    data = {key: entry.get(key) for key in
            ("ok", "status", "title", "server", "has_icon",
             "icon_type", "checked_at")}
    icon_bytes = entry.get("icon_bytes")
    if icon_bytes:
        data["icon_b64"] = base64.b64encode(icon_bytes).decode("ascii")
    return data


def _entry_from_disk(data):
    entry = {"ok": data.get("ok"), "status": data.get("status"),
             "title": data.get("title"), "server": data.get("server"),
             "has_icon": data.get("has_icon", False),
             "icon_type": data.get("icon_type"), "icon_bytes": None,
             "checked_at": data.get("checked_at")}
    b64 = data.get("icon_b64")
    if b64:
        try:
            entry["icon_bytes"] = base64.b64decode(b64)
        except Exception:
            entry["icon_bytes"] = None
    return entry


def _cache_save():
    global _CACHE_DISK_OK
    if not PANEL_CACHE_FILE or not _CACHE_DISK_OK:
        return
    with _PROBE_LOCK:
        payload = {"saved_at": _now_iso(),
                   "entries": {str(port): _entry_to_disk(entry)
                               for port, entry in _PROBE_CACHE.items()}}
    try:
        tmp = PANEL_CACHE_FILE + ".tmp"
        with open(tmp, "w") as handle:
            handle.write(json.dumps(payload))
        os.replace(tmp, PANEL_CACHE_FILE)
    except OSError:
        _CACHE_DISK_OK = False
        print("probe: cache em disco desativado (%s)" % PANEL_CACHE_FILE,
              file=sys.stderr, flush=True)


def _cache_load():
    if not PANEL_CACHE_FILE:
        return
    try:
        with open(PANEL_CACHE_FILE, "r") as handle:
            payload = json.load(handle)
    except (OSError, ValueError):
        return
    with _PROBE_LOCK:
        for key, data in (payload.get("entries") or {}).items():
            try:
                port = int(key)
            except (TypeError, ValueError):
                continue
            _PROBE_CACHE[port] = _entry_from_disk(data)


def _http_snapshot(port):
    with _PROBE_LOCK:
        entry = _PROBE_CACHE.get(port)
        if entry is None:
            return {"ok": None, "status": None, "title": None,
                    "server": None, "has_icon": False, "checked_at": None}
        return {"ok": entry.get("ok"), "status": entry.get("status"),
                "title": entry.get("title"), "server": entry.get("server"),
                "has_icon": entry.get("has_icon", False),
                "checked_at": entry.get("checked_at")}


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
            "http": _http_snapshot(port),
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

    def _handle_icon(self):
        params = parse_qs(urlparse(self.path).query)
        raw = (params.get("port") or [""])[0]
        try:
            port = int(raw)
        except ValueError:
            self._json(404, {"error": "not found"})
            return
        listening = port in {record["port"] for record in listening_tcp()}
        with _PROBE_LOCK:
            entry = _PROBE_CACHE.get(port)
        if not listening or entry is None or not entry.get("has_icon") \
                or not entry.get("icon_bytes"):
            self._json(404, {"error": "not found"})
            return
        body = entry["icon_bytes"]
        ctype = entry.get("icon_type") or "image/png"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, max-age=%d" % PANEL_PROBE_TTL)
        self.end_headers()
        self.wfile.write(body)

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
        if path == "/api/icon":
            self._handle_icon()
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
    _cache_load()
    server = ThreadingHTTPServer((PANEL_BIND, PANEL_PORT), Handler)
    server.daemon_threads = True
    probe_thread = threading.Thread(target=_probe_loop, daemon=True)
    probe_thread.start()

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
