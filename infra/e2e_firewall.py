"""Agent-stage network egress firewall for cybergym-e2e.

The e2e contract withholds the answer (no description, no crash trace, no fix).
That withholding is only meaningful if the AGENT cannot simply fetch the answer
from the internet -- the CVE writeup, the upstream fix commit, an ARVO/OSS-Fuzz
record. Upstream enforces this with a Squid proxy pinned to an allowlist of LLM
API domains; the agent can reach its model but nothing else.

This is a dependency-free equivalent: a small threaded forward proxy that only
permits CONNECT/HTTP to an allowlisted set of domains and refuses everything
else with 403, logging every decision. The deny log doubles as a cheating
signal -- if an agent tried to reach `nvd.nist.gov` or `github.com/.../commit`,
it shows up here (and `e2e_trajectory.scan_*` can cross-check the agent log).

It is pure infrastructure: it observes/forwards/denies connections by hostname.
It contains no vulnerability logic and never inspects payloads.

ENFORCEMENT. The proxy is the policy; making the agent *use only* it is the
deployment's job. Two layers, strongest first:
  1. Run the agent in a network namespace / container whose ONLY egress route is
     this proxy (e.g. a docker custom network with the proxy as the sole
     reachable host, or an iptables rule dropping all egress except to the proxy
     port). Then the allowlist is actually enforced.
  2. At minimum, set HTTP(S)_PROXY for the agent process (see `proxy_env`). This
     is cooperative -- an agent that bypasses the env var escapes it -- so it is
     a convenience, not containment, and should be paired with layer 1.

CLI:
  python3 e2e_firewall.py start [--port 3128] [--allowlist FILE] [--log FILE]
  python3 e2e_firewall.py check <host> [--allowlist FILE]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import socket
import sys
import threading
from pathlib import Path

_HERE = Path(__file__).resolve().parent
DEFAULT_ALLOWLIST = _HERE / "firewall" / "default_allowlist.txt"
_BUFSIZE = 65536


def load_allowlist(path: Path | str | None = None) -> set[str]:
    """Read an allowlist file: one domain per line, '#' comments and blanks
    ignored. A leading dot is stripped (`.anthropic.com` == `anthropic.com`);
    matching is always suffix-wise (see `is_allowed`)."""
    path = Path(path) if path else DEFAULT_ALLOWLIST
    if not path.is_file():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        rule = line.split("#", 1)[0].strip().lower().lstrip(".")
        if rule:                       # drop blanks and dots-only lines (no empty rule)
            out.add(rule)
    return out


def is_allowed(host: str, allow: set[str]) -> bool:
    """True iff `host` is the allowlisted domain or a subdomain of one. Host is
    lowercased and any :port / trailing dot stripped. An empty allowlist denies
    everything (fail-closed)."""
    if not host:
        return False
    host = host.strip().lower().rstrip(".")
    host = host.rsplit("@", 1)[-1]                                   # drop user:pass@ userinfo
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host  # host:port (not IPv6)
    for rule in allow:
        if host == rule or host.endswith("." + rule):
            return True
    return False


def proxy_env(url: str, base: dict | None = None) -> dict:
    """Env overlay that points a child process's HTTP(S) traffic at the proxy and
    clears NO_PROXY so nothing bypasses it. Cooperative layer -- see module doc."""
    env = dict(base or {})
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        env[k] = url
    for k in ("NO_PROXY", "no_proxy"):
        env[k] = ""
    return env


class AllowlistProxy:
    """A threaded forward proxy that only serves allowlisted hosts.

    Handles HTTPS via CONNECT tunnelling and plain HTTP via absolute-URI
    forwarding. Any request to a non-allowlisted host gets 403 and is recorded in
    `.denied`. Bind to an ephemeral port with port=0 and read `.url`.
    """

    def __init__(self, allow: set[str], *, host: str = "127.0.0.1", port: int = 0,
                 log_path: Path | str | None = None, idle_timeout: int = 600,
                 max_connections: int = 256):
        self.allow = set(allow)
        self.host = host
        self._want_port = port
        self.log_path = Path(log_path) if log_path else None
        # Tunnels get a finite idle timeout so an agent cannot pin threads/fds with
        # silent keep-alive CONNECTs; a semaphore caps concurrent connections.
        self.idle_timeout = idle_timeout
        self._sema = threading.BoundedSemaphore(max_connections)
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.denied: list[str] = []
        self.allowed: list[str] = []
        self.port = 0

    # -- lifecycle --
    def start(self) -> "AllowlistProxy":
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self._want_port))
        srv.listen(128)
        srv.settimeout(0.5)
        self._srv = srv
        self.port = srv.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._srv:
            self._srv.close()
            self._srv = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # -- internals --
    def _log(self, verdict: str, host: str) -> None:
        with self._lock:
            (self.denied if verdict == "DENY" else self.allowed).append(host)
        if self.log_path:
            ts = _dt.datetime.now(_dt.timezone.utc).isoformat()
            try:
                with self.log_path.open("a", encoding="utf-8") as fh:
                    fh.write(f"{ts} {verdict} {host}\n")
            except OSError:
                pass

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        if not self._sema.acquire(blocking=False):      # too many concurrent conns
            try:
                self._respond(conn, 503, "Proxy busy")
            finally:
                conn.close()
            return
        try:
            conn.settimeout(30)
            header = self._read_header(conn)          # raw bytes (forwarded as-is)
            if not header:
                return
            if b"\r\n\r\n" not in header:             # never completed / oversized
                self._respond(conn, 431, "Request Header Fields Too Large")
                return
            request_line = header.split(b"\r\n", 1)[0].decode("latin-1")
            parts = request_line.split(" ")
            if len(parts) < 2:
                self._respond(conn, 400, "Bad Request")
                return
            method, target = parts[0].upper(), parts[1]
            if method == "CONNECT":
                self._do_connect(conn, target)
            else:
                self._do_http(conn, method, target, header)
        except Exception:  # noqa: BLE001 -- a proxy must never crash the server on one bad conn
            pass
        finally:
            self._sema.release()
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _read_header(conn: socket.socket) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < _BUFSIZE:
            chunk = conn.recv(_BUFSIZE)
            if not chunk:
                break
            data += chunk
        return data

    def _respond(self, conn: socket.socket, code: int, msg: str) -> None:
        body = f"{code} {msg}\n".encode()
        conn.sendall(
            f"HTTP/1.1 {code} {msg}\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n".encode() + body)

    def _do_connect(self, conn: socket.socket, target: str) -> None:
        target = target.rsplit("@", 1)[-1]          # strip any userinfo
        host = target.rsplit(":", 1)[0]
        try:
            port = int(target.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            port = 443
        if not is_allowed(host, self.allow):
            self._log("DENY", host)
            self._respond(conn, 403, "Forbidden by e2e egress allowlist")
            return
        self._log("ALLOW", host)
        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError:
            self._respond(conn, 502, "Bad Gateway")
            return
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._pump(conn, upstream)

    def _do_http(self, conn: socket.socket, method: str, target: str, header: bytes) -> None:
        # absolute-form request line: METHOD http://host[:port]/path HTTP/x
        authority, path = "", "/"
        if "://" in target:
            rest = target.split("://", 1)[1]
            authority, _, rem = rest.partition("/")
            path = "/" + rem
        authority = authority.rsplit("@", 1)[-1]        # strip userinfo
        if not is_allowed(authority, self.allow):
            self._log("DENY", authority or target)
            self._respond(conn, 403, "Forbidden by e2e egress allowlist")
            return
        self._log("ALLOW", authority)
        hostname = authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority
        try:
            port = int(authority.rsplit(":", 1)[1]) if authority.count(":") == 1 else 80
        except ValueError:
            port = 80
        try:
            upstream = socket.create_connection((hostname, port), timeout=30)
        except OSError:
            self._respond(conn, 502, "Bad Gateway")
            return
        # Rewrite the request line to RFC origin-form; origin servers reject the
        # absolute-form a proxy receives. Headers/body after the first line are kept.
        first, sep, tail = header.partition(b"\r\n")
        bits = first.decode("latin-1").split(" ")
        proto = bits[2] if len(bits) >= 3 else "HTTP/1.1"
        upstream.sendall(f"{method} {path} {proto}".encode("latin-1") + sep + tail)
        self._pump(conn, upstream)

    def _pump(self, a: socket.socket, b: socket.socket) -> None:
        """Bidirectional byte pump until either side closes or goes idle past
        `idle_timeout` (so a silent tunnel cannot pin threads/fds forever)."""
        a.settimeout(self.idle_timeout)
        b.settimeout(self.idle_timeout)
        done = threading.Event()

        def one(src, dst):
            try:
                while not done.is_set():
                    data = src.recv(_BUFSIZE)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                done.set()
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t = threading.Thread(target=one, args=(b, a), daemon=True)
        t.start()
        one(a, b)
        t.join(timeout=5)
        b.close()


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description="cybergym-e2e agent egress firewall")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start", help="run the allowlist proxy in the foreground")
    s.add_argument("--port", type=int, default=3128)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--allowlist", default=None, help=f"default: {DEFAULT_ALLOWLIST}")
    s.add_argument("--log", default=None, help="append ALLOW/DENY decisions here")
    c = sub.add_parser("check", help="print whether a host would be allowed")
    c.add_argument("host")
    c.add_argument("--allowlist", default=None)
    args = ap.parse_args(argv[1:])

    allow = load_allowlist(args.allowlist)
    if args.cmd == "check":
        ok = is_allowed(args.host, allow)
        print(f"{'ALLOW' if ok else 'DENY '} {args.host}")
        return 0 if ok else 1
    if not allow:
        sys.stderr.write("refusing to start with an EMPTY allowlist (would deny all egress; "
                         "pass --allowlist or populate the default)\n")
        return 2
    proxy = AllowlistProxy(allow, host=args.host, port=args.port, log_path=args.log).start()
    print(f"e2e egress firewall on {proxy.url}  (allow: {', '.join(sorted(allow))})", flush=True)
    print(f"point the agent at it:  export HTTPS_PROXY={proxy.url} HTTP_PROXY={proxy.url}", flush=True)
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        proxy.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
