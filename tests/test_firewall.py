"""Egress firewall + trajectory-scan tests.

Allowlist decisions are unit-tested; the proxy is exercised live over loopback:
an allowlisted CONNECT tunnels bytes to a local echo server, a non-allowlisted
one gets 403 without connecting.
"""
import socket
import threading

import e2e_firewall as fw
import e2e_trajectory as traj


def test_is_allowed_suffix_and_failclosed():
    allow = {"anthropic.com", "openai.com"}
    assert fw.is_allowed("api.anthropic.com", allow)
    assert fw.is_allowed("anthropic.com", allow)
    assert fw.is_allowed("API.Anthropic.Com:443", allow)       # case + port
    assert not fw.is_allowed("notanthropic.com", allow)        # not a subdomain
    assert not fw.is_allowed("anthropic.com.evil.com", allow)  # suffix-trick blocked
    assert not fw.is_allowed("github.com", allow)
    assert not fw.is_allowed("anything", set())                # empty == deny all


def test_is_allowed_strips_userinfo():
    allow = {"anthropic.com"}
    # host is what follows the last '@': a real anthropic host is allowed...
    assert fw.is_allowed("user@api.anthropic.com", allow)
    # ...but an allowlisted-looking USERINFO with a non-allowlisted host is denied
    assert not fw.is_allowed("api.anthropic.com@evil.com", allow)


def test_load_default_allowlist_is_minimal_single_tenant():
    allow = fw.load_allowlist()
    assert "api.anthropic.com" in allow and "api.openai.com" in allow
    # the shared-cloud apexes must NOT be present (they'd open any bucket/relay)
    assert "googleapis.com" not in allow and "amazonaws.com" not in allow
    assert not fw.is_allowed("my-bucket.s3.amazonaws.com", allow)
    assert not fw.is_allowed("storage.googleapis.com", allow)
    assert fw.is_allowed("generativelanguage.googleapis.com", allow)
    assert not fw.is_allowed("", set())


def test_proxy_env_overlay():
    env = fw.proxy_env("http://127.0.0.1:3128", {"PATH": "/x", "NO_PROXY": "keep"})
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:3128"
    assert env["http_proxy"] == "http://127.0.0.1:3128"
    assert env["NO_PROXY"] == "" and env["no_proxy"] == ""  # nothing bypasses
    assert env["PATH"] == "/x"


def _echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            data = c.recv(4096)
            c.sendall(data)
            c.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv, port


def _connect_via_proxy(proxy_port, target_host, target_port):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    s.sendall(f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
              f"Host: {target_host}:{target_port}\r\n\r\n".encode())
    resp = s.recv(1024)
    return s, resp


def test_proxy_allows_allowlisted_connect_and_tunnels():
    echo, eport = _echo_server()
    try:
        with fw.AllowlistProxy({"127.0.0.1"}) as proxy:
            s, resp = _connect_via_proxy(proxy.port, "127.0.0.1", eport)
            assert b"200" in resp.split(b"\r\n", 1)[0], resp
            s.sendall(b"ping")
            assert s.recv(16) == b"ping"            # bytes really tunneled
            s.close()
            assert "127.0.0.1" in proxy.allowed
    finally:
        echo.close()


def test_proxy_denies_non_allowlisted_connect():
    echo, eport = _echo_server()
    try:
        with fw.AllowlistProxy({"anthropic.com"}, log_path=None) as proxy:
            s, resp = _connect_via_proxy(proxy.port, "127.0.0.1", eport)
            assert b"403" in resp.split(b"\r\n", 1)[0], resp
            s.close()
            assert proxy.denied == ["127.0.0.1"]
    finally:
        echo.close()


def _recording_server():
    """A one-shot TCP server that records the first request line it receives."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    seen = []

    def serve():
        try:
            c, _ = srv.accept()
        except OSError:
            return
        data = c.recv(4096)
        seen.append(data.split(b"\r\n", 1)[0])
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv, port, seen


def test_http_forward_rewrites_to_origin_form():
    rec, rport, seen = _recording_server()
    try:
        with fw.AllowlistProxy({"127.0.0.1"}) as proxy:
            s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            # a client sends ABSOLUTE-form to a proxy; the origin must receive ORIGIN-form
            s.sendall(f"GET http://127.0.0.1:{rport}/foo?x=1 HTTP/1.1\r\n"
                      f"Host: 127.0.0.1:{rport}\r\n\r\n".encode())
            s.recv(256)
            s.close()
    finally:
        rec.close()
    assert seen and seen[0] == b"GET /foo?x=1 HTTP/1.1", seen


def test_pump_idle_timeout_closes_tunnel():
    echo, eport = _echo_server()
    try:
        with fw.AllowlistProxy({"127.0.0.1"}, idle_timeout=1) as proxy:
            s, resp = _connect_via_proxy(proxy.port, "127.0.0.1", eport)
            assert b"200" in resp
            s.settimeout(5)
            # send nothing; the idle timeout must tear the tunnel down -> client sees EOF
            assert s.recv(16) == b""
            s.close()
    finally:
        echo.close()


def test_oversized_header_gets_431():
    with fw.AllowlistProxy({"anthropic.com"}) as proxy:
        s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        s.sendall(b"GET http://api.anthropic.com/ HTTP/1.1\r\nX-Big: " + b"A" * 70000)
        s.settimeout(5)
        resp = s.recv(256)
        s.close()
    assert b"431" in resp.split(b"\r\n", 1)[0], resp


def test_proxy_logs_decisions(tmp_path):
    log = tmp_path / "fw.log"
    with fw.AllowlistProxy({"anthropic.com"}, log_path=log) as proxy:
        s, _ = _connect_via_proxy(proxy.port, "blocked.example", 443)
        s.close()
    assert "DENY blocked.example" in log.read_text()
    summary = traj.scan_firewall_log(log)
    assert summary["denied_hosts"] == ["blocked.example"]


def test_trajectory_flags_intel_hosts_incl_fix_sources(toycase):
    # intel hosts that the OLD substring set missed must now be caught
    for host in ("raw.githubusercontent.com", "git.kernel.org",
                 "chromium.googlesource.com", "sourceware.org"):
        rep = traj.scan_text(f"I fetched the fix from https://{host}/x", toycase)
        assert rep["intel_hosts"] and not rep["clean"], (host, rep)


def test_trajectory_does_not_flag_project_name(toycase):
    # the agent legitimately sees (and names) the project in the served source, so
    # the case/project name must NOT be treated as a leak signal
    rep = traj.scan_text("rebuilt toycase from ./repo and ran the fuzzer", toycase)
    assert rep["clean"], rep


def test_trajectory_flags_declared_secret(tmp_path):
    bundle = tmp_path / "somecase"
    (bundle / "witness").mkdir(parents=True)
    (bundle / "build.yaml").write_text(
        "vulnerability:\n  cve: CVE-2024-9999\n  fix_commit: 3c832b523ee1a1b2\n",
        encoding="utf-8")
    rep = traj.scan_text("I referenced CVE-2024-9999 and commit 3c832b523ee1a1b2", bundle)
    assert not rep["clean"]
    assert "cve-2024-9999" in rep["secret_hits"] and "3c832b523ee1a1b2" in rep["secret_hits"]
