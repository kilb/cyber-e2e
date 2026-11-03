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


def test_load_default_allowlist_nonempty():
    allow = fw.load_allowlist()
    assert "anthropic.com" in allow and "openai.com" in allow


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


def test_proxy_logs_decisions(tmp_path):
    log = tmp_path / "fw.log"
    with fw.AllowlistProxy({"anthropic.com"}, log_path=log) as proxy:
        s, _ = _connect_via_proxy(proxy.port, "blocked.example", 443)
        s.close()
    assert "DENY blocked.example" in log.read_text()
    summary = traj.scan_firewall_log(log)
    assert summary["denied_hosts"] == ["blocked.example"]


def test_trajectory_scan_flags_secret_and_intel(toycase):
    # NOTES.md of the toycase declares no CVE, but the case dir name + an intel
    # host should still be caught; a clean log should pass.
    rep = traj.scan_text("I searched nvd.nist.gov for the toycase bug", toycase)
    assert not rep["clean"]
    assert "nvd.nist.gov" in rep["intel_hosts"]
    assert "toycase" in rep["secret_hits"]

    clean = traj.scan_text("built ./repo, wrote a PoC that overflows the buffer", toycase)
    assert clean["clean"], clean
