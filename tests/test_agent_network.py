"""Regression tests for the agent's network isolation (Method 3): the agent
container must have NO route to anything except whatever is explicitly also
attached to its `--internal` network (e.g. the firewall-proxy container) --
not a cooperative HTTP_PROXY env-var convention it could choose to bypass.
Verified live on blk.so before this was written: a plain `curl` with no
`-x` flag, inside an agent-network container, failed to reach even a bare
IP address (http_code=000) -- this test locks in the same property without
depending on real internet access (so it stays meaningful offline/in CI):
a peer on an ORDINARY network is unreachable from the internal one, and a
peer explicitly attached to BOTH networks (what AgentFirewallContainer does)
is reachable from it.

Skipped where Docker isn't installed, or (for the tests that actually run a
container) where the `ubuntu:26.04` base image isn't already cached offline
-- same convention and same image as test_exec.py's real-docker test, so no
new image needs pulling just for this file.
"""
import shutil
import subprocess
import time
import uuid

import pytest

import e2e_exec

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")

_NET = f"e2e-agent-net-test-{uuid.uuid4().hex[:8]}"


def _image_available(img="ubuntu:26.04"):
    try:
        return subprocess.run(["docker", "image", "inspect", img],
                              capture_output=True, timeout=30).returncode == 0
    except Exception:  # noqa: BLE001
        return False


_needs_image = pytest.mark.skipif(not _image_available(), reason="no base image available offline")


def _test_image() -> str:
    """Build (or reuse the cache for) a minimal image via the SAME
    DockerBackend.prepare() path the real agent/scoring containers use --
    NOT the bare `ubuntu:26.04` Hub image directly. The bare image has no
    python3 (confirmed: `sh: 1: python3: not found`), and without some tool
    proven-present inside the container to actually test connectivity with,
    a "cannot reach" assertion would trivially pass because the exec itself
    failed to find python3 -- not because the network was isolated. Using
    prepare()'s own image (which always adds python3, see e2e_exec.py)
    avoids that false-positive class of bug and matches the real deployment."""
    be = e2e_exec.DockerBackend(network="none")
    be.prepare({"system_packages": []})
    return be._image


@pytest.fixture
def agent_net():
    subprocess.run(["docker", "network", "create", "--internal", _NET],
                   capture_output=True, timeout=15, check=True)
    yield _NET
    subprocess.run(["docker", "network", "rm", _NET], capture_output=True, timeout=15, check=False)


_LISTEN_PORT = 8000


def _run_sleeper(name, *, network, listen: bool = False):
    """A container that just sleeps, or (if `listen=True`) ALSO runs a tiny
    HTTP listener on _LISTEN_PORT. Tests that assert "cannot reach" need a
    REAL listener on the target to be meaningful -- connecting to a port
    with nothing listening fails with "connection refused" regardless of
    whether the network route exists at all, which would make the
    isolation test pass for the wrong reason (and pass just as "well" if
    isolation were completely broken)."""
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15, check=False)
    cmd = (f"python3 -m http.server {_LISTEN_PORT} & sleep 60"
          if listen else "sleep 60")
    subprocess.run(["docker", "run", "-d", "--name", name, "--network", network,
                    _test_image(), "sh", "-c", cmd], capture_output=True, timeout=120, check=True)
    if listen:
        time.sleep(1.5)  # let http.server actually bind before anyone connects


def _ip_of(name):
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
        capture_output=True, text=True, timeout=15, check=True)
    return out.stdout.strip()


def _can_connect(from_container, host, port=80, timeout_s=2):
    """True iff a TCP connect to (host, port) succeeds from inside
    `from_container`, using plain Python socket (portable -- no reliance on
    ping/curl/wget being installed in a bare base image, and no CAP_NET_RAW
    dependency the way ping would have)."""
    r = subprocess.run(
        ["docker", "exec", from_container, "python3", "-c",
         f"import socket,sys; s=socket.socket(); s.settimeout({timeout_s})\n"
         f"try:\n    s.connect(('{host}', {port}))\n    print('OK')\n"
         f"except Exception as e:\n    print('FAIL', e); sys.exit(1)"],
        capture_output=True, text=True, timeout=timeout_s + 5, check=False)
    return r.returncode == 0


def test_network_is_marked_internal(agent_net):
    out = subprocess.run(["docker", "network", "inspect", "-f", "{{.Internal}}", agent_net],
                         capture_output=True, text=True, timeout=15, check=True)
    assert out.stdout.strip() == "true"


@_needs_image
def test_internal_network_container_cannot_reach_ordinary_network_peer(agent_net):
    """A peer on the plain `bridge` network must be UNREACHABLE from a
    container on the `--internal` agent network -- this is the property
    AgentFirewallContainer relies on: nothing leaks a route to anything it
    wasn't explicitly attached to."""
    _run_sleeper("e2e-net-test-bridge-peer", network="bridge", listen=True)
    _run_sleeper("e2e-net-test-agent-peer", network=agent_net)
    try:
        peer_ip = _ip_of("e2e-net-test-bridge-peer")
        assert not _can_connect("e2e-net-test-agent-peer", peer_ip, port=_LISTEN_PORT), (
            f"agent-network container reached a bridge-network peer at {peer_ip} -- "
            "the internal network is leaking a route it shouldn't have"
        )
    finally:
        subprocess.run(["docker", "rm", "-f", "e2e-net-test-bridge-peer",
                        "e2e-net-test-agent-peer"], capture_output=True, timeout=15, check=False)


@_needs_image
def test_peer_attached_to_both_networks_is_reachable(agent_net):
    """The firewall-proxy container attaches to BOTH the internal agent
    network and `bridge` -- exactly the shape AgentFirewallContainer uses.
    A peer on the agent network must be able to reach it (by name), or the
    whole scheme can't forward allowlisted traffic at all."""
    _run_sleeper("e2e-net-test-bridge-only", network="bridge", listen=True)
    subprocess.run(["docker", "network", "connect", agent_net, "e2e-net-test-bridge-only"],
                   capture_output=True, timeout=15, check=True)
    _run_sleeper("e2e-net-test-agent-only", network=agent_net)
    try:
        assert _can_connect("e2e-net-test-agent-only", "e2e-net-test-bridge-only",
                            port=_LISTEN_PORT)
    finally:
        subprocess.run(["docker", "rm", "-f", "e2e-net-test-bridge-only",
                        "e2e-net-test-agent-only"], capture_output=True, timeout=15, check=False)


def test_ensure_agent_network_is_idempotent():
    name = e2e_exec.ensure_agent_network()
    try:
        name2 = e2e_exec.ensure_agent_network()  # must not error on a second call
        assert name == name2 == e2e_exec._AGENT_NETWORK
        out = subprocess.run(["docker", "network", "inspect", "-f", "{{.Internal}}", name],
                             capture_output=True, text=True, timeout=15, check=True)
        assert out.stdout.strip() == "true"
    finally:
        subprocess.run(["docker", "network", "rm", e2e_exec._AGENT_NETWORK],
                       capture_output=True, timeout=15, check=False)
