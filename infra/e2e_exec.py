"""Execution backends for the scorer's build / test / oracle steps.

The scorer runs three kinds of subprocess: a shell build command, a shell test
command, and the per-case oracle (a python invocation). A backend abstracts WHERE
those run:

  * HostBackend (default) -- directly on the host, inheriting its toolchain/env.
    Simple; fine for a trusted, controlled box. Current behavior.
  * DockerBackend ("plan B") -- inside a container built from a base image + the
    case's declared `system_packages` (installed once, image cached by content).
    Gives per-project toolchain isolation, reproducibility, a real containment
    boundary for untrusted patches/PoCs, and enforceable network policy. Build AND
    oracle run in the SAME image, so a binary built there also runs there (ABI match).

Backends take an `env` of INTENDED overrides (the case's build.yaml `environment`
plus TMPDIR); HostBackend layers those over os.environ, DockerBackend applies them
to a clean container env (no host env leakage -> more reproducible).
"""
from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
import threading
import uuid
from collections import namedtuple
from pathlib import Path

ExecResult = namedtuple("ExecResult", "returncode stdout stderr")

_PROBE = "e2e_probe.py"


def _run_group_killed(cmd, *, shell: bool, cwd, env: dict, timeout: int,
                      stdin=None) -> ExecResult:
    """subprocess.run equivalent that kills the WHOLE process group on timeout,
    not just the directly-spawned process. `subprocess.run(..., timeout=...)`
    only SIGKILLs the one PID it spawned; a command that forks or backgrounds
    children (a parallel `make -j`, a hung child of the target binary under
    test) leaves those children running past the timeout -- free to keep
    mutating a tree a LATER trial reuses (e.g. `CaseContext`'s cached
    vulnerable tree), or to keep consuming resources indefinitely. Re-raises
    `subprocess.TimeoutExpired` exactly as `subprocess.run` would (same
    exception type/semantics for every existing caller), just with the group
    actually cleaned up first."""
    proc = subprocess.Popen(  # noqa: S602,S603 -- trusted bundle recipe / oracle
        cmd, shell=shell, cwd=cwd, env=env, text=True, stdin=stdin,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,  # own process group, so killpg reaches descendants
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()  # reap + drain pipes so nothing leaks a zombie/fd
        raise
    return ExecResult(proc.returncode, stdout, stderr)


class HostBackend:
    name = "host"
    _warned = False

    def _warn_once(self) -> None:
        # Nothing in this module enforces that untrusted agent-submitted
        # patch/PoC content runs under DockerBackend instead of this one -- a
        # caller that leaves `backend=None` (the default throughout
        # repo_e2e_task.py) silently compiles and executes that content
        # directly on the host with full process privileges. That's a
        # deliberate, documented tradeoff for a trusted/controlled box, not a
        # bug to "fix" by changing the default -- but it should never be a
        # SILENT one. Warn once per process, on first actual use (not merely
        # on construction -- `HOST` is a module-level singleton instantiated
        # at import time regardless of whether it's ever actually invoked).
        if not HostBackend._warned:
            print("[e2e_exec] WARNING: HostBackend executes agent-submitted "
                  "patch/PoC content directly on the host, with NO sandboxing "
                  "(cap-drop/pids/memory/cpu limits only apply to DockerBackend). "
                  "Use backend='docker' for any untrusted/adversarial run.",
                  file=sys.stderr)
            HostBackend._warned = True

    def prepare(self, spec: dict) -> None:
        pass

    def run_shell(self, command: str, *, cwd, env: dict, timeout: int) -> ExecResult:
        self._warn_once()
        return _run_group_killed(command, shell=True, cwd=cwd,
                                 env={**os.environ, **env}, timeout=timeout)

    def run_oracle(self, closure, tree, probe: str, poc_name: str, *, env: dict, timeout: int) -> ExecResult:
        self._warn_once()
        return _run_group_killed(
            [sys.executable, "-I", "-B", probe, "observe", poc_name, str(tree)],
            shell=False, cwd=closure, env={**os.environ, **env}, timeout=timeout,
            stdin=subprocess.DEVNULL)


# Images are content-addressed by (base, package-set); build once, reuse across
# cases/jobs/threads. Locking is PER-KEY (not one global lock) so an unrelated
# image build never blocks behind this one -- the global lock used to be held
# for the full `_build_image` call (up to `build_timeout`, default 1800s),
# serializing every concurrent build regardless of key and defeating the
# parallelism the benchmark driver is built for.
_image_cache: dict[str, str] = {}
# Exported rootfs directories, by image tag -- see DockerBackend.export_rootfs.
_rootfs_cache: dict[str, Path] = {}
_image_locks: dict[str, threading.Lock] = {}
_image_locks_guard = threading.Lock()


def _lock_for(key: str) -> threading.Lock:
    with _image_locks_guard:
        lock = _image_locks.get(key)
        if lock is None:
            lock = _image_locks[key] = threading.Lock()
        return lock


# Generous-but-real ceilings, not unlimited -- see DockerBackend.__init__.
_DEFAULT_DOCKER_MEMORY = "8g"
_DEFAULT_DOCKER_CPUS = "4"


class DockerBackend:
    name = "docker"

    def __init__(self, base_image: str = "ubuntu:26.04", network: str = "none",
                 docker: str = "docker", build_timeout: int = 1800,
                 *, pids_limit: int = 1024, memory: str | None = _DEFAULT_DOCKER_MEMORY,
                 cpus: str | None = _DEFAULT_DOCKER_CPUS,
                 cpuset_cpus: str | None | bool = True, cap_drop: bool = True,
                 no_new_privs: bool = True):
        self.base_image = base_image
        self.network = network
        self.docker = docker
        self.build_timeout = build_timeout
        # Containment for untrusted patch/PoC code executing during build/run.
        self.pids_limit = pids_limit          # cap fork-bombs
        # memory/cpus default to a generous-but-real ceiling, not unlimited:
        # cap-drop/no-new-privs/pids-limit being on by default while memory/cpus
        # were silently unbounded meant a submitted patch/PoC doing a single-
        # process huge allocation or CPU spin (no forking, so pids_limit alone
        # doesn't help) was completely unconstrained on any deployment that
        # didn't separately export E2E_DOCKER_MEMORY/CPUS. Pass memory=None /
        # cpus=None explicitly to opt back out for a case with real heavy
        # build needs.
        self.memory = memory                  # e.g. "4g" (None => unlimited)
        self.cpus = cpus                      # e.g. "2"  (None => unlimited)
        # `--cpus` alone is CFS quota/period throttling: it slows the container
        # down but does NOT change what nproc()/sched_getaffinity() report
        # inside it, which still see the HOST's full core count. A case's own
        # build.sh (`jobs=${RRG_BUILD_JOBS:-$(nproc)}`) then launches e.g.
        # `make -j24` inside a container only entitled to 4 CPUs' worth of CFS
        # time -- severe throttling, builds run far slower than correctly-sized
        # parallelism would, raising the odds of a spurious timeout under
        # concurrency (the exact failure mode `--cpus` was meant to prevent).
        # `--cpuset-cpus` pins the container to an actual, small CPU set, so
        # nproc() inside it honestly reports that count and `-j$(nproc)`
        # self-sizes correctly. `True` (default) auto-derives a range from
        # `cpus` when it's a plain integer (e.g. cpus="4" -> "0-3"); pass an
        # explicit string to pin a specific set, or False/None to disable
        # (accepting the nproc-overreports-capacity gap) for a case that
        # genuinely needs to see the real core count.
        if cpuset_cpus is True:
            try:
                n = int(cpus) if cpus else 0
            except ValueError:
                n = 0
            cpuset_cpus = f"0-{n - 1}" if n > 1 else ("0" if n == 1 else None)
        elif cpuset_cpus is False:
            cpuset_cpus = None
        self.cpuset_cpus = cpuset_cpus
        self.cap_drop = cap_drop              # drop all Linux capabilities
        self.no_new_privs = no_new_privs      # block setuid privilege escalation
        self._image: str | None = None

    # -- image (plan B: base + declared system_packages, python3 for the oracle) --
    def prepare(self, spec: dict) -> None:
        pkgs = sorted(set(spec.get("system_packages") or []) | {"python3", "ca-certificates"})
        key = hashlib.sha256(("|".join([self.base_image, *pkgs])).encode()).hexdigest()[:16]
        tag = _image_cache.get(key)
        if tag is None:
            # Lock PER KEY, not globally: two threads building DIFFERENT
            # (base, package-set) images must not serialize behind each other.
            with _lock_for(key):
                tag = _image_cache.get(key)  # re-check: another thread may have
                if tag is None:              # finished this exact build while
                    tag = f"cybergym-e2e-planb:{key}"  # we were waiting for the lock
                    self._build_image(tag, pkgs)
                    _image_cache[key] = tag
        self._image = tag

    def _build_image(self, tag: str, pkgs: list) -> None:
        dockerfile = (
            f"FROM {self.base_image}\n"
            "ENV DEBIAN_FRONTEND=noninteractive\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends "
            + " ".join(pkgs) +
            " && rm -rf /var/lib/apt/lists/*\n"
        )
        p = subprocess.run([self.docker, "build", "-t", tag, "-"],
                           input=dockerfile, capture_output=True, text=True,
                           timeout=self.build_timeout, check=False)
        if p.returncode != 0:
            raise RuntimeError(f"docker image build failed for {tag}: {p.stderr[-1500:]}")

    def _base_args(self, env: dict, mounts: list, *, name: str) -> list:
        uid, gid = os.getuid(), os.getgid()
        # --name lets a timed-out run be force-stopped by name (see run_shell/
        # run_oracle): `docker run` with no `-d` blocks the CLIENT while the
        # container runs server-side in the daemon, so killing the client
        # process on a client-side subprocess timeout does NOT stop the
        # container -- it keeps running, still bind-mounted read-write onto
        # the same host paths, until something explicitly stops it.
        args = [self.docker, "run", "--rm", "--name", name,
                "--network", self.network, "--user", f"{uid}:{gid}"]
        # Containment flags: these constrain a maliciously-crafted patch/PoC that
        # executes during build/test/oracle. Kept conservative so real builds work
        # (no --read-only; memory/cpus opt-in).
        if self.cap_drop:
            args += ["--cap-drop", "ALL"]
        if self.no_new_privs:
            args += ["--security-opt", "no-new-privileges"]
        if self.pids_limit:
            args += ["--pids-limit", str(self.pids_limit)]
        if self.memory:
            args += ["--memory", str(self.memory)]
        if self.cpus:
            args += ["--cpus", str(self.cpus)]
        if self.cpuset_cpus:
            args += ["--cpuset-cpus", str(self.cpuset_cpus)]
        for m in mounts:
            m = Path(m).resolve()
            args += ["-v", f"{m}:{m}"]
        # HOME in a writable mounted dir (an arbitrary --user has no /etc/passwd home)
        args += ["-e", f"HOME={Path(mounts[0]).resolve()}"]
        for k, v in env.items():
            args += ["-e", f"{k}={v}"]
        return args

    def _ensure_image(self, spec_hint=None):
        if self._image is None:
            raise RuntimeError("DockerBackend.prepare(spec) must be called before running")

    def export_rootfs(self, cache_dir: Path) -> Path:
        """Export this backend's prepared image's filesystem to a plain
        directory on disk (`docker create` + `docker export` + tar
        extraction), cached by image tag so repeat calls for the same
        (base_image, packages) key reuse it. This is NOT for running
        anything -- the build/test/oracle steps still use the live
        container via run_shell/run_oracle. It exists to give
        infra/sandbox_wrapper.sh a case-specific-MINIMAL root filesystem
        (just the declared `system_packages`, nothing else) to bind the
        agent's OWN process against, instead of the live host's real
        /usr/bin/lib -- which also carries whatever else happens to be
        installed on a shared host (another project's own tools, etc.)."""
        self._ensure_image()
        key = self._image
        dest = _rootfs_cache.get(key)
        if dest is not None and dest.is_dir():
            return dest
        with _lock_for(f"rootfs:{key}"):
            dest = _rootfs_cache.get(key)
            if dest is not None and dest.is_dir():
                return dest
            dest = cache_dir / key.replace(":", "_").replace("/", "_")
            if not (dest / "usr").is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                cid = subprocess.run([self.docker, "create", self._image],
                                     capture_output=True, text=True, timeout=60,
                                     check=True).stdout.strip()
                try:
                    export = subprocess.run([self.docker, "export", cid],
                                            capture_output=True, timeout=self.build_timeout,
                                            check=True)
                    subprocess.run(["tar", "-xf", "-", "-C", str(dest)],
                                   input=export.stdout, timeout=self.build_timeout, check=True)
                finally:
                    subprocess.run([self.docker, "rm", "-f", cid],
                                   capture_output=True, timeout=30, check=False)
            _rootfs_cache[key] = dest
            return dest

    def _run_container(self, cmd: list, *, name: str, timeout: int) -> ExecResult:
        """Run a `docker run ...` command, and on a client-side timeout,
        explicitly `docker kill` the named container before re-raising --
        otherwise it keeps running in the daemon indefinitely (see the --name
        comment in `_base_args`)."""
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            subprocess.run([self.docker, "kill", name], capture_output=True,
                           timeout=30, check=False)
            raise
        return ExecResult(p.returncode, p.stdout, p.stderr)

    def run_shell(self, command: str, *, cwd, env: dict, timeout: int) -> ExecResult:
        self._ensure_image()
        cwd = Path(cwd).resolve()
        name = f"e2e-shell-{uuid.uuid4().hex[:12]}"
        cmd = [*self._base_args(env, [cwd], name=name), "-w", str(cwd), self._image,
               "sh", "-c", command]
        return self._run_container(cmd, name=name, timeout=timeout)

    def run_oracle(self, closure, tree, probe: str, poc_name: str, *, env: dict, timeout: int) -> ExecResult:
        self._ensure_image()
        closure = Path(closure).resolve()
        tree = Path(tree).resolve()
        name = f"e2e-oracle-{uuid.uuid4().hex[:12]}"
        cmd = [*self._base_args(env, [closure, tree], name=name), "-w", str(closure), self._image,
               "python3", "-I", "-B", probe, "observe", poc_name, str(tree)]
        return self._run_container(cmd, name=name, timeout=timeout)

    def run_agent(self, cli_argv: list, *, work_dir, env: dict, timeout: int,
                 proxy_url: str, agent_log) -> ExecResult:
        """Run the agent CLI itself (e.g. `claude --model X -p PROMPT
        --dangerously-skip-permissions`) in a FRESH container on the
        isolated agent network -- true containment (Method 3): nothing from
        the host is visible except (a) the trial's own work dir -- the ONE
        bind mount, read-write, also HOME (so `~/.claude`'s session data
        lands at `work_dir/.claude`, already host-persistent because the
        whole work_dir is bind-mounted -- no separate bind needed, and it
        survives this container's `--rm`) -- and (b) the `claude` CLI binary
        itself, read-only, bind-mounted from wherever it's installed on this
        host (the per-case image doesn't need its own copy baked in).
        Network is the `--internal` agent network (see ensure_agent_network)
        -- the only reachable peer is the firewall-proxy container at
        `proxy_url`; this is real network-layer enforcement, not a
        cooperative HTTP_PROXY convention the agent could bypass. The REAL
        model credential goes in `env` directly (no credential-indirection
        proxy -- the network isolation is what bounds where it could ever be
        used from, not hiding it from the sandboxed process)."""
        self._ensure_image()
        work_dir = Path(work_dir).resolve()
        (work_dir / ".claude").mkdir(parents=True, exist_ok=True)
        ensure_agent_network(self.docker)
        name = f"e2e-agent-{uuid.uuid4().hex[:12]}"
        uid, gid = os.getuid(), os.getgid()
        claude_bin = Path(os.environ.get(
            "E2E_CLAUDE_BIN", str(Path.home() / ".local/bin/claude"))).resolve()
        claude_share = Path(os.environ.get(
            "E2E_CLAUDE_SHARE", str(Path.home() / ".local/share/claude")))

        args = [self.docker, "run", "--rm", "--name", name,
                "--network", _AGENT_NETWORK, "--user", f"{uid}:{gid}"]
        if self.cap_drop:
            args += ["--cap-drop", "ALL"]
        if self.no_new_privs:
            args += ["--security-opt", "no-new-privileges"]
        if self.pids_limit:
            args += ["--pids-limit", str(self.pids_limit)]
        if self.memory:
            args += ["--memory", str(self.memory)]
        if self.cpus:
            args += ["--cpus", str(self.cpus)]
        if self.cpuset_cpus:
            args += ["--cpuset-cpus", str(self.cpuset_cpus)]
        args += ["-v", f"{work_dir}:{work_dir}", "-e", f"HOME={work_dir}"]
        if claude_bin.is_file():
            args += ["-v", f"{claude_bin}:/usr/local/bin/claude:ro"]
        if claude_share.is_dir():
            args += ["-v", f"{claude_share}:{claude_share}:ro"]
        args += ["-e", f"HTTP_PROXY={proxy_url}", "-e", f"HTTPS_PROXY={proxy_url}",
                 "-e", "NO_PROXY=", "-e", "no_proxy="]
        for k, v in env.items():
            args += ["-e", f"{k}={v}"]
        args += ["-w", str(work_dir), self._image, *cli_argv]

        try:
            with open(agent_log, "w") as lf:
                p = subprocess.run(args, stdout=lf, stderr=subprocess.STDOUT,  # noqa: S603
                                   stdin=subprocess.DEVNULL, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            subprocess.run([self.docker, "kill", name], capture_output=True,
                           timeout=30, check=False)
            raise
        return ExecResult(p.returncode, "", "")


_AGENT_NETWORK = "e2e-agent-net"


def ensure_agent_network(docker: str = "docker") -> str:
    """Idempotently create the `--internal` Docker network agent containers
    run on. `--internal` means Docker gives this network NO route to the
    outside world at all -- not a cooperative HTTP_PROXY env-var convention
    an agent process could choose to ignore (verified live: without this, a
    plain `curl` with no `-x` flag reached the open internet directly even
    though HTTP_PROXY was set), an actually-missing network route. The only
    peer reachable from containers on this network is whatever else is
    explicitly ALSO attached to it -- see AgentFirewallContainer, the one
    bridge between this network and the real internet by construction."""
    exists = subprocess.run([docker, "network", "inspect", _AGENT_NETWORK],
                            capture_output=True, timeout=15, check=False)
    if exists.returncode != 0:
        subprocess.run([docker, "network", "create", "--internal", _AGENT_NETWORK],
                       capture_output=True, timeout=15, check=True)
    return _AGENT_NETWORK


class AgentFirewallContainer:
    """A containerized instance of e2e_firewall.py's AllowlistProxy, attached
    to BOTH the internal agent network (so agent containers can reach it)
    and the normal externally-reaching `bridge` network (so it can actually
    forward allowlisted traffic) -- this one container is the ONLY bridge
    between the two, by construction; nothing else on the internal network
    can reach the outside world at all."""

    def __init__(self, *, allowlist_path, log_path, docker: str = "docker",
                name: str = "e2e-agent-firewall", proxy_image: str = "python:3.12-slim"):
        self.docker = docker
        self.name = name
        self.proxy_image = proxy_image
        self.firewall_script = Path(__file__).resolve().parent / "e2e_firewall.py"
        self.allowlist_path = Path(allowlist_path).resolve()
        self.log_path = Path(log_path).resolve()  # MUST be host-persistent storage

    def ensure_running(self) -> str:
        """Idempotent: start the container if it isn't already running.
        Returns the proxy URL agent containers should use (resolved by
        Docker's embedded DNS for container names on a shared network)."""
        running = subprocess.run(
            [self.docker, "inspect", "-f", "{{.State.Running}}", self.name],
            capture_output=True, text=True, timeout=15, check=False)
        if running.returncode != 0 or running.stdout.strip() != "true":
            subprocess.run([self.docker, "rm", "-f", self.name],
                           capture_output=True, timeout=15, check=False)
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self.log_path.touch(exist_ok=True)
            subprocess.run([
                self.docker, "run", "-d", "--name", self.name,
                "--network", "bridge",
                "-v", f"{self.allowlist_path}:/allowlist.txt:ro",
                "-v", f"{self.log_path}:/firewall.log",
                "-v", f"{self.firewall_script}:/e2e_firewall.py:ro",
                self.proxy_image,
                "python3", "/e2e_firewall.py", "start",
                "--port", "3128", "--host", "0.0.0.0",
                "--allowlist", "/allowlist.txt", "--log", "/firewall.log",
            ], capture_output=True, timeout=60, check=True)
            net = ensure_agent_network(self.docker)
            subprocess.run([self.docker, "network", "connect", net, self.name],
                           capture_output=True, timeout=15, check=False)
        return f"http://{self.name}:3128"

    def stop(self) -> None:
        subprocess.run([self.docker, "rm", "-f", self.name],
                       capture_output=True, timeout=15, check=False)


def make_backend(kind: str | None = None, *, base_image: str | None = None,
                 network: str | None = None):
    """Factory from a kind string / env. kind defaults to $E2E_BACKEND or 'host'.
    Docker config falls back to $E2E_BASE_IMAGE and $E2E_DOCKER_NETWORK."""
    kind = kind or os.environ.get("E2E_BACKEND", "host")
    if kind == "host":
        return HostBackend()
    if kind == "docker":
        return DockerBackend(
            base_image=base_image or os.environ.get("E2E_BASE_IMAGE", "ubuntu:26.04"),
            network=network or os.environ.get("E2E_DOCKER_NETWORK", "none"),
            # `or None` here would silently throw away DockerBackend's own
            # sane (non-unlimited) memory/cpus defaults whenever the env var
            # isn't set -- fall back to those same defaults, not None, so this
            # factory path is bounded by default too.
            memory=os.environ.get("E2E_DOCKER_MEMORY") or _DEFAULT_DOCKER_MEMORY,
            cpus=os.environ.get("E2E_DOCKER_CPUS") or _DEFAULT_DOCKER_CPUS,
            cpuset_cpus=os.environ.get("E2E_DOCKER_CPUSET") or True,
            pids_limit=int(os.environ.get("E2E_DOCKER_PIDS", "1024") or "1024"))
    raise ValueError(f"unknown backend kind: {kind!r}")


HOST = HostBackend()  # module default singleton

__all__ = ["ExecResult", "HostBackend", "DockerBackend", "make_backend", "HOST"]
