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

    def __init__(self, base_image: str = "ubuntu:24.04", network: str = "none",
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


def make_backend(kind: str | None = None, *, base_image: str | None = None,
                 network: str | None = None):
    """Factory from a kind string / env. kind defaults to $E2E_BACKEND or 'host'.
    Docker config falls back to $E2E_BASE_IMAGE and $E2E_DOCKER_NETWORK."""
    kind = kind or os.environ.get("E2E_BACKEND", "host")
    if kind == "host":
        return HostBackend()
    if kind == "docker":
        return DockerBackend(
            base_image=base_image or os.environ.get("E2E_BASE_IMAGE", "ubuntu:24.04"),
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
