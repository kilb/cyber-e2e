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
import subprocess
import sys
import threading
from collections import namedtuple
from pathlib import Path

ExecResult = namedtuple("ExecResult", "returncode stdout stderr")

_PROBE = "e2e_probe.py"


class HostBackend:
    name = "host"

    def prepare(self, spec: dict) -> None:
        pass

    def run_shell(self, command: str, *, cwd, env: dict, timeout: int) -> ExecResult:
        p = subprocess.run(  # noqa: S602 -- trusted bundle recipe
            command, shell=True, cwd=cwd, env={**os.environ, **env},
            capture_output=True, text=True, timeout=timeout, check=False)
        return ExecResult(p.returncode, p.stdout, p.stderr)

    def run_oracle(self, closure, tree, probe: str, poc_name: str, *, env: dict, timeout: int) -> ExecResult:
        p = subprocess.run(  # noqa: S603 -- trusted per-case oracle, isolated interp
            [sys.executable, "-I", "-B", probe, "observe", poc_name, str(tree)],
            cwd=closure, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=timeout, check=False, env={**os.environ, **env})
        return ExecResult(p.returncode, p.stdout, p.stderr)


# Images are content-addressed by (base, package-set); build once, reuse across
# cases/jobs/threads.
_image_cache: dict[str, str] = {}
_image_lock = threading.Lock()


class DockerBackend:
    name = "docker"

    def __init__(self, base_image: str = "ubuntu:24.04", network: str = "none",
                 docker: str = "docker", build_timeout: int = 1800,
                 *, pids_limit: int = 1024, memory: str | None = None,
                 cpus: str | None = None, cap_drop: bool = True,
                 no_new_privs: bool = True):
        self.base_image = base_image
        self.network = network
        self.docker = docker
        self.build_timeout = build_timeout
        # Containment for untrusted patch/PoC code executing during build/run.
        self.pids_limit = pids_limit          # cap fork-bombs
        self.memory = memory                  # e.g. "4g" (None => unlimited)
        self.cpus = cpus                      # e.g. "2"  (None => unlimited)
        self.cap_drop = cap_drop              # drop all Linux capabilities
        self.no_new_privs = no_new_privs      # block setuid privilege escalation
        self._image: str | None = None

    # -- image (plan B: base + declared system_packages, python3 for the oracle) --
    def prepare(self, spec: dict) -> None:
        pkgs = sorted(set(spec.get("system_packages") or []) | {"python3", "ca-certificates"})
        key = hashlib.sha256(("|".join([self.base_image, *pkgs])).encode()).hexdigest()[:16]
        with _image_lock:
            tag = _image_cache.get(key)
            if tag is None:
                tag = f"cybergym-e2e-planb:{key}"
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

    def _base_args(self, env: dict, mounts: list) -> list:
        uid, gid = os.getuid(), os.getgid()
        args = [self.docker, "run", "--rm", "--network", self.network,
                "--user", f"{uid}:{gid}"]
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

    def run_shell(self, command: str, *, cwd, env: dict, timeout: int) -> ExecResult:
        self._ensure_image()
        cwd = Path(cwd).resolve()
        cmd = [*self._base_args(env, [cwd]), "-w", str(cwd), self._image, "sh", "-c", command]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return ExecResult(p.returncode, p.stdout, p.stderr)

    def run_oracle(self, closure, tree, probe: str, poc_name: str, *, env: dict, timeout: int) -> ExecResult:
        self._ensure_image()
        closure = Path(closure).resolve()
        tree = Path(tree).resolve()
        cmd = [*self._base_args(env, [closure, tree]), "-w", str(closure), self._image,
               "python3", "-I", "-B", probe, "observe", poc_name, str(tree)]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return ExecResult(p.returncode, p.stdout, p.stderr)


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
            memory=os.environ.get("E2E_DOCKER_MEMORY") or None,
            cpus=os.environ.get("E2E_DOCKER_CPUS") or None,
            pids_limit=int(os.environ.get("E2E_DOCKER_PIDS", "1024") or "1024"))
    raise ValueError(f"unknown backend kind: {kind!r}")


HOST = HostBackend()  # module default singleton

__all__ = ["ExecResult", "HostBackend", "DockerBackend", "make_backend", "HOST"]
