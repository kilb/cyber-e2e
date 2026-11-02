#!/usr/bin/env python3
"""Observe-only e2e oracle for the toy self-test case.

Interface (invoked by the framework, see docs/case-authoring.md):

    python3 -I -B e2e_probe.py observe <poc_filename> <tree_path>

cwd is a private copy of witness/ with <poc_filename> present in it. <tree_path>
is a built tree (the vulnerable tree OR the agent's patched tree -- this script
must NOT assume which). It runs the already-built target against the PoC and
prints exactly one JSON line {"faulted": bool, "detail": {...}}.

`faulted` is true ONLY when THE SPECIFIC synthetic bug fired: an AddressSanitizer
report that implicates an allowlisted source token (`process` / `prog.c`) with an
overflow fault class. An unrelated crash, a clean run, or a timeout is NOT a
reproduction. The script observes; it never synthesizes or mutates the PoC.
"""
import json
import subprocess
import sys
from pathlib import Path

ALLOWLIST_FRAMES = ("process", "prog.c")      # the specific vulnerable function/file
FAULT_CLASS_TOKENS = ("stack-buffer-overflow", "global-buffer-overflow",
                      "heap-buffer-overflow", "dynamic-stack-buffer-overflow")
TARGET_REL = ".rrg-build/bin/prog"
RUN_TIMEOUT = 60


def observe(poc_name: str, tree: str) -> dict:
    binary = Path(tree) / TARGET_REL
    if not binary.is_file():
        return {"faulted": False, "detail": {"error": f"target not built: {binary}"}}
    poc = Path(poc_name)
    if not poc.is_file():
        return {"faulted": False, "detail": {"error": f"poc not found in closure: {poc_name}"}}
    try:
        done = subprocess.run(
            [str(binary), str(poc.resolve())],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=RUN_TIMEOUT, check=False,
            # Deterministic sanitizer behavior; report (not silent abort) to stderr.
            env={"ASAN_OPTIONS": "abort_on_error=0:exitcode=99:detect_leaks=0",
                 "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        )
    except subprocess.TimeoutExpired:
        return {"faulted": False, "detail": {"timeout": RUN_TIMEOUT}}

    err = done.stderr or ""
    is_asan = "AddressSanitizer" in err
    frame = next((f for f in ALLOWLIST_FRAMES if f in err), None)
    fault_class = next((t for t in FAULT_CLASS_TOKENS if t in err), None)
    faulted = bool(is_asan and frame and fault_class)
    return {
        "faulted": faulted,
        "detail": {
            "returncode": done.returncode,
            "asan": is_asan,
            "frame": frame,
            "fault_class": fault_class,
        },
    }


def main(argv: list) -> int:
    if len(argv) != 4 or argv[1] != "observe":
        sys.stderr.write("usage: e2e_probe.py observe <poc_filename> <tree_path>\n")
        return 2
    sys.stdout.write(json.dumps(observe(argv[2], argv[3])) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
