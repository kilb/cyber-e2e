"""Leakage / readiness audit for cybergym-e2e case bundles.

Two independent questions about one case bundle:

  * READY  -- is it a fully-converted e2e case the scorer can actually drive to
    accepted=true? (repo/ + witness/e2e_probe.py + a row-4 reference PoC +
    a non-empty row-3 public_tests). Mirrors the server's discovery gate.

  * LEAK-FREE -- does the payload the server would hand the agent (repo/ only)
    withhold EVERYTHING it must? The whole e2e contract rests on the agent
    seeing only vulnerable source: no oracle, no reference PoC, no fix, no NOTES,
    no witness/, and no file content that fingerprints THIS case's vulnerability
    (its declared CVE id / fix-commit hash).

`served_source_files` is the single source of truth for "what gets served" and
is imported by server.py, so this audit validates the real serving path, not a
copy of its logic.

CLI:  python3 e2e_audit.py <case_dir> [<case_dir> ...]   # non-zero if any bad
"""
from __future__ import annotations

import dataclasses
import hashlib
import re
import sys
from pathlib import Path

# Directories never included in the served payload (build artifacts, VCS).
SERVED_EXCLUDE_DIRS = frozenset({".git", ".rrg-build", ".tmp"})

# Answer artifacts that must never appear inside the served repo/ tree. Matched by
# EXACT basename / distinctive prefix (not substring), so ordinary source files
# like `probe.py` or `narrow_window.c` are not wrongly flagged. These prefixes are
# this harness's own artifact names and are vanishingly unlikely to collide with
# real project source.
_ANSWER_EXACT_NAMES = frozenset({"e2e_probe.py"})
_ANSWER_NAME_PREFIXES = ("model_poc", "narrow_patch", "narrow_poc")
# Names that MIGHT be an answer artifact but are plausible real source -> warning.
_SUSPICIOUS_EXACT_NAMES = frozenset({"probe.py"})
_ANSWER_PATH_PARTS = frozenset({"witness", ".git"})

_CVE_RE = re.compile(rb"CVE-\d{4}-\d{3,}", re.I)
# commit-ish hashes: 10-64 lowercase hex (covers git short/full and sha256). The
# lower bound keeps short hex tokens from becoming noisy false secrets.
_HASH_RE = re.compile(rb"\b[0-9a-f]{10,64}\b", re.I)


def _is_answer_name(name: str) -> bool:
    return name in _ANSWER_EXACT_NAMES or name.startswith(_ANSWER_NAME_PREFIXES)
# Only scan plausibly-text files for secret tokens (cap per-file read size).
_SCAN_MAX_BYTES = 1_000_000


@dataclasses.dataclass
class AuditReport:
    case_id: str
    ready: bool
    reasons: list        # why NOT ready (empty iff ready)
    leaks: list          # hard leaks (empty iff leak-free)
    warnings: list       # soft findings for human review
    served_count: int
    served_bytes: int

    @property
    def ok(self) -> bool:
        return self.ready and not self.leaks


def served_source_files(bundle: Path | str) -> list[Path]:
    """Exactly the files the server packs into source.zip: every file under
    repo/, minus build-artifact/VCS directories. Absolute paths, sorted."""
    bundle = Path(bundle)
    repo = bundle / "repo"
    if not repo.is_dir():
        return []
    out = []
    for path in sorted(repo.rglob("*")):
        if not path.is_file():
            continue
        if SERVED_EXCLUDE_DIRS & set(path.relative_to(repo).parts):
            continue
        out.append(path)
    return out


def case_fingerprint(bundle: Path | str) -> str:
    """A content hash of exactly what the agent is served (repo/ only), so a run
    can be tied to the precise tree it used and tree-drift between runs is
    detectable. Stable across machines (relative paths + bytes, sorted)."""
    bundle = Path(bundle)
    h = hashlib.sha256()
    for path in served_source_files(bundle):
        rel = path.relative_to(bundle).as_posix().encode()
        h.update(len(rel).to_bytes(4, "big"))
        h.update(rel)
        data = path.read_bytes()
        h.update(len(data).to_bytes(8, "big"))
        h.update(data)
    return h.hexdigest()


def _declared_public_tests(bundle: Path) -> list:
    import yaml
    spec = yaml.safe_load((bundle / "build.yaml").read_text(encoding="utf-8"))
    return list((spec.get("recipe") or {}).get("public_tests") or [])


def _readiness(bundle: Path) -> list[str]:
    """Granular reasons the case is NOT e2e-ready (empty list == ready)."""
    reasons = []
    if not (bundle / "repo").is_dir():
        reasons.append("missing repo/ (vulnerable source tree)")
    if not (bundle / "witness" / "e2e_probe.py").is_file():
        reasons.append("missing witness/e2e_probe.py (the oracle)")
    if not sorted((bundle / "witness").glob("model_poc_reference.*")):
        reasons.append("missing witness/model_poc_reference.* (row-4 reference PoC)")
    if not (bundle / "build.yaml").is_file():
        reasons.append("missing build.yaml")
    else:
        try:
            if not _declared_public_tests(bundle):
                reasons.append("empty recipe.public_tests (row-3 suite not authored)")
        except Exception as exc:  # noqa: BLE001
            reasons.append(f"unreadable build.yaml: {exc}")
    return reasons


def _secret_tokens(bundle: Path) -> set[bytes]:
    """Case-specific identifiers that must never reach the agent, harvested from
    the server-side (NOT served) material: CVE ids from every non-served file
    (NOTES.md, fix.patch, build.yaml, witness/...), and commit-ish hashes from
    NOTES.md only. Hashes are restricted to NOTES.md on purpose: a hex constant
    could legitimately appear both in a fix.patch's context lines and in the
    served vulnerable source, so harvesting hashes broadly would false-positive."""
    served = set(served_source_files(bundle))
    tokens: set[bytes] = set()
    for f in bundle.rglob("*"):
        if not f.is_file() or f in served:
            continue
        if ".git" in f.relative_to(bundle).parts:
            continue
        try:
            raw = f.read_bytes()[:_SCAN_MAX_BYTES]
        except OSError:
            continue
        tokens.update(m.group(0) for m in _CVE_RE.finditer(raw))
        if f.name == "NOTES.md":
            tokens.update(m.group(0) for m in _HASH_RE.finditer(raw))
    return {t.lower() for t in tokens}


def _scan_content(served: list[Path], bundle: Path) -> tuple[list[str], list[str]]:
    leaks, warnings = [], []
    secrets = _secret_tokens(bundle)  # lowercased
    for path in served:
        rel = path.relative_to(bundle)
        try:
            blob = path.read_bytes()[:_SCAN_MAX_BYTES]
        except OSError:
            continue
        # CVE ids: a declared one is a hard leak; an undeclared one is a warning.
        for m in _CVE_RE.finditer(blob):
            tok = m.group(0).decode("ascii", "replace")
            if m.group(0).lower() in secrets:
                leaks.append(f"{rel}: contains case secret {tok}")
            else:
                warnings.append(f"{rel}: stray CVE id {tok} (not declared by this case; review)")
        # commit-ish hashes: only a DECLARED one is a leak (undeclared hex is noise).
        for m in _HASH_RE.finditer(blob):
            if m.group(0).lower() in secrets:
                tok = m.group(0).decode("ascii", "replace")
                leaks.append(f"{rel}: contains case secret {tok}")
    return leaks, warnings


def audit_case(bundle: Path | str, *, scan_content: bool = True) -> AuditReport:
    """Audit one case. `scan_content=True` (default) reads every served file to
    catch case-secret / stray-CVE content leaks -- the thorough pre-flight gate
    run by the CLI and certification. `scan_content=False` does only the cheap
    structural checks (readiness + answer-artifact paths/names) and is what the
    server uses at discovery, so startup does not read every file of every large
    repo on each restart. Going live requires a full (scan_content=True) audit."""
    bundle = Path(bundle)
    served = served_source_files(bundle)
    leaks: list[str] = []
    warnings: list[str] = []

    # (1) answer artifacts served to the agent (cheap: path/name only)
    for path in served:
        rel = path.relative_to(bundle)
        if _ANSWER_PATH_PARTS & set(rel.parts):
            leaks.append(f"{rel}: served path includes a withheld directory")
        if _is_answer_name(rel.name):
            leaks.append(f"{rel}: served file looks like an answer artifact")
        elif rel.name in _SUSPICIOUS_EXACT_NAMES:
            warnings.append(f"{rel}: served file name resembles an answer artifact (review)")

    # (2) case-specific secrets / stray CVEs in served content (expensive: reads files)
    if scan_content:
        content_leaks, content_warnings = _scan_content(served, bundle)
        leaks.extend(content_leaks)
        warnings.extend(content_warnings)

    reasons = _readiness(bundle)
    served_bytes = sum(p.stat().st_size for p in served)
    return AuditReport(
        case_id=bundle.name,
        ready=not reasons,
        reasons=reasons,
        leaks=sorted(set(leaks)),
        warnings=sorted(set(warnings)),
        served_count=len(served),
        served_bytes=served_bytes,
    )


def main(argv: list) -> int:
    cases = argv[1:]
    if not cases:
        sys.stderr.write("usage: e2e_audit.py <case_dir> [<case_dir> ...]\n")
        return 2
    worst = 0
    for c in cases:
        rep = audit_case(c)
        status = "OK   " if rep.ok else ("LEAK " if rep.leaks else "RAW  ")
        print(f"[{status}] {rep.case_id}  served={rep.served_count} files "
              f"({rep.served_bytes} B)")
        for r in rep.reasons:
            print(f"    not-ready: {r}")
        for leak in rep.leaks:
            print(f"    LEAK: {leak}")
        for w in rep.warnings:
            print(f"    warn: {w}")
        if not rep.ok:
            worst = 1
    return worst


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
