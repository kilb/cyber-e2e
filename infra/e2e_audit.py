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
import re
import sys
from pathlib import Path

# Directories never included in the served payload (build artifacts, VCS).
SERVED_EXCLUDE_DIRS = frozenset({".git", ".rrg-build", ".tmp"})

# Answer artifacts that must never appear inside the served repo/ tree.
_ANSWER_NAME_RE = re.compile(r"(e2e_probe|model_poc|narrow_patch|probe\.py|fix\.patch|NOTES\.md)", re.I)
_ANSWER_PATH_PARTS = frozenset({"witness", ".git"})

_CVE_RE = re.compile(rb"CVE-\d{4}-\d{3,}", re.I)
_HASH_RE = re.compile(rb"\b[0-9a-f]{12,40}\b", re.I)
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
    """Case-specific identifiers that must never reach the agent: CVE ids and
    commit-ish hashes declared in server-side NOTES.md / fix.patch filenames."""
    tokens: set[bytes] = set()
    notes = bundle / "NOTES.md"
    if notes.is_file():
        raw = notes.read_bytes()
        tokens.update(m.group(0) for m in _CVE_RE.finditer(raw))
        tokens.update(m.group(0) for m in _HASH_RE.finditer(raw))
    # normalize to lowercase bytes for case-insensitive matching
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


def audit_case(bundle: Path | str) -> AuditReport:
    bundle = Path(bundle)
    served = served_source_files(bundle)
    leaks: list[str] = []

    # (1) answer artifacts served to the agent
    for path in served:
        rel = path.relative_to(bundle)
        if _ANSWER_PATH_PARTS & set(rel.parts):
            leaks.append(f"{rel}: served path includes a withheld directory")
        if _ANSWER_NAME_RE.search(rel.name):
            leaks.append(f"{rel}: served file looks like an answer artifact")

    # (2) case-specific secrets / stray CVEs in served content
    content_leaks, warnings = _scan_content(served, bundle)
    leaks.extend(content_leaks)

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
