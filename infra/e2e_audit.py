"""Leakage / readiness audit for cybergym-e2e case bundles.

Two independent questions about one case bundle:

  * READY  -- is it a fully-converted e2e case the scorer can actually drive to
    accepted=true? (repo/ + witness/e2e_probe.py + a row-4 reference PoC +
    a non-empty row-3 public_tests). Delegates to repo_e2e_task.readiness_reasons
    so the discovery gate and the scorer cannot disagree.

  * LEAK-FREE -- does the payload the server would hand the agent (repo/ only)
    withhold EVERYTHING it must? The whole e2e contract rests on the agent seeing
    only vulnerable source: no oracle, no reference PoC, no fix, no NOTES, no
    witness/, no byte-identical copy of any of those under a different name, and no
    content that fingerprints THIS case's vulnerability (its CVE id / fix-commit).

The withheld-artifact check is DERIVED from the bundle's actual witness/ +
fix.patch + NOTES.md, not a hand-maintained denylist, so it auto-adapts to the
authoring contract and catches renamed copies by content hash.

`served_source_files` is the single source of truth for "what gets served" and is
imported by server.py, so this audit validates the real serving path.

CLI:  python3 e2e_audit.py <case_dir> [<case_dir> ...]   # non-zero if any bad
"""
from __future__ import annotations

import dataclasses
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import repo_e2e_task as scorer  # noqa: E402 -- single definition of readiness/spec helpers

# Directories never included in the served payload (build artifacts, VCS). Single
# definition lives in the scorer (also used when copying a pristine build tree).
SERVED_EXCLUDE_DIRS = scorer._ARTIFACT_DIRS
# Path components that must never appear in a served file's path.
_WITHHELD_PATH_PARTS = frozenset({"witness", ".git"})
# Bundle-root answer files (besides witness/) that must never reach the agent.
_ROOT_ANSWER_FILES = ("fix.patch", "NOTES.md")

_CVE_RE = re.compile(rb"CVE-\d{4}-\d{3,}", re.I)
# commit-ish hashes: 10-64 lowercase hex (covers git short/full and sha256). The
# lower bound keeps short hex tokens from becoming noisy false secrets.
_HASH_RE = re.compile(rb"\b[0-9a-f]{10,64}\b", re.I)
# Only scan the first N bytes of each file for secret tokens (hashing uses all).
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


def _witness_files(bundle: Path) -> list[Path]:
    w = bundle / "witness"
    return [p for p in sorted(w.rglob("*")) if p.is_file()] if w.is_dir() else []


def _withheld_answer_files(bundle: Path) -> list[Path]:
    """The files that must never reach the agent, AS THEY EXIST in this bundle:
    everything under witness/ plus the bundle-root fix.patch / NOTES.md. Used to
    derive both the name check and the byte-identical-copy check."""
    files = _witness_files(bundle)
    files += [bundle / name for name in _ROOT_ANSWER_FILES if (bundle / name).is_file()]
    return files


def _declared_secret_values(bundle: Path) -> set[bytes]:
    """Explicitly declared identifiers from build.yaml `vulnerability:` (preferred,
    exact, location-independent): e.g. `vulnerability: {cve: ..., fix_commit: ...}`
    (scalars or lists)."""
    out: set[bytes] = set()
    try:
        vuln = (scorer.load_spec(bundle).get("vulnerability") or {})
    except Exception:  # noqa: BLE001 -- unreadable build.yaml handled by readiness
        return out
    for key in ("cve", "cves", "fix_commit", "fix_commits"):
        v = vuln.get(key)
        if isinstance(v, str):
            out.add(v.encode())
        elif isinstance(v, (list, tuple)):
            out.update(str(x).encode() for x in v if x)
    return out


def _secret_tokens(bundle: Path, served_set: set) -> set[bytes]:
    """Case identifiers that must never reach the agent (lowercased bytes):
    (a) values DECLARED in build.yaml `vulnerability:` (exact, any location);
    (b) a regex fallback for undeclared cases -- CVE ids from every non-served
        file, and commit-ish hashes from NOTES.md only (a bare hex token can
        legitimately appear in both a fix.patch's context and the served source,
        so broad hash harvesting would false-positive)."""
    tokens: set[bytes] = set(_declared_secret_values(bundle))
    for f in bundle.rglob("*"):
        if not f.is_file() or f in served_set:
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


def _content_findings(served: list[Path], served_set: set, bundle: Path) -> tuple[list[str], list[str]]:
    """One read per served file: flag a byte-identical copy of any withheld answer
    file, flag content containing a case secret, and warn on stray (undeclared)
    CVE ids."""
    leaks, warnings = [], []
    withheld_hashes = {}
    for p in _withheld_answer_files(bundle):
        try:
            withheld_hashes[hashlib.sha256(p.read_bytes()).hexdigest()] = p.name
        except OSError:
            continue
    secrets = _secret_tokens(bundle, served_set)
    for path in served:
        rel = path.relative_to(bundle)
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        digest = hashlib.sha256(blob).hexdigest()
        if digest in withheld_hashes:
            leaks.append(f"{rel}: byte-identical copy of withheld {withheld_hashes[digest]}")
        head = blob[:_SCAN_MAX_BYTES]
        low = head.lower()
        for tok in secrets:
            idx = low.find(tok)
            if idx >= 0:
                original = head[idx:idx + len(tok)].decode("ascii", "replace")  # as it appears in the file
                leaks.append(f"{rel}: contains case secret {original}")
        for m in _CVE_RE.finditer(head):
            if m.group(0).lower() not in secrets:
                warnings.append(f"{rel}: stray CVE id {m.group(0).decode('ascii','replace')} "
                                "(not declared by this case; review)")
    return leaks, warnings


def audit_case(bundle: Path | str, *, scan_content: bool = True) -> AuditReport:
    """Audit one case. `scan_content=True` (default) reads every served file to
    catch byte-identical copies of withheld artifacts and case-secret content --
    the thorough pre-flight gate run by the CLI and certification. `scan_content=
    False` does only the cheap structural checks (readiness + withheld paths/names)
    and is what the server uses at discovery, so startup does not read every file
    of every large repo on each restart. Going live requires a full audit."""
    bundle = Path(bundle)
    served = served_source_files(bundle)
    served_set = set(served)
    leaks: list[str] = []
    warnings: list[str] = []

    # (1) structural (cheap): no withheld dir component, and no served file whose
    # NAME matches a real witness/ artifact in this bundle (derived, not hardcoded).
    witness_names = {p.name for p in _witness_files(bundle)}
    for path in served:
        rel = path.relative_to(bundle)
        if _WITHHELD_PATH_PARTS & set(rel.parts):
            leaks.append(f"{rel}: served path includes a withheld directory")
        elif rel.name in witness_names:
            leaks.append(f"{rel}: served file name matches a withheld witness artifact")

    # (2) content (expensive, reads files): byte-identical copies + secret tokens.
    if scan_content:
        content_leaks, content_warnings = _content_findings(served, served_set, bundle)
        leaks.extend(content_leaks)
        warnings.extend(content_warnings)

    reasons = scorer.readiness_reasons(bundle)
    served_bytes = sum(p.stat().st_size for p in served) if scan_content else 0
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
