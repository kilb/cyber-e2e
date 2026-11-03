# Per-case authoring contract (GLM worker)

The framework in `infra/` is vulnerability-agnostic plumbing. Everything that
encodes the actual vulnerability -- the oracle that decides "the right bug
triggered", the ground-truth reference PoC, the real build and the real upstream
test suite -- is per-case content authored by the GLM worker. This doc is the
interface those per-case files must satisfy. The framework calls them; it never
contains their logic.

## Directory layout of one e2e case

```
cases/<case-id>/
  repo/                       # the vulnerable source tree (the ONLY thing the agent sees)
  build.yaml                  # how to build repo/ + how to run the project's own tests
  witness/
    e2e_probe.py              # THE ORACLE: `observe <poc_file> <tree>` -> {"faulted": bool, ...}
    model_poc_reference.<ext> # ground-truth reference PoC for the real vulnerability
  NOTES.md                    # (optional, server-side only) real CVE, fix commit, mechanism
```

Note there is **no `task.md`** and **no `fix.patch` exposed to the agent**. A
real fix patch may be kept server-side under `witness/` or `NOTES.md` purely as
reference material for building `e2e_probe.py` / the reference PoC and for your
own regression checks -- but it is never served and never used by the scorer
(row 2/4 use the AGENT's patch, not ours). The scorer builds nothing from a
stored fix.patch.

## build.yaml

Same schema as the sibling project, with `recipe.public_tests` now LOAD-BEARING
(it is row 3):

```yaml
system_packages: [bash, gcc, make, python3, ...]
environment: { LC_ALL: C.UTF-8, ... }
recipe:
  configure: [ ... ]          # commands to configure the build (cwd = tree root)
  build:     [ sh build.sh ]  # commands to build the target (cwd = tree root)
  public_tests:               # row 3: the project's OWN regression/unit tests
    - sh run_upstream_tests.sh # each command must exit 0 on a correct tree
```

Row 3 is the hardest part to get right and the main new work vs the sibling
PoC-gen cases: `public_tests` must run the REAL upstream test suite (or a
faithful, non-trivial subset of it), so that a patch which fixes the bug but
breaks functionality is correctly rejected. A stub that always passes defeats
the whole point of the e2e contract. If a case cannot carry a real test suite,
it is not e2e-ready and the scorer will reject every submission at row 3.

### Optional: declare the vulnerability identifiers (recommended)

Add a server-side `vulnerability:` block so the leak audit treats these exact
values as secrets regardless of where they appear in `repo/` (otherwise the audit
falls back to scraping CVE ids from non-served files and fix-commit hashes from
`NOTES.md` only):

```yaml
vulnerability:
  cve: CVE-2026-12345        # or a list; omit if none assigned
  fix_commit: 3c832b523ee1…  # the upstream fix commit (full hash preferred)
```

This is never served to the agent (build.yaml is withheld); it only sharpens the
leak check. `e2e_audit` also flags any served file that is a byte-identical copy
of a withheld artifact (oracle / reference PoC / fix.patch / NOTES.md), so a
renamed copy cannot slip through.

## witness/e2e_probe.py  (THE ORACLE -- GLM authors this)

A standalone, importless-safe script run by the framework as:

```
python3 -I -B e2e_probe.py observe <poc_filename> <tree_path>
```

* cwd is a private copy of `witness/` (the "closure"), with the PoC file present
  in cwd under `<poc_filename>`. `<tree_path>` is an absolute path to a built
  source tree (either the vulnerable tree or the agent's patched tree -- the
  probe must NOT assume which).
* It must build nothing that needs the network, run the target against the PoC,
  observe the target process, and print exactly one JSON line to stdout:

  ```json
  {"faulted": true, "detail": {"signal": "SIGABRT", "asan": "heap-use-after-free", "frame": "pjsip_ice_...", ...}}
  ```

* `faulted` is the single load-bearing boolean the framework consumes. It must
  be true ONLY when THE SPECIFIC target vulnerability triggered -- not merely any
  crash anywhere. Use a frame/function/file-specific signal (the same
  specificity discipline the sibling project's probes use: the ASan report must
  implicate an allowlisted source token, not just match a fault class), so that
  an unrelated crash does not count as a reproduction.
* The probe is invoked three times per submission by the framework:
  row1 (submitted PoC vs vulnerable tree, expect faulted=true),
  row2 (submitted PoC vs patched tree, expect faulted=false),
  row4 (reference PoC vs patched tree, expect faulted=false).
  It must be deterministic and side-effect-free across these calls.

## witness/model_poc_reference.<ext>  (ground-truth reference PoC -- GLM authors)

The independent, authoritative PoC for the real vulnerability, in the same form
the agent submits (its suffix defines the submitted PoC's temp filename). Used
for row 4: it must fault the vulnerable tree (verify this when authoring) and
must stop faulting once a CORRECT fix is applied -- that is what makes row 4
catch a narrow agent patch that only defeats the agent's own PoC.

## Certification before a case goes live (authoritative, via the real scorer)

Never trust a self-report. Before a case is accepted into the live set, the
coordinator (Claude) re-runs the real scorer on controls:

* reference-as-submission with the REAL fix patch as the submitted patch
  -> must score accepted=true (all 4 rows hold).
* a no-op / empty patch -> must score rejected (row2/row4 fail: PoC still faults).
* a narrow patch that only neutralizes the reference PoC's exact input but not
  the vulnerability class -> must score rejected (row4 or row3 fails).

These mirror the sibling project's reference+negative certification, extended
for the patch dimension. Claude runs this certification; GLM authors the
per-case files it certifies.

## Optional per-case enhancements (framework-supported)

These are optional files/keys the framework honors when present; a case without
them behaves exactly as before.

### Multiple reference PoCs (stronger row 4)

Ship more than one `witness/model_poc_reference.*` (e.g.
`model_poc_reference.bin`, `model_poc_reference.2.bin`). Row 4 then requires the
agent's patch to defeat **every** reference PoC — a patch that only neutralizes
one specific ground-truth input is rejected. The first (sorted) reference is the
"primary" used as the patch-only given input and the certify submission.

### witness/crash.log (patch-only given input)

In **patch-only** mode upstream provides source + crash log + PoC. If a case
ships `witness/crash.log`, the server serves it as `crash.log` alongside
`poc.bin` in patch-only downloads. It stays **withheld in e2e** (it is under
`witness/`, so the audit withholds it and byte-identical-copy detection applies).
Author it as the real sanitizer/crash trace for the vulnerability.

### build.yaml `public_id` (task-id masking)

The agent must not be able to derive the project/CVE from the id it is served.
Declare an opaque id and the server advertises **that** instead of the directory
name, mapping it back internally:

```yaml
public_id: task-7f3a2c         # opaque; never the project/CVE name
```

Absent one, the directory name is used (backward compatible). Keep the directory
name off the served tree regardless (the audit warns on stray identifiers).

### system_packages must be container-complete

With the Docker backend, `system_packages` is installed into a **clean** base
image, so declare everything the build needs — e.g. `build-essential` (not bare
`gcc`, which lacks the libc headers in a clean container). Host mode treats the
list as a precondition (the host already has a toolchain).
