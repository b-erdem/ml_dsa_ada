#!/usr/bin/env python3
"""SPARK workspace governance tool.

Single-file, standard-library only. Run from anywhere; it locates the
workspace root (the directory that holds CONSTITUTION.md) automatically.

    python3 governance/governance.py <command> [options]

Commands
    scan          flag constitutional violations across registered crates
    index         regenerate (or --check) the decision-log index
    ledger        regenerate PROOF_STATUS.md from manifests + proof evidence
    audit         emit a deep-audit prompt (modes A-D) to paste into an agent
    install-hooks point each crate's git core.hooksPath at .githooks

A crate is *registered* with the workspace governance iff it contains a
`.governance.toml` manifest. The manifest declares the crate's profile and any
scoped, justified exceptions. See CONSTITUTION.md and docs/governance/ for the
rules enforced here, and docs/governance/exceptions-policy.md for the manifest.

This tool mechanically checks the regex-detectable subset of the constitution
(P2, P3, P9, P10, P11, P12). The judgement-heavy principles (P1, P4, P5, P6, P7,
P8) are covered by the `audit` process, not by `scan`.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

# --------------------------------------------------------------------------- #
# Workspace-wide invariants (P11 — cross-crate coherence).                     #
# --------------------------------------------------------------------------- #
WORKSPACE_LICENSE = "Apache-2.0"
WORKSPACE_EMAIL = "baris@erdem.dev"

ALL_PRINCIPLES = [f"P{i}" for i in range(1, 13)]

# Which principles a profile is held to. A principle absent from a profile's set
# is *structurally not applicable* (e.g. a Python tool has no SPARK proof bar) —
# distinct from a per-crate [[exceptions]] waiver, which is a deliberate, logged
# departure from an otherwise-applicable rule.
PROFILE_PRINCIPLES: dict[str, set[str]] = {
    "proved-crypto":   set(ALL_PRINCIPLES),
    "proved-protocol": set(ALL_PRINCIPLES),
    "ada-tool":        set(ALL_PRINCIPLES) - {"P1", "P2", "P4"},
    "python-tool":     {"P7", "P8", "P10", "P11", "P12"},
    "gh-action":       {"P8", "P10", "P11", "P12"},
    "spec":            {"P8", "P11", "P12"},
    "meta":            {"P11", "P12"},
    "incubating":      set(),  # registered only; exempt from release gates
}

# Files each profile must ship (P12 — every crate is self-describing).
PROFILE_REQUIRED_FILES: dict[str, list[str]] = {
    "proved-crypto":   ["README.md", "CHANGELOG.md", "LICENSE", "SECURITY.md", ".governance.toml"],
    "proved-protocol": ["README.md", "CHANGELOG.md", "LICENSE", "SECURITY.md", ".governance.toml"],
    "ada-tool":        ["README.md", "CHANGELOG.md", "LICENSE", ".governance.toml"],
    "python-tool":     ["README.md", "LICENSE", "SECURITY.md", ".governance.toml"],
    "gh-action":       ["README.md", "LICENSE", ".governance.toml"],
    "spec":            ["README.md", "LICENSE", ".governance.toml"],
    "meta":            ["README.md", ".governance.toml"],
    "incubating":      [".governance.toml"],
}

PRINCIPLE_NAMES = {
    "P1": "Proof is the product",
    "P2": "Claims backed by committed evidence",
    "P3": "No unjustified assumptions",
    "P4": "Constant-time discipline for secrets",
    "P5": "Validate at the boundary, fail closed",
    "P6": "One canonical representation",
    "P7": "Honest qualification and security posture",
    "P8": "Public contracts are versioned",
    "P9": "Dependencies pinned and minimal",
    "P10": "Reproducible, artifact-clean builds",
    "P11": "Cross-crate coherence",
    "P12": "Every crate is self-describing",
}

INDEX_BEGIN = "<!-- INDEX:BEGIN -->"
INDEX_END = "<!-- INDEX:END -->"

# Build/throwaway artifacts that must never be committed (P10).
ARTIFACT_RE = re.compile(r"\.(ali|o|so|obj|gcno|gcda|pyc)$|(^|/)(obj|__pycache__|alire/cache)/")
DEC_CITE_RE = re.compile(r"DEC-\d+")


# --------------------------------------------------------------------------- #
# Data model.                                                                  #
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    principle: str
    blocking: bool
    crate: str
    path: str          # relative to the crate, or "" for crate-level findings
    line: int          # 1-based, or 0 if not line-specific
    msg: str
    excepted: bool = False


@dataclass
class Crate:
    name: str
    path: Path
    profile: str
    published: bool = True
    gpr: str | None = None
    claimed_level: object = 0          # 0 | 1 | 2 | "flow"
    claimed_vcs: int | None = None
    exceptions: set[str] = field(default_factory=set)   # principle IDs waived
    raw: dict = field(default_factory=dict)

    @property
    def is_git(self) -> bool:
        return (self.path / ".git").exists()

    def applies(self, principle: str) -> bool:
        return principle in PROFILE_PRINCIPLES.get(self.profile, set())

    def waived(self, principle: str) -> bool:
        return principle in self.exceptions


# --------------------------------------------------------------------------- #
# Discovery and small helpers.                                                 #
# --------------------------------------------------------------------------- #
def find_root(start: Path | None = None) -> Path:
    """Walk upward from this file (or `start`) to the dir holding CONSTITUTION.md."""
    here = (start or Path(__file__)).resolve()
    for d in [here, *here.parents]:
        if (d / "CONSTITUTION.md").exists() and (d / "governance").is_dir():
            return d
    # Fallback: the parent of governance/ (lets the tool run before the
    # constitution exists, e.g. during bootstrap).
    return Path(__file__).resolve().parent.parent


def load_crate(d: Path) -> Crate | None:
    manifest = d / ".governance.toml"
    if not manifest.is_file():
        return None
    try:
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:  # pragma: no cover
        print(f"  [ERROR] {d.name}/.governance.toml: {exc}", file=sys.stderr)
        return None
    exc_ids = {str(e.get("principle", "")).upper()
               for e in data.get("exceptions", []) if e.get("principle")}
    return Crate(
        name=data.get("name", d.name),
        path=d,
        profile=data.get("profile", "meta"),
        published=bool(data.get("published", True)),
        gpr=data.get("gpr"),
        claimed_level=data.get("claimed_proof_level", 0),
        claimed_vcs=data.get("claimed_vcs"),
        exceptions=exc_ids,
        raw=data,
    )


def find_crates(root: Path, only: Path | None = None) -> list[Crate]:
    if only is not None:
        c = load_crate(only.resolve())
        return [c] if c else []
    crates = []
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        c = load_crate(d)
        if c:
            crates.append(c)
    return crates


def git_tracked(crate: Crate) -> list[str]:
    if not crate.is_git:
        return []
    try:
        out = subprocess.run(
            ["git", "-C", str(crate.path), "ls-files"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        return out.stdout.splitlines()
    except (OSError, subprocess.SubprocessError):  # pragma: no cover
        return []


def crate_source_files(crate: Crate) -> list[Path]:
    """Committed Ada spec/body files, excluding tests, build output, and worktrees."""
    def keep(rel: str) -> bool:
        if not (rel.endswith(".ads") or rel.endswith(".adb")):
            return False
        if "/test" in f"/{rel}" or "obj/" in f"/{rel}":
            return False
        # skip dotted dirs (.git, .claude/worktrees, …) and vendored caches
        return not any(seg.startswith(".") for seg in rel.split("/")) and "alire/cache" not in rel

    if crate.is_git:
        return [crate.path / rel for rel in git_tracked(crate) if keep(rel)]
    return sorted(p for p in crate.path.rglob("*.ad[sb]")
                  if keep(p.relative_to(crate.path).as_posix()))


def proof_summary(crate: Crate) -> Path | None:
    """Committed proof evidence wins; fall back to a fresh local run's output."""
    for cand in (crate.path / "proof" / "gnatprove.out",
                 crate.path / "proof" / "summary.txt",
                 crate.path / "obj" / "gnatprove" / "gnatprove.out"):
        if cand.is_file():
            return cand
    return None


def parse_gnatprove_total(out_file: Path) -> tuple[int, int] | None:
    """Return (total_checks, unproved) from a gnatprove.out summary table.

    The summary's columns vary (Flow/Interval/CodePeer/Provers/Justified/Unproved),
    empty cells render as ".", and counts carry a "(NN%)" suffix — so we align the
    "Total" data row to the header and read the Total and Unproved columns by name.
    """
    try:
        text = out_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    header = next((l for l in lines if "Total" in l and "Unproved" in l), None)
    data = next((l for l in lines if re.match(r"^\s*Total\b", l)), None)
    if header and data:
        cols = header.split()
        try:
            i_tot, i_un = cols.index("Total"), cols.index("Unproved")
        except ValueError:
            i_tot = None
        if i_tot is not None:
            vals = re.sub(r"\([^)]*\)", "", data).split()[1:]  # drop label + "(NN%)"
            span = cols[i_tot:i_un + 1]
            if len(vals) >= len(span):
                num = lambda t: 0 if t == "." else (int(t) if t.lstrip("-").isdigit() else 0)
                return num(vals[0]), num(vals[len(span) - 1])
    # summary.txt fallback: key=value pairs
    m_tot = re.search(r"vcs?\s*=\s*(\d+)", text, re.I)
    m_un = re.search(r"unproved\s*=\s*(\d+)", text, re.I)
    if m_tot:
        return int(m_tot.group(1)), int(m_un.group(1)) if m_un else 0
    return None


# --------------------------------------------------------------------------- #
# scan — the mechanical checks.                                                #
# --------------------------------------------------------------------------- #
def check_required_files(crate: Crate) -> list[Finding]:
    if not crate.applies("P12"):
        return []
    out = []
    for fname in PROFILE_REQUIRED_FILES.get(crate.profile, []):
        if not (crate.path / fname).exists():
            out.append(Finding("P12", True, crate.name, fname, 0,
                               f"missing required file {fname!r} for profile {crate.profile} (P12)",
                               excepted=crate.waived("P12")))
    return out


def check_artifacts(crate: Crate) -> list[Finding]:
    if not crate.applies("P10"):
        return []
    hits = [rel for rel in git_tracked(crate) if ARTIFACT_RE.search(rel)]
    if not hits:
        return []
    eg = hits[0] + (f" (+{len(hits) - 1} more)" if len(hits) > 1 else "")
    return [Finding("P10", True, crate.name, "", 0,
                   f"{len(hits)} build artifact(s) committed to git, e.g. {eg} — "
                   "keep the tree artifact-clean (P10)", excepted=crate.waived("P10"))]


def check_alire(crate: Crate) -> list[Finding]:
    if not crate.applies("P9"):
        return []
    alire = crate.path / "alire.toml"
    if not alire.is_file():
        return []
    out = []
    lines = alire.read_text(encoding="utf-8", errors="replace").splitlines()
    for i, line in enumerate(lines, 1):
        excepted = crate.waived("P9") or bool(DEC_CITE_RE.search(line))
        if re.match(r'^\s*[A-Za-z0-9_]+\s*=\s*"\*"\s*$', line):
            out.append(Finding("P9", True, crate.name, "alire.toml", i,
                               "bare wildcard dependency (= \"*\") — pin with ^ or ~ (P9)", excepted))
        if re.search(r'=\s*\{\s*path\s*=', line) and crate.published:
            out.append(Finding("P9", True, crate.name, "alire.toml", i,
                               "sibling-path [[pins]] in a published crate — remove before release (P9)", excepted))
    return out


def check_proof_evidence(crate: Crate) -> list[Finding]:
    if not crate.applies("P2") or not crate.published:
        return []
    level = crate.claimed_level
    # A numeric level >= 1 or an explicit VC count is a proof claim that needs
    # committed evidence (P2). A "flow"-only declaration is recorded, not VC-backed.
    claims_proof = (isinstance(level, int) and level >= 1) or bool(crate.claimed_vcs)
    if not claims_proof:
        return []
    if proof_summary(crate) is None:
        return [Finding("P2", True, crate.name, "", 0,
                        f"claims proof (level {level!r}"
                        + (f", {crate.claimed_vcs} VCs" if crate.claimed_vcs else "")
                        + ") but no committed proof/ evidence — claim is unbacked (P2)",
                        excepted=crate.waived("P2"))]
    return []


def check_assumptions(crate: Crate) -> list[Finding]:
    if not crate.applies("P3"):
        return []
    out = []
    comment = re.compile(r"(^|\s)--")  # an Ada comment on a line
    for f in crate_source_files(crate):
        rel = f.relative_to(crate.path).as_posix()
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            if re.search(r"\bpragma\s+Assume\b", line, re.I):
                # The statement may span several lines; collect up to its ';'.
                end = i
                while end < len(lines) and end < i + 12 and ";" not in lines[end]:
                    end += 1
                stmt = " ".join(lines[i:end + 1])
                window = lines[max(0, i - 1): end + 3]
                # A 2-argument `pragma Assume (Cond, "reason")` carries its own
                # justification — the sanctioned SPARK idiom. Otherwise accept an
                # adjacent comment or a DEC cite.
                justified = (crate.waived("P3")
                             or bool(re.search(r'pragma\s+Assume\s*\(.*,\s*"', stmt, re.I | re.S))
                             or any(DEC_CITE_RE.search(w) for w in window)
                             or any(comment.search(w) for w in window))
                out.append(Finding("P3", True, crate.name, rel, i + 1,
                                   "pragma Assume without an inline justification or DEC cite (P3)",
                                   excepted=justified))
            elif re.search(r"SPARK_Mode\s*(=>|\()\s*Off", line, re.I):
                prev = lines[i - 1] if i > 0 else ""
                justified = (crate.waived("P3") or bool(DEC_CITE_RE.search(line + " " + prev))
                             or bool(comment.search(line)) or bool(comment.search(prev)))
                out.append(Finding("P3", False, crate.name, rel, i + 1,
                                   "SPARK_Mode Off — confirm this unit is out of proof scope by design (P3)",
                                   excepted=justified))
    return out


def check_coherence(crate: Crate) -> list[Finding]:
    if not crate.applies("P11"):
        return []
    out = []
    lic = crate.path / "LICENSE"
    if lic.is_file():
        txt = lic.read_text(encoding="utf-8", errors="replace")
        if "[yyyy]" in txt or "[name of copyright owner]" in txt:
            out.append(Finding("P11", True, crate.name, "LICENSE", 0,
                               "LICENSE has an unfilled template placeholder (P11/P12)",
                               excepted=crate.waived("P11")))
    alire = crate.path / "alire.toml"
    if alire.is_file():
        txt = alire.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'licenses\s*=\s*"([^"]+)"', txt)
        if m and WORKSPACE_LICENSE not in m.group(1):
            out.append(Finding("P11", False, crate.name, "alire.toml", 0,
                               f"license {m.group(1)!r} deviates from workspace {WORKSPACE_LICENSE} (P11)",
                               excepted=crate.waived("P11")))
        emails = re.findall(r"<([^>]+@[^>]+)>", txt)
        for e in emails:
            if e != WORKSPACE_EMAIL:
                out.append(Finding("P11", False, crate.name, "alire.toml", 0,
                                   f"maintainer email {e!r} deviates from {WORKSPACE_EMAIL} (P11)",
                                   excepted=crate.waived("P11")))
    return out


def check_vendored(crate: Crate) -> list[Finding]:
    """Flag a vendored CI checker that has drifted from the canonical tool.

    The vendored copy is this very tool, byte-for-byte, so we compare against the
    running script. In a crate's own CI the script *is* the copy, so it never
    false-flags; only a workspace-level scan (running the canonical copy) detects drift.
    """
    if not crate.applies("P12"):
        return []
    vend = crate.path / "tools" / "governance_check.py"
    if not vend.is_file():
        return []
    try:
        if vend.read_bytes() != Path(__file__).resolve().read_bytes():
            return [Finding("P12", False, crate.name, "tools/governance_check.py", 0,
                           "vendored CI check is out of sync with the workspace tool — "
                           "run `governance.py sync-ci` (P12)", excepted=crate.waived("P12"))]
    except OSError:
        pass
    return []


CHECKS = [check_required_files, check_artifacts, check_alire,
          check_proof_evidence, check_assumptions, check_coherence, check_vendored]


# Self-contained per-crate CI workflow. tools/governance_check.py is a verbatim copy
# of this tool (see cmd_sync_ci); the crate's CI runs it with no workspace present.
WORKFLOW_YAML = """name: governance
# tools/governance_check.py is a byte-for-byte copy of the workspace governance tool,
# kept in sync by `governance.py sync-ci` (a workspace scan flags drift).
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  constitution:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Constitutional scan (blocking)
        # The workspace backlog is clear, so this gates: a new blocking-class
        # violation fails CI. Document a justified exception in .governance.toml to clear it.
        run: python3 tools/governance_check.py scan --crate . --gate
"""


def scan_crate(crate: Crate) -> list[Finding]:
    findings: list[Finding] = []
    for chk in CHECKS:
        findings.extend(chk(crate))
    return findings


def report(findings: list[Finding], gate: bool, strict: bool) -> int:
    findings.sort(key=lambda f: (f.crate, f.path, f.line, f.principle))
    blocking = warn = info = 0
    for f in findings:
        if f.excepted:
            tag = "INFO"
            info += 1
        elif f.blocking:
            tag = "BLOCK"
            blocking += 1
        else:
            tag = "WARN"
            warn += 1
        loc = f.crate + (f"/{f.path}" if f.path else "")
        loc += f":{f.line}" if f.line else ""
        print(f"  [{tag:<5}] {f.principle:<3} {loc}  {f.msg}")
    if blocking == 0 and warn == 0:
        print("scan: clean (no blocking or warn findings)"
              + (f"; {info} excepted" if info else ""))
    else:
        print(f"\nscan: {blocking} blocking, {warn} warn, {info} excepted (informational)")
    if strict and (blocking or warn):
        return 1
    if gate and blocking:
        return 1
    return 0


def cmd_scan(args, root: Path) -> int:
    only = Path(args.crate) if args.crate else None
    crates = find_crates(root, only)
    if not crates:
        where = args.crate or "workspace"
        print(f"scan: no registered crates found ({where}); add a .governance.toml")
        return 0
    findings: list[Finding] = []
    for c in crates:
        findings.extend(scan_crate(c))
    print(f"scanned {len(crates)} crate(s): {', '.join(c.name for c in crates)}\n")
    return report(findings, args.gate, args.strict)


# --------------------------------------------------------------------------- #
# index — regenerate the decision-log table (port of cloudcost index.go).      #
# --------------------------------------------------------------------------- #
RE_H1 = re.compile(r"^#\s+(DEC-\d+)\s+[—\-]\s+(.+?)\s*$")
RE_STATUS = re.compile(r"(?m)^\*\*Status:\*\*\s+(.+?)\s*$")
RE_DATE = re.compile(r"(?m)^\*\*Date:\*\*\s+(\d{4}-\d{2}-\d{2})")
RE_PRINC = re.compile(r"\bP(?:1[0-2]|[1-9])\b")
RE_ALL = re.compile(r"(?i)\ball (?:ten|twelve)\b")
RE_NUM = re.compile(r"DEC-(\d+)")


def _extract_section(text: str, heading: str) -> str | None:
    lines = text.splitlines()
    start = next((i + 1 for i, l in enumerate(lines) if l.strip() == "## " + heading), None)
    if start is None:
        return None
    body = []
    for l in lines[start:]:
        if l.startswith("## "):
            break
        body.append(l)
    return "\n".join(body)


def _render_principles(section: str | None) -> str:
    if not section:
        return "—"
    if RE_ALL.search(section):
        return "All"
    nums = sorted({int(p[1:]) for p in RE_PRINC.findall(section)})
    return ", ".join(f"P{n}" for n in nums) if nums else "—"


def _collect_adrs(decisions: Path) -> list[dict]:
    adrs = []
    for f in sorted(decisions.glob("DEC-*.md")):
        text = f.read_text(encoding="utf-8")
        h1 = next((l for l in text.splitlines() if l.strip()), "")
        m = RE_H1.match(h1)
        if not m:
            raise SystemExit(f"{f.name}: first line is not `# DEC-NNN — Title` (got {h1!r})")
        sm, dm = RE_STATUS.search(text), RE_DATE.search(text)
        if not sm:
            raise SystemExit(f"{f.name}: missing `**Status:**` line")
        if not dm:
            raise SystemExit(f"{f.name}: missing/malformed `**Date:**` line")
        adrs.append({
            "num": int(RE_NUM.search(m.group(1)).group(1)),
            "id": m.group(1), "file": f.name,
            "title": m.group(2).replace("|", r"\|"),
            "status": sm.group(1).strip(), "date": dm.group(1),
            "principles": _render_principles(_extract_section(text, "Constitutional principles touched")),
        })
    adrs.sort(key=lambda a: a["num"], reverse=True)
    return adrs


def _render_index(adrs: list[dict]) -> str:
    rows = ["| ID | Title | Status | Date | Principles |", "|---|---|---|---|---|"]
    for a in adrs:
        rows.append(f"| [{a['id']}]({a['file']}) | {a['title']} | {a['status']} | {a['date']} | {a['principles']} |")
    return INDEX_BEGIN + "\n" + "\n".join(rows) + "\n" + INDEX_END


def cmd_index(args, root: Path) -> int:
    decisions = root / "decisions"
    readme = decisions / "README.md"
    adrs = _collect_adrs(decisions)
    cur = readme.read_text(encoding="utf-8")
    bi, ei = cur.find(INDEX_BEGIN), cur.find(INDEX_END)
    if bi == -1 or ei == -1 or ei < bi:
        raise SystemExit(f"index markers not found in {readme}")
    updated = cur[:bi] + _render_index(adrs) + cur[ei + len(INDEX_END):]
    if cur == updated:
        if not args.check:
            print(f"decision index up to date ({len(adrs)} decisions)")
        return 0
    if args.check:
        print("decision index is stale — run `python3 governance/governance.py index`")
        return 1
    readme.write_text(updated, encoding="utf-8")
    print(f"decision index updated ({len(adrs)} decisions)")
    return 0


# --------------------------------------------------------------------------- #
# ledger — regenerate PROOF_STATUS.md.                                         #
# --------------------------------------------------------------------------- #
def _ci_status(crate: Crate) -> str:
    wf = crate.path / ".github" / "workflows"
    if not wf.is_dir():
        return "none"
    blob = " ".join(p.read_text(encoding="utf-8", errors="replace")
                    for p in wf.glob("*.yml")) + \
           " ".join(p.read_text(encoding="utf-8", errors="replace")
                    for p in wf.glob("*.yaml"))
    if "gnatprove" in blob:
        return "build+prove"
    return "build" if blob else "none"


def cmd_ledger(args, root: Path) -> int:
    crates = find_crates(root)
    rows = []
    for c in sorted(crates, key=lambda c: (c.profile, c.name)):
        summ = proof_summary(c)
        verified = "—"
        committed = (c.path / "proof").is_dir()
        if summ:
            parsed = parse_gnatprove_total(summ)
            if parsed:
                total, unproved = parsed
                ok = "✅" if unproved == 0 else f"⚠ {unproved} unproved"
                tracked = set(git_tracked(c))
                where = "committed" if {"proof/gnatprove.out", "proof/summary.txt"} & tracked \
                    else "local"
                verified = f"{total} VCs {ok} ({where})"
        claim = c.claimed_level
        claim_s = (f"L{claim}" if isinstance(claim, int) and claim else str(claim)) \
            if claim else "—"
        if c.claimed_vcs:
            claim_s += f" / {c.claimed_vcs} VCs"
        rows.append((c.name, c.profile, "yes" if c.published else "no",
                     claim_s, verified, _ci_status(c),
                     str(len(c.exceptions)) if c.exceptions else "—"))

    header = (
        "# Proof status — ada-experiments workspace\n\n"
        f"_Generated by `governance/governance.py ledger` on {date.today().isoformat()}. "
        "Do not edit by hand._\n\n"
        "This is the recovered status dashboard for the workspace. **Claim** is what a\n"
        "crate's `.governance.toml` / README asserts; **Verified** is parsed from committed\n"
        "`proof/gnatprove.out` (or a fresh local `obj/gnatprove/` run). A crate is only at\n"
        "100% provability when Verified shows ✅ with 0 unproved *and* the evidence is committed.\n\n"
        "| Crate | Profile | Published | Claim | Verified | CI | Exc. |\n"
        "|---|---|---|---|---|---|---|\n"
    )
    body = "".join("| " + " | ".join(r) + " |\n" for r in rows)
    legend = (
        "\n**Legend** — Verified: `✅` all checks proved · `⚠ N unproved` gaps remain · "
        "`—` no proof evidence found. CI: `build+prove` runs gnatprove · `build` build/test only · "
        "`none`. Exc.: count of logged constitutional exceptions (see each crate's `.governance.toml`).\n"
    )
    (root / "PROOF_STATUS.md").write_text(header + body + legend, encoding="utf-8")
    print(f"PROOF_STATUS.md regenerated ({len(rows)} crates)")
    return 0


# --------------------------------------------------------------------------- #
# audit — emit a deep-audit prompt.                                            #
# --------------------------------------------------------------------------- #
def cmd_audit(args, root: Path) -> int:
    today = date.today().isoformat()
    if args.principle:
        p = args.principle.upper()
        scope = f"principle {p} ({PRINCIPLE_NAMES.get(p, '?')})"
        out_path = f"reports/audits/principle-{p.lower()}-{today}.md"
        focus = (f"Audit **only {p} — {PRINCIPLE_NAMES.get(p, '')}** across every registered crate. "
                 "For each crate, decide: does it satisfy this principle? Cite file:line evidence.")
    elif args.crate:
        scope = f"crate {args.crate}"
        out_path = f"reports/audits/crate-{args.crate}-{today}.md"
        focus = (f"Audit the crate **{args.crate}** against ALL twelve principles. "
                 "Read its sources, alire.toml, README, proof evidence, and .governance.toml.")
    else:
        raise SystemExit("audit: pass --principle Pn or --crate NAME")

    print(f"""# Audit prompt — {scope}  (mode {args.mode}, {today})

You are auditing the ada-experiments SPARK workspace. Read `CONSTITUTION.md` and
`docs/governance/audit-playbook.md` first.

## Scope
{focus}

## Method
- Honour each crate's profile and logged exceptions (`.governance.toml`); a waived
  rule is not a finding, but note if a waiver looks stale or unjustified.
- For every finding, record: severity (HIGH/MEDIUM/LOW), principle, file:line,
  what is wrong, why it violates the principle, and a remediation path
  (FIX / DOCUMENT-EXCEPTION / AMEND / ACCEPT-DEBT / REWRITE).
- `governance.py scan` already covers the mechanical subset (P2/P3/P9/P10/P11/P12);
  spend your effort on the judgement principles (P1/P4/P5/P6/P7/P8).

## Output
Write findings to `{out_path}` using the report template in the audit playbook.
End with a verdict (and for a pre-release mode-D audit, a GO / NO-GO).
""")
    return 0


# --------------------------------------------------------------------------- #
# install-hooks — wire each crate's git hooks path.                            #
# --------------------------------------------------------------------------- #
def cmd_sync_ci(args, root: Path) -> int:
    """Vendor the governance tool + a CI workflow into every git crate (Phase 3)."""
    canonical = (root / "governance" / "governance.py").read_bytes()
    n = 0
    for c in find_crates(root):
        if not c.is_git:
            continue
        tools = c.path / "tools"
        tools.mkdir(exist_ok=True)
        (tools / "governance_check.py").write_bytes(canonical)
        wf = c.path / ".github" / "workflows"
        wf.mkdir(parents=True, exist_ok=True)
        (wf / "governance.yml").write_text(WORKFLOW_YAML, encoding="utf-8")
        n += 1
        print(f"  vendored: {c.name}")
    print(f"sync-ci: vendored the governance check + workflow into {n} crate(s)")
    return 0


def cmd_install_hooks(args, root: Path) -> int:
    n = 0
    for c in find_crates(root):
        if not c.is_git:
            continue
        hook = c.path / ".githooks" / "pre-commit"
        if not hook.exists():
            continue
        subprocess.run(["git", "-C", str(c.path), "config", "core.hooksPath", ".githooks"],
                       check=False)
        hook.chmod(0o755)
        n += 1
        print(f"  hooks wired: {c.name}")
    print(f"install-hooks: configured {n} crate(s) (bypass a hook with `git commit --no-verify`)")
    return 0


# --------------------------------------------------------------------------- #
# CLI.                                                                         #
# --------------------------------------------------------------------------- #
def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="governance", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", help="workspace root (default: auto-detected)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="flag constitutional violations")
    s.add_argument("--crate", help="scan a single crate directory (default: all)")
    s.add_argument("--gate", action="store_true", help="exit 1 on any blocking finding (CI)")
    s.add_argument("--strict", action="store_true", help="exit 1 on any finding (local)")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("index", help="regenerate the decision-log index")
    s.add_argument("--check", action="store_true", help="exit 1 if stale; do not write")
    s.set_defaults(func=cmd_index)

    s = sub.add_parser("ledger", help="regenerate PROOF_STATUS.md")
    s.set_defaults(func=cmd_ledger)

    s = sub.add_parser("audit", help="emit a deep-audit prompt")
    s.add_argument("--principle", help="audit one principle (e.g. P4)")
    s.add_argument("--crate", help="audit one crate")
    s.add_argument("--mode", default="B", choices=list("ABCD"), help="A continuous / B crate / C principle / D pre-release")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("sync-ci", help="vendor the tool + CI workflow into each crate")
    s.set_defaults(func=cmd_sync_ci)

    s = sub.add_parser("install-hooks", help="wire git core.hooksPath in each crate")
    s.set_defaults(func=cmd_install_hooks)

    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else find_root()
    return args.func(args, root)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
