#!/usr/bin/env python3
"""Set Goss meta NIST800-53R4 from Private-RHEL10-STIG task tags (scalar if one, list if several)."""
from __future__ import annotations

import re
import sys
from pathlib import Path

NIST_PREFIX = "NIST800-53R4_"
STIG_TAG = re.compile(r"^    - (RHEL-10-\d{6})\s*$")
NIST_TAG = re.compile(r"^    - (NIST800-53R4_(.+))\s*$")


def load_nist_from_remediation(tasks_dir: Path) -> dict[str, list[str]]:
    """Map STIG ID -> ordered unique NIST control ids (no NIST800-53R4_NA)."""
    out: dict[str, list[str]] = {}
    for yml in sorted(tasks_dir.rglob("RHEL-10-*.yml")):
        if yml.name == "main.yml":
            continue
        text = yml.read_text(encoding="utf-8")
        for block in re.split(r"(?m)^(?=- name:)", text):
            if not block.startswith("- name:"):
                continue
            if "tags:" not in block:
                continue
            try:
                tidx = block.index("tags:")
            except ValueError:
                continue
            stigs: list[str] = []
            nist_vals: list[str] = []
            for line in block[tidx:].splitlines()[1:]:
                if not line.startswith("    - "):
                    break
                raw = line[6:].strip()
                m_stig = STIG_TAG.match(line)
                if m_stig:
                    stigs.append(m_stig.group(1))
                    continue
                m_nist = NIST_TAG.match(line)
                if m_nist and m_nist.group(2) != "NA":
                    nist_vals.append(m_nist.group(2))
            if not stigs or not nist_vals:
                continue
            for sid in stigs:
                cur = out.setdefault(sid, [])
                for v in nist_vals:
                    if v not in cur:
                        cur.append(v)
    return out


def format_nist_yaml(values: list[str]) -> str:
    """Match repo style: same indent as CCI lists (6 spaces)."""
    ind = "      "
    if len(values) == 1:
        return f"{ind}NIST800-53R4: {values[0]}\n"
    lines = [f"{ind}NIST800-53R4:\n"]
    for v in values:
        lines.append(f"{ind}- {v}\n")
    return "".join(lines)


NIST_BLOCK_RE = re.compile(
    r"(?m)^      NIST800-53R4:[^\n]*(?:\n      - [^\n]+)*\n?"
)


def set_nist_in_inner(inner: str, nist_yaml: str) -> str | None:
    """Insert or replace NIST block after Vul_ID; preserve trailing spacing after meta (e.g. blank lines before sibling keys)."""
    m = NIST_BLOCK_RE.search(inner)
    if m:
        head = inner[: m.start()]
        tail = inner[m.end() :]
    else:
        vm = re.search(r"(?m)^      Vul_ID: .+\n", inner)
        if not vm:
            return None
        head = inner[: vm.end()]
        tail = inner[vm.end() :]
    return head + nist_yaml + tail


def iter_meta_blocks(text: str) -> list[tuple[int, int, str]]:
    """Return (start, end, inner) for each `    meta:` block; inner is lines under meta (excl. header)."""
    lines = text.splitlines(keepends=True)
    spans: list[tuple[int, int, str]] = []
    i = 0
    char = 0
    while i < len(lines):
        if lines[i].rstrip() == "    meta:":
            start = char
            char += len(lines[i])
            i += 1
            body_lines: list[str] = []
            while i < len(lines):
                ln = lines[i]
                if ln.strip() == "":
                    body_lines.append(ln)
                    char += len(ln)
                    i += 1
                    continue
                # End meta: top-level `{{`, non-indented line, or 4-space sibling key / list item
                if not ln.startswith(" ") and ln.strip():
                    break
                if ln.startswith("    ") and not ln.startswith("      ") and not ln.startswith("    -"):
                    break
                if ln.startswith("    -") and not ln.startswith("      -"):
                    break
                body_lines.append(ln)
                char += len(ln)
                i += 1
            spans.append((start, char, "".join(body_lines)))
            continue
        char += len(lines[i])
        i += 1
    return spans


def sync_file(path: Path, nist_map: dict[str, list[str]]) -> bool:
    text = path.read_text(encoding="utf-8")
    out: list[str] = []
    pos = 0
    changed = False
    for start, end, inner in iter_meta_blocks(text):
        out.append(text[pos:start])
        m_stig = re.search(r"(?m)^      STIG_ID: (RHEL-10-\d{6})\s*$", inner)
        if not m_stig:
            out.append(text[start:end])
            pos = end
            continue
        stig = m_stig.group(1)
        if stig not in nist_map:
            out.append(text[start:end])
            pos = end
            continue
        nist_yaml = format_nist_yaml(nist_map[stig])
        new_inner = set_nist_in_inner(inner, nist_yaml)
        if new_inner is None:
            out.append(text[start:end])
            pos = end
            continue
        nl = text.find("\n", start)
        header = text[start : nl + 1] if nl != -1 else "    meta:\n"
        new_chunk = header + new_inner
        old_chunk = text[start:end]
        if new_chunk != old_chunk:
            changed = True
        out.append(new_chunk)
        pos = end
    out.append(text[pos:])
    if changed:
        path.write_text("".join(out), encoding="utf-8", newline="\n")
    return changed


def main() -> int:
    audit_root = Path(__file__).resolve().parents[1]
    remediation_tasks = audit_root.parent / "Private-RHEL10-STIG" / "tasks"
    if not remediation_tasks.is_dir():
        print(f"Remediation tasks not found: {remediation_tasks}", file=sys.stderr)
        return 1
    nist_map = load_nist_from_remediation(remediation_tasks)
    updated = 0
    for yml in sorted(audit_root.rglob("RHEL-10-*.yml")):
        if "scripts" in yml.parts:
            continue
        if not re.fullmatch(r"RHEL-10-\d{6}", yml.stem):
            continue
        if sync_file(yml, nist_map):
            updated += 1
    print(f"Updated {updated} audit files from remediation NIST tags.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
