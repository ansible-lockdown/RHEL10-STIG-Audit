#!/usr/bin/env python3
"""Rewrite Goss meta (CCI, Group_Title, Rule_ID, STIG_ID, Vul_ID) from DISA XCCDF Manual.

When the rule has no CCI idents, emit the scalar ``CCI: NA`` (not a list). Otherwise use
``CCI:`` with one or more ``- CCI-…`` lines.

Run with project venv, for example:
  ~/.venvs/ansible2.19/bin/python scripts/sync_audit_meta_from_xccdf.py
"""
from __future__ import annotations

import html
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"x": "http://checklists.nist.gov/xccdf/1.1"}
SRG_IN_SATISFIES_RE = re.compile(r"SRG-OS-\d+-GPOS-\d+")
META_RE = re.compile(
    r"(?ms)^    meta:\n"
    r"      Cat: (?P<cat>\d+)\n"
    r"(?:      CCI: NA\n|      CCI:\n(?:      - CCI-[^\n]+\n)+)"
    r"      Group_Title:\n"
    r"(?:      - SRG-[^\n]+\n)+"
    r"      Rule_ID: (?P<rule>[^\n]+)\n"
    r"      STIG_ID: (?P<stig>RHEL-10-\d{6})\n"
    r"      Vul_ID: (?P<vul>V-\d+)\n"
)


def srgs_from_xccdf_rule(description_text: str | None, group_title: str) -> list[str]:
    raw = html.unescape(description_text or "")
    sm = re.search(r"Satisfies:\s*([^<\n]+)", raw)
    if sm:
        chunk = sm.group(1).strip()
        found = SRG_IN_SATISFIES_RE.findall(chunk)
        if found:
            seen: set[str] = set()
            ordered: list[str] = []
            for s in found:
                if s not in seen:
                    seen.add(s)
                    ordered.append(s)
            return ordered
    gt = group_title.strip()
    return [gt] if gt else []


def load_xccdf(path: Path) -> dict[str, dict]:
    root = ET.parse(path).getroot()
    idx: dict[str, dict] = {}
    for group in root.findall(".//x:Group", NS):
        vid = group.get("id")
        gtitle_el = group.find("x:title", NS)
        gtitle = gtitle_el.text.strip() if gtitle_el is not None and gtitle_el.text else ""
        for rule in group.findall("x:Rule", NS):
            ver_el = rule.find("x:version", NS)
            if ver_el is None or ver_el.text is None:
                continue
            ver = ver_el.text.strip()
            if not ver.startswith("RHEL-10-"):
                continue
            rid = rule.get("id") or ""
            desc_el = rule.find("x:description", NS)
            srgs = srgs_from_xccdf_rule(desc_el.text if desc_el is not None else None, gtitle)
            if not srgs and gtitle.strip():
                srgs = [gtitle.strip()]
            ccis = []
            for ident in rule.findall("x:ident", NS):
                if ident.get("system") == "http://cyber.mil/cci" and ident.text:
                    ccis.append(ident.text.strip())
            idx[ver] = {"v_id": vid, "sv_id": rid, "srgs": srgs, "ccis": ccis}
    return idx


def replace_meta_block(text: str, xm: dict, stig: str, cat: str) -> str:
    indent = "      "
    if xm["ccis"]:
        cci_section = f"{indent}CCI:\n" + "\n".join(f"{indent}- {c}" for c in xm["ccis"]) + "\n"
    else:
        cci_section = f"{indent}CCI: NA\n"
    srg_block = "\n".join(f"{indent}- {s}" for s in xm["srgs"])
    new_meta = (
        f"    meta:\n"
        f"{indent}Cat: {cat}\n"
        f"{cci_section}"
        f"{indent}Group_Title:\n"
        f"{srg_block}\n"
        f"{indent}Rule_ID: {xm['sv_id']}\n"
        f"{indent}STIG_ID: {stig}\n"
        f"{indent}Vul_ID: {xm['v_id']}\n"
    )
    m = META_RE.search(text)
    if not m:
        return text
    start, end = m.span()
    return text[:start] + new_meta + text[end:]


def find_rhel10_manual_xccdf(audit_root: Path) -> Path:
    """Resolve Manual XCCDF beside RHEL10 (same folder as RHEL10-STIG-Audit) or under .../Rhel/RHEL10/."""
    cand = audit_root.parent / "U_RHEL_10_STIG_V1R1_Manual-xccdf.xml"
    if cand.is_file():
        return cand
    for parent in audit_root.resolve().parents:
        c2 = parent / "Rhel" / "RHEL10" / "U_RHEL_10_STIG_V1R1_Manual-xccdf.xml"
        if c2.is_file():
            return c2
    raise FileNotFoundError(
        "U_RHEL_10_STIG_V1R1_Manual-xccdf.xml not found next to RHEL10-STIG-Audit "
        "or at <repo>/Rhel/RHEL10/U_RHEL_10_STIG_V1R1_Manual-xccdf.xml"
    )


def main() -> int:
    audit_root = Path(__file__).resolve().parents[1]
    xccdf = find_rhel10_manual_xccdf(audit_root)
    idx = load_xccdf(xccdf)
    updated = 0
    skipped = 0
    for yml in sorted(audit_root.rglob("RHEL-10-*.yml")):
        if "scripts" in yml.parts:
            continue
        stem = yml.stem
        if not re.match(r"RHEL-10-\d{6}$", stem):
            continue
        if stem not in idx:
            skipped += 1
            continue
        text = yml.read_text(encoding="utf-8")
        m = META_RE.search(text)
        if not m:
            skipped += 1
            continue
        cat = m.group("cat")
        new_text = replace_meta_block(text, idx[stem], stem, cat)
        if new_text != text:
            yml.write_text(new_text, encoding="utf-8", newline="\n")
            updated += 1
    print(f"Updated {updated} files; skipped (no match or unknown STIG): {skipped}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
