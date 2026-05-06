#!/usr/bin/env python3
"""Rewrite Goss meta (CCI, Group_Title, Rule_ID, STIG_ID, Vul_ID) from DISA XCCDF Manual."""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"x": "http://checklists.nist.gov/xccdf/1.1"}
META_RE = re.compile(
    r"(?ms)^    meta:\n"
    r"      Cat: (?P<cat>\d+)\n"
    r"      CCI:\n"
    r"(?:      - CCI-[^\n]+\n)+"
    r"      Group_Title:\n"
    r"(?:      - SRG-[^\n]+\n)+"
    r"      Rule_ID: (?P<rule>[^\n]+)\n"
    r"      STIG_ID: (?P<stig>RHEL-10-\d{6})\n"
    r"      Vul_ID: (?P<vul>V-\d+)\n"
)


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
            ccis = []
            for ident in rule.findall("x:ident", NS):
                if ident.get("system") == "http://cyber.mil/cci" and ident.text:
                    ccis.append(ident.text.strip())
            idx[ver] = {"v_id": vid, "sv_id": rid, "group_title": gtitle, "ccis": ccis}
    return idx


def replace_meta_block(text: str, xm: dict, stig: str, cat: str) -> str:
    indent = "      "
    cci_block = "\n".join(f"{indent}- {c}" for c in xm["ccis"])
    new_meta = (
        f"    meta:\n"
        f"{indent}Cat: {cat}\n"
        f"{indent}CCI:\n"
        f"{cci_block}\n"
        f"{indent}Group_Title:\n"
        f"{indent}- {xm['group_title']}\n"
        f"{indent}Rule_ID: {xm['sv_id']}\n"
        f"{indent}STIG_ID: {stig}\n"
        f"{indent}Vul_ID: {xm['v_id']}\n"
    )
    m = META_RE.search(text)
    if not m:
        return text
    start, end = m.span()
    return text[:start] + new_meta + text[end:]


def main() -> int:
    audit_root = Path(__file__).resolve().parents[1]
    xccdf = audit_root.parent / "U_RHEL_10_STIG_V1R1_Manual-xccdf.xml"
    if not xccdf.is_file():
        xccdf = Path("/Users/mbolwell/Documents/git/MPG/STIG/Rhel/RHEL10/U_RHEL_10_STIG_V1R1_Manual-xccdf.xml")
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
