## July 2026

- Updated links that the audit comes from, goss-org moved to krameff
- Fixed goss version discovery to read only the first line of `goss -v` (krameff builds emit a second banner line)
- Simplified OS discovery to use the BENCHMARK_OS variable
- RHEL-10-701250 / 701260: relaxed the goss checks to verify only that the override drop-in under `/etc/systemd/system/*.service.d/` carries the sulogin `ExecStart`; removed the requirement that the RPM-owned base units `/usr/lib/systemd/system/{emergency,rescue}.service` have their `ExecStart`/`ExecStartPre` commented out (that required modifying vendor files). Matches DISA's check and the remediation role's reset-style drop-in
- README: pointed the `[Goss]` link at the krameff fork (`github.com/krameff/goss`) instead of the upstream `goss.rocks`, matching the migrated audit binary source and the RHEL10-CIS-Audit sibling; removed the stray parentheses around the `[goss documentation]` reference-link target (they broke the link)

RHEL10 STIG v1r1 - March 2026
# Initial
