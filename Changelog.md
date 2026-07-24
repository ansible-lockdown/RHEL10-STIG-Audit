## July 2026

- RHEL-10-800060: made the two-name-server check systemd-resolved aware. It counted nameservers in /etc/resolv.conf only, so a host using systemd-resolved (where resolv.conf is the 127.0.0.53 stub and the real servers live in /etc/systemd/resolved.conf) false-failed. The command now counts non-stub nameservers in /etc/resolv.conf and DNS= servers in /etc/systemd/resolved.conf (+ resolved.conf.d/*.conf), passing when either location provides at least two; FallbackDNS is not counted. Also widened the count match to accept 10+ servers
- Updated links that the audit comes from, goss-org moved to krameff
- Fixed goss version discovery to read only the first line of `goss -v` (krameff builds emit a second banner line)
- Simplified OS discovery to use the BENCHMARK_OS variable
- RHEL-10-701250 / 701260: relaxed the goss checks to verify only that the override drop-in under `/etc/systemd/system/*.service.d/` carries the sulogin `ExecStart`; removed the requirement that the RPM-owned base units `/usr/lib/systemd/system/{emergency,rescue}.service` have their `ExecStart`/`ExecStartPre` commented out (that required modifying vendor files). Matches DISA's check and the remediation role's reset-style drop-in
- README: pointed the `[Goss]` link at the krameff fork (`github.com/krameff/goss`) instead of the upstream `goss.rocks`, matching the migrated audit binary source and the RHEL10-CIS-Audit sibling; removed the stray parentheses around the `[goss documentation]` reference-link target (they broke the link)

RHEL10 STIG v1r1 - March 2026
# Initial
