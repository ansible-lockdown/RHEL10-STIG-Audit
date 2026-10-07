## RHEL10 STIG v1.2.0 - 2026 October - Benchmark version string moved to the dotted form

- the benchmark version string changes from `v1r2` to `v1.2.0`, and this content is published on a
  new `benchmark_v1.2.0` branch. `benchmark_v1r2` is left in place and unchanged, so any remediation
  role still pointing at the old string keeps resolving; nothing is cut over by this alone
- updated in the three places that define or state it: `vars/STIG.yml`, `run_audit.sh`
  (`BENCHMARK_VER`) and `README.md`. `goss.yml` and the `audit_json_vars` line in `run_audit.sh`
  consume the value rather than defining it, so they follow automatically
- **RHEL-10-600010 tested an unrelated control.** Its title is the grub superusers requirement, but
  the exec ran `awk -F: '$4 < 1' /etc/shadow`, a minimum-password-age check that never reads grub.
  Any host with no zero-min-age account passed it unconditionally. It now uses a `file:` resource
  against `/etc/grub2.cfg` asserting `set superusers="<name>"`, matching the benchmark check text
  and the sibling RHEL-10-600000 test
- **`rhel10stig_grub_superuser` defaulted to `root`.** The benchmark requires a unique superuser
  name and the paired remediation's own comment says it "must not be a common name such as root".
  Run standalone the audit therefore asserted the forbidden value; run through the role the bridge
  template overrode it, so the defect only showed outside the role. Now `stig_boot_user`, matching
  the remediation default
- **RHEL-10-800310 asserted against the vendor unit.** It grepped `ExecStart` in
  `/usr/lib/systemd/system/tftp.service`, which remediation never modifies - the secure-mode setting
  is written to a drop-in at `/etc/systemd/system/tftp.service.d/secure.conf`. The test failed
  permanently after remediation. It now reads `systemctl cat tftp.service`, which renders the merged
  unit including drop-ins
- RHEL-10-800310 was also the only one of the 434 test files missing the blank line after `---`;
  restored, so the set is uniform
- the dotted form matches the convention the Ubuntu audit content already uses, where a `vXrY`
  remediation pairs with a `vX.Y.0` audit branch. The paired remediation role resolves this branch
  through `audit_git_version: "benchmark_{{ benchmark_version }}"`, so the two must move together

## RHEL10 STIG v1r2 - 2026 August - Company name updated to Quantum Sky

- the parent company name changed from Tyto Athene to Quantum Sky. Renamed in `LICENSE`, the only place this repository carries it
- deliberately not renamed: existing entries in this file, which record what was true when written

## RHEL10 STIG v1r2 - 01 July 2026

- RHEL-10-800060: made the two-name-server check systemd-resolved aware. It counted nameservers in /etc/resolv.conf only, so a host using systemd-resolved (where resolv.conf is the 127.0.0.53 stub and the real servers live in /etc/systemd/resolved.conf) false-failed. The command now counts non-stub nameservers in /etc/resolv.conf and DNS= servers in /etc/systemd/resolved.conf (+ resolved.conf.d/*.conf), passing when either location provides at least two; FallbackDNS is not counted. Also widened the count match to accept 10+ servers
- Updated to DISA RHEL 10 STIG Version 1, Release 2 (434 controls, none added or removed)
- README: pointed the `[Goss]` link at the krameff fork (`github.com/krameff/goss`) instead of the upstream `goss.rocks`, matching the migrated audit binary source and the RHEL10-CIS-Audit sibling; removed the stray parentheses around the `[goss documentation]` reference-link target (they broke the link)
- RHEL-10-701250 / 701260: relaxed the goss checks to verify only that the override drop-in under `/etc/systemd/system/*.service.d/` carries the sulogin `ExecStart`; removed the requirement that the RPM-owned base units `/usr/lib/systemd/system/{emergency,rescue}.service` have their `ExecStart`/`ExecStartPre` commented out (that required modifying vendor files). Matches DISA's check (which accepts the drop-in) and the remediation role's reset-style drop-in
- Bumped the DISA rule revision on the 10 rules revised in V1R2: 200530, 200611, 200691, 500040, 500410, 600730, 600750, 700750, 700920, 701130
- RHEL-10-200530: removed CCI-002314 and CCI-002322
- RHEL-10-700920: removed CCI-000057
- RHEL-10-200611: check the pcscd socket (was the pcscd service) per the V1R2 "specify socket" requirement; title updated
- RHEL-10-700750: idle-delay threshold 900 -> 600 (10 minutes); title updated
- Reconciled three pre-existing goss CCI sets to the XCCDF (500690, 700980, 701050)
- Fixed a mislabeled duplicate sub-check in cat_1/RHEL-10-701050.yml (was tagged RHEL-10-700930 with RHEL 9 SV/V IDs; retagged to 701050 with CCI-003992)
- benchmark_version updated to v1r2 (vars/STIG.yml, run_audit.sh, README)

## July 2026

- Updated links that the audit comes from, goss-org moved to krameff
- Fixed goss version discovery to read only the first line of `goss -v` (krameff builds emit a second banner line)
- Simplified OS discovery to use the BENCHMARK_OS variable

RHEL10 STIG v1r1 - March 2026
# Initial
