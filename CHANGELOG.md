## RHEL10 STIG v1.3.0 - 2026 October - V1R2 -> V1R3 benchmark alignment

Aligned to DISA RHEL 10 STIG Version 1, Release 3 (30 September 2026). Two rules added, one
removed, 435 controls in total, and no severity changed, so nothing moved between `cat_` directories.

- **RHEL-10-300085 is new and had no test.** The benchmark now requires
  `/etc/pki/tls/openssl.cnf` to carry `.include = /etc/crypto-policies/back-ends/opensslcnf.config`,
  which is what makes the systemwide crypto policy reach OpenSSL at all. Added as a CAT I `file:`
  test with its own toggle; without the include, every other crypto-policy control can pass while
  OpenSSL quietly ignores the policy
- **RHEL-10-500605 is new and had no test.** Added the paired `audit_conf_useradd` and
  `audit_running_useradd` checks for the `privileged-useradd` rule, following the shape already used
  for the neighbouring privileged-command controls
- **RHEL-10-200050 was withdrawn as a duplicate.** Its test file and toggle are removed.
  `rhel10stig_tftp_server_required` stays: RHEL-10-800310 still consumes it for secure-mode
  enforcement, and dropping it would break that control
- **132 Rule_ID values carried the previous release revision.** Only the `r<revision>` suffix moved;
  the `SV-` and `V-` numbers are unchanged. 144 occurrences across 132 files, because a control with
  two tests carries two `meta:` blocks and both had to move
- **17 titles did not match the V1R3 wording**, across 14 files. Includes the benchmark-wide
  `DOD` to `DoW` rename, RHEL-10-600000 retitled to the single-user and maintenance modes wording,
  and RHEL-10-700920 restated from 15 minutes to 10
- **RHEL-10-600100 and RHEL-10-600110 still enforced the 60-day maximum password lifetime.** The
  benchmark raised it to 180 days. The first capped `PASS_MAX_DAYS` at 60 by regex, the second
  compared `$5 > 60` against `/etc/shadow`, so both reported a finding on a host configured exactly
  as V1R3 requires
- **RHEL-10-500450 and RHEL-10-500490 required an `auid` filter the benchmark removed.** The rules
  now monitor all users, so a correctly configured host failed both tests
- **RHEL-10-500680 asserted the wrong audit key.** The benchmark changed the `/etc/sudoers` rule key
  to `identity`; the test still grepped for and asserted `logins`
- **RHEL-10-500690 pinned the sudoers.d watch to `-F dir=` with a trailing slash.** The benchmark
  now shows `-F path=/etc/sudoers.d`. Since auditd renders a directory watch as `dir=` whichever
  form is written, the test accepts either spelling with an optional trailing slash, and pins the
  key to `identity`
- **RHEL-10-600750 failed on any host without libuser.** The benchmark adds a not-applicable note
  for that case. The test was a `file:` resource asserting on `/etc/libuser.conf`, so a missing
  package produced a finding rather than an exemption; it is now a command that reports the
  package-absent case explicitly
- **RHEL-10-600000 pinned the GRUB password hash to 10000 iterations.** The benchmark asks only that
  the hash begin `grub.pbkdf2.sha512`, so a host hashed at any other iteration count failed
- **RHEL-10-001030, RHEL-10-001040, RHEL-10-001050 and RHEL-10-200000 accepted only `1` or `True`.**
  The benchmark now allows `1`, `true` or `yes`, and the repository check additionally missed
  `gpgcheck=false` and `gpgcheck=no`, which are findings it was silently passing
- **RHEL-10-200648 asserted the superseded cron logging shape.** The benchmark rewrote the control
  around a dedicated `cron.*` rule writing to `/var/log/cron` and dropped the
  `cron.none /var/log/messages` requirement. The test accepts both the modern `action(type="omfile")`
  form and the legacy form
- **RHEL-10-701270 asserted a Subject line that could never match.** The pattern was `^\*Subject:`
  where the adjacent Issuer pattern is `^\s*Issuer:`; `\*` matches a literal asterisk, which
  `openssl x509 -text` never emits. Corrected to `^\s*Subject:`
- **The certificate distinguished name in RHEL-10-701270 is deliberately not renamed.** V1R3 rewrote
  `OU = DoD` to `OU = DoW` in its sample output while leaving `CN = DoD Root CA 3` in the same
  distinguished name. A name is a property of the issued certificate, not of the benchmark, and
  matching `DoW` would fail against the certificate the benchmark itself names
- benchmark version string moved to `v1.3.0` in the three places that define or state it:
  `vars/STIG.yml`, `run_audit.sh` (`BENCHMARK_VER`) and `README.md`. The paired remediation role
  resolves this branch through `audit_git_version: "benchmark_{{ benchmark_version }}"`, so the two
  must move together

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
- **38 test titles did not match the benchmark.** Titles are the text an assessor reads in the report,
  and they had drifted in three ways. Five said `for tmp.` or `for var/log.` where the benchmark says
  `/tmp` and `/var/log`, the leading slash having been lost when the benchmark's quotation marks were
  stripped. Four carried escaped `\"` quotes, which no other audit role in the fleet does. The rest
  were stale wording the benchmark has since changed, including RHEL-10-500780 and RHEL-10-500810,
  whose titles still listed the old syscall sets although both the tests and the paired remediation
  template already cover `fchmodat2` and `renameat2`. The clearest was RHEL-10-400250, titled for
  `/etc/passwd` while correctly testing `/etc/group-`. Titles now carry the benchmark text with the
  quotation marks removed, matching the STIG RHEL Fleet convention, and the per-resource
  qualifier suffixes such as `| conf` are preserved. No test logic is touched; all 538 titles now
  agree with V1R2 and the rendered suite still holds 974 tests

- **66 tests reported identifiers from the DISA RHEL 9 STIG.** Each test file carries one or two `meta:` blocks, and in
  66 files the second block had been left behind when the content was first derived:
  it still held that benchmark's `Vul_ID` and `Rule_ID`, and in one case (RHEL-10-700420) a `STIG_ID`
  of `RHEL-09-431010`. The whole RHEL-10-500300 to RHEL-10-500810 run was affected. Because goss
  gates on the `rhel10stig_NNNNNN` toggles rather than on these fields, every test still ran and
  passed correctly, but the JSON report cited identifiers that do not appear in the RHEL 10
  benchmark, so a report could not be reconciled against a checklist. The second block in each file
  now matches the first, which was already correct; this also brings four `Vul_ID`/`Rule_ID` pairs
  that pointed at a neighboring RHEL 10 control into line, corrects two `Cat` values
  (RHEL-10-000510 is CAT I, RHEL-10-700420 is CAT II), and fills in CCI and SRG references the stale
  blocks were missing. Verified by rendering and running the full suite before and after: 974 tests
  and 144 failures either way, with no `exec`, `stdout` or `exit-status` line changed

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
