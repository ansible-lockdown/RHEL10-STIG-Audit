## RHEL10 STIG v1r2 - 01 July 2026

- Updated to DISA RHEL 10 STIG Version 1, Release 2 (434 controls, none added or removed)
- Bumped the DISA rule revision on the 10 rules revised in V1R2: 200530, 200611, 200691, 500040, 500410, 600730, 600750, 700750, 700920, 701130
- RHEL-10-200530: removed CCI-002314 and CCI-002322
- RHEL-10-700920: removed CCI-000057
- RHEL-10-200611: check the pcscd socket (was the pcscd service) per the V1R2 "specify socket" requirement; title updated
- RHEL-10-700750: idle-delay threshold 900 -> 600 (10 minutes); title updated
- Reconciled three pre-existing goss CCI sets to the XCCDF (500690, 700980, 701050)
- benchmark_version updated to v1r2 (vars/STIG.yml, run_audit.sh, README)

## July 2026

- Updated links that the audit comes from, goss-org moved to krameff
- Fixed goss version discovery to read only the first line of `goss -v` (krameff builds emit a second banner line)
- Simplified OS discovery to use the BENCHMARK_OS variable

RHEL10 STIG v1r1 - March 2026
# Initial
