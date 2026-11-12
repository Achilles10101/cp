# 2026-11-12 container test run (Mac, colima, arm64)

Old = `old/2026-11-10/` (pre-rework, the baseline). New = `competition/` with the evening fixes (docs/CHANGES.md).
Scores = `mintchecks.py` (145 checks: Aperture/1984/recon scoring configs + the planted-image checks). `state.txt` =
full state dump (`statedump.sh`), diffed old vs new.

| run | image | checks | planted | services answering | regressions vs old |
|---|---|---|---|---|---|
| old-planted-2 (old scripts) | cp-mint-planted | 105/145 | 38/45 | ssh | - |
| modular-planted-2 (checklist order) | cp-mint-planted | **111/145** | **44/45** | ssh | none |
| speedrun-planted (speedrun.sh) | cp-mint-planted | **111/145** | **44/45** | ssh | none |
| old-svc-2 (old scripts*) | cp-mint-svcplanted | 133/145 | 41/45 | 12 (nginx off by design) | - |
| modular-svc-2 | cp-mint-svcplanted | 133/145 | 41/45 | 12 | none |
| speedrun-svc | cp-mint-svcplanted | 133/145 | 41/45 | 12 | none |
| deb12-modular | cp-deb12-planted | 105/145 | 42/45 | ssh | n/a (no old run) |
| deb12-speedrun-rerun (+ systemconfig/critical again) | cp-deb12-planted | 105/145 | 42/45 | ssh | none vs deb12-modular |
| ssh-stopped (ssh.sh with ssh.service stopped) | cp-mint-svcplanted | - | - | ssh | hardened + started |
| baseline-clean (scan only) | cp-mint-clean | 7 findings, all harness artefacts (docker apt files, arm64 mirror) | | | |

\* old/2026-11-10/services/mail.sh hangs: `if exec 3<>/dev/tcp/... 2>/dev/null` sends the rest of the script's stderr
(its `read -p` prompts) to /dev/null. old-svc-2 ran a scratch copy with only that line fixed; the current mail.sh had
the same line and is fixed.

State diff old vs new (planted): sysctl, login.defs, PAM, `sshd -T`, ufw, accounts, password aging, sudoers, installed
packages, permissions and SUID are identical. New only adds: backdoor service stopped, hidden user / autologin drop-in
removed, media quarantined, avahi/cups stopped (answered y), no SUID copies under /root/baseline/_pristine.
Services image: same, plus a tighter Squid rule (3128 only), fail2ban, password aging.

Still failing everywhere = not applicable here: services not on that image, README-specific values (port 1382,
DenyGroups, SFTP chroot, passive range), faillock (manual LAST step - tested by hand: `pam-auth-update --enable` works
after the scripts' PAM edits and keeps remember/minlen/pwquality), /boot/grub (container), the plaintext password
file (listed for you on purpose), Ubuntu-only gdm3 custom.conf checks on Debian, nginx (port 80 is apache's here).

Superseded first-round runs (same code minus some fixes, no state.txt): modular-planted, old-planted, modular-svc.
