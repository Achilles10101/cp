# cp
CyberPatriot misc (CP19 Linux)

## Layout

**`competition/` is everything you need during a round** — download or copy just that folder onto the image and run the scripts from inside it.

| Path | What it is |
|---|---|
| `competition/CP Linux Checklist.txt` | Main checklist. Manual steps first; the scripts (in run order, with what each covers) are at the bottom |
| `competition/services/baseline.sh` | **Run first.** Detection-only baselining of every critical service (reports in `/root/baseline/<svc>/`) |
| `competition/usersandsudo.sh` | Users, UID 0 accounts, system users, sudoers, groups, password aging |
| `competition/systemconfig.sh` | UFW, APT, LightDM/GDM, UMASK, sysctl (edited in place), PAM/pwquality, sudo, limits, auditd/apparmor, GRUB, permission and persistence checks |
| `competition/fileandpackage.sh` | Unauthorized packages (asks per package family, previews, purges, verifies with dpkg, autoremoves), services and files; SUID/SGID/sticky bits. `--scan` = report only |
| `competition/portandmisc.sh` | Lynis, listening ports, nmap |
| `competition/services/*.sh` | ssh, vsftpd, apache2, nginx, php, mysql, postgresql, samba, bind9, mail (postfix/dovecot), wordpress, openvpn, squid |
| `competition/cp-common.sh` | Shared helpers (sourced by the other scripts; keep the folder layout intact) |
| `competition/baseline/` | Clean-VM baseline packs (see its README). `linuxmint-21.3/` captured 2026-10-21, also used for Mint 21.1/21.2 |
| `tools/verify/` | Scoring harness used to verify the scripts (`plant.sh` is TEST-VM ONLY). `mint21/` = the 2026-10-21 Mint 21.3 container test harness (`plant-mint.sh` is TEST-ONLY) |
| `docs/` | Research findings, change list, scoring verification |
| `old/` | Previous versions, unchanged (`old/2026-10-21/` = scripts/checklist before the Mint 21 test-run fixes, `_apply/` = the archives they came in; `old/2026-10-20/` = fileandpackage.sh and checklist before the live-image fixes; `old/local-cp-stuff/` = older copies from the local folder: the Jan 2026 backup, `-1` duplicates, earlier Claude outputs) |

## Order

From inside `competition/`: README → forensics → manual checklist steps → `sudo bash services/baseline.sh` → review the `!!` findings → `usersandsudo.sh`, `systemconfig.sh`, `fileandpackage.sh`, `portandmisc.sh` → the service scripts for the README's critical services.

Every script backs up what it changes to `/root/cp-backups/<timestamp>/`.
