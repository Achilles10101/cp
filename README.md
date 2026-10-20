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
| `competition/fileandpackage.sh` | Unauthorized packages, services and files; SUID/SGID/sticky bits |
| `competition/portandmisc.sh` | Lynis, listening ports, nmap |
| `competition/services/*.sh` | ssh, vsftpd, apache2, nginx, php, mysql, postgresql, samba, bind9, mail (postfix/dovecot), wordpress, openvpn, squid |
| `competition/cp-common.sh` | Shared helpers (sourced by the other scripts; keep the folder layout intact) |
| `competition/baseline/` | Optional clean-VM baseline pack (see its README) |
| `tools/verify/` | Scoring harness used to verify the scripts (`plant.sh` is TEST-VM ONLY) |
| `docs/` | Research findings, change list, scoring verification |
| `old/` | Previous versions, unchanged (`old/local-cp-stuff/` = older copies from the local folder: the Jan 2026 backup, `-1` duplicates, earlier Claude outputs) |

## Order

From inside `competition/`: README → forensics → manual checklist steps → `sudo bash services/baseline.sh` → review the `!!` findings → `usersandsudo.sh`, `systemconfig.sh`, `fileandpackage.sh`, `portandmisc.sh` → the service scripts for the README's critical services.

Every script backs up what it changes to `/root/cp-backups/<timestamp>/`.
