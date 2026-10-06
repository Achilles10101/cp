# cp
CyberPatriot misc (CP19 Linux)

## Layout

| Path | What it is |
|---|---|
| `CP Linux Checklist.txt` | Main checklist |
| `scripts/systemconfig.sh` | UFW, APT, LightDM/GDM, UMASK, sysctl (edited in place), PAM/pwquality, sudo, limits, auditd/apparmor, GRUB, permission and persistence checks |
| `scripts/usersandsudo.sh` | Users, UID 0 accounts, system users, sudoers, groups, password aging |
| `scripts/fileandpackage.sh` | Unauthorized packages, services and files; SUID/SGID/sticky bits |
| `scripts/portandmisc.sh` | Lynis, listening ports, nmap |
| `scripts/cp-common.sh` | Shared helpers (sourced by the other scripts; keep the layout intact) |
| `scripts/services/baseline.sh` | **Run first.** Detection-only baselining of every critical service (reports in `/root/baseline/<svc>/`) |
| `scripts/services/*.sh` | ssh, vsftpd, apache2, nginx, php, mysql, postgresql, samba, bind9, mail (postfix/dovecot), wordpress, openvpn, squid |
| `scripts/baseline/` | Optional clean-VM baseline pack (see its README) |
| `tools/verify/` | Scoring harness used to verify the scripts (`plant.sh` is TEST-VM ONLY) |
| `docs/` | Research findings, change list, scoring verification |
| `old/` | Previous version of the repo, unchanged |

## Order

README → forensics → `sudo bash scripts/services/baseline.sh` → review the `!!` findings → `usersandsudo.sh`, `fileandpackage.sh`, `systemconfig.sh` → the service scripts for the README's critical services.

Every script backs up what it changes to `/root/cp-backups/<timestamp>/`.
