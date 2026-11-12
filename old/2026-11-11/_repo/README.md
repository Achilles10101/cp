# cp
CyberPatriot misc (CP19 Linux)

## Quick start (in a round)

Copy or download the `competition/` folder onto the image, then from inside it:

```
sudo bash start.sh
```

That is the one entry point. It:

1. **Starts the slow work in the background at once:** `apt-get update`, then a download-only run of every upgrade (into its own folder `/var/cache/apt/cp-upgrades/`, so it never holds the lock the scripts' own `apt-get` calls need; nothing is installed until you say yes), and the baseline scan `services/baseline.sh` (detection only).
2. **README intake** (`readme.sh`) until the answers are saved: click in the README page, Ctrl-A, Ctrl-C, paste. Admins, users and critical services are entered once and reused by every script (`/root/cp-state/readme.conf`). This step is not logged (the paste contains passwords); if the answers are not saved, the run stops there.
3. **Forensics reminder + the EARLY MANUAL list**, then the only start.sh pause: "Forensics + early manual items done? Press Enter to continue" (forensics must happen before anything changes).
4. **Then straight through**, no menu (only the scripts' own questions; always CP_AUTO=1): baseline review, users, system, packages/files, ports, critical services, upgrades (one y/N, installed in the background), then it prints the LATE MANUAL list and the TODO list and ends with a one-line summary (total time, per-step durations). Ctrl-C stops the run; run it again and the finished steps are skipped (one line says which), the interrupted one runs again. Background jobs keep running.

Steps that change the system wait for the background baseline scan (it has to see the untouched image), the apt steps (system, packages, ports, critical services, upgrades) wait for the background `apt-get update` (the baseline review does not) (a live counter shows the wait). Every step's full output is kept in `/root/cp-state/logs/<step>.log`. Before each script step the CyberPatriot scoring report (`/opt/CyberPatriot/ScoringReport.html`) is copied to `/root/cp-backups/score-<step>-<time>.html` and the score is printed with the change since the last snapshot (a drop goes on the TODO list); on an image without the report you get one screenshot reminder per step instead (Enter = yes). Everything a script changes is backed up to `/root/cp-backups/<timestamp>/`.

`sudo bash start.sh --reset` forgets which steps are done (README answers are kept; `readme.sh --reset` forgets those). Every script still works on its own (`sudo bash usersandsudo.sh` etc.) with its existing flags.

## Layout

**`competition/` is everything you need during a round** - download or copy just that folder onto the image and run the scripts from inside it.

| Path | What it is |
|---|---|
| `competition/start.sh` | **Run this.** Background jobs, then the whole round straight through, as described above |
| `competition/CP Linux Checklist.txt` | Main checklist: FAST PATH (= the start.sh steps), EARLY MANUAL (start.sh step 2), LATE MANUAL (step 10), OPTIONAL (slow, low-yield), and at the bottom the SCRIPTS section (what each script covers) |
| `competition/CP Checklist Tracker.html` | The checklist as a click-through tracker in the browser (copy commands with a click). After editing the .txt run `python3 update-tracker.py` |
| `competition/readme.sh` | README intake: click in the README page, Ctrl-A, Ctrl-C, paste (asked once; `--show`, `--reset`). Critical services have no default; "none" with service packages installed asks y/N. Passwords never reach the disk (start.sh runs this step unlogged) |
| `competition/services/baseline.sh` | Detection-only baselining of every critical service; start here: `/root/baseline/FINDINGS.txt` (FIX NOW first; per-service reports in `/root/baseline/<svc>/`); `--review` = triage: FIX NOW first, then an optional pass over the REVIEW items (key + Enter per finding) |
| `competition/usersandsudo.sh` | Users, UID 0 accounts, system users, sudoers, groups, password aging |
| `competition/systemconfig.sh` | UFW (rules from the README's critical services + one extra-ports question), "Disable IPv6?" (Enter = yes), APT, LightDM/GDM, UMASK, sysctl (edited in place), PAM/pwquality, sudo, limits, auditd/apparmor, GRUB, permission and persistence checks |
| `competition/fileandpackage.sh` | Unauthorized packages in two lists (remove = Enter yes, review = Enter no; README critical services kept without asking; the OpenSSH server only ever in the review list), previews, purges, verifies with dpkg, autoremoves; services; media quarantined to `/root/cp-quarantine` (Enter = yes, restorable), password files -> TODO; SUID/SGID/sticky bits. `--scan` = report only |
| `competition/portandmisc.sh` | Listening ports with process/package/unit, stop + disable for backdoors and unlisted services; optional lynis / nmap. No menu; `--scan`, `--lynis`, `--nmap` |
| `competition/services/critical.sh` | Runs the service scripts for every README critical service, in a safe order. Each asks one "Does the README change any of these?" question (Enter = no), answers are remembered (`--reask` to change) |
| `competition/services/*.sh` | ssh, vsftpd, apache2, nginx, php, mysql, postgresql, samba, bind9, mail (postfix/dovecot), wordpress, openvpn, squid |
| `competition/cp-common.sh` | Shared helpers (sourced by the other scripts; keep the folder layout intact) |
| `competition/baseline/` | Clean-VM baseline packs (see its README). `linuxmint-21.3/` captured 2026-10-21, also used for Mint 21.1/21.2 |
| `tools/verify/` | Scoring harness used to verify the scripts (`plant.sh` is TEST-VM ONLY). `mint21/` = the Mint 21.3 container test harness (`plant-mint.sh` is TEST-ONLY) |
| `docs/` | Research findings, change list, scoring verification |
| `old/` | Previous versions, unchanged (`old/2026-11-10/` = everything before the speed refactor (start.sh, readme.sh, new baseline flow), `_apply/` = the review package it came in; `old/2026-10-21/` = scripts/checklist before the Mint 21 test-run fixes, `_apply/` = the archives they came in; `old/2026-10-20/` = fileandpackage.sh and checklist before the live-image fixes; `old/local-cp-stuff/` = older copies from the local folder: the Jan 2026 backup, `-1` duplicates, earlier Claude outputs) |

## Order

`sudo bash start.sh` runs everything in this order. By hand (from inside `competition/`) it is the same:
`readme.sh` -> forensics + EARLY MANUAL checklist items -> `services/baseline.sh` (started by start.sh in the background) -> `services/baseline.sh --review` -> `usersandsudo.sh`, `systemconfig.sh`, `fileandpackage.sh`, `portandmisc.sh` -> `services/critical.sh` (the service scripts for the README's critical services) -> install upgrades -> LATE MANUAL checklist items -> the TODO list (`/root/cp-state/TODO.txt`).

Every script backs up what it changes to `/root/cp-backups/<timestamp>/`. The scoring engine in `/opt/CyberPatriot` is never touched.
