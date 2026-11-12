# cp
CyberPatriot misc (CP19 Linux)

## In a round

Copy or download the `competition/` folder onto the image and work from inside it. Follow `CP Linux Checklist.txt` (or its click-through tracker):

1. README, then the **Forensics Questions before anything is changed**, then the MANUAL items.
2. `sudo bash services/baseline.sh` (or `sudo ./baseline.sh` from `services/`): read-only scan, prints the findings (`/root/baseline/FINDINGS.txt`), then asks once `Go through the findings now? [y/N]` (`--review` later is optional).
3. The category scripts one at a time, checking the score after each (every script first copies the scoring report to `/root/cp-backups/score-<script>-<time>.html` and prints the score and the change, or asks for a screenshot when there is no report): `usersandsudo.sh`, `systemconfig.sh`, `fileandpackage.sh`, `portandmisc.sh`.
4. `sudo bash services/critical.sh` (asks per detected service whether the README lists it as critical), then `sudo bash upgrades.sh`.
5. LAST: account expiry defaults and the lockout policy (faillock, then nullok) from the checklist's LAST section. Every script ends with a numbered list of what it found for you to act on.

Every script asks for the README facts it needs itself and backs up what it changes to `/root/cp-backups/<timestamp>/`. The scoring engine in `/opt/CyberPatriot` is never touched.

### Speedrun (intro rounds)

```
sudo bash speedrun.sh
```

Runs the same scripts in one go and passes nothing to them (each asks its own questions):
- starts only the read-only baseline scan in the background, then stops once: "Do the Forensics Questions now - nothing has been changed yet. Press Enter when done."
- then starts `apt-get update` and a download-only run of the upgrades in the background (its own folder `/var/cache/apt/cp-upgrades/`, so it never blocks the scripts' apt calls)
- runs `usersandsudo.sh`, `services/baseline.sh --review`, `systemconfig.sh`, `fileandpackage.sh`, `portandmisc.sh`, `services/critical.sh`, `upgrades.sh`. Changes wait for the baseline scan, the apt steps for the background `apt-get update` (live counter).
- ends with the reminder that the lockout policy comes last and the time per step (each script ends with a list of what it found for you to act on).

Each step's output goes to `/root/cp-state/logs/<step>.log` (except usersandsudo, which may hold README passwords). Ctrl-C stops the run; run it again and finished steps are skipped (`--reset` forgets them).

## Layout

**`competition/` is everything you need during a round** - download or copy just that folder onto the image and run the scripts from inside it.

| Path | What it is |
|---|---|
| `competition/speedrun.sh` | Intro-round speedrun: the scripts below in one go (see above) |
| `competition/upgrades.sh` | Lists apt repositories (non-official -> warning + listed as not done), shows what the full-upgrade installs, one y/N, installs keeping hardened config files; uses speedrun's pre-downloaded upgrades if present |
| `competition/CP Linux Checklist.txt` | Main checklist: MAIN FLOW (modular order), SPEEDRUN, MANUAL, LAST (expiry defaults + lockout policy), OPTIONAL (slow, low-yield), and at the bottom the SCRIPTS section (what each script covers) |
| `competition/CP Checklist Tracker.html` | The checklist as a click-through tracker in the browser (copy commands with a click). After editing the .txt run `python3 update-tracker.py` |
| `competition/readme.sh` | The README paste parser used by usersandsudo.sh (admins, users, your account, insecure README passwords). `bash readme.sh` = preview what a paste parses to (saves nothing). Passwords never reach the disk |
| `competition/services/baseline.sh` | Detection-only baselining of every critical service; start here: `/root/baseline/FINDINGS.txt` (FIX NOW first; per-service reports in `/root/baseline/<svc>/`); after the scan it asks once whether to go through the findings (optional later: `--review`; FIX NOW first, then the REVIEW items, key + Enter per finding) |
| `competition/usersandsudo.sh` | Asks for the README paste on every run; users, UID 0 accounts, system users, sudoers, groups, password aging; one "Change it now? [Y/n]" per insecure README password |
| `competition/systemconfig.sh` | UFW (server daemons found installed/listening listed with the rule each needs, you choose; + one extra-ports question), "Disable IPv6?" (Enter = yes), APT, LightDM/GDM, UMASK, sysctl (edited in place), PAM/pwquality, sudo, limits, auditd/apparmor, GRUB, permission and persistence checks |
| `competition/fileandpackage.sh` | Unauthorized packages in two lists (hacking tools/games = Enter yes; service families = Enter no, each with an installed/running/port hint; the OpenSSH server its own [y/N]), previews, purges, verifies with dpkg, autoremoves; services; media quarantined to `/root/cp-quarantine` (Enter = yes, restorable), password files listed as not done; SUID/SGID/sticky bits. `--scan` = report only |
| `competition/portandmisc.sh` | Listening ports with process/package/unit, stop + disable for backdoors and unlisted services; optional lynis / nmap. No menu; `--scan`, `--lynis`, `--nmap` |
| `competition/services/critical.sh` | Detects the services installed here and asks for each "Run <svc>.sh (the README must list it as critical)? [y/N]", then runs them in a safe order. Each service script asks its own README questions (Enter = no; its own answers remembered, `--reask` to change) |
| `competition/services/*.sh` | ssh, vsftpd, apache2, nginx, php, mysql, postgresql, samba, bind9, mail (postfix/dovecot), wordpress, openvpn, squid |
| `competition/cp-common.sh` | Shared helpers (sourced by the other scripts; keep the folder layout intact) |
| `competition/baseline/` | Clean-VM baseline packs (see its README). `linuxmint-21.3/` captured 2026-10-21, also used for Mint 21.1/21.2 |
| `tools/verify/` | Scoring harness used to verify the scripts (`plant.sh` is TEST-VM ONLY). `mint21/` = the Mint 21.3 container test harness (`plant-mint.sh` is TEST-ONLY) |
| `docs/` | Research findings, change list, scoring verification |
| `old/` | Previous versions, unchanged (`old/2026-11-12/` = the version before the 2026-11-12 fixes; `old/2026-11-11/` = the version before the evening redesign (start.sh, shared README answers); `old/2026-11-10/` = everything before the speed refactor (start.sh, readme.sh, new baseline flow), `_apply/` = the review package it came in; `old/2026-10-21/` = scripts/checklist before the Mint 21 test-run fixes, `_apply/` = the archives they came in; `old/2026-10-20/` = fileandpackage.sh and checklist before the live-image fixes; `old/local-cp-stuff/` = older copies from the local folder: the Jan 2026 backup, `-1` duplicates, earlier Claude outputs) |

## Order

`README` -> forensics -> MANUAL items -> `services/baseline.sh` + `--review` -> `usersandsudo.sh`, `systemconfig.sh`, `fileandpackage.sh`, `portandmisc.sh` (check the score after each) -> `services/critical.sh` -> `upgrades.sh` -> LAST (expiry defaults, faillock, then nullok) -> the by-hand items each script listed at its end. `speedrun.sh` does the script part of this in one go.
