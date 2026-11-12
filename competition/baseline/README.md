# Baselining (research doc section B, B1-B11)

"To find evil, you must know good." Baselining is its own step: the **scan** only detects, the **review** acts.

## In a round (3 commands)

```
sudo bash services/baseline.sh            # scan: ~5 s, detection only, no questions (fine in the background)
less /root/baseline/FINDINGS.txt          # or just read what the scan printed
sudo bash services/baseline.sh --review   # triage, one key per finding
```

`FINDINGS.txt` lists every finding once, one line each plus what to do. Sections:

- **FIX NOW** (likely planted): unowned files in config/drop-in dirs, unit drop-ins/overrides, unit running an unowned binary, unexpected listeners, phpinfo/webshells, modified package binaries, world-writable or SUID files in service paths, non-default DB/Samba/WordPress accounts, DB on all interfaces.
- **REVIEW** (differs from the default): config files that differ from pristine, with the changed lines shown inline (`+ PermitRootLogin yes`), plus permission differences. Keep only what the README needs.
- **INFO**: no action needed.

`--review [svc...]` walks FIX NOW first, then REVIEW. **Enter** takes the default shown in brackets: quarantine or fix for clearly planted items, skip for everything that might be README-required. Keys:

| key | action |
|---|---|
| d | show the coloured diff / the file / the process |
| r | restore the pristine copy. Backed up first, then validated (`sshd -t`, `apache2ctl configtest`, `nginx -t`, `named-checkconf`, `postfix check`, `testparm -s`, vsftpd test start, `mysqld --validate-config`, `visudo -c` ...), service restarted and checked, rolled back on any failure. Asks first for files that can hold README settings (sshd_config, smb.conf, sites, zones ...) |
| q | quarantine: move to `/root/cp-quarantine/<original path>` (undo: `INDEX.txt` there). Units are stopped and disabled; drop-ins get a daemon-reload, and the unit is restarted. If the service then fails, the file is put back |
| e / m | edit in `$EDITOR` (nano) / Meld, then validate + restart (offers rollback) |
| f | fix permissions to the clean-VM value (undo script in the backup dir) |
| i | reinstall a package whose binary was modified (needs APT) |
| k | kill/stop an unexpected listener, or drop a DB/Samba account (asks y/N) |
| s / x | skip / exit |

Service scripts call `cp_baseline_gate`. If the service has no baseline yet, it is scanned automatically. Only that service's findings are shown, and the gate pauses only when there is a FIX NOW. Hardening is refused if the scan fails.

Other flags: `--meld` (all changed configs in one Meld window), `--no-download`, `--list`, `--capture DIR`.

Output in `/root/baseline/` (root only): `FINDINGS.txt`, and per service `report.txt` (full report, `!!` = finding), `findings.tsv`, `diff.patch`, `pairs.txt`, `before/` (snapshot of the first scan = rollback point + forensics evidence), `runs/<ts>/`. `.scan.lock` is held while a scan runs, so a second run waits instead of racing.

## Where "known good" comes from

1. This folder's pack for the image's OS (`baseline/<os-id>/`, same distro major version also matches, e.g. linuxmint-21.1 uses linuxmint-21.3). No network.
2. Pristine copies on the image (ucf cache, `php.ini-production`, `*.sample`, `main.cf.debian` ...).
3. Only for services no pack covers: `apt-get download` of the installed version, done up front for all packages in parallel with a 20 s cap each (skip with `--no-download`). Package permission defaults (B4) also come from these .debs only when the pack has no `stat.txt`.

The pack's postfix `main.cf` contains the capture VM's hostname. The scan swaps in the live hostname before comparing, so that difference never shows.

## Building a pack (before the season)

1. Make a clean VM for each likely CP19 OS: Ubuntu 22.04 and 24.04, Linux Mint 21.x and 22.x, Debian 12.
2. Install every critical service with default settings and configure nothing: `openssh-server vsftpd apache2 nginx php libapache2-mod-php php-fpm mariadb-server (or mysql-server) postgresql samba bind9 postfix dovecot-imapd openvpn squid`.
3. Copy the repo onto the VM and run `sudo bash services/baseline.sh --capture /tmp/pack`.
4. Copy `/tmp/pack/<os-id>/` into this folder, e.g. `baseline/ubuntu-22.04/`. Remove files that differ on every install (ssh host keys, `/etc/hosts`, `/etc/mysql/debian.cnf`, `/etc/bind/rndc.key`).

## Layout

```
baseline/<os-id>/                 os-id = ID-VERSION_ID from /etc/os-release (ubuntu-22.04, linuxmint-21.3 ...)
  dpkg-l.txt, unit-files.txt, listening-all.txt, world-writable.txt, suid-sgid.txt   (whole system)
  <svc>/pristine/<full path>      default config files (e.g. ssh/pristine/etc/ssh/sshd_config)
  <svc>/stat.txt                  "mode user:group path" (the scan only uses lines under that service's own paths)
  <svc>/accounts.txt              default DB / Samba accounts
  <svc>/listen.txt                default listening sockets
  <svc>/packages.txt              package versions
  <svc>/hardened/<full path>      B11: YOUR hardened version of the same files (fill these in by hand)
```

## 3-way Meld (B11)

```
meld baseline/<os-id>/<svc>/pristine/etc/ssh/sshd_config /etc/ssh/sshd_config baseline/<os-id>/<svc>/hardened/etc/ssh/sshd_config
```

Left = default, middle = live image, right = your target. Anything in the middle that differs from the left is a potential planted vuln. Merge from the right to harden, then re-run the service script, which validates and restarts the service.
