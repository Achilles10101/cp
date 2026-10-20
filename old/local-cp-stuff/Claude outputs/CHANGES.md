# Changes applied 2026-09-29 (from "CP19 Service Research Findings.md")

Untouched copies of the original files are in `_original_backup_20260929-2324/`.

When the scripts run, everything they change on the image is backed up to `/root/cp-backups/<timestamp>/<original path>`. Backups are no longer kept next to the file, because include folders such as `apt.conf.d`, `sshd_config.d` and nginx `sites-enabled` would load a `.bak` copy, planted vulnerability and all.

## New files

| File | What it is |
|---|---|
| `cp-common.sh` | Shared helpers: in-place config editing (G1), README prompts, backups, UFW profiles (G3), the baseline gate (B-4) and the web-content scan |
| `Services/baseline.sh` | **Section B.** Detection-only baselining (B1–B9), `--meld`, `--capture` to build a baseline pack (B10/B11) |
| `baseline/README.md` | How to build and use the clean-VM baseline pack |
| `Services/php.sh`, `nginx.sh`, `postgresql.sh`, `samba.sh`, `bind9.sh`, `mail.sh`, `wordpress.sh`, `openvpn.sh`, `squid.sh` | New service scripts (PHP1–4, NGX1–3, PG1–5, SMB1–6, DNS1–3, MAIL1–4, WP1–3, VPN1, Squid) |
| `CHANGES.md` | This file |

Every service script now starts by requiring a baseline for its service. If none exists, it offers to run `baseline.sh`.

---

## Replaced or deleted items (original → new)

### Services/ssh.sh

| # | Original | Now | Why |
|---|---|---|---|
| 1 | `set -e` | **Deleted**; each step checks its own result | A single failed `chown` aborted the script before any hardening (SSH1) |
| 2 | Step 4 looped over every directory in `/home/*` and ran `chown "$USERNAME:$USERNAME"` | Loops over real accounts in `/etc/passwd` (UID ≥ 1000, plus root) and uses `chown "$USERNAME":` (the user's login group) | SSH1 |
| 3 | Private-key perms for `id_rsa` / `id_rsa.pub` only | All key types: `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `*_sk` (600) and their `.pub` files (644) | SSH10 |
| 4 | Settings applied by `sed …/Id` (deleted **every** matching line, commented ones included) and then **appending** the settings at the end of the file | Each key is edited **in place** (first occurrence), duplicates are deleted, and new keys go **above the first `Match` block**. The same keys are also **deleted from `/etc/ssh/sshd_config.d/*.conf`** | SSH2, SSH3, G1 |
| 5 | `ufw allow ssh` | `ufw allow OpenSSH` (falls back to 22/tcp; a custom README port is opened instead when set) | G3 / SSH11 |
| 6 | `apt update` / `apt install fail2ban` | `apt-get update` / `apt-get install fail2ban` (same effect, stable CLI for scripts) | – |
| 7 | `/etc/issue.net` (whatever it contained) | Replaced with "Authorized users only. All activity may be monitored and reported." (old one backed up) | CIS banner without OS info (SSH6) |

All 12 original sshd values are kept unchanged. New keys: `ClientAliveInterval 300`, `Protocol 2`, `PermitUserEnvironment no`, `UsePAM yes`, `StrictModes yes`, `MaxSessions 4`, `MaxStartups 10:30:60`, `GSSAPIAuthentication no`, `KbdInteractiveAuthentication no`, `PubkeyAuthentication yes`, `Banner /etc/issue.net`, `DisableForwarding yes`, `DebianBanner no`, and README prompts for `PasswordAuthentication`, `Port`, `AllowUsers`, `DenyUsers`, `DenyGroups`, and SFTP-only.

### Services/vsftpd.sh

| # | Original | Now | Why |
|---|---|---|---|
| 1 | `set -e` | **Deleted** | – |
| 2 | Deleted every `^KEY=` line and **appended** the whole parameter block at the end (via a temp file + `mv`) | Each key is edited **in place** in the config the unit actually uses | G1, B5 |
| 3 | `write_enable=YES` (hard-coded) | README prompt (default YES) | FTP9 |
| 4 | `allow_writeable_chroot=NO` (hard-coded) | Prompt: **a)** `NO` + a root-owned `/home/<user>/ftp` jail with a writable `files/` folder, or **b)** `YES` (default) | FTP1: `NO` locked every user out of FTP |
| 5 | `force_local_logins_ssl=YES`, `force_local_data_ssl=YES` (hard-coded) | README prompt (default YES) | FTP4 |
| 6 | `anonymous_enable=NO` (hard-coded) | README prompt (default NO) | – |
| 7 | `pasv_min_port=40000` / `pasv_max_port=50000` (hard-coded) | Prompt (default 40000-50000) | FTP10 |
| 8 | `chown root:root "$LOCAL_ROOT"; chmod 755 "$LOCAL_ROOT"/*` (chmodded the **contents**) | `chmod 755` on the **directory itself** + `chmod -R o-w` on the contents, also for `anon_root` and `/srv/ftp` | FTP2 |
| 9 | `ufw allow 21/tcp` | `ufw allow vsftpd` profile when it exists, else 21/tcp (passive-range rule kept) | G3 |
| 10 | Restart failure → `exit 1`, leaving the broken config in place | Config is **test-started first**; on failure the backup is restored | G2 |

All other original values are kept, including `ssl_tlsv1=YES`. **Correction to FTP3:** testing on Ubuntu 24.04 showed vsftpd rejects the manpage spellings `ssl_tlsv1_2` etc. (it won't start) and accepts `ssl_tlsv12` etc. The script therefore reads the real option names from the binary. New keys: `ssl_ciphers=HIGH`, `allow_anon_ssl=NO`, `anon_upload_enable=NO`, `anon_mkdir_write_enable=NO`, `anon_other_write_enable=NO`, `hide_ids=YES`, `ls_recurse_enable=NO`, `ftpd_banner`, `max_login_fails=3`, `delay_failed_login=3`, `idle_session_timeout=300`, `data_connection_timeout=120`, `max_per_ip=5`, `pam_service_name`, `secure_chroot_dir`, plus `ssl_tlsv11=NO` / `ssl_tlsv12=YES` / `ssl_tlsv13=YES` when supported. It also audits `chroot_list`, `userlist` and `ftpusers` (FTP5).

### Services/apache2.sh

| # | Original | Now | Why |
|---|---|---|---|
| 1 | `set -euo pipefail` | `set -uo pipefail` (**`-e` removed**) | – |
| 2 | `a2dismod "$module"` | `a2dismod -f "$module"` | Dependent modules no longer block disabling |
| 3 | Standard removal list: status, autoindex, negotiation, cgi, cgid, userdir | Same, **plus** `info`, `dav`, `dav_fs` | WEB6 |
| 4 | security.conf: deleted lines, then appended `ServerTokens Prod` / `ServerSignature Off` / `TraceEnable Off` | The same three values set **in place**; conflicting copies removed from other enabled confs | G1 |
| 5 | `Header set X-XSS-Protection "1; mode=block"` | `Header set X-XSS-Protection "0"` | WEB7 (deprecated value) |
| 6 | `Content-Security-Policy` header always added | Prompt (default yes) | WEB7 (can break CDN-loading sites) |
| 7 | `LogLevel info` deleted + appended | Set in place | G1 |
| 8 | `/var/www/html`: `Options -Indexes -ExecCGI -Includes -FollowSymLinks`, `AllowOverride None` (always) | Same by default. If you answer yes to "web app uses .htaccess": `Options -Indexes -ExecCGI -Includes +SymLinksIfOwnerMatch` + `AllowOverride All` | WordPress permalinks need it |
| 9 | (untouched) default `<Directory /var/www/>` line `Options Indexes FollowSymLinks` | Replaced with `Options -Indexes +SymLinksIfOwnerMatch -ExecCGI -Includes` | WEB3 |
| 10 | **`find /var/www -name .htaccess -delete`** | **Deleted.** `.htaccess` files are now listed for review only | WEB1 |
| 11 | `chown -R root:root /var/www` + `chmod -R 755` + files 644 (always) | Prompt (default yes); www-data-owned `uploads`/`cache`/`tmp`/`sessions`/`files` folders stay writable | WEB2 |
| 12 | Configtest/restart failure → `exit 1`, broken config left in place | Whole `/etc/apache2` is rolled back | G2 |

New: `FileETag None`, `LimitRequestBody 10485760`, `Timeout 60`, optional HTTPS (mod_ssl, TLS 1.2/1.3, HSTS), run-user check, `DocumentRoot`/`Alias` check, `/etc/apache2`, `/var/log/apache2` and `/etc/ssl/private` perms, phpinfo/webshell scan, `ufw allow 'Apache Full'`, optional mod_security, and HTTP/TRACE tests.

### Services/mysql.sh

| # | Original | Now | Why |
|---|---|---|---|
| 1 | `set -e` | **Deleted** | – |
| 2 | `detect_database_type` echoed its status messages to stdout (so `DB_TYPE` never equalled `mariadb`) | Messages go to stderr | DB1 |
| 3 | `DELETE FROM mysql.user WHERE User='';` | `DROP USER IF EXISTS ''@'localhost', ''@'%', ''@'<hostname>'` | DB2 (a view on MariaDB 10.4+) |
| 4 | `UPDATE mysql.user SET Host='localhost' WHERE User='root' AND Host='%';` | `DROP USER 'root'@'<each non-local host>'` (only if `root@localhost` exists) | DB2 |
| 5 | **`CREATE USER IF NOT EXISTS 'admin'@'localhost' IDENTIFIED BY 'Cyb3rPatr3ot@2026!'`** | **Deleted** | DB3 |
| 6 | **`GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost' WITH GRANT OPTION`** | **Deleted**; offers to drop `admin@localhost` if an earlier run created it | DB3 |
| 7 | **"Admin credentials: admin / Cyb3rPatr3ot@2026!" printed at the end** | **Deleted** | DB3 |
| 8 | `chmod 750 /etc/mysql` (owner root:root) + `chmod 640 /etc/mysql/my.cnf` | `chown -R root:mysql /etc/mysql`, dirs 750, `*.cnf` 640, `debian.cnf` 600 root. Checks that the mysql user can read each file and falls back to 755/644 if not | DB4 |
| 9 | Logs: `touch mysql.log error.log`, `chown -R mysql:mysql`, 640 | `error.log` only; `/var/log/mysql` mysql:adm 2750, logs 640 | – |
| 10 | Cert perms: `chmod 600 *-key.pem` **then** `chmod 644 *.pem` (the second command made the keys 644 again) | 644 first, then 600 for keys; `/etc/mysql/ssl` 750 | Bug fix |
| 11 | **`cat >` overwrote the whole `50-server.cnf` / `mysqld.cnf`** | Keys edited **in place** in `[mysqld]`; conflicting copies removed from every other `.cnf` | DB5 |
| 12 | `require_secure_transport = ON` | Prompt (default **OFF**) | DB6 |
| 13 | `general_log = 1` | Prompt (default **0**) | DB9 |
| 14 | `bind-address = 127.0.0.1` | Prompt (default 127.0.0.1; 0.0.0.0 only if the README needs remote access) | – |
| 15 | `chmod 644` on the config file | 640 root:mysql | DB4 |
| 16 | Order: accounts → perms → certs → config → restart; restart failure = broken DB | Perms → certs → config → **validate** → restart → accounts; rollback of `/etc/mysql` on failure | DB8, G2 |

Kept: `ssl-ca`/`ssl-cert`/`ssl-key`, `local-infile = 0`, `sql_mode`, `general_log_file`, `log_error`, `performance_schema = OFF`, `DROP DATABASE test`. New: `secure_file_priv`, `skip-symbolic-links`, `log_warnings`/`log_error_verbosity`, removal of `skip-grant-tables`/`old_passwords`/`symbolic-links`, and the account audit (DB10).

### systemconfig.sh

| # | Original | Now | Why |
|---|---|---|---|
| 1 | `set -e` | **Deleted** | – |
| 2 | `while true` (UFW port prompt loop) | `while [ -t 0 ]` | Looped forever when run without a terminal |
| 3 | LightDM: `exit 1` when `/etc/lightdm/lightdm.conf` is missing (the rest of the script never ran, e.g. on Mint) | Creates the file with `[Seat:*]` and continues | Bug fix |
| 4 | **`cat >> /etc/sysctl.conf`** (appended all 33 parameters) | The **same 33 values** set **in place** (a planted `ip_forward=1` is replaced, not left above ours). They are also removed from planted or later-sorting `/etc/sysctl.d` files | SYS1, G1 |
| 5 | IPv6 disable/harden blocks appended with `cat >>` | Same values set in place. The "enable" branch now also sets `disable_ipv6 = 0` | SYS1 |
| 6 | `read -p "Enable IPv6?"` (always) | Only when interactive | – |
| 7 | `sysctl -p` | `sysctl --system` (same order as at boot, so sysctl.d files are accounted for) | SYS1 |

Kept unchanged: UFW setup, the APT/unattended-upgrades block (including `50auto-upgrades`), the LightDM keys, `UMASK 027` in login.defs and /etc/profile. New: `xserver-allow-tcp=false` + LightDM drop-in cleanup, GDM3, `ENCRYPT_METHOD SHA512`, `LOGIN_RETRIES 3`, 11 extra sysctl keys (SYS2), and PAM checks + pwquality (SYS3). Also: sudo.conf / sudoers defaults (SYS4), limits (SYS5), apparmor/auditd (SYS7), GRUB (SYS8), permission plants (SYS9) and persistence checks (SYS10; `ld.so.preload` is checked first).

### users.sh

| # | Original | Now |
|---|---|---|
| 1 | `echo "$SUDOERS_CONTENT"` (printed the temp-file **path**) | `cat "$SUDOERS_CONTENT"` |
| 2 | `ok` / `err` called but never defined | Defined at the top |

### fileandpackage.sh

Nothing replaced or deleted. Added `avahi-daemon cups cups-browsed rpcbind xrdp inspircd squid` to the scan list.

### CP Linux Checklist.txt

| # | Original | Now |
|---|---|---|
| 1 | `add minlen=10 remember=3 to line with pam_unix.so` | `remember=5` (Aperture's scoring regex requires ≥ 5) |

Added: pwquality.conf and login.defs lines, the sudoers `Defaults` note, the pam_deny/pam_exec check, and the "baseline first" service order.

### port:cyber.sh

Unchanged.

---

## Tested (Ubuntu 24.04 container with the real packages)

Every script passes `bash -n`, and the service scripts pass `shellcheck -S warning` (except intentional word-splitting warnings). Each service script was run against a planted-vuln setup, and all validators pass: `sshd -t`/`sshd -T`, `apachectl configtest`, a vsftpd test start, `nginx -t`, MariaDB 10.11 `--help --verbose`, PostgreSQL 16, `testparm`, `named-checkconf -z`, `postfix check`, `doveconf -n` and `squid -k parse`. Rollback on failure was exercised for sshd and nginx.

**Not testable in a container:** real systemd restarts, UFW, `ssh.socket`, and GUI/LightDM/GDM. **Test once on a practice image before competition day.**

---

## Round 2 (2026-09-29, after scoring verification; see VERIFICATION.md)

| File | Original (round 1 / checklist) | Now |
|---|---|---|
| systemconfig.sh | ld.so.preload emptied only | Also offers to delete the preloaded rootkit library (Aperture check) |
| systemconfig.sh | `pam_exec` lines only warned about | Offers to remove them (Aperture check) |
| systemconfig.sh | aliases only listed | Aliases in system-wide shell files can be removed; user `.bashrc` files are listed only |
| systemconfig.sh | FACL strip: all paths, default **no** | System dirs stripped by default; `/home` and `/var/www` listed only (a restrictive ACL there can be REQUIRED) |
| systemconfig.sh | (no gdm AllowRoot) | `AllowRoot=false` added |
| systemconfig.sh | login.defs aging not set by any script | `PASS_MAX_DAYS 30`, `PASS_MIN_DAYS 7`, `PASS_WARN_AGE 14` |
| systemconfig.sh | common-password untouched | pam_unix `remember=5 minlen=10`; pam_pwquality `dictcheck=1 usercheck=1 minlen=10` + credits |
| Services/apache2.sh | UFW always `Apache Full` with HTTPS | Asks: `Apache Secure` (HTTPS only) or `Apache Full` |
| users.sh | `chage -M 90 -m 7 -W 14` | `chage -M 30 -m 7 -W 14` |
| CP Linux Checklist.txt | `pass_max_days 90` | `pass_max_days 30` (90 fails the Aperture check; 30 passes all seen) |
| CP Linux Checklist.txt | faillock_reset `required pam_faillock.so authsucc` | `sufficient pam_faillock.so authsucc` (what the Aperture check matches) |
