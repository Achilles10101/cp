# CP19 Linux – Service Research Findings (for review)

Compiled 2026-09-29. **Applied to the scripts on 2026-09-29** (see "Applied changes" at the end). Every item has an ID so you can reply with something like "apply B1–B9, G1–G3, SSH1–SSH9, skip FTP3".

## How to read this

**Evidence tags (strongest first)**

- **[OFFICIAL]**: scored in an official AFA answer key (CP17 Training 2 Ubuntu 22, CP18 R1/R2 Mint 21).
- **[PRACTICE]**: scored in a community practice image's real scoring config or writeup. Sources: *Aperture Science* Ubuntu 22.04 (state/semis level, full aeacus `scoring.conf`), *1984* Mint 22.3 (Apr 2026, "Hard", full `scoring.conf`), eth007's *Syshardening 6 / Narnia* (the image the blog recommends), and *Resident Ubuntu*.
- **[HIVESTORM]**: scored in Hivestorm 2021 (a similar competition), from sourque's writeup.
- **[BLOG]**: a principle from Akshay's post. **This outranks every other source.**
- **[CIS]**: CIS Ubuntu 24.04 benchmark, taken from ComplianceAsCode's `controls/cis_ubuntu2404.yml`.
- **[DOCS]**: checked against the vendor manpage or docs (Ubuntu jammy/noble vsftpd.conf(5), samba.org smb.conf(5), MySQL 8.4 manual).
- **[BUG]**: a defect I found in your current service scripts.

**Risk flags**

- ⚠ **README**: only do this if the README allows it, because it can break a required function.
- ⚠ **BREAK**: can take the service down if done blindly.

---

## 0. The blog's rules for services (these govern every section below)

Straight from "How To Win CyberPatriot". Anything below that conflicts with these loses.

1. **Security mindset.** For every service: turn logging on and make it verbose, hide version information, enable encrypted connections, and lock down permissions on config files, password-hash files and raw database data directories.
2. **Respect the challenge.** Avoid deprecated or malformed directives. Restart or reload the service and confirm the change actually took effect.
3. **Baselining ("To find evil, you must know good").** Diff each service's config against a pristine default, ideally in Meld. The first hour goes to baselining. **This has its own category: section B.**
4. **Gameplan order:** README → FQs → fix broken mechanisms (APT repos, `chattr +i`, `$PATH`) → baseline → users → backdoors → updates → reboot for kernel → packages/services → system hardening (PAM, sysctl, sudoers, polkit, bootloader) → **critical service security** → file perms → point scrounging.
5. **Critical services to research** (the blog's list, Linux side): Apache2, Bind9, OpenSSH, MySQL/MariaDB, Postfix, Sendmail, vsftpd, Samba, WordPress, Joomla, OpenVPN. You currently script 4 of these 11.

---

## B. BASELINING: separate category (run before any service hardening)

The blog calls baselining *"the single most consistent and effective strategy"*. Its team spent the first hour on it and did all config hardening through Meld against default filesystems built into their scripts. None of your current service scripts baseline. Everything in this category is **detection only**: it produces diffs and reports for a human to act on and changes nothing. The hardening suggestions (G, SSH, FTP, …) come after it and are kept completely separate.

### B-1. What to baseline for each service

| ID | Item | How | Evidence |
|---|---|---|---|
| **B1** | **Package integrity of the service** (binaries, PAM modules, shipped files) | `dpkg -V <pkg>` (a `c` in the output marks a conffile) or `debsums -c <pkg>`. This catches a trojaned `/usr/sbin/sshd` or `vsftpd`, or a replaced `pam_unix.so` (`dpkg -V libpam-modules`). Run it **after** fixing APT sources (blog gameplan step 3). | [BLOG] |
| **B2** | **Config content vs pristine default**: every conffile of the service | See B-2 for where pristine copies live. `diff -ru pristine/ live/`, or Meld for side-by-side. Quick check with no network: `dpkg-query -W -f='${Conffiles}\n' <pkg>` gives each conffile's original md5, then compare with `md5sum`. | [BLOG] |
| **B3** | **Files in config dirs that no package owns** (planted drop-ins) | For each file under the service's config dirs : `dpkg -S <file>` fails → not package-shipped → review it. Dirs: `/etc/ssh/sshd_config.d/`, `/etc/apache2/{conf,sites,mods}-{available,enabled}/`, `/etc/nginx/{conf.d,sites-*}/`, `/etc/mysql/**`, `/etc/php/*/*/conf.d/`, `/etc/samba/`, `/etc/bind/`, `/etc/postfix/`, `/etc/dovecot/conf.d/`, `/etc/sysctl.d/`, `/etc/sudoers.d/`, `/etc/lightdm/lightdm.conf.d/`, `/etc/apt/apt.conf.d/`. Scored examples: `99autotrust` (Aperture), a planted `10-*.conf` in `sysctl.d` (Narnia). | [BLOG] [PRACTICE] |
| **B4** | **Permissions and ownership vs default** (config files, keys, data dirs, web/FTP roots) | Defaults come from the package itself: `dpkg-deb -c <pkg>.deb` lists each shipped file's mode and owner. For dirs created at install time (e.g. `/var/lib/mysql`, `/srv/ftp`), use a clean-VM capture (B-3). Compare against `stat -c '%a %U:%G %n'`. Scored: FTP root perms, PostgreSQL conf perms, sshd_config owner. | [OFFICIAL] [HIVESTORM] [PRACTICE] [BLOG] |
| **B5** | **systemd units of the service** (ExecStart, User, sandboxing) | `systemd-delta --type=overridden,extended,redirected` lists every unit overridden or extended by a drop-in. `systemctl cat <svc>` shows the effective unit. `dpkg -S` on each unit in `/etc/systemd/system/` flags units no package owns. Scored: custom service had to run as its own user with `ProtectSystem=true` (Narnia). | [PRACTICE] [BLOG] |
| **B6** | **Listening sockets vs expected** | `ss -tulpn` compared against a per-service expected list: ssh 22 (or README port); vsftpd 21 + passive range; apache/nginx 80/443; mysql 3306 on 127.0.0.1; postgres 5432 on localhost; smbd 139/445; named 53; postfix 25/587; dovecot 143/993. Anything extra (or a service bound to `0.0.0.0` when it should be local) is a finding. Your `port:cyber.sh` already lists ports; this adds the expected-vs-actual comparison. | [BLOG] |
| **B7** | **Service-internal accounts vs defaults** | Default MySQL 8 accounts: `root`, `mysql.sys`, `mysql.session`, `mysql.infoschema`, `debian-sys-maint`. Default MariaDB accounts: `root`, `mysql`, `mariadb.sys`. PostgreSQL: only role `postgres`. Samba (`pdbedit -L`): empty on a clean install. WordPress: only README admins. Any other account is a finding. | [BLOG] [HIVESTORM] |
| **B8** | **Web/FTP content vs default** | A clean Apache or nginx ships only `/var/www/html/index.html` (or `index.nginx-debian.html`). List every other file with owner, mode and mtime (`find /var/www /srv -type f -printf '%TY-%Tm-%Td %u:%g %m %p\n' \| sort`). This catches webshells, `phpinfo()` files ("Removed phpinfo file" was scored) and planted uploads. | [HIVESTORM] [BLOG] |
| **B9** | **Snapshot the live service state before changing anything** | Copy each service's config dirs to e.g. `/root/baseline/<svc>/before/`. Two uses: a rollback point if a change breaks the critical service, and preserved evidence for FQs (the blog and Hivestorm writeup both warn that hardening destroys FQ evidence). | [BLOG] |

### B-2. Where the pristine copy of each service config comes from

| Service | Pristine source on the image (no download needed) | Otherwise |
|---|---|---|
| OpenSSH | `/usr/share/openssh/sshd_config` (ucf template) | `apt-get download openssh-server` |
| Samba | `/usr/share/samba/smb.conf` | `apt-get download samba-common` |
| PHP | `/usr/lib/php/<ver>/php.ini-production` (the source `php.ini` is installed from) and `php.ini-development` | – |
| PostgreSQL | `/usr/share/postgresql/<ver>/pg_hba.conf.sample`, `postgresql.conf.sample`, `pg_ident.conf.sample` | – |
| Postfix | `/usr/share/postfix/main.cf.debian`, `main.cf.dist` (then `postconf -n` vs `postconf -d` shows **only** non-default values) | – |
| Files managed by ucf | `/var/lib/ucf/cache/` (colon-encoded paths, e.g. `:etc:ssh:sshd_config`) | – |
| vsftpd, Apache, nginx, MySQL/MariaDB, Bind9, Dovecot | – | `apt-get download <pkg>` then `dpkg-deb -x <pkg>.deb /root/pristine/<pkg>` (packages: `vsftpd`, `apache2`, `nginx-common`, `mysql-server-8.0` or `mariadb-server`, `bind9`, `dovecot-core`) |
| Any service, runtime defaults | `postconf -d`, `sshd -T -f /dev/null`, `testparm -s <pristine smb.conf>`, `mysqld --no-defaults --verbose --help`, `named-checkconf -p` | – |

### B-3. Prebuilt "baseline pack" from clean VMs (the blog's exact method)

| ID | Item | Evidence |
|---|---|---|
| **B10** | Before the season, build clean VMs of each likely CP19 OS: Ubuntu 22.04 and 24.04, Mint 21.x and 22.x, and Debian 12 for later rounds. Install each critical service with **default** settings. From each one, capture into the repo: `/etc` for every service; `stat` of config and data dirs; `systemctl list-unit-files`; `ss -tulpn`; default DB/Samba accounts; `dpkg -l`. The blog's team *"incorporated entire default filesystems into our script"*. It removes the dependency on network or APT during the round, and it covers state that isn't in any `.deb` (install-time dirs, generated certs, DB users). | [BLOG] |
| **B11** | Next to each pristine config, store **your hardened version** of the same file. At competition time Meld then shows pristine, live image and your hardened target, and you merge by hand. The blog team did *all* config hardening this way, and it avoids the blind-append problems found in the SSH/MySQL scripts. | [BLOG] |

### B-4. Proposed script implementation (for your go-ahead; nothing is written yet)

- New **`Services/baseline.sh`**, detection only. It auto-detects which critical-service packages are installed. For each one it runs B1 → B9 and writes `/root/baseline/<svc>/report.txt` plus `diff.patch`, and never modifies anything. Optional `--meld` flag opens the pristine vs live diff per file.
- Each existing service script (`ssh.sh`, `vsftpd.sh`, `apache2.sh`, `mysql.sh`) gets a first step that **refuses to continue** until `baseline.sh` has been run for that service (checks for `/root/baseline/<svc>/before/`), then prints that service's findings. This enforces the blog's order: baseline → review → harden.
- The baseline pack (B10/B11) lives in the repo as `baseline/<os>/<svc>/{pristine,hardened}/` and is used when present, falling back to on-image sources (B-2), then `apt-get download`.

---

## G. Cross-service hardening and verification (apply to every service script)

Baselining items have moved to their own category, **B** (above).

| ID | Item | Evidence |
|---|---|---|
| **G1** | **Edit in place and remove conflicting duplicates. Don't just append.** Scoring checks such as `FileContainsRegexNot '^net.ipv4.ip_forward=1'` or `'^PermitRootLogin yes'` fail if the bad line is still in the file, even when a later line overrides it. The official CP17 key literally says *"change `ip_forward=1` to `0`"*. Your SSH and vsftpd scripts already delete-then-append. **`systemconfig.sh` sysctl and the MySQL cnf approach don't** (see SYS1 and DB5). | [OFFICIAL] [PRACTICE] |
| **G2** | **Add a post-change functional test to every service script**, not just `systemctl is-active`. Examples: `curl -sI http://localhost`, `curl -k --ftp-ssl -u user:pass ftp://localhost/`, `smbclient -L localhost -U user`, `mysql -e 'select 1'`, `sshd -T`. The 1984 image literally checked that required ports 25/587/143 were still accepting connections. | [BLOG] [PRACTICE] |
| **G3** | **Use UFW application profiles when they exist.** Scoring regexes matched `OpenSSH *ALLOW *Anywhere`, `Apache Secure *ALLOW`, and `vsftpd *ALLOW`. Your scripts use `ufw allow ssh` and `21/tcp`, which show as port numbers and would not match. Use `ufw app list`, then `ufw allow OpenSSH`, `'Apache Full'` or `'Apache Secure'`, `'Nginx Full'`, `Samba`, `Postfix`, `'Dovecot Secure IMAP'`, `Bind9`, etc. | [PRACTICE] (Aperture ×4) |
| **G4** | **Update every critical service package** (`apt install --only-upgrade <pkg>`). Scored repeatedly: "OpenSSH/Vsftpd/Samba/PostgreSQL has been updated". Your checklist has this. It's listed here only to confirm it is repeatedly scored. | [OFFICIAL] [HIVESTORM] |
| **G5** | **Fix perms and ownership on every service's config and data** (the differences B4 finds; target values in each section). "Insecure permissions on PostgreSQL configuration files fixed", "Insecure permissions on FTP root directory fixed" and "sshd_config owned by root" were all scored. | [OFFICIAL] [HIVESTORM] [PRACTICE] [BLOG] |

---

## SSH (`Services/ssh.sh`)

| ID | Item | Evidence |
|---|---|---|
| **SSH1** [BUG] | **The script can abort before hardening anything.** The Step 4 loop runs `chown "$USERNAME:$USERNAME"` for every dir in `/home`. A leftover home with no matching user, `lost+found`, or a user whose primary group has a different name makes `chown` fail, and `set -e` then exits. Step 5 (the config changes) never runs. I reproduced this. Fix: `id "$USERNAME" &>/dev/null || continue`, and use `chown "$USERNAME": ...` (the login group). | reproduced |
| **SSH2** [BUG] | **`/etc/ssh/sshd_config.d/*.conf` overrides your values.** On Ubuntu/Mint, `Include /etc/ssh/sshd_config.d/*.conf` sits at the **top** of sshd_config, and sshd uses the **first** value it sees. A planted `PermitRootLogin yes` in e.g. `50-cloud-init.conf` wins over the line you append at the bottom. Fix: grep and clean the drop-ins too, then verify with `sshd -T \| grep -i <key>`. | sshd_config(5) first-match rule |
| **SSH3** [BUG] | **Appending at the end of the file lands inside any active `Match` block.** Some keywords (LoginGraceTime, LogLevel, Compression…) aren't allowed inside `Match`, so `sshd -t` fails and your script restores the backup (all hardening lost). Others silently apply only to the matched users. Fix: insert the settings **above** the first `Match` line, or right after the `Include` line. | sshd_config(5) |
| **SSH4** [BUG] | **`ClientAliveCountMax 2` does nothing without `ClientAliveInterval`** (the default interval is 0, which disables it). Add `ClientAliveInterval 300` (most common across scripts). CIS 24.04 uses `15`/`3`. | [CIS] |
| **SSH5** | Add `Protocol 2`. Deprecated and ignored by modern OpenSSH (`sshd -t` still passes), but **scored** as "SSH forces protocol 2". Harmless. | [PRACTICE] (Narnia, 4 pts) |
| **SSH6** | Add the CIS set that's missing: `PermitUserEnvironment no`, `UsePAM yes`, `StrictModes yes`, `MaxSessions 10` (or lower), `MaxStartups 10:30:60`, `GSSAPIAuthentication no`, `KbdInteractiveAuthentication no`, `PubkeyAuthentication yes`, `Banner /etc/issue.net`, `DisableForwarding yes` (OpenSSH ≥ 7.4, which covers Ubuntu 22+/Mint 21+). Keep your existing `AllowTcpForwarding no` and `AllowAgentForwarding no` as well, for scoring regexes. | [CIS] |
| **SSH7** | `DebianBanner no`: hides the Debian/Ubuntu version string in the SSH banner (the blog's "hide version info"). It's a Debian/Ubuntu-only option, so it works on Ubuntu, Mint and Debian. | [BLOG] |
| **SSH8** ⚠ README | **Prompt for the README-driven items**, which were scored as vulns when set wrong: `PasswordAuthentication no` (Aperture, when README wanted keys) versus keeping it `yes` (Narnia README required it); `Port <n>`; `AllowUsers`/`DenyUsers`/`DenyGroups <group>`; SFTP-only with `ForceCommand internal-sftp` + `ChrootDirectory <dir>` (1984). | [PRACTICE] ×3 |
| **SSH9** | **Audit key and backdoor mechanisms:** every `~/.ssh/authorized_keys` **including `/root/.ssh`**; "Removed SFTP key from Julia" was scored. Also check `AuthorizedKeysFile` pointing somewhere odd, `AuthorizedKeysCommand`, `PermitUserRC` with `~/.ssh/rc`, and `/etc/ssh/sshrc`. | [PRACTICE] (1984) |
| **SSH10** | Private-key perms loop handles only `id_rsa`. Extend it to `id_ed25519`, `id_ecdsa`, `id_dsa` (600) and their `.pub` (644). Also host keys: CIS allows 600 root:root, or 640 root:ssh_keys on distros that use that group. | [CIS] |
| **SSH11** | UFW: use `ufw allow OpenSSH` instead of `ufw allow ssh` (G3). If the README changes the port, allow that port instead. | [PRACTICE] |
| **SSH12** | Ubuntu 24.04 and Mint 22 use `ssh.socket` activation. After a `Port`/`ListenAddress` change, run `systemctl daemon-reload && systemctl restart ssh.socket ssh`, or the old port stays live. | Ubuntu 24.04 behavior |
| **SSH13** | Verify with `sshd -T` (effective config) instead of trusting the file, and keep the `Subsystem sftp` line. One GitHub script I reviewed (CPLHF) overwrites sshd_config wholesale and drops it, which breaks SFTP. | [BLOG] |

---

## FTP – vsftpd (`Services/vsftpd.sh`)

| ID | Item | Evidence |
|---|---|---|
| **FTP1** ⚠ BREAK [BUG] | **Chroot lockout risk.** `chroot_local_user=YES` + `allow_writeable_chroot=NO` makes vsftpd refuse login ("500 OOPS: refusing to run with writable root inside chroot()") whenever the user's home or `local_root` is writable by that user. That is true of every normal home, and your `users.sh` sets homes to 750, still owner-writable. Result: the critical service is broken. **Pick one:** (a) set `local_root` to a root-owned 755 dir with a user-writable subdir, or (b) `allow_writeable_chroot=YES` if the README needs uploads into home. Either way, **test a login** afterwards (G2). | vsftpd behavior |
| **FTP2** [BUG] | `chmod 755 "$LOCAL_ROOT"/*` chmods the **contents**, not the directory. The FTP-root fix that was scored ("Insecure permissions on FTP root directory fixed", CP18 R2) is the root dir itself. It should be `chown root:root "$LOCAL_ROOT"; chmod 755 "$LOCAL_ROOT"` (plus `chmod o-w` on the contents). Also check `anon_root` and the default `/srv/ftp` (should be root:ftp 755, never 777). | [OFFICIAL] |
| **FTP3** ⚠ decision | **`ssl_tlsv1=YES` means different things per distro.** On Ubuntu/Mint, `ssl_tlsv1` means **TLS 1.0 only**, so your script *re-enables* TLS 1.0 there. **However,** Aperture's scoring checks literally require `^ssl_tlsv1=YES$`. **Correction from testing (2026-09-29):** the manpage documents `ssl_tlsv1_1`/`ssl_tlsv1_2`/`ssl_tlsv1_3`, but Ubuntu 24.04's vsftpd (3.0.5-0ubuntu3.1) **refuses to start** with those names. It accepts `ssl_tlsv11`/`ssl_tlsv12`/`ssl_tlsv13`. Debian bookworm has neither. **Applied:** keep `ssl_tlsv1=YES`; the script reads the real option names from the vsftpd binary, adds `…11=NO`, `…12=YES`, `…13=YES` only when they exist, and test-starts vsftpd before restarting. | [DOCS] [PRACTICE] tested |
| **FTP4** ⚠ README | `force_local_logins_ssl=YES` / `force_local_data_ssl=YES` block plain-FTP clients. The official CP18 item was "FTP users *may* log in with SSL" (`ssl_enable=YES`). Keep forcing only if the README doesn't imply plain FTP. | [OFFICIAL] |
| **FTP5** | **`/etc/vsftpd.chroot_list`**: with `chroot_local_user=YES`, users listed there are **exempt** from chroot. Scored: "Test subject turret is chrooted" (remove them from the list). Also audit `chroot_list_enable` and `userlist_file`, `/etc/vsftpd.userlist`, and `/etc/ftpusers` (root must be in it). | [PRACTICE] (Aperture) |
| **FTP6** | Add explicit anonymous lock-down lines, so they still apply if the README requires anonymous access: `anon_upload_enable=NO`, `anon_mkdir_write_enable=NO`, `anon_other_write_enable=NO`, `allow_anon_ssl=NO` ("Anonymous TLS/SSL has been disabled" was scored). | [PRACTICE] |
| **FTP7** | Hide the version: `ftpd_banner=Welcome to FTP` (the default banner shows `vsFTPd 3.0.x`; a CP18 R2 FQ answer was literally the FTP banner). Add `hide_ids=YES` and `ls_recurse_enable=NO`. | [BLOG] [OFFICIAL]-adjacent |
| **FTP8** | Brute-force and session limits: `max_login_fails=3`, `delay_failed_login=3`, `idle_session_timeout=300`, `data_connection_timeout=120`, `max_per_ip=5`. Add `ssl_ciphers=HIGH` (the default is `DES-CBC3-SHA`). | [DOCS] |
| **FTP9** ⚠ README | `write_enable=YES` is hard-coded. Make it a prompt: NO if the README only needs downloads. | – |
| **FTP10** | Passive range: if the README specifies one, match it exactly (Aperture scored the exact `pasv_min_port`/`pasv_max_port` **plus** a matching UFW rule). Otherwise 40000:50000 is fine. | [PRACTICE] |

---

## Apache2 (`Services/apache2.sh`)

| ID | Item | Evidence |
|---|---|---|
| **WEB1** ⚠ BREAK [BUG] | **Deleting every `.htaccess` in `/var/www`** can break a required app (WordPress permalinks) and **removes protective files** (e.g. deny rules on `uploads/` or `.git`). Replace with: list them and review each one. | [BLOG] (respect the challenge) |
| **WEB2** ⚠ BREAK [BUG] | `chown -R root:root /var/www` + `chmod -R 755` kills any app that must write (WordPress `wp-content/uploads`, caches, sessions). Prompt instead, and keep writable dirs owned by `www-data`. | – |
| **WEB3** [BUG] | The default `<Directory /var/www/>` block in `apache2.conf` still has `Options Indexes FollowSymLinks`. You only override `/var/www/html`, so any other vhost `DocumentRoot` under `/var/www` still lists directories. Change that block to `Options -Indexes` (and `-FollowSymLinks` or `+SymLinksIfOwnerMatch`), and check every `sites-enabled/*.conf` for `Indexes`. | [PRACTICE] (directory listing is a staple) |
| **WEB4** | **TLS** (the blog's "enable encrypted connections"): `a2enmod ssl && a2ensite default-ssl`, then `SSLProtocol -all +TLSv1.2 +TLSv1.3`, `SSLHonorCipherOrder on`, `SSLCompression off`, and HSTS (`Header always set Strict-Transport-Security "max-age=31536000"`) on the SSL vhost only. UFW: `'Apache Full'` or `'Apache Secure'` (Aperture scored `Apache Secure`). | [BLOG] [PRACTICE] |
| **WEB5** | **Apache must not run as root:** check `APACHE_RUN_USER`/`APACHE_RUN_GROUP` in `/etc/apache2/envvars` (should be `www-data`) and any `User`/`Group` directives. | [PRACTICE] (Narnia pattern: service runs as its own user) |
| **WEB6** | Info leaks: `FileETag None`; disable `mod_info` and `mod_status` (or restrict `/server-status` to `Require local`); `a2dismod -f dav dav_fs` if unused. `Timeout 60` (default 300) and `LimitRequestBody` set to a sane value. | [BLOG] |
| **WEB7** | Replace `X-XSS-Protection "1; mode=block"` with `"0"` or drop it. It's deprecated (the blog: no deprecated directives). Also: your strict CSP `default-src 'self'` can break a README-required site that loads CDN assets. Test the page after (G2). | [BLOG] |
| **WEB8** | Perms: `/etc/apache2` root:root, files 644; `/var/log/apache2` 750 root:adm; private keys in `/etc/ssl/private` 600/640 root:ssl-cert. | [BLOG] |
| **WEB9** ⚠ README | Optional hardening seen in scripts: `libapache2-mod-security2` (`SecRuleEngine On` + CRS) and `libapache2-mod-evasive`. No scoring evidence found; nice to have if time allows. | scripts only |
| **WEB10** | Act on B8's findings: remove any planted `phpinfo()` files and web shells ("Removed phpinfo file" was scored). Fix `Alias` or `DocumentRoot` lines in `sites-enabled` that point at `/`, `/etc` or home dirs. | [HIVESTORM] |

## PHP (new – none of your scripts cover it; it comes with Apache/nginx/WordPress)

| ID | Item | Evidence |
|---|---|---|
| **PHP1** | Edit **every** SAPI `php.ini` (`/etc/php/*/apache2/`, `fpm/`, `cli/`) and grep `conf.d/` for overrides (B3). Set: `expose_php = Off`, `display_errors = Off`, `display_startup_errors = Off`, `log_errors = On`, `allow_url_include = Off`. "PHP display errors has been disabled" was scored. | [HIVESTORM] [BLOG] |
| **PHP2** ⚠ README | `allow_url_fopen = Off`; `disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec`; `open_basedir = /var/www/:/tmp/`; `file_uploads = Off` (only if the README doesn't need uploads). Each can break an app, so test after. | – |
| **PHP3** | Sessions: `session.cookie_httponly = 1`, `session.use_strict_mode = 1`, `session.use_only_cookies = 1`, `session.cookie_secure = 1` (only when served over HTTPS), `session.cookie_samesite = Strict`. With nginx+php-fpm also `cgi.fix_pathinfo = 0`. | CIS-style |
| **PHP4** | Restart the right unit: `apache2` for mod_php, `php8.x-fpm` for FPM. | [BLOG] |

## Nginx (new)

| ID | Item | Evidence |
|---|---|---|
| **NGX1** | `server_tokens off;` in the `http {}` block of `/etc/nginx/nginx.conf`. | [PRACTICE] (Narnia, 4 pts) |
| **NGX2** | **Off-by-slash `alias` LFI:** `location /cdn { alias /srv/files/; }` must become `location /cdn/ { ... }`. Also check every `root`/`alias` against the README (Narnia had root pointing at `/etc/nginx`, scored). | [PRACTICE] (Narnia ×2) |
| **NGX3** | `autoindex off;`, `ssl_protocols TLSv1.2 TLSv1.3;`, `ssl_prefer_server_ciphers on;`, deny dotfiles (`location ~ /\. { deny all; }`), `client_max_body_size` set to a sane value, `limit_except GET HEAD POST { deny all; }` where appropriate, `user www-data;`. Validate with `nginx -t`. | CIS-style |

## MySQL / MariaDB (`Services/mysql.sh`)

| ID | Item | Evidence |
|---|---|---|
| **DB1** [BUG] | **`detect_database_type` output is captured wrong.** Its `echo "Detecting…"`/`"Found…"` lines go to stdout, so `DB_TYPE` becomes a 3-line string and never equals `mariadb`. On MariaDB it writes to `/etc/mysql/mysql.conf.d/mysqld.cnf`, which MariaDB doesn't read, so **none of the hardening applies**. I reproduced this. Fix: send the messages to stderr (`>&2`). | reproduced |
| **DB2** [BUG] | **On MariaDB ≥ 10.4, `mysql.user` is a VIEW.** `UPDATE mysql.user …` and `DELETE FROM mysql.user …` error out, and with `set -e` the script aborts at step 1. Use account statements instead: `DROP USER IF EXISTS ''@'localhost', ''@'%', 'root'@'%';`. This also applies to MySQL 8, where editing grant tables directly is discouraged. | MariaDB KB / iRedMail report |
| **DB3** ⚠ [BUG] | **The script creates `admin@localhost` with `ALL … WITH GRANT OPTION` and a hard-coded password.** That's an unauthorized privileged DB account, which is exactly what the scoring engine penalizes or what you should be removing. Recommend deleting this step. | [BLOG] (incident-response framing) |
| **DB4** ⚠ BREAK [BUG] | **`chmod 750 /etc/mysql` (root:root) + `chmod 640 my.cnf`**: mysqld runs as user `mysql` under systemd and **can no longer read its own config**. It then silently falls back to defaults (MySQL 8 default `bind-address=*`), undoing the hardening. Use `chown -R root:mysql /etc/mysql`, dirs 750, `*.cnf` 640, keep `debian.cnf` 600 root. Check with `sudo -u mysql cat /etc/mysql/my.cnf`. | systemd `User=mysql` |
| **DB5** ⚠ BREAK | `cat >` **overwrites** `50-server.cnf`/`mysqld.cnf` wholesale, losing `datadir`, `socket`, `pid-file`, charset and log paths. It also defeats scoring checks that look for a *specific* line in that file (G1). Edit the keys in place and grep all of `/etc/mysql` for conflicting duplicates. | [OFFICIAL]-pattern |
| **DB6** ⚠ BREAK | `require_secure_transport = ON` breaks any app that connects over TCP (`127.0.0.1`) without TLS, such as a WordPress `DB_HOST='127.0.0.1'`. Unix-socket connections are unaffected. Prompt first. | MySQL docs |
| **DB7** | **Look for and remove `skip-grant-tables`** anywhere in `/etc/mysql` (it disables all authentication), plus `skip-networking` misuse, `old_passwords`, and `bind-address = 0.0.0.0`. | [BLOG] |
| **DB8** | Add `secure_file_priv = /var/lib/mysql-files` (never empty), `local_infile = 0` (you have this), `skip-symbolic-links` (still valid in MySQL 8.4, deprecated, default off), and error logging: `log_error_verbosity = 3` (MySQL) or `log_warnings = 2` (MariaDB). Validate before restarting: `mysqld --validate-config` (MySQL 8.0.16+); on MariaDB, `mariadbd --help --verbose >/dev/null`. | [DOCS] [BLOG] |
| **DB9** | `general_log = 1` writes every query **including passwords in `ALTER USER`/`CREATE USER`** to disk. Keep it only if you want it for forensics, and make the log 640 mysql:adm. | – |
| **DB10** | Act on B7's account diff: drop users with empty auth, users with a `%` host, and README-unauthorized users. Revoke unneeded `SUPER`/`FILE`/`PROCESS`/`GRANT OPTION`. Also remove `~/.mysql_history` and `~/.my.cnf` files with plaintext creds, and fix `/etc/mysql/debian.cnf` perms. | [BLOG] |

## PostgreSQL (new)

| ID | Item | Evidence |
|---|---|---|
| **PG1** | `pg_hba.conf`: **no `trust` entries**, and no `host all all 0.0.0.0/0`. Use `scram-sha-256` (and `peer` for local postgres). "PostgreSQL requires authentication for all connections" was scored. | [HIVESTORM] |
| **PG2** | `pg_ident.conf`: no map of arbitrary OS users to `postgres`. "Does not map any user to the postgres account" was scored. | [HIVESTORM] |
| **PG3** | `postgresql.conf`: `ssl = on` (README asked, scored), `listen_addresses = 'localhost'` (⚠ README), `password_encryption = scram-sha-256`, `log_connections = on`, `log_disconnections = on`. | [HIVESTORM] [CIS-style] |
| **PG4** | Perms: `/etc/postgresql/<v>/main/*.conf` 640 postgres:postgres; data dir `/var/lib/postgresql/<v>/main` 700 (Postgres refuses to start otherwise). "Insecure permissions on PostgreSQL configuration files" was scored. | [HIVESTORM] |
| **PG5** | `\du`: remove unauthorized `SUPERUSER`/`CREATEROLE` roles (`ALTER ROLE x NOSUPERUSER`). Reset passwords after switching to scram. | [BLOG] |

## Samba (new)

| ID | Item | Evidence |
|---|---|---|
| **SMB1** | `[global]`: `server min protocol = SMB2_10` (or `SMB3`) and `client min protocol = SMB2_10`. The current default is `SMB2_02`, so a planted `NT1` is the vuln. "SMB1 protocol disabled" was scored. | [HIVESTORM] [PRACTICE] [DOCS] |
| **SMB2** | `smb encrypt = required` (a synonym of `server smb encrypt`; valid globally **or per share**). "Encryption is required" was scored. | [HIVESTORM] [PRACTICE] [DOCS] |
| **SMB3** | `server signing = mandatory`, `restrict anonymous = 2`, `map to guest = never`, `usershare allow guests = no`, `null passwords = no`, `ntlm auth = ntlmv2-only` (or `disabled`), `obey pam restrictions = yes`, `security = user`. Most of these were scored in Resident Ubuntu. | [PRACTICE] [DOCS] |
| **SMB4** | Per share: `guest ok = no`, `read only = yes` unless the README needs writes, `valid users = @group` per README, `browseable = no` for hidden `$` shares, sane `create mask`/`directory mask` (0660/0770), `wide links = no`, and no `root preexec`/`preexec`/`magic script` (command-execution backdoors). Remove shares the README doesn't list. | [DOCS] [BLOG] |
| **SMB5** | Don't add `lanman auth`, `encrypt passwords` or `raw NTLMv2 auth`. All are deprecated since 4.11/4.13, and their defaults are already secure (the blog: no deprecated directives). Validate with `testparm -s`. Logging: `log level = 2`, `vfs objects = full_audit` optional. | [DOCS] [BLOG] |
| **SMB6** | `smbpasswd`/`pdbedit -L`: remove Samba accounts for unauthorized users (Samba keeps its own user DB, so `userdel` doesn't remove them). UFW: `ufw allow Samba`. | [BLOG] |

## Bind9 / DNS (new – on the blog's list, no scored example found)

| ID | Item | Evidence |
|---|---|---|
| **DNS1** | `named.conf.options`: `version "not disclosed";`, `allow-transfer { none; };` (or the README's secondaries), `recursion no;` for an authoritative-only server or `allow-recursion { localhost; localnets; };` otherwise, `dnssec-validation auto;`. | [BLOG] (hide version) + CIS/NIST DNS guides |
| **DNS2** | Per zone: `allow-update { none; };` (a dynamic-update backdoor is a common plant). Check zone files for rogue records. Validate with `named-checkconf -z`. | – |
| **DNS3** | Runs as `bind`: check `OPTIONS="-u bind"` in `/etc/default/named`. Perms: `/etc/bind` root:bind 2755, zone files 644 or 640 root:bind. Enable `querylog yes;` or a `logging {}` channel. | [BLOG] |

## Mail – Postfix / Dovecot (new)

| ID | Item | Evidence |
|---|---|---|
| **MAIL1** | Postfix (`postconf -e`): `smtpd_banner = $myhostname ESMTP` (hides version), `disable_vrfy_command = yes` (VRFY/EXPN disabling was scored in 1984), `smtpd_helo_required = yes`, `mynetworks = 127.0.0.0/8 [::1]/128`, `smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination` (no open relay). | [PRACTICE] [BLOG] |
| **MAIL2** | Postfix TLS: `smtpd_tls_security_level = may` (or `encrypt` if the README says so), `smtpd_tls_auth_only = yes`, `smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1` (same for `smtpd_tls_mandatory_protocols`). | [BLOG] |
| **MAIL3** ⚠ README | `inet_interfaces = loopback-only` is the CIS item, but **only if mail is not a critical service**. 1984 required 25/587/143 to stay open. | [CIS] [PRACTICE] |
| **MAIL4** | Dovecot: `ssl = required` (scored), `auth_debug_passwords = no` (scored), `disable_plaintext_auth = yes`, `ssl_min_protocol = TLSv1.2`. These names are for Dovecot 2.3; 2.4 renamed some (e.g. `auth_allow_cleartext`), so check `dovecot --version` and validate with `doveconf -n`. | [PRACTICE] (1984 ×2) |

## WordPress / CMS (new – on the blog's list)

| ID | Item | Evidence |
|---|---|---|
| **WP1** | `wp-config.php`: 640 (owner root or www-data, group www-data), `define('DISALLOW_FILE_EDIT', true);`, `define('WP_DEBUG', false);`, `define('FORCE_SSL_ADMIN', true);` (only if HTTPS), unique salts. | [BLOG] |
| **WP2** | Update core, plugins and themes. Remove unused or unauthorized plugins (the blog's example attack chain was a vulnerable plugin). Remove `readme.html`/`license.txt` (version leak). Audit admin users in `wp_users`/`wp_usermeta` against the README. | [BLOG] |
| **WP3** | Block PHP execution in `wp-content/uploads` (this is exactly the kind of `.htaccess` WEB1 would delete). | – |

## OpenVPN (new – on the blog's list)

| ID | Item | Evidence |
|---|---|---|
| **VPN1** | `server.conf`: `tls-crypt` (or `tls-auth`) key, `data-ciphers AES-256-GCM:AES-128-GCM`, `auth SHA256`, `tls-version-min 1.2`, `user nobody` + `group nogroup`, `persist-key`, `persist-tun`, remove `duplicate-cn`, `verb 3` + `status` + `log-append`. Key files 600. | [BLOG] + OpenVPN hardening guide |

## Other services seen in scored images (quick hits)

- **Squid** [PRACTICE, student image]: no `http_access allow all`; end with `http_access deny all`; `manager` restricted to localhost; `httpd_suppress_version_string on`; `via off`; `forwarded_for delete`.
- **CUPS / Avahi / NFS / nginx-when-unneeded**: "disabled or removed" was scored in Aperture (CUPS, avahi, NFS ×6 units) and in OFFICIAL/HIVESTORM keys (Apache, FTP, SSH, DNS, IRC disabled when not critical). Your `fileandpackage.sh` flags most of these. Add `avahi-daemon`, `cups-browsed`, `rpcbind`, `xrdp`, `inspircd`/IRC and `squid` to its list.
- **Custom or unknown services** (Minecraft, Seafile, custom SMTP daemon in 1984, Seahub in Nevermore): the blog's advice is to read the service's config and apply the mindset (logging, version hiding, TLS, perms, run as its own user). The systemd sandbox check (B5) was scored.

---

## SYS. Non-service items not in your checklist (found in scored configs)

Lower priority for this session, but real points.

- **SYS1** [BUG-ish] `systemconfig.sh` **appends** to `/etc/sysctl.conf` without removing existing lines. A planted `net.ipv4.ip_forward=1` stays in the file, and `FileContainsRegexNot` checks fail (see G1). Also scan `/etc/sysctl.d/` for planted files (Narnia).
- **SYS2** Extra sysctl keys scored in practice images, not in your list: `net.ipv4.tcp_rfc1337=1`, `net.ipv4.conf.{all,default}.rp_filter=1`, `kernel.kptr_restrict=2`, `kernel.kexec_load_disabled=1`, `dev.tty.ldisc_autoload=0`, `kernel.perf_event_paranoid=3`, `fs.protected_{hardlinks,symlinks}=1`, `kernel.yama.ptrace_scope=1`, and `kernel.exec-shield=1`. That last one doesn't exist on modern kernels, and `sysctl -p` prints an error, yet Aperture scored it anyway.
- **SYS3** PAM: look for `pam_permit.so` replacing `pam_deny.so` [PRACTICE Narnia] and `pam_exec.so` backdoors in `common-auth` [PRACTICE Aperture]. Aperture's history check required `remember` ≥ **5**, and your checklist uses 3. Aperture also checked `/etc/security/pwquality.conf` for `minlen`, `ucredit/lcredit/dcredit/ocredit=-1`, `dictcheck=1`, `usercheck=1`; your checklist puts `minlen` on the `pam_unix` line. `login.defs`: `ENCRYPT_METHOD SHA512` (or YESCRYPT) and `LOGIN_RETRIES 3`.
- **SYS4** `/etc/sudo.conf`: `Set developer_mode false`, `Set disable_coredump true`, `Set probe_interfaces false`. In sudoers: remove `Defaults !env_reset` and `env_keep += "PATH"` [PRACTICE Resident Ubuntu]. CIS also wants `Defaults use_pty` and `Defaults logfile=/var/log/sudo.log`.
- **SYS5** `/etc/security/limits.conf`: `* hard core 0`, `* hard nproc 2500` or lower [PRACTICE Aperture].
- **SYS6** Display manager: gdm3 `custom.conf` needs `AutomaticLoginEnable=False` and `DisallowTCP=true`, with no `User=`/`Group=` lines [PRACTICE]. LightDM needs `xserver-allow-tcp=false` [HIVESTORM], and check the `lightdm.conf.d` drop-ins (B3). Your script only edits `lightdm.conf`.
- **SYS7** Services that must be **running**: `apparmor`, `auditd` (with `local_events = yes` in `auditd.conf`), `ufw`, `unattended-upgrades` [PRACTICE ×3].
- **SYS8** GRUB: `/etc/grub.d/40_custom` needs a legitimate `set superusers` (remove rogue superusers and passwords), and `grub.cfg` must not be world-readable [PRACTICE] [HIVESTORM].
- **SYS9** Odd permission plants: FACLs (`getfacl -R -s -p /usr/bin /etc /home`; a FACL on `/usr/bin/sudo` was scored), `/etc/gshadow` group passwords, `/home` owned by root, `/swapfile` 600, system accounts with passwords or login shells, SUID on common binaries (`cp`, `wget`, `date`) [PRACTICE ×4].
- **SYS10** Persistence spots: `/etc/ld.so.preload` and `.so` rootkits, DKMS keylogger modules in `/lib/modules/$(uname -r)/updates/dkms`, aliases in `/etc/bash.bashrc`, `/etc/hosts` hijacks, `apt-mark showhold` requirements [PRACTICE ×5].

## Incidental bugs in the "proven" scripts (FYI, not service-related)

- `users.sh` calls `ok` and `err`, which are never defined (prints "command not found" at the end of the aging step).
- `users.sh` prints `echo "$SUDOERS_CONTENT"`, which is the temp-file **path**, not its contents. Should be `cat "$SUDOERS_CONTENT"`.
- `systemconfig.sh` writes `50auto-upgrades`. Ubuntu's real file is `50unattended-upgrades`, so both files now coexist. It works, but confirm the origins are what you intend.

---

## Sources

- Akshay Rohatgi, *How To Win CyberPatriot* (authoritative): https://akshayrohatgi.com/blog/posts/How-To-Win-CyberPatriot/
- CP18 R1/R2 official answers (fstk5/cypat-linux-checklist): https://github.com/fstk5/cypat-linux-checklist
- CP17 Ubuntu 22 Training 2 answer key (Studocu copy): https://www.studocu.com/en-us/document/palm-harbor-university-high/cybersecurity-cte/cp17-ubuntu-22-training-2-answer-key/112889982
- Aperture Science Ubuntu scoring.conf (anishgoyal1108): https://github.com/anishgoyal1108/Aperture-Science-Practice-Image-Bundle
- 1984 Mint 22.3 scoring.conf (Matthiasclee, Apr 2026): https://github.com/Matthiasclee/1984-Mint22.3
- eth007 Syshardening 6 (Narnia) writeup: https://github.com/Quasar0147/Syshardening-6-Writeup
- Resident Ubuntu writeup (Neptunexz): https://github.com/Neptunexz/Linux-Image-Writeups
- Hivestorm 2021 writeup (sourque): https://sourque.com/ctf/hivestorm/hs21/
- ComplianceAsCode CIS Ubuntu 24.04 controls: https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml
- vsftpd.conf(5), Ubuntu noble/jammy and Debian bookworm: https://manpages.ubuntu.com/manpages/noble/en/man5/vsftpd.conf.5.html · https://manpages.debian.org/bookworm/vsftpd/vsftpd.conf.5.en.html
- smb.conf(5), samba.org: https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html
- MySQL 8.4 symbolic links: https://dev.mysql.com/doc/refman/8.4/en/symbolic-links-to-tables.html
- MariaDB 10.4 `mysql.user` view breakage (iRedMail forum): https://forum.iredmail.org/post73478.html
- Script repos surveyed (2025–2026): WhereIsXuezugi/CPLHF, gobbler56/cp-linux-auto, brooksonline/Linux-CYP, SunJay-EDU/CyberPatriot-Linux-Scripts, maytees/cypat-ubuntu-script, Kevinogram/Cyberpatriots-v2, Blzzxrd/EB-cyberpat-26-27, tanav-malhotra/cyberpatriot-scripts, plus about 20 smaller ones. Most were low quality or AI-generated, so the scored configs above were weighted far higher.
