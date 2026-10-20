# Does it actually score? Verification of the CP19 script changes (2026-09-29)

## How this was tested

I didn't trust my own claims. I rebuilt the scoring engine, planted the vulnerabilities, and measured.

1. **Scoring engine.** `checks.py` re-implements the check types of **aeacus**, the engine community practice images use (per-line regex, `*Not` inversion, permission masks). Its semantics were copied from aeacus's own source (`checks.go`).
2. **Checks: 100 in total, from three levels of evidence.**
   - **Copied verbatim from real scoring configs:** 46 from *Aperture Science* (Ubuntu 22.04, state/semis difficulty) and 16 from *1984* (Mint 22.3, April 2026, "Hard").
   - **Reconstructed by me:** 38 checks built from writeups and official answer keys (Narnia/eth007, Resident Ubuntu, Hivestorm 2021, CP17/CP18 keys). The check **wording** is real; the **regex** is my reconstruction, so these are weaker evidence and could be biased toward my own implementation.
3. **Planted image.** In an Ubuntu 24.04 container with the real services installed, I planted the vulnerable state for every check. The pristine configs came from the packages.
4. **Three runs of the same checks:**
   - planted state, nothing run;
   - your **original** scripts (only systemconfig, ssh, vsftpd and apache2 existed);
   - the **new** scripts.

   Everything ran non-interactively on the default answers. README prompts were then tested separately through a simulated terminal.

## Results

| State | Checks passing (of 100) |
|---|---|
| Planted image, nothing run | 12 (mostly checks that pass by default) |
| Your original scripts | 31 |
| New scripts, round 1 (as first delivered) | 79 |
| **New scripts, round 2 (after the fixes below)** | **89**, plus 5 more when the README prompts are answered = **94** |

**No regressions:** no check that the originals passed fails with the new scripts.

**The 6 that still fail, and why:**

| Check | Reason |
|---|---|
| UFW `OpenSSH ALLOW` profile | Needs a real UFW, which can't run in the container. The code path is correct (`ufw allow OpenSSH`) |
| faillock `sufficient ... authsucc` | Manual checklist step. **The checklist said `required`**, which fails this check; now changed to `sufficient` |
| Root account locked (`^root:!`) | Manual checklist step (`passwd -l root`) |
| LightDM `xserver-allow-tcp=false` | LightDM isn't installed in the container. The code is in systemconfig.sh |
| `grub.cfg` not world-readable | There's no `/boot/grub` in the container. The code is in systemconfig.sh |
| IPv6 disabled | Only when you answer **n** to "Enable IPv6?" (verified: the written line matches the check) |

**README prompts verified through a simulated terminal:** `Port 1382`, `DenyGroups testsubjects`, `PasswordAuthentication no`, `pasv_min_port=50000` / `pasv_max_port=50100` plus the UFW `50000:50100/tcp` rule, `ForceCommand internal-sftp` and `ChrootDirectory /opt/documents`. Every one produces exactly the line the real checks match.

## Gaps found by the harness and fixed (round 2)

| Problem | Real check it failed | Fix |
|---|---|---|
| Emptied `/etc/ld.so.preload` but left the rootkit `.so` on disk | Aperture `PathExistsNot /usr/src/evil_rabbit.so` | Also offers to delete each preloaded library that no package owns |
| Only **warned** about `pam_exec` backdoors | Aperture "Malicious PAM backdoor removed" | Offers to remove `pam_exec` lines from `common-*`, `sshd`, `login`, `sudo`, `su` |
| Only **listed** aliases | Aperture "Removed malicious bash alias" | Offers to remove aliases from system-wide shell files (stock Ubuntu/Mint has none there). User `.bashrc` files are listed only |
| gdm3 `AllowRoot` not set | Resident "gdm3 does not allow root login" | `AllowRoot=false` in `[security]` |
| `PASS_MAX_DAYS 90` (checklist) | Aperture accepts only 1-30 | **30**. It passes every max-age check seen and fails none. Also `chage -M 30` in users.sh |
| `PASS_MIN_DAYS` never set by any script | 1984 "min age is set" (not 0); Aperture ≥ 5 | systemconfig sets `PASS_MIN_DAYS 7`, `PASS_WARN_AGE 14` |
| `remember` / `dictcheck` only in the checklist or pwquality.conf | 1984 checks them **on the common-password line** | pam_unix gets `remember=5 minlen=10`; pam_pwquality gets `dictcheck=1 usercheck=1 minlen=10` and the credits |
| faillock `required ... authsucc` (checklist) | Aperture requires `sufficient` | Checklist changed to `sufficient` |
| Only one UFW choice for Apache ("Apache Full") | Aperture scored the exact profile **"Apache Secure"** | Asks: HTTPS-only (Apache Secure) or Full |
| FACL strip covered everything, default **no** (so the sudo FACL stayed) | 1984 "Removed malicious FACL from /bin/sudo" | System dirs (`/usr/bin`, `/etc`…) are stripped by default. `/home` and `/var/www` are **only listed**, because Aperture *required* a restrictive ACL there (`group:testsubjects:---`) and blind stripping would have lost that point |

---

## Verdict on each change

### Tier 1: proven to flip a check copied from a real scoring config

- **sysctl** (edited in place in `/etc/sysctl.conf`): `tcp_rfc1337`, `tcp_syncookies`, `ip_forward` (the planted `=1` line is replaced, **which the original append method failed**), `accept_source_route`, `send_redirects`, `log_martians`, `rp_filter`, `accept_redirects`, `randomize_va_space`, `suid_dumpable`, `kernel.exec-shield`, `disable_ipv6`. Applied with `sysctl --system` so the live `/proc` values (checked by 1984) match too.
- **limits.conf** `* hard core 0`, `* hard nproc 2500`; **auditd** `local_events = yes`.
- **gdm3** `AutomaticLoginEnable=False`, rogue `User=`/`Group=` removed, `DisallowTCP=true`.
- **Password policy:** `ENCRYPT_METHOD SHA512`, `LOGIN_RETRIES 3`, `PASS_MAX_DAYS 30`, `PASS_MIN_DAYS 7`, pwquality `minlen` and credits, common-password `remember=5` and `dictcheck=1`.
- **Plants:**
  - PAM: `pam_exec` removal.
  - Rootkits and aliases: LD_PRELOAD library removal, system-wide alias removal.
  - Accounts: system-account shell set to `nologin`, gshadow group password removed.
  - Permissions: `/home` owned by root, `/swapfile` 600, SUID removed from `cp`, FACL on `sudo` stripped.
- **SSH:** `PermitRootLogin` (in place + drop-ins), and the README prompts `Port`, `DenyGroups`, `PasswordAuthentication`, `ForceCommand internal-sftp` + `ChrootDirectory`.
- **Apache:** `ServerTokens Prod`, `ServerSignature Off`.
- **vsftpd:** `anonymous_enable=NO`, `ssl_enable=YES` + `ssl_tlsv1=YES` + no SSLv2/v3, `allow_anon_ssl` not YES, `chroot_list` emptied, passive range (README).
- **Dovecot:** `ssl = required`, `auth_debug_passwords` not yes.
- **UFW application profile names** (OpenSSH / vsftpd / Apache Secure): the checks are real; the code couldn't be run live here.

### Tier 2: matches a scored item's wording (official key or writeup); check regex reconstructed by me

- **Official CP17/CP18:** SSH root login, FTP `ssl_enable`, FTP root directory not world-writable, syncookies, `ip_forward` edited in place.
- **Narnia (eth007):** `sshd_config` owned by root, `PermitEmptyPasswords no`, `Protocol 2`, nginx `server_tokens off`, nginx off-by-slash alias, nginx root vs README, `pam_deny` restored.
- **Resident Ubuntu:** `dev.tty.ldisc_autoload`, `kexec_load_disabled`, sudo.conf ×3, sudoers `!env_reset` / `env_keep PATH`, gdm3 `AllowRoot`. Samba: encryption required, SMB1 off, no usershare guests, obey pam restrictions, `security = user`, signing mandatory. Also: Squid no `allow all`, SUID on `wget`, system-account password removed.
- **Hivestorm 2021:** PostgreSQL (no `trust`, no ident map to postgres, config perms, `ssl` per README), PHP `display_errors Off`, phpinfo file removed, LightDM no TCP, `grub.cfg` perms, `dmesg_restrict`, ICMP broadcasts.

### Tier 3: no scoring evidence found (security best practice; may be placebo)

These are harmless or low-risk and **might** score on an image whose author followed CIS or common guides, but **I found no proof they're scored**. Don't spend competition time on them before Tier 1/2 work is done.

- **SSH:** `ClientAliveInterval`, `UsePAM`, `StrictModes`, `MaxSessions`, `MaxStartups`, `GSSAPIAuthentication`, `KbdInteractiveAuthentication`, `PubkeyAuthentication`, `Banner` + `/etc/issue.net`, `DisableForwarding`, `DebianBanner`, `PermitUserEnvironment`. (Your original values `LoginGraceTime`, `MaxAuthTries`, `LogLevel`, `X11Forwarding`, `IgnoreRhosts`, `HostbasedAuthentication`, `AllowTcpForwarding`, `AllowAgentForwarding`, `Compression` also have no evidence in the configs I could get. They're widely believed to be scored in real rounds, but that's unconfirmed.)
- **vsftpd:** `ssl_tlsv11/12/13`, `ssl_ciphers`, `hide_ids`, `ls_recurse_enable`, `ftpd_banner`, `max_login_fails`, `delay_failed_login`, timeouts, `max_per_ip`.
- **Apache:** `FileETag`, `LimitRequestBody`, `Timeout`, all security headers, disabling the extra modules, `Options -Indexes` (no scored example found, surprisingly), HTTPS/`SSLProtocol`/HSTS, run-user check, mod_security.
- **PHP:** everything except `display_errors` and phpinfo removal (`expose_php`, `allow_url_*`, `disable_functions`, `open_basedir`, sessions).
- **MySQL/MariaDB:** **no MySQL item appears in any source I could access.** The value of `mysql.sh` is that it now **works at all** (before, it never recognized MariaDB, crashed on MariaDB 10.4+, and left the DB unable to read its config) and **no longer creates a backdoor admin account**. The individual settings are unverified.
- **PostgreSQL:** `password_encryption`, `log_connections`, `listen_addresses`, the role audit.
- **Samba:** `client min protocol`, `restrict anonymous`, `map to guest`, `null passwords`, `ntlm auth`, logging, per-share masks, `wide links`, preexec removal.
- **Bind9, Postfix, OpenVPN, WordPress** (all of it), and Squid beyond removing `allow all`.
- **SYS:** `perf_event_paranoid`, `fs.protected_*`, `ptrace_scope`, sudo `use_pty` / `logfile`.

### Kept only because a check wants them (no real security effect)

- `Protocol 2` and `kernel.exec-shield = 1` do nothing on modern OpenSSH and kernels, but both were scored. They're kept on purpose.
- `ssl_tlsv1=YES` enables TLS 1.0 on Ubuntu, a small security **regression**, but it's what Aperture checks.
- `anon_upload_enable=NO` etc. have no effect once `anonymous_enable=NO`. They matter only if the README requires anonymous FTP.
- pwquality `dictcheck`/`usercheck` in pwquality.conf: Aperture's unanchored regex already matches the **commented** defaults, so that point is free anyway.

### Not points, but where the points come from

**Baselining (section B)** scores nothing by itself. It's how you find the planted, image-specific vulnerabilities (the blog's #1 strategy). Most of the 100 test checks were *plants*: rogue drop-ins, changed permissions, backdoor units and files. `baseline.sh` flags exactly those. Treat it as the highest-value tool, not a checklist item.

## Risks that could COST points (read before running)

- **SSH `AllowUsers` / `DenyUsers` / key-only prompts:** a wrong answer can lock out README users, which is a penalty. Enter nothing unless the README says so.
- **FTP chroot option b** sets `allow_writeable_chroot=YES`. I found no check for either value, but the original script had `NO`. If the README doesn't need uploads into home folders, choose **a**.
- **SYS9 system accounts → nologin** (default yes): skip any service account the README says needs a shell.
- **Tier 3 service restrictions** (`DisableForwarding`, `disable_functions`, `LimitExcept`, `require_secure_transport`, `smb encrypt = required`) can break a README-required feature. Every script ends with a functional test; read it.

## Artifacts

- Harness: `checks.py` (the checks), `plant.sh` (plants the vulnerable state), `drive.py` (answers the README prompts). All three are in the session workspace, not in your folder; they can be added to the repo if you want to re-run the verification.
