#!/usr/bin/env python3
"""Mini re-implementation of the aeacus check types used by real CyberPatriot practice images,
evaluated against the live container. Sources:
  APERTURE  - Aperture Science Ubuntu 22.04 scoring.conf (real, copied check-by-check)
  1984      - 1984 Mint 22.3 scoring.conf (real, loaded from the repo file)
  NARNIA / RESIDENT / HIVESTORM / OFFICIAL - reconstructed from writeups / answer keys
            (the check TEXT is real, the regex is my best reconstruction -> marked 'recon')
Semantics follow aeacus checks.go: FileContains* match per line; *Not inverts; all conds must pass.
"""
import os, re, stat, subprocess, sys, glob, json

def read(p):
    try: return open(p, errors="replace").read()
    except Exception: return None

def line_match(path, rx, regex=True):
    c = read(path)
    if c is None: return None
    for l in c.split("\n"):
        if (re.search(rx, l) if regex else rx in l): return True
    return False

def perm_str(p):
    try: m = os.stat(p).st_mode
    except Exception: return None
    s = stat.filemode(m)
    return s

def perm_match(p, pattern):
    s = perm_str(p)
    if s is None: return None
    return all(pc == "?" or pc == sc for pc, sc in zip(pattern, s))

def cmd_out(c):
    try: return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception: return ""

def ev(cond):
    t = cond["type"]; neg = t.endswith("Not"); base = t[:-3] if neg else t
    r = None
    if base == "FileContainsRegex": r = line_match(cond["path"], cond["value"])
    elif base == "FileContains":    r = line_match(cond["path"], cond["value"], regex=False)
    elif base == "DirContainsRegex":
        r = any(line_match(f, cond["value"]) for f in glob.glob(cond["path"] + "/**", recursive=True) if os.path.isfile(f))
    elif base == "PermissionIs":    r = perm_match(cond["path"], cond["value"])
    elif base == "PathExists":      r = os.path.exists(cond["path"])
    elif base == "CommandContainsRegex": r = re.search(cond["value"], cmd_out(cond["cmd"])) is not None
    elif base == "CommandContains": r = cond["value"] in cmd_out(cond["cmd"])
    elif base == "FileOwner":
        try:
            import pwd; r = pwd.getpwuid(os.stat(cond["path"]).st_uid).pw_name == cond["name"]
        except Exception: r = None
    else:
        return "skip"
    if r is None:
        # aeacus: missing file -> error -> check does not pass (for both normal and Not variants)
        return False
    return (not r) if neg else r

C = []  # (source, id, message, [conds], note)
def add(src, msg, conds, note=""):
    C.append((src, msg, conds, note))

FC = lambda p, v: {"type": "FileContainsRegex", "path": p, "value": v}
FCN = lambda p, v: {"type": "FileContainsRegexNot", "path": p, "value": v}
S = "/etc/sysctl.conf"

# ---------------------------------------------------------------- APERTURE (real) --
A = "APERTURE"
add(A, "TIME-WAIT assassination protection", [FC(S, r'^\s*net\.ipv4\.tcp_rfc1337\s*=\s*1\s*$')])
add(A, "TCP SYN cookies", [FC(S, r'^\s*net\.ipv4\.tcp_syncookies\s*=\s*1\s*$')])
add(A, "IPv4 forwarding disabled", [FCN(S, r'^\s*net\.ipv4\.ip_forward\s*=\s*1\s*$')])
add(A, "Source routing disabled", [FC(S, r'^\s*net\.ipv4\.conf\.all\.accept_source_route\s*=\s*0\s*$'), FC(S, r'^\s*net\.ipv4\.conf\.default\.accept_source_route\s*=\s*0\s*$')])
add(A, "Send redirects ignored", [FC(S, r'^\s*net\.ipv4\.conf\.all\.send_redirects\s*=\s*0\s*$'), FC(S, r'^\s*net\.ipv4\.conf\.default\.send_redirects\s*=\s*0\s*$')])
add(A, "Martian logging", [FC(S, r'^\s*net\.ipv4\.conf\.all\.log_martians\s*=\s*1\s*$')])
add(A, "Source address verification (rp_filter)", [FC(S, r'^\s*net\.ipv4\.conf\.default\.rp_filter\s*=\s*1\s*$'), FC(S, r'^\s*net\.ipv4\.conf\.all\.rp_filter\s*=\s*1\s*$')])
add(A, "ICMP redirects ignored", [FC(S, r'^\s*net\.ipv4\.conf\.all\.accept_redirects\s*=\s*0\s*$'), FC(S, r'^\s*net\.ipv4\.conf\.default\.accept_redirects\s*=\s*0\s*$')])
add(A, "ASLR enabled", [FC(S, r'^\s*kernel\.randomize_va_space\s*=\s*[12]\s*$')])
add(A, "Kernel ExecShield", [FC(S, r'^\s*kernel\.exec-shield\s*=\s*1\s*$')])
add(A, "Core dumps disabled", [FC(S, r'^fs.suid_dumpable\s*=\s*0$'), FC("/etc/security/limits.conf", r'^\*\s*hard\s*core\s*0$')])
add(A, "Hard nproc <= 2500", [FC("/etc/security/limits.conf", r'^\*\s*hard\s*nproc\s*(?:[1-9]|[1-9][0-9]{1,2}|1[0-9]{3}|2[0-4][0-9]{2}|2500)$')])
add(A, "IPv6 disabled", [FC(S, r'^net.ipv6.conf.all.disable_ipv6\s*=\s*1$'), FC(S, r'^net.ipv6.conf.default.disable_ipv6\s*=\s*1$')], "README-dependent: only if you answer 'n' to 'Enable IPv6?'")
add(A, "SSH root login disabled", [FCN("/etc/ssh/sshd_config", r'^\s*PermitRootLogin\s+yes\s*$')])
add(A, "SSH port 1382 (README)", [FC("/etc/ssh/sshd_config", r'^Port\s*1382$')], "README prompt")
add(A, "SSH DenyGroups testsubjects (README)", [FC("/etc/ssh/sshd_config", r'^DenyGroups\s*testsubjects$')], "README prompt")
add(A, "Apache ServerTokens Prod", [FCN("/etc/apache2/conf-enabled/security.conf", r'^ServerTokens\s*Full$'), FC("/etc/apache2/conf-enabled/security.conf", r'^ServerTokens\s*Prod$')])
add(A, "Apache ServerSignature Off", [FCN("/etc/apache2/conf-enabled/security.conf", r'^ServerSignature\s*On$'), FC("/etc/apache2/conf-enabled/security.conf", r'^ServerSignature\s*Off$')])
add(A, "Anonymous FTP disabled", [FC("/etc/vsftpd.conf", r'^anonymous_enable\s*=\s*NO$'), FCN("/etc/vsftpd.conf", r'^anonymous_enable\s*=\s*YES$')])
add(A, "FTP only TLS", [FC("/etc/vsftpd.conf", r'^ssl_enable=YES$'), FC("/etc/vsftpd.conf", r'^ssl_tlsv1=YES$'), FCN("/etc/vsftpd.conf", r'^ssl_sslv2=YES$'), FCN("/etc/vsftpd.conf", r'^ssl_sslv3=YES$')])
add(A, "Anonymous TLS disabled", [FC("/etc/vsftpd.conf", r'^ssl_enable=YES$'), FCN("/etc/vsftpd.conf", r'^allow_anon_ssl=YES$')])
add(A, "turret chrooted (chroot_list)", [FCN("/etc/vsftpd.chroot_list", r'^turret$')])
add(A, "Passive range 50000-50100 (README)", [FC("/etc/vsftpd.conf", r'^pasv_min_port=50000$'), FC("/etc/vsftpd.conf", r'^pasv_max_port=50100$')], "README prompt")
add(A, "gdm3 AutomaticLoginEnable=False", [{"type": "FileContains", "path": "/etc/gdm3/custom.conf", "value": "AutomaticLoginEnable=False"}])
add(A, "gdm3 not running as rick", [FCN("/etc/gdm3/custom.conf", r'^User=rick$'), FCN("/etc/gdm3/custom.conf", r'^Group=rick$')])
add(A, "gdm3 DisallowTCP", [FC("/etc/gdm3/custom.conf", r'^DisallowTCP=true$'), FCN("/etc/gdm3/custom.conf", r'^DisallowTCP=false$')])
add(A, "auditd local_events", [FC("/etc/audit/auditd.conf", r'^local_events\s*=\s*yes$')])
add(A, "pwquality minlen", [FC("/etc/security/pwquality.conf", r'^minlen\s*=\s*(?:[89]|[1-9][0-9]{1,2}|1000)')])
add(A, "pwquality credits", [FC("/etc/security/pwquality.conf", r'ucredit\s*=\s*-\d+'), FC("/etc/security/pwquality.conf", r'lcredit\s*=\s*-\d+'), FC("/etc/security/pwquality.conf", r'ocredit\s*=\s*-\d+'), FC("/etc/security/pwquality.conf", r'dcredit\s*=\s*-\d+')])
add(A, "pwquality dictcheck", [FC("/etc/security/pwquality.conf", r'dictcheck\s*=\s*-?[1-9]\d*')])
add(A, "pwquality usercheck", [FC("/etc/security/pwquality.conf", r'usercheck\s*=\s*-?[1-9]\d*')])
add(A, "ENCRYPT_METHOD SHA512", [FC("/etc/login.defs", r'ENCRYPT_METHOD\s*SHA512')])
add(A, "LOGIN_RETRIES 1-5", [FC("/etc/login.defs", r'LOGIN_RETRIES\s+[1-5]')])
add(A, "PASS_MAX_DAYS <= 30", [FC("/etc/login.defs", r'^PASS_MAX_DAYS\s+(?:[1-9]|[12][0-9]|30)\s*$')], "checklist says 90 (manual step)")
add(A, "PASS_MIN_DAYS >= 5", [FC("/etc/login.defs", r'^PASS_MIN_DAYS\s*(?:[5-9]|[1-9][0-9]|100)\s*$')], "checklist says 7 (manual step)")
add(A, "remember >= 5 on pam_unix", [FC("/etc/pam.d/common-password", r'pam_unix\.so.*?remember=(?:[5-9]|[1-9][0-9]{1,2}|1000)')], "checklist (manual step)")
add(A, "faillock authfail + authsucc(sufficient)", [FC("/etc/pam.d/common-auth", r'^\s*auth\s+\[default=die\]\s+pam_faillock.so\s+authfail\s*$'), FC("/etc/pam.d/common-auth", r'^\s*auth\s+sufficient\s+pam_faillock.so\s+authsucc\s*$')], "checklist (manual step)")
add(A, "PAM pam_exec backdoor removed", [FCN("/etc/pam.d/common-auth", r'^\s*auth\s+sufficient\s+pam_exec\.so\s+expose_authtok\s+quiet\s+\/lib\/x86_64-linux-gnu\/security\/pam-bd\s*$')])
add(A, "syslog has nologin shell", [FC("/etc/passwd", r'^syslog:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:(\/usr\/sbin\/nologin|\/bin\/false)$')])
add(A, "/home owned by root", [{"type": "FileOwner", "path": "/home", "name": "root"}])
add(A, "/swapfile 600", [{"type": "PermissionIs", "path": "/swapfile", "value": "-rw?------"}])
add(A, "cp not SUID", [{"type": "PermissionIsNot", "path": "/usr/bin/cp", "value": "???s??????"}])
add(A, "LD_PRELOAD rootkit .so removed", [{"type": "PathExistsNot", "path": "/usr/src/evil_rabbit.so"}])
add(A, "malicious bash alias removed", [{"type": "FileContainsNot", "path": "/etc/bash.bashrc", "value": "alias GOODBYE="}])
add(A, "shadow not world-readable", [{"type": "PermissionIsNot", "path": "/etc/shadow", "value": "???????r??"}])
add(A, "UFW OpenSSH profile", [{"type": "CommandContainsRegex", "cmd": "ufw status", "value": "OpenSSH *ALLOW *Anywhere"}], "needs real ufw")

# ---------------------------------------------------------------- 1984 (real, from file) --
R1984 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "1984-scoring.json")
KEEP = ["group password", "minimum password age", "remembered", "dictionary", "Root account", "Kernel pointers", "broadcast",
        "unprivileged kernel", "SYN cookies", "randomization", "forwarding", "FACL", "Dovecot SSL", "Dovecot debug", "forces SFTP", "chroots"]
if os.path.exists(R1984):
    d = json.load(open(R1984))
    for ch in d["check"]:
        if any(k.lower() in ch["message"].lower() for k in KEEP):
            conds = ch.get("pass", []) + ch.get("passoverride", [])
            note = "README" if ("SFTP" in ch["message"]) else ("live /proc value" if any(c.get("path", "").startswith("/proc") for c in conds) else "")
            add("1984", ch["message"], conds, note)

# ---------------------------------------------------------------- reconstructed --
N = "NARNIA(recon)"
add(N, "sshd_config owned by root", [{"type": "FileOwner", "path": "/etc/ssh/sshd_config", "name": "root"}])
add(N, "SSH PermitEmptyPasswords no", [FC("/etc/ssh/sshd_config", r'^\s*PermitEmptyPasswords\s+no\s*$')])
add(N, "SSH Protocol 2", [FC("/etc/ssh/sshd_config", r'^\s*Protocol\s+2\s*$')])
add(N, "SSH PermitRootLogin no", [FC("/etc/ssh/sshd_config", r'^\s*PermitRootLogin\s+no\s*$')])
add(N, "nginx server_tokens off", [FC("/etc/nginx/nginx.conf", r'^\s*server_tokens\s+off\s*;')])
add(N, "PAM requisite pam_deny", [FC("/etc/pam.d/common-auth", r'^\s*auth\s+requisite\s+pam_deny\.so')])
R = "RESIDENT(recon)"
add(R, "dev.tty.ldisc_autoload=0", [FC(S, r'^\s*dev\.tty\.ldisc_autoload\s*=\s*0\s*$')])
add(R, "kexec_load_disabled=1", [FC(S, r'^\s*kernel\.kexec_load_disabled\s*=\s*1\s*$')])
add(R, "sudo developer_mode false", [FC("/etc/sudo.conf", r'^\s*Set\s+developer_mode\s+false')])
add(R, "sudo disable_coredump true", [FC("/etc/sudo.conf", r'^\s*Set\s+disable_coredump\s+true')])
add(R, "sudo probe_interfaces false", [FC("/etc/sudo.conf", r'^\s*Set\s+probe_interfaces\s+false')])
add(R, "sudoers !env_reset removed", [FCN("/etc/sudoers", r'^\s*Defaults\s+!env_reset')])
add(R, "sudoers env_keep PATH removed", [FCN("/etc/sudoers", r'^\s*Defaults\s+env_keep\s*\+=\s*"?PATH')])
add(R, "gdm3 root login disallowed", [FC("/etc/gdm3/custom.conf", r'^\s*AllowRoot\s*=\s*false')])
add(R, "Samba encryption required", [FC("/etc/samba/smb.conf", r'^\s*(server\s+)?smb\s+encrypt\s*=\s*(required|mandatory)')])
add(R, "Samba SMB1 disabled", [FC("/etc/samba/smb.conf", r'^\s*server\s+min\s+protocol\s*=\s*SMB[23]')])
add(R, "Samba no usershare guests", [FC("/etc/samba/smb.conf", r'^\s*usershare\s+allow\s+guests\s*=\s*no')])
add(R, "Samba obey pam restrictions", [FC("/etc/samba/smb.conf", r'^\s*obey\s+pam\s+restrictions\s*=\s*yes')])
add(R, "Samba security = user", [FC("/etc/samba/smb.conf", r'^\s*security\s*=\s*user')])
add(R, "Samba server signing mandatory", [FC("/etc/samba/smb.conf", r'^\s*server\s+signing\s*=\s*(mandatory|required)')])
add(R, "Squid no 'http_access allow all'", [FCN("/etc/squid/squid.conf", r'^\s*http_access\s+allow\s+all\s*$')])
add(R, "wget not SUID", [{"type": "PermissionIsNot", "path": "/usr/bin/wget", "value": "???s??????"}])
add(R, "system account bin has no password", [FC("/etc/shadow", r'^bin:[*!]')])
H = "HIVESTORM(recon)"
add(H, "PostgreSQL no trust auth", [FCN(glob.glob("/etc/postgresql/*/main/pg_hba.conf")[0] if glob.glob("/etc/postgresql/*/main/pg_hba.conf") else "/x", r'^\s*[^#].*\strust\s*$')])
add(H, "PostgreSQL no map to postgres", [FCN(glob.glob("/etc/postgresql/*/main/pg_ident.conf")[0] if glob.glob("/etc/postgresql/*/main/pg_ident.conf") else "/x", r'^\s*[^#\s]+\s+\S+\s+postgres\s*$')])
add(H, "PostgreSQL pg_hba not world-readable", [{"type": "PermissionIsNot", "path": (glob.glob("/etc/postgresql/*/main/pg_hba.conf") or ["/x"])[0], "value": "???????r??"}])
add(H, "PostgreSQL ssl on (README)", [FC((glob.glob("/etc/postgresql/*/main/postgresql.conf") or ["/x"])[0], r'^\s*ssl\s*=\s*on')])
add(H, "PHP display_errors Off", [FC((glob.glob("/etc/php/*/apache2/php.ini") or ["/x"])[0], r'^\s*display_errors\s*=\s*Off')])
add(H, "phpinfo file removed", [{"type": "PathExistsNot", "path": "/var/www/html/info.php"}])
add(H, "LightDM X server no TCP", [FC("/etc/lightdm/lightdm.conf", r'^\s*xserver-allow-tcp\s*=\s*false')], "only if LightDM installed")
add(H, "grub.cfg not world-readable", [{"type": "PermissionIsNot", "path": "/boot/grub/grub.cfg", "value": "???????r??"}], "no /boot/grub in container")
add(H, "dmesg_restrict", [FC(S, r'^\s*kernel\.dmesg_restrict\s*=\s*1\s*$')])
add(H, "icmp_echo_ignore_broadcasts", [FC(S, r'^\s*net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*1\s*$')])
O = "OFFICIAL(recon)"
add(O, "SSH root login disabled (CP18 R1)", [FCN("/etc/ssh/sshd_config", r'^\s*PermitRootLogin\s+yes')])
add(O, "FTP users may log in with SSL (CP18 R2)", [FC("/etc/vsftpd.conf", r'^\s*ssl_enable\s*=\s*YES')])
add(O, "FTP root dir not world-writable (CP18 R2)", [{"type": "PermissionIsNot", "path": "/srv/ftp", "value": "????????w?"}])
add(O, "IPv4 TCP SYN cookies (CP18 R2)", [FC(S, r'^\s*net\.ipv4\.tcp_syncookies\s*=\s*1')])
add(O, "IPv4 forwarding disabled (CP17 TR2)", [FCN(S, r'^\s*net\.ipv4\.ip_forward\s*=\s*1')])

if __name__ == "__main__":
    tag = sys.argv[1] if len(sys.argv) > 1 else "result"
    res = {}
    for src, msg, conds, note in C:
        vals = [ev(c) for c in conds]
        if "skip" in vals: r = "SKIP"
        else: r = "PASS" if all(vals) else "FAIL"
        res[(src, msg)] = (r, note)
    import json
    json.dump({f"{k[0]}|{k[1]}": v for k, v in res.items()}, open(f"{tag}.json", "w"), indent=0)
    for (src, msg), (r, note) in res.items():
        print(f"{r:4}  {src:17} {msg}" + (f"   [{note}]" if note else ""))
