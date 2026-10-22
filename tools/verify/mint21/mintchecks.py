#!/usr/bin/env python3
"""Scores the container: the existing checks.py set (Aperture/1984/recon) + checks for the plants in plant-mint.sh."""
import sys, subprocess, json, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from checks_cp import C, ev, add, FC, FCN
def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True).returncode == 0
CMD = lambda c: {"type": "Cmd", "cmd": c}
P = "PLANTED-MINT"
add(P, "Unauthorized user eve removed", [CMD("! id eve")])
add(P, "Unauthorized user mallory removed", [CMD("! id mallory")])
add(P, "Hidden user sysbackup removed or no shell", [CMD("! id sysbackup || getent passwd sysbackup | grep -qE '(nologin|false)$'")])
add(P, "No UID 0 user except root", [CMD("[ \"$(awk -F: '$3==0' /etc/passwd | cut -d: -f1)\" = root ]")])
add(P, "bob is not an administrator", [CMD("! id -nG bob | tr ' ' '\\n' | grep -qxE 'sudo|adm|admin'")])
add(P, "alice is an administrator", [CMD("id -nG alice | tr ' ' '\\n' | grep -qx sudo")])
add(P, "cpuser still an administrator", [CMD("id -nG cpuser | tr ' ' '\\n' | grep -qx sudo")])
add(P, "carol has a password", [CMD("[ -n \"$(getent shadow carol | cut -d: -f2)\" ]")])
add(P, "No NOPASSWD sudo for bob", [CMD("! grep -rqsE '^[^#]*bob.*NOPASSWD' /etc/sudoers /etc/sudoers.d")])
add(P, "LightDM autologin disabled (all files)", [CMD("! grep -rhsE '^\\s*autologin-user\\s*=\\s*[A-Za-z]' /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.d /usr/share/lightdm/lightdm.conf.d | grep -vq 'NONE' && ! grep -rhsE '^\\s*autologin-user\\s*=\\s*(bob|nancy)' /etc/lightdm /usr/share/lightdm")])
add(P, "LightDM guest disabled", [CMD("! grep -rhsE '^\\s*allow-guest\\s*=\\s*true' /etc/lightdm /usr/share/lightdm")])
for pkg in ["nmap", "john", "hydra", "wireshark", "wireshark-common", "tshark", "aircrack-ng", "ophcrack", "minetest", "netcat-traditional", "telnetd"]:
    add(P, f"Prohibited package {pkg} removed", [CMD(f"! dpkg-query -W -f='${{Status}}' {pkg} 2>/dev/null | grep -q 'ok installed'")])
add(P, "vsftpd (not authorized) stopped or removed", [CMD("! systemctl is-active --quiet vsftpd")])
add(P, "apache2 (not authorized) stopped or removed", [CMD("! systemctl is-active --quiet apache2")])
add(P, "OpenSSH still running (critical)", [CMD("systemctl is-active --quiet ssh && ssh-keyscan -T 3 127.0.0.1 2>/dev/null | grep -q ssh")])
add(P, "Prohibited mp3 in bob's home removed", [{"type": "PathExistsNot", "path": "/home/bob/Music/never_gonna.mp3"}])
add(P, "Prohibited mp4 in carol's home removed", [{"type": "PathExistsNot", "path": "/home/carol/Videos/movie.mp4"}])
add(P, "Hidden ogg in dave's home removed", [{"type": "PathExistsNot", "path": "/home/dave/.local/share/.cache/stash.ogg"}])
add(P, "Hidden mp3 under /usr/share removed", [{"type": "PathExistsNot", "path": "/usr/share/fonts/truetype/.x/track01.mp3"}])
add(P, "Plaintext password file removed", [{"type": "PathExistsNot", "path": "/home/bob/passwords.txt"}])
add(P, "netcat cron backdoor removed", [{"type": "PathExistsNot", "path": "/etc/cron.d/0hourly-sync"}])
add(P, "python http.server backdoor stopped", [CMD("! ss -tlnp | grep -q ':31337 '")])
add(P, "Unknown root authorized_keys removed", [CMD("! grep -qs 'eve@kali' /root/.ssh/authorized_keys")])
add(P, "SSH PermitEmptyPasswords not yes", [FCN("/etc/ssh/sshd_config", r'^\s*PermitEmptyPasswords\s+yes')])
add(P, "SSH drop-in PermitRootLogin yes removed", [CMD("! grep -rqsiE '^\\s*PermitRootLogin\\s+yes' /etc/ssh/sshd_config.d")])
add(P, "Effective sshd PermitRootLogin no", [CMD("sshd -T 2>/dev/null | grep -qx 'permitrootlogin no'")])
add(P, "sysctl.d override of ip_forward removed", [CMD("! grep -rqsE '^\\s*net\\.ipv4\\.ip_forward\\s*=\\s*1' /etc/sysctl.d")])
add(P, "shadow not world readable (perm fixed)", [CMD("[ $(( 0$(stat -c %a /etc/shadow) & 4 )) -eq 0 ]")])
add(P, "pam_pwquality args on common-password line", [FC("/etc/pam.d/common-password", r'pam_pwquality\.so.*dictcheck=1')])
add(P, "Firewall (ufw) active", [CMD("ufw status | grep -q 'Status: active'")])
add(P, "Mint Update Manager installs updates automatically (1984 check)", [{"type": "PathExists", "path": "/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled"}])
add(P, "Root password locked", [CMD("passwd -S root | awk '{print $2}' | grep -qx L")], "manual checklist step")
add(P, "Desktop still installed (cinnamon, lightdm, mint-meta-cinnamon)", [CMD("dpkg -s cinnamon lightdm mint-meta-cinnamon network-manager >/dev/null 2>&1")])
add(P, "cpuser can still sudo (account not expired/locked)", [CMD("chage -l cpuser | grep -q 'Last password change.*[0-9]' && passwd -S cpuser | awk '{print $2}' | grep -qx P")])

import checks_cp
orig = checks_cp.ev
def ev2(c):
    if c["type"] == "Cmd": return sh(c["cmd"])
    return orig(c)
tag = sys.argv[1] if len(sys.argv) > 1 else "result"
res = {}
for src, msg, conds, note in C:
    vals = [ev2(c) for c in conds]
    r = "SKIP" if "skip" in vals else ("PASS" if all(vals) else "FAIL")
    res[f"{src}|{msg}"] = [r, note]
json.dump(res, open(f"/root/logs/score-{tag}.json", "w"), indent=0)
for k, (r, note) in res.items():
    s, m = k.split("|", 1); print(f"{r:4}  {s:17} {m}" + (f"   [{note}]" if note else ""))
tot = [v[0] for v in res.values()]
print(f"\nTOTAL {tag}: PASS {tot.count('PASS')} / FAIL {tot.count('FAIL')} / SKIP {tot.count('SKIP')}")
