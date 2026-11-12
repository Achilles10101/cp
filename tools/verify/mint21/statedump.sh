#!/bin/bash
# statedump.sh - TEST HARNESS: print the security-relevant state of a container (run-pipeline.sh -> OUTDIR/state.txt),
# so two runs (old vs new scripts) can be diffed beyond the scored checks.
s() { echo; echo "## $1"; }
s sysctl;      sysctl -a 2>/dev/null | grep -E '^(net\.ipv4\.(conf\.(all|default)\.|ip_forward|tcp_syncookies|icmp_)|net\.ipv6\.conf\.(all|default)\.(disable_ipv6|accept_ra|accept_redirects|forwarding)|kernel\.(randomize_va_space|kptr_restrict|dmesg_restrict|yama|sysrq|core_uses_pid|perf_event_paranoid|unprivileged_bpf)|fs\.(suid_dumpable|protected_))' | sort
s sysctl-files; cat /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null | grep -vE '^\s*(#|;|$)' | sort -u
s login.defs;  grep -E '^\s*[A-Z_]+\s' /etc/login.defs | sort
s useradd;     cat /etc/default/useradd 2>/dev/null | grep -vE '^\s*(#|$)'
for f in common-auth common-password common-account common-session; do s "pam $f"; grep -vE '^\s*(#|$)' /etc/pam.d/$f; done
s pwquality;   grep -vE '^\s*(#|$)' /etc/security/pwquality.conf 2>/dev/null
s faillock;    grep -vE '^\s*(#|$)' /etc/security/faillock.conf 2>/dev/null
s limits;      grep -vE '^\s*(#|$)' /etc/security/limits.conf 2>/dev/null
s "sshd -T";   mkdir -p /run/sshd; sshd -T 2>/dev/null | sort
s ufw;         ufw status verbose 2>/dev/null
s accounts;    getent passwd | awk -F: '{print $1, $3, $4, $6, $7}'
s groups;      getent group | awk -F: '$4 != "" || $1 ~ /^(sudo|adm|admin|wheel|root|lpadmin|sambashare)$/ {print $1, $3, $4}'
s shadow;      getent shadow | awk -F: '{h = $2; t = (h == "") ? "EMPTY" : (h ~ /^[!*]/ ? "LOCKED:" substr(h,1,1) : substr(h, 1, 3)); print $1, t, "last=" ($3 == "0" ? "0(forced)" : ($3 ? "set" : "-")), "min=" $4, "max=" $5, "warn=" $6, "inact=" $7, "exp=" $8}'
s gshadow;     awk -F: '$2 != "" && $2 != "!" && $2 != "*" && $2 != "!*" {print $1, "HAS-PASSWORD"}' /etc/gshadow
s sudoers;     cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vE '^\s*(#|$)' | grep -v '^@includedir'
s lightdm;     grep -rHvE '^\s*(#|$)' /etc/lightdm 2>/dev/null
s gdm;         grep -rHvE '^\s*(#|$)' /etc/gdm3/custom.conf /etc/gdm3/daemon.conf 2>/dev/null
s apt-config;  apt-config dump 2>/dev/null | grep -iE 'periodic|unattended-upgrade::(allowed|origins)' | sort
s sources;     grep -hvE '^\s*(#|$)' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null; ls /etc/apt/sources.list.d 2>/dev/null
s holds;       apt-mark showhold 2>/dev/null
s packages-installed; dpkg-query -W -f='${Package}\t${db:Status-Abbrev}\n' 2>/dev/null | awk '$2 ~ /^ii/ {print $1}' | sort
s services-running;   systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}' | sort
s services-enabled;   systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | sort
s listening;   ss -Htuln 2>/dev/null | awk '{print $1, $5}' | sort -u
s perms;       stat -c '%a %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config /etc/crontab /boot/grub/grub.cfg /home /root /home/* /swapfile /etc/hosts.allow /etc/hosts.deny /var/log 2>/dev/null
s suid;        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort
s acl;         getfacl -R -s -p /usr/bin /usr/sbin /etc 2>/dev/null | grep '^# file:' | sort
s world-writable; find /etc /usr /var/www /home /root -xdev -perm -0002 ! -type l 2>/dev/null | sort
s cron;        ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily 2>/dev/null | awk '{print $1, $NF}'; for u in $(cut -d: -f1 /etc/passwd); do c="$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)')"; [ -n "$c" ] && echo "crontab $u: $c"; done
s preload;     cat /etc/ld.so.preload 2>/dev/null
s bashrc-aliases; grep -hE '^\s*alias ' /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh 2>/dev/null
s umask;       grep -hE '^\s*umask' /etc/profile /etc/bash.bashrc /etc/login.defs 2>/dev/null
s media;       find /home /root /usr/share /srv /opt -xdev -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.ogg' -o -iname '*.wav' -o -iname '*.avi' -o -iname '*.mkv' -o -iname '*.flac' \) 2>/dev/null | grep -v '^/usr/share/sounds' | sort
