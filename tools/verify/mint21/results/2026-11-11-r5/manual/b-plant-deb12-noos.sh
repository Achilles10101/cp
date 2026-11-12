#!/bin/bash
# TEST CONTAINER ONLY - accounts from the real CyberPatriot Intro/R2 Debian 12 README + plants for agent B.
set -u
# (V: os-release NOT faked - keeps systemconfig's Debian sources rewrite out of a jammy container)
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null 2>&1 && echo "openssh-server installed"
mk() { useradd -m -s /bin/bash "$1"; echo "$1:$2" | chpasswd; }
mk pparker 'Fr13ndlyN31ghb0r!'; mk tstark '1AmIr0nM4n!'; mk ppotts 'RunTh3C0mp4ny!'; mk hhogan 'security1'
mk nfury 'D1r3ct0r0fSH13LD'; mk mhill 'D3putyD1r3ct0r!'; mk pcoulson 'V1nt4g3Tr4d1ngC4rds'
for u in pparker tstark ppotts hhogan mhill pcoulson; do usermod -aG sudo "$u"; done   # nfury: admin MISSING from sudo (plant)
for u in bbanner swilson sstrange slang cdanvers okoye kbishop ybelova jfoster nleeds mjwatson jtorres; do mk "$u" 'Us3r-Pass-2026!'; done
# pcarter: README user MISSING (plant)
usermod -aG sudo bbanner                                       # authorized standard user wrongly in sudo (plant)
mk loki 'Mischief!1'; mk thanos 'inevitable'; usermod -aG sudo thanos   # 2 unauthorized users (plant), one an admin
for u in $(awk -F: '$3>=1000 && $3<60000 {print $1}' /etc/passwd); do echo "keep $u" > "/home/$u/keep.txt"; chown "$u:" "/home/$u/keep.txt"; done
getent shadow pparker > /root/pparker.shadow.before
echo planted-ok
