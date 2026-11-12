#!/bin/bash
# finalize-clean.sh - runs INSIDE the build container after the jammy package set + Mint debs are installed.
# Makes it look like a freshly installed Linux Mint 21.3 Cinnamon with one logged-in admin user (cpuser).
set -e; umask 022
# real Mint has this file (written at install time); mintsystem keeps it identical to its own copy
install -m644 /usr/share/linuxmint/mintsystem/apt/official-package-repositories.pref /etc/apt/preferences.d/official-package-repositories.pref
/usr/lib/linuxmint/mintsystem/mint-adjust.py || true
# Mint-style sources (packages.linuxmint.com line disabled: unreachable), same as the 2026-10-21 pack
: > /etc/apt/sources.list
systemctl set-default graphical.target >/dev/null 2>&1 || ln -sf /lib/systemd/system/graphical.target /etc/systemd/system/default.target
# locale as on a Mint install (the 2026-10-21 image had en_US.UTF-8: PostgreSQL's cluster inherited it)
if [ -f /etc/locale.gen ]; then
    sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen; locale-gen >/dev/null
    update-locale LANG=en_US.UTF-8 2>/dev/null || echo 'LANG=en_US.UTF-8' > /etc/default/locale
fi
# first user, as the Mint installer creates it
for g in adm cdrom sudo dip plugdev lpadmin sambashare; do getent group $g >/dev/null || continue; G="${G:+$G,}$g"; done
id cpuser >/dev/null 2>&1 || useradd -m -u 1000 -s /bin/bash -c "CP User" -G "$G" cpuser
echo 'cpuser:Cpus3r-Passw0rd!' | chpasswd
sudo -u cpuser xdg-user-dirs-update >/dev/null 2>&1 || mkdir -p /home/cpuser/{Desktop,Documents,Downloads,Music,Pictures,Public,Templates,Videos}
chown -R cpuser: /home/cpuser
# build leftovers + files that maintainer scripts created world-writable (docker exec umask is 0000)
rm -f /usr/sbin/policy-rc.d /etc/apt/apt.conf.d/00cptest-norecommends /root/bulk-install.log
rm -rf /tmp/cpbuild
find / -xdev -perm -0002 ! -type l ! -path '/proc/*' ! -path '/tmp' ! -path '/var/tmp' ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/dev/*' -exec chmod o-w {} + 2>/dev/null || true
apt-get clean
rm -rf /var/log/apt/*.log /var/log/dpkg.log.* 2>/dev/null || true
truncate -s0 /etc/machine-id 2>/dev/null || true
echo finalized
